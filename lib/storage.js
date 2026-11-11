/* Uploaded images live in GridFS, in the same MongoDB instance as the rest of
   the data — no bucket, no CDN, no second service to configure. The same code
   runs against a local mongod and an Atlas cluster; only MONGO_URI differs.

   Files are served back through GET /api/images/:id, which is why the URL we
   store is relative: it keeps working behind whatever host the app is deployed
   on, and it leaves the absolute Steam CDN URLs already in the database alone. */
const crypto = require('crypto');
const mongoose = require('mongoose');

const BUCKET = 'images';

/* Per-kind ceiling. An avatar is rendered at 40px, so 2 MB is already generous;
   cover art gets more room because it is shown full width. */
const KINDS = {
  avatar: { max: 2 * 1024 * 1024 },
  game: { max: 5 * 1024 * 1024 },
  mod: { max: 5 * 1024 * 1024 },
};

const EXT = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
};

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const SIGNATURES = [
  { mime: 'image/jpeg', test: (b) => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { mime: 'image/png', test: (b) => b.length > 8 && b.subarray(0, 8).equals(PNG_SIGNATURE) },
  { mime: 'image/gif', test: (b) => b.length > 6 && b.toString('ascii', 0, 4) === 'GIF8' },
  { mime: 'image/webp', test: (b) => b.length > 12 && b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP' },
];

const URL_RE = /^\/api\/images\/([0-9a-fA-F]{24})$/;

function fail(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

/* The Content-Type header is the client's claim; the first bytes are the
   evidence. SVG is deliberately absent from the list — it can carry script and
   these files are served from the app's own origin. */
function sniff(buffer) {
  const hit = SIGNATURES.find((s) => s.test(buffer));
  return hit ? hit.mime : null;
}

function bucket() {
  const db = mongoose.connection.db;
  if (!db) throw fail(503, 'Database is not connected yet.');
  return new mongoose.mongo.GridFSBucket(db, { bucketName: BUCKET });
}

async function putImage(buffer, { kind = 'avatar', ownerId } = {}) {
  const rule = KINDS[kind];
  if (!rule) throw fail(400, 'Unknown image kind.');
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw fail(400, 'The request body was empty.');
  if (buffer.length > rule.max) {
    throw fail(413, `Image is larger than ${Math.round(rule.max / 1024 / 1024)} MB.`);
  }

  const contentType = sniff(buffer);
  if (!contentType) throw fail(415, 'Only JPEG, PNG, WebP or GIF images are accepted.');

  const id = new mongoose.Types.ObjectId();
  const owner = ownerId ? String(ownerId) : 'anon';
  const filename = `${kind}/${owner}/${Date.now()}-${crypto.randomBytes(6).toString('hex')}.${EXT[contentType]}`;

  await new Promise((resolve, reject) => {
    const stream = bucket().openUploadStreamWithId(id, filename, {
      contentType,
      metadata: { kind, ownerId: ownerId ? String(ownerId) : null },
    });
    stream.on('finish', resolve);
    stream.on('error', reject);
    stream.end(buffer);
  });

  return { id: String(id), url: `/api/images/${id}` };
}

async function openImage(id) {
  if (!mongoose.Types.ObjectId.isValid(id)) throw fail(404, 'Image not found');
  const _id = new mongoose.Types.ObjectId(id);
  const [meta] = await bucket().find({ _id }).limit(1).toArray();
  if (!meta) throw fail(404, 'Image not found');
  return {
    stream: bucket().openDownloadStream(_id),
    contentType: meta.contentType || 'application/octet-stream',
    length: meta.length,
  };
}

async function deleteImage(id) {
  try {
    if (!mongoose.Types.ObjectId.isValid(id)) return false;
    await bucket().delete(new mongoose.Types.ObjectId(id));
    return true;
  } catch {
    // Already gone, or the collection was dropped. Nothing to clean up.
    return false;
  }
}

/* Returns the GridFS id for a URL this module handed out, or null for a URL we
   do not own (a Steam CDN link, a Google avatar, an empty field). */
function idFromUrl(url) {
  const m = typeof url === 'string' ? url.match(URL_RE) : null;
  return m ? m[1] : null;
}

module.exports = { KINDS, sniff, putImage, openImage, deleteImage, idFromUrl };
