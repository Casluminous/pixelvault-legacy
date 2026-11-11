'use strict';
const test = require('node:test');
const assert = require('node:assert');

/* keyCrypto — pure Node crypto, no network or database. */
process.env.KEY_ENCRYPTION_SECRET = 'test-secret-that-is-at-least-32-chars-long';
const { encryptKey, decryptKey, hashKey, makeDemoKey } = require('../lib/keyCrypto');

test('keyCrypto round-trips a plaintext key', () => {
  const plain = 'DEMO-ABCDE-FGHIJ-KLMNO';
  const enc = encryptKey(plain);
  assert.ok(typeof enc === 'string' && enc.split('.').length === 3, 'payload is iv.tag.cipher');
  assert.strictEqual(decryptKey(enc), plain);
});

test('keyCrypto produces a unique ciphertext for the same plaintext', () => {
  assert.notStrictEqual(encryptKey('DEMO-AAAAA-BBBBB-CCCCC'), encryptKey('DEMO-AAAAA-BBBBB-CCCCC'));
});

test('hashKey is deterministic and trims', () => {
  assert.strictEqual(hashKey(' abc '), hashKey('abc'));
  assert.notStrictEqual(hashKey('abc'), hashKey('abd'));
});

test('makeDemoKey is unmistakably a demo key', () => {
  assert.match(makeDemoKey(), /^DEMO-[0-9A-F]{5}-[0-9A-F]{5}-[0-9A-F]{5}$/);
});

/* paymentGateway — the VNPay HMAC-SHA512 signing scheme, in sandbox mode. */
delete process.env.VNP_TMN_CODE;
delete process.env.VNP_HASH_SECRET;
delete process.env.VNP_URL;
process.env.SANDBOX_HASH_SECRET = 'sandbox-secret-for-tests';
const gateway = require('../lib/paymentGateway');

function signedQuery() {
  const url = gateway.createPaymentUrl({
    amount: 250000000,
    orderId: 'PVTEST' + Date.now(),
    orderInfo: 'PixelVault test order',
    ipAddr: '127.0.0.1',
    returnUrl: 'http://127.0.0.1:3000/payment/return',
    locale: 'vn',
  });
  return Object.fromEntries(new URL(url.url).searchParams);
}

test('sandbox payment URL verifies against its own signature', () => {
  assert.strictEqual(gateway.verifyCallback(signedQuery()), true);
});

test('a tampered amount fails signature verification', () => {
  const q = signedQuery();
  q.vnp_Amount = '1';
  assert.strictEqual(gateway.verifyCallback(q), false);
});

test('hmac is deterministic for the same input and secret', () => {
  assert.strictEqual(gateway.hmac('a=1&b=2', 'secret'), gateway.hmac('a=1&b=2', 'secret'));
});

/* storage — the validation half. putImage's rejections all happen before it
   touches GridFS, so they are testable without a database. */
const storage = require('../lib/storage');

const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(16)]);
const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(16)]);
const gif = Buffer.concat([Buffer.from('GIF89a', 'ascii'), Buffer.alloc(16)]);
const webp = Buffer.concat([Buffer.from('RIFF', 'ascii'), Buffer.alloc(4), Buffer.from('WEBP', 'ascii'), Buffer.alloc(16)]);

test('sniff reads the magic bytes, not the extension', () => {
  assert.strictEqual(storage.sniff(png), 'image/png');
  assert.strictEqual(storage.sniff(jpeg), 'image/jpeg');
  assert.strictEqual(storage.sniff(gif), 'image/gif');
  assert.strictEqual(storage.sniff(webp), 'image/webp');
});

test('sniff rejects text and SVG, which could carry script', () => {
  assert.strictEqual(storage.sniff(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"></svg>')), null);
  assert.strictEqual(storage.sniff(Buffer.from('not an image at all')), null);
  assert.strictEqual(storage.sniff(Buffer.alloc(0)), null);
});

test('putImage refuses an unknown kind', async () => {
  await assert.rejects(storage.putImage(png, { kind: 'nope' }), /Unknown image kind/);
});

test('putImage refuses an empty body', async () => {
  await assert.rejects(storage.putImage(Buffer.alloc(0), { kind: 'avatar' }), /empty/);
});

test('putImage enforces the per-kind size ceiling', async () => {
  const tooBig = Buffer.concat([png, Buffer.alloc(2 * 1024 * 1024)]);
  await assert.rejects(storage.putImage(tooBig, { kind: 'avatar' }), /larger than 2 MB/);
});

test('putImage refuses a body that is not a real image', async () => {
  await assert.rejects(storage.putImage(Buffer.from('<svg/>'), { kind: 'avatar' }), /Only JPEG, PNG, WebP or GIF/);
});

test('idFromUrl only claims URLs this module handed out', () => {
  const id = '507f1f77bcf86cd799439011';
  assert.strictEqual(storage.idFromUrl(`/api/images/${id}`), id);
  assert.strictEqual(storage.idFromUrl('https://cdn.cloudflare.steamstatic.com/steam/apps/1/header.jpg'), null);
  assert.strictEqual(storage.idFromUrl(''), null);
  assert.strictEqual(storage.idFromUrl(undefined), null);
});
