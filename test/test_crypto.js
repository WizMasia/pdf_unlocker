/**
 * @file test/test_crypto.js
 * @description Unit tests for pure JS crypto engine compared against Node.js native crypto.
 *              Node.js 네이티브 crypto와 비교 검증하는 순수 JS 암호화 엔진 단위 테스트.
 */

import assert from 'assert';
import crypto from 'crypto';
import { md5, sha256, sha384, sha512, computeHash2A, computeHash2B, rc4, aesEncryptCbc, aesDecryptCbc } from '../src/core/crypto.js';

console.log('Testing Crypto Engine...');

// 1. MD5 Hash Tests against native crypto / 네이티브 crypto와 MD5 비교 검증
const testInputs = [
  Buffer.from(''),
  Buffer.from('PDFPermissionUnlocker'),
  Buffer.from('Standard Security Handler R3 MD5 Key Derivation Test 12345'),
  crypto.randomBytes(64)
];

for (const input of testInputs) {
  const pureMd5 = Buffer.from(md5(input)).toString('hex');
  const nativeMd5 = crypto.createHash('md5').update(input).digest('hex');
  assert.strictEqual(pureMd5, nativeMd5, `MD5 mismatch for input: ${input.toString('utf-8')}`);
}
console.log('  ✓ MD5 tests passed');

// 2. SHA-256 Hash Tests against native crypto / 네이티브 crypto와 SHA-256 비교 검증
for (const input of testInputs) {
  const pureSha = Buffer.from(sha256(input)).toString('hex');
  const nativeSha = crypto.createHash('sha256').update(input).digest('hex');
  assert.strictEqual(pureSha, nativeSha, `SHA-256 mismatch for input: ${input.toString('utf-8')}`);
}
console.log('  ✓ SHA-256 tests passed');

// 2-B. SHA-384 & SHA-512 Hash Tests against native crypto / 네이티브 crypto와 SHA-384, SHA-512 비교 검증
for (const input of testInputs) {
  const pureSha384 = Buffer.from(sha384(input)).toString('hex');
  const nativeSha384 = crypto.createHash('sha384').update(input).digest('hex');
  assert.strictEqual(pureSha384, nativeSha384, `SHA-384 mismatch`);

  const pureSha512 = Buffer.from(sha512(input)).toString('hex');
  const nativeSha512 = crypto.createHash('sha512').update(input).digest('hex');
  assert.strictEqual(pureSha512, nativeSha512, `SHA-512 mismatch`);
}
console.log('  ✓ SHA-384 and SHA-512 tests passed');

// 3. RC4 Stream Cipher Tests / RC4 암복호화 검증
const rc4Key = crypto.randomBytes(16);
const rc4Plain = Buffer.from('Confidential PDF Stream Data for Permission Testing 1234567890');
const rc4Cipher = rc4(rc4Key, rc4Plain);

const rc4Decrypted = rc4(rc4Key, rc4Cipher);
assert.strictEqual(
  Buffer.from(rc4Decrypted).toString('utf-8'),
  rc4Plain.toString('utf-8'),
  'RC4 decrypt mismatch'
);
console.log('  ✓ RC4 tests passed (roundtrip)');

// 4. AES-128-CBC Encryption & Decryption Tests / AES-128-CBC 암복호화 검증
for (let i = 0; i < 5; i++) {
  const key128 = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const plain = Buffer.from(`Testing AES-128-CBC Block ${i}: ${crypto.randomBytes(24).toString('hex')}`);

  // Pure JS encrypt
  const pureCipher = aesEncryptCbc(key128, iv, plain, true);

  // Native Node.js encrypt
  const nativeCipher = crypto.createCipheriv('aes-128-cbc', key128, iv);
  const expectedCipher = Buffer.concat([nativeCipher.update(plain), nativeCipher.final()]);

  assert.strictEqual(
    Buffer.from(pureCipher).toString('hex'),
    expectedCipher.toString('hex'),
    'Pure AES-128-CBC encryption mismatch with Node native crypto'
  );

  // Pure JS decrypt
  const decrypted = aesDecryptCbc(key128, iv, pureCipher, true);
  assert.strictEqual(
    Buffer.from(decrypted).toString('utf-8'),
    plain.toString('utf-8'),
    'AES-128-CBC decryption mismatch'
  );
}
console.log('  ✓ AES-128-CBC encrypt & decrypt tests passed');

// 5. AES-256-CBC Encryption & Decryption Tests / AES-256-CBC 암복호화 검증
for (let i = 0; i < 5; i++) {
  const key256 = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const plain = Buffer.from(`Testing AES-256-CBC Block ${i}: ${crypto.randomBytes(36).toString('hex')}`);

  // Pure JS encrypt
  const pureCipher = aesEncryptCbc(key256, iv, plain, true);

  // Native Node.js encrypt
  const nativeCipher = crypto.createCipheriv('aes-256-cbc', key256, iv);
  const expectedCipher = Buffer.concat([nativeCipher.update(plain), nativeCipher.final()]);

  assert.strictEqual(
    Buffer.from(pureCipher).toString('hex'),
    expectedCipher.toString('hex'),
    'Pure AES-256-CBC encryption mismatch with Node native crypto'
  );

  // Pure JS decrypt
  const decrypted = aesDecryptCbc(key256, iv, pureCipher, true);
  assert.strictEqual(
    Buffer.from(decrypted).toString('utf-8'),
    plain.toString('utf-8'),
    'AES-256-CBC decryption mismatch'
  );
}
console.log('  ✓ AES-256-CBC encrypt & decrypt tests passed');

console.log('🎉 ALL CRYPTO TESTS PASSED!');
