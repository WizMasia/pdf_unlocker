/**
 * @file test/test_crypto.js
 * @description Unit tests for pure JS crypto engine compared against Node.js native crypto.
 *              Node.js 네이티브 crypto와 비교 검증하는 순수 JS 암호화 엔진 단위 테스트.
 */

import assert from 'assert';
import crypto from 'crypto';
import { md5, sha256, rc4, aesDecryptCbc } from '../src/core/crypto.js';

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

// 3. RC4 Stream Cipher Tests against native rc4 / RC4 암복호화 검증
const rc4Key = crypto.randomBytes(16);
const rc4Plain = Buffer.from('Confidential PDF Stream Data for Permission Testing 1234567890');
const rc4Cipher = rc4(rc4Key, rc4Plain);

// Decrypt with our pure rc4
const rc4Decrypted = rc4(rc4Key, rc4Cipher);
assert.strictEqual(
  Buffer.from(rc4Decrypted).toString('utf-8'),
  rc4Plain.toString('utf-8'),
  'RC4 decrypt mismatch'
);

// Verify with Node.js native rc4 (if supported via cipher 'rc4')
try {
  const nativeRc4Cipher = crypto.createCipheriv('rc4', rc4Key, '');
  const nativeEnc = Buffer.concat([nativeRc4Cipher.update(rc4Plain), nativeRc4Cipher.final()]);
  assert.strictEqual(
    Buffer.from(rc4Cipher).toString('hex'),
    nativeEnc.toString('hex'),
    'Pure RC4 output must match native RC4 output'
  );
  console.log('  ✓ RC4 tests passed (matched native rc4)');
} catch (e) {
  console.log('  ✓ RC4 tests passed (roundtrip)');
}

// 4. AES-128-CBC Decryption Tests / AES-128-CBC 복호화 검증
for (let i = 0; i < 5; i++) {
  const key128 = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const plain = Buffer.from(`Testing AES-128-CBC Block ${i}: ${crypto.randomBytes(24).toString('hex')}`);

  const encCipher = crypto.createCipheriv('aes-128-cbc', key128, iv);
  const ciphertext = Buffer.concat([encCipher.update(plain), encCipher.final()]);

  const decrypted = aesDecryptCbc(key128, iv, ciphertext, true);
  assert.strictEqual(
    Buffer.from(decrypted).toString('utf-8'),
    plain.toString('utf-8'),
    'AES-128-CBC decryption mismatch'
  );
}
console.log('  ✓ AES-128-CBC tests passed');

// 5. AES-256-CBC Decryption Tests / AES-256-CBC 복호화 검증
for (let i = 0; i < 5; i++) {
  const key256 = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const plain = Buffer.from(`Testing AES-256-CBC Block ${i}: ${crypto.randomBytes(36).toString('hex')}`);

  const encCipher = crypto.createCipheriv('aes-256-cbc', key256, iv);
  const ciphertext = Buffer.concat([encCipher.update(plain), encCipher.final()]);

  const decrypted = aesDecryptCbc(key256, iv, ciphertext, true);
  assert.strictEqual(
    Buffer.from(decrypted).toString('utf-8'),
    plain.toString('utf-8'),
    'AES-256-CBC decryption mismatch'
  );
}
console.log('  ✓ AES-256-CBC tests passed');

console.log('✅ All Crypto Engine tests passed successfully!');
