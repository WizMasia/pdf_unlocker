/**
 * @file test/test_pdf_serializer.js
 * @description Unit tests for PDF serializer and rebuilder.
 *              PDF 직렬화기 및 재작성기 단위 테스트.
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { parsePdf } from '../src/core/pdf_parser.js';
import { unlockPdfDocument } from '../src/core/pdf_decryptor.js';
import { serializePdf } from '../src/core/pdf_serializer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, 'fixtures');

console.log('Testing PDF Serializer & Rebuilder...');

// 1. Serialize unlocked RC4-128 PDF / 복호화된 RC4-128 PDF 직렬화 및 무결성 테스트
const rc4Bytes = fs.readFileSync(path.join(fixturesDir, 'restricted_all_rc4.pdf'));
const docRc4 = parsePdf(rc4Bytes);
const unlockRes = unlockPdfDocument(docRc4, '');
assert.strictEqual(unlockRes.success, true);

const rebuiltBytes = serializePdf(docRc4);
assert.ok(rebuiltBytes instanceof Uint8Array, 'Should return Uint8Array');
assert.ok(rebuiltBytes.length > 0, 'Rebuilt PDF should not be empty');

// Re-parse the rebuilt PDF to verify standard compliance / 재파싱하여 비암호화 무결성 검증
const reparsedDoc = parsePdf(rebuiltBytes);
assert.strictEqual(reparsedDoc.encryptRef, null, 'Rebuilt PDF must not have encryptRef');
assert.strictEqual(reparsedDoc.trailer.has('/Encrypt'), false, 'Trailer must not contain /Encrypt');

// Check stream content in reparsed document
const streamObj4 = reparsedDoc.getObject(4, 0);
assert.ok(streamObj4 && streamObj4.stream, 'Stream object 4 should be preserved');
const streamText = new TextDecoder('utf-8').decode(streamObj4.stream.bytes);
assert.ok(streamText.includes('PDF Permission Unlocker Test'), 'Decrypted stream content preserved');
console.log('  ✓ RC4-128 Rebuilt PDF successfully serialized & verified');

// 2. Serialize unlocked AES-128 PDF / 복호화된 AES-128 PDF 직렬화 테스트
const aesBytes = fs.readFileSync(path.join(fixturesDir, 'restricted_all_aes.pdf'));
const docAes = parsePdf(aesBytes);
unlockPdfDocument(docAes, '');
const rebuiltAesBytes = serializePdf(docAes);

const reparsedAesDoc = parsePdf(rebuiltAesBytes);
assert.strictEqual(reparsedAesDoc.encryptRef, null, 'AES Rebuilt PDF must not have encryptRef');
console.log('  ✓ AES-128 Rebuilt PDF successfully serialized & verified');

console.log('✅ All PDF Serializer tests passed successfully!');
