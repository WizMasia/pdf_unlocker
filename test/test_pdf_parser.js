/**
 * @file test/test_pdf_parser.js
 * @description Unit tests for low-level PDF parser and lexer.
 *              저수준 PDF 파서 및 렉서 단위 테스트.
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { parsePdf } from '../src/core/pdf_parser.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, 'fixtures');

console.log('Testing PDF Parser & Lexer...');

// 1. Test parsing unencrypted PDF / 비암호화 PDF 파싱 테스트
const unencryptedBytes = fs.readFileSync(path.join(fixturesDir, 'unencrypted.pdf'));
const docUnencrypted = parsePdf(unencryptedBytes);

assert.ok(docUnencrypted, 'Parsed doc should not be null');
assert.strictEqual(docUnencrypted.headerVersion, '1.6', 'PDF version mismatch');
assert.ok(docUnencrypted.trailer, 'Trailer dictionary should exist');
assert.strictEqual(docUnencrypted.trailer.get('/Root').num, 1, 'Root catalog object mismatch');
assert.strictEqual(docUnencrypted.encryptRef, null, 'Unencrypted PDF should have null encryptRef');
assert.strictEqual(docUnencrypted.objects.size, 5, 'Object count mismatch');
console.log('  ✓ Unencrypted PDF parsed successfully');

// 2. Test parsing permission-restricted PDF / 권한 제한 PDF 파싱 테스트
const restrictedBytes = fs.readFileSync(path.join(fixturesDir, 'restricted_print.pdf'));
const docRestricted = parsePdf(restrictedBytes);

assert.ok(docRestricted.encryptRef, 'Encrypted PDF should have encryptRef');
assert.strictEqual(docRestricted.encryptRef.num, 6, 'Encrypt object reference mismatch');

const encryptObj = docRestricted.getObject(6, 0);
assert.ok(encryptObj && encryptObj.data, 'Encrypt dictionary object should exist');
assert.strictEqual(encryptObj.data.get('/Filter'), '/Standard', 'Filter mismatch');
assert.strictEqual(encryptObj.data.get('/V'), 2, 'V mismatch');
assert.strictEqual(encryptObj.data.get('/R'), 3, 'R mismatch');
assert.strictEqual(encryptObj.data.get('/P'), -8, 'P mismatch');
assert.ok(encryptObj.data.get('/O'), 'O hash should exist');
assert.ok(encryptObj.data.get('/U'), 'U hash should exist');
console.log('  ✓ Encrypted PDF with permissions parsed successfully');

// 3. Test parsing AES encrypted PDF / AES 암호화 PDF 파싱 테스트
const aesBytes = fs.readFileSync(path.join(fixturesDir, 'restricted_all_aes.pdf'));
const docAes = parsePdf(aesBytes);

assert.ok(docAes.encryptRef, 'AES PDF should have encryptRef');
const aesEncObj = docAes.getObject(6, 0);
assert.strictEqual(aesEncObj.data.get('/V'), 4, 'AES V mismatch');
assert.strictEqual(aesEncObj.data.get('/R'), 4, 'AES R mismatch');
console.log('  ✓ AES Encrypted PDF parsed successfully');

console.log('✅ All PDF Parser tests passed successfully!');
