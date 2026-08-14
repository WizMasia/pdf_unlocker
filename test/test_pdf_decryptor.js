/**
 * @file test/test_pdf_decryptor.js
 * @description Unit tests for PDF decryptor and permission analyzer.
 *              PDF 복호화기 및 권한 분석기 단위 테스트.
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { parsePdf } from '../src/core/pdf_parser.js';
import { analyzePdfSecurity, unlockPdfDocument } from '../src/core/pdf_decryptor.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, 'fixtures');

console.log('Testing PDF Decryptor & Security Analyzer...');

// 1. Analyze Print Restricted PDF / 인쇄 제한 PDF 분석 테스트
const printPdfBytes = fs.readFileSync(path.join(fixturesDir, 'restricted_print.pdf'));
const docPrint = parsePdf(printPdfBytes);
const printSec = analyzePdfSecurity(docPrint);

assert.strictEqual(printSec.isEncrypted, true, 'Should be encrypted');
assert.strictEqual(printSec.permissions.canPrint, false, 'Printing should be restricted');
assert.strictEqual(printSec.permissions.canCopy, true, 'Copying should be allowed');
assert.strictEqual(printSec.requiresPassword, false, 'Should not require user password');
console.log('  ✓ Print restriction analysis passed');

// 2. Analyze Copy Restricted PDF / 클립보드 복사 제한 PDF 분석 테스트
const copyPdfBytes = fs.readFileSync(path.join(fixturesDir, 'restricted_copy.pdf'));
const docCopy = parsePdf(copyPdfBytes);
const copySec = analyzePdfSecurity(docCopy);

assert.strictEqual(copySec.isEncrypted, true, 'Should be encrypted');
assert.strictEqual(copySec.permissions.canCopy, false, 'Copying should be restricted');
assert.strictEqual(copySec.permissions.canPrint, true, 'Printing should be allowed');
console.log('  ✓ Copy restriction analysis passed');

// 3. Analyze Modify Restricted PDF / 수정 제한 PDF 분석 테스트
const modifyPdfBytes = fs.readFileSync(path.join(fixturesDir, 'restricted_modify.pdf'));
const docModify = parsePdf(modifyPdfBytes);
const modSec = analyzePdfSecurity(docModify);

assert.strictEqual(modSec.permissions.canModify, false, 'Modifying should be restricted');
assert.strictEqual(modSec.permissions.canAnnotate, false, 'Annotations should be restricted');
console.log('  ✓ Modify restriction analysis passed');

// 4. Test Unlocking RC4-128 Encrypted Document / RC4-128 권한 해제 및 스트림 복호화 검증
const allRc4Bytes = fs.readFileSync(path.join(fixturesDir, 'restricted_all_rc4.pdf'));
const docAllRc4 = parsePdf(allRc4Bytes);
const unlockResRc4 = unlockPdfDocument(docAllRc4, '');

assert.strictEqual(unlockResRc4.success, true, 'Unlock should succeed');
const streamObj4 = docAllRc4.getObject(4, 0);
assert.ok(streamObj4 && streamObj4.stream, 'Stream object 4 should exist');
const streamTextRc4 = new TextDecoder('utf-8').decode(streamObj4.stream.bytes);
assert.ok(streamTextRc4.includes('Confidential Document Content for Testing'), 'Decrypted plaintext stream mismatch');
console.log('  ✓ RC4-128 Permission unlock and stream decryption passed');

// 5. Test Unlocking AES-128 Encrypted Document / AES-128 권한 해제 및 스트림 복호화 검증
const allAesBytes = fs.readFileSync(path.join(fixturesDir, 'restricted_all_aes.pdf'));
const docAllAes = parsePdf(allAesBytes);
const unlockResAes = unlockPdfDocument(docAllAes, '');

assert.strictEqual(unlockResAes.success, true, 'Unlock AES should succeed');
const streamObj4Aes = docAllAes.getObject(4, 0);
const streamTextAes = new TextDecoder('utf-8').decode(streamObj4Aes.stream.bytes);
assert.ok(streamTextAes.includes('Confidential Document Content for Testing'), 'Decrypted AES stream mismatch');
console.log('  ✓ AES-128 Permission unlock and stream decryption passed');

// 6. User Password Protected Document / 열기 비밀번호 문서 테스트
const passPdfBytes = fs.readFileSync(path.join(fixturesDir, 'password_open.pdf'));
const docPass = parsePdf(passPdfBytes);
const passSec = analyzePdfSecurity(docPass);
assert.strictEqual(passSec.requiresPassword, true, 'Should detect required user password');

// Unlock with wrong password -> fail
const failUnlock = unlockPdfDocument(docPass, 'wrongpassword');
assert.strictEqual(failUnlock.success, false, 'Should fail with wrong password');

// Unlock with correct password -> succeed
const passUnlock = unlockPdfDocument(docPass, 'secret123');
assert.strictEqual(passUnlock.success, true, 'Should succeed with correct password');
console.log('  ✓ User password protected unlock passed');

console.log('✅ All PDF Decryptor tests passed successfully!');
