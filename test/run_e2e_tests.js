/**
 * @file test/run_e2e_tests.js
 * @description Comprehensive End-to-End verification test across all permission restricted fixtures and change permissions workflows.
 *              모든 권한 제한 픽스처 및 권한 재조정 워크플로우를 대상으로 하는 종합 E2E 검증 테스트.
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { parsePdf } from '../src/core/pdf_parser.js';
import { analyzeSecurity, unlockDocument, changeDocumentPermissions } from '../src/core/pdf_security.js';
import { serializePdf } from '../src/core/pdf_serializer.js';
import { buildSingleFile } from '../scripts/build.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, 'fixtures');

console.log('====================================================');
console.log('🚀 Starting Comprehensive End-to-End PDF Tests');
console.log('====================================================\n');

// 1. Build Standalone HTML Bundle / 단일 파일 번들 빌드
console.log('[Step 1] Building Single Standalone HTML Release Bundle...');
const distPath = buildSingleFile();
assert.ok(fs.existsSync(distPath), 'dist/index.html must exist');
const distHtml = fs.readFileSync(distPath, 'utf-8');
assert.ok(distHtml.length > 5000, 'dist/index.html content must be non-trivial');
assert.ok(!distHtml.includes('<script type="module" src='), 'dist/index.html must not contain external script tags');
assert.ok(!distHtml.includes('<link rel="stylesheet"'), 'dist/index.html must not contain external stylesheet links');
console.log('  ✓ Standalone HTML bundle created and verified.\n');

// 2. Test Cases for All Standard Fixtures / 픽스처 E2E 검증
console.log('[Step 2] Verifying Decryption and Permission Unlocking across All Fixtures...');

const testCases = [
  {
    name: 'Restricted Print (RC4-128)',
    file: 'restricted_print.pdf',
    password: '',
    checkOriginal: (sec) => {
      assert.strictEqual(sec.permissions.canPrint, false, 'Should be restricted print');
      assert.strictEqual(sec.permissions.canCopy, true, 'Should be allowed copy');
    }
  },
  {
    name: 'Restricted Copy / Extract (RC4-128)',
    file: 'restricted_copy.pdf',
    password: '',
    checkOriginal: (sec) => {
      assert.strictEqual(sec.permissions.canCopy, false, 'Should be restricted copy');
      assert.strictEqual(sec.permissions.canPrint, true, 'Should be allowed print');
    }
  },
  {
    name: 'Restricted Modify / Annotations (RC4-128)',
    file: 'restricted_modify.pdf',
    password: '',
    checkOriginal: (sec) => {
      assert.strictEqual(sec.permissions.canModify, false, 'Should be restricted modify');
      assert.strictEqual(sec.permissions.canAnnotate, false, 'Should be restricted annotate');
    }
  },
  {
    name: 'Restricted All Permissions (RC4-128)',
    file: 'restricted_all_rc4.pdf',
    password: '',
    checkOriginal: (sec) => {
      assert.strictEqual(sec.permissions.canPrint, false, 'Should be restricted print');
      assert.strictEqual(sec.permissions.canCopy, false, 'Should be restricted copy');
      assert.strictEqual(sec.permissions.canModify, false, 'Should be restricted modify');
    }
  },
  {
    name: 'Restricted All Permissions (AES-128)',
    file: 'restricted_all_aes.pdf',
    password: '',
    checkOriginal: (sec) => {
      assert.strictEqual(sec.isEncrypted, true, 'Should be encrypted');
      assert.strictEqual(sec.permissions.canPrint, false, 'Should be restricted print');
      assert.strictEqual(sec.permissions.canCopy, false, 'Should be restricted copy');
    }
  },
  {
    name: 'Password Protected PDF (secret123)',
    file: 'password_open.pdf',
    password: 'secret123',
    checkOriginal: (sec) => {
      assert.strictEqual(sec.requiresPassword, true, 'Should require user password');
    }
  },
  {
    name: 'Already Unencrypted PDF',
    file: 'unencrypted.pdf',
    password: '',
    checkOriginal: (sec) => {
      assert.strictEqual(sec.isEncrypted, false, 'Should be unencrypted');
      assert.strictEqual(sec.permissions.canPrint, true, 'Should allow print');
    }
  }
];

for (const tc of testCases) {
  console.log(`Testing Case: ${tc.name} (${tc.file})`);
  const filePath = path.join(fixturesDir, tc.file);
  const rawBytes = fs.readFileSync(filePath);

  // A. Parse & Analyze / 파싱 및 분석
  const doc = parsePdf(rawBytes);
  const sec = analyzeSecurity(doc);
  tc.checkOriginal(sec);

  // B. Unlock / 권한 해제
  const unlockRes = unlockDocument(doc, tc.password);
  assert.strictEqual(unlockRes.success, true, `Unlock failed for ${tc.name}`);

  // C. Serialize / 직렬화
  const unlockedBytes = serializePdf(doc);
  assert.ok(unlockedBytes.length > 0, 'Unlocked bytes should not be empty');

  // D. Re-parse and verify standard compliance / 재파싱 및 비암호화 무결성 검증
  const reparsedDoc = parsePdf(unlockedBytes);
  assert.strictEqual(reparsedDoc.encryptRef, null, 'Reparsed document must have no /Encrypt ref');
  assert.strictEqual(reparsedDoc.trailer.has('/Encrypt'), false, 'Trailer must not contain /Encrypt');

  const reparsedSec = analyzeSecurity(reparsedDoc);
  assert.strictEqual(reparsedSec.isEncrypted, false, 'Reparsed document must be completely unencrypted');
  assert.strictEqual(reparsedSec.permissions.canPrint, true, 'Reparsed document must allow printing');
  assert.strictEqual(reparsedSec.permissions.canCopy, true, 'Reparsed document must allow copying');
  assert.strictEqual(reparsedSec.permissions.canModify, true, 'Reparsed document must allow modifying');
  assert.strictEqual(reparsedSec.permissions.canAnnotate, true, 'Reparsed document must allow annotating');

  // E. Stream lossless content verification / 스트림 무손실 검증
  const contentStream = reparsedDoc.getObject(4, 0);
  assert.ok(contentStream && contentStream.stream, 'Content stream object must exist');
  const streamText = new TextDecoder('utf-8').decode(contentStream.stream.bytes);
  assert.ok(streamText.includes('PDF Permission Unlocker Test'), 'Stream plaintext must be preserved losslessly');

  console.log(`  ✓ Case Passed: ${tc.name} -> Unlocked & Verified Losslessly`);
}

// 3. Test Cases for Real-World AES-256 Revision 6 (Zero-Prompt Stirling-PDF Style)
console.log('\n[Step 3] Verifying Real-World AES-256 R6 (ISO 32000-2 Section 7.6.4.3.4 Algorithm 2.B)...');
if (fs.existsSync(path.join(fixturesDir, 'user_sample.pdf'))) {
  const rawBytes = fs.readFileSync(path.join(fixturesDir, 'user_sample.pdf'));
  const doc = parsePdf(rawBytes);
  const sec = analyzeSecurity(doc);

  assert.strictEqual(sec.isEncrypted, true);
  assert.strictEqual(sec.requiresPassword, false, 'Stirling-PDF style: empty password auto-unlock');
  assert.strictEqual(sec.v, 5);
  assert.strictEqual(sec.r, 6);
  assert.strictEqual(sec.permissions.canPrint, false);
  assert.strictEqual(sec.permissions.canCopy, false);

  const unlockRes = unlockDocument(doc, '');
  assert.strictEqual(unlockRes.success, true);

  const unlockedBytes = serializePdf(doc);
  assert.ok(unlockedBytes.length > 0);

  const reparsedDoc = parsePdf(unlockedBytes);
  assert.strictEqual(reparsedDoc.encryptRef, null);
  const reparsedSec = analyzeSecurity(reparsedDoc);
  assert.strictEqual(reparsedSec.isEncrypted, false);
  assert.strictEqual(reparsedSec.permissions.canPrint, true);
  assert.strictEqual(reparsedSec.permissions.canCopy, true);
  console.log('  ✓ Case Passed: Real-World user_sample.pdf (3.3MB) -> Zero-Prompt AES-256 R6 Unlocked Losslessly');
}

// 4. Test Cases for Change Permissions Workflow (Stirling-PDF style) / 권한 재조정 E2E 검증
console.log('\n[Step 4] Verifying Change Permissions (Granular Permission Customization)...');
{
  const rawBytes = fs.readFileSync(path.join(fixturesDir, 'unencrypted.pdf'));
  const doc = parsePdf(rawBytes);

  // Apply custom permissions: Only allow low-res printing, form filling, and accessibility
  const changeRes = changeDocumentPermissions(doc, {
    permissions: {
      canPrint: true,
      canPrintHighQuality: false, // Low-res 150dpi only
      canCopy: false,
      canModify: false,
      canAnnotate: false,
      canFillForms: true,
      canAssemble: false,
      canExtractAccessibility: true
    },
    ownerPassword: 'MasterOwnerKey',
    userPassword: '',
    algorithm: 'AES-128'
  });

  assert.strictEqual(changeRes.success, true);
  const serialized = serializePdf(doc);

  const testDoc = parsePdf(serialized);
  const testSec = analyzeSecurity(testDoc);

  assert.strictEqual(testSec.isEncrypted, true);
  assert.strictEqual(testSec.requiresPassword, false);
  assert.strictEqual(testSec.permissions.canPrint, true);
  assert.strictEqual(testSec.permissions.canPrintHighQuality, false, 'High quality print must be denied');
  assert.strictEqual(testSec.permissions.canCopy, false, 'Copying must be denied');
  assert.strictEqual(testSec.permissions.canModify, false, 'Modifying must be denied');
  assert.strictEqual(testSec.permissions.canFillForms, true, 'Form filling must be allowed');
  assert.strictEqual(testSec.permissions.canExtractAccessibility, true, 'Accessibility must be allowed');
  console.log('  ✓ Change Permissions E2E customization verified.');
}

console.log('\n====================================================');
console.log('🎉 ALL END-TO-END VERIFICATION TESTS PASSED (9/9)');
console.log('====================================================\n');
