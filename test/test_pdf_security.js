/**
 * @file test/test_pdf_security.js
 * @description Unit tests for PDF permission control, standard security handler, and cryptographic re-encryption.
 *              PDF 권한 제어, 표준 보안 핸들러 및 암호화/복호화 엔진 단위 테스트.
 */

import assert from 'assert';
import { parsePdf } from '../src/core/pdf_parser.js';
import {
  parsePermissions,
  buildPermissions,
  analyzeSecurity,
  unlockDocument,
  changeDocumentPermissions,
  PDF_PERM_FLAGS
} from '../src/core/pdf_security.js';
import { serializePdf } from '../src/core/pdf_serializer.js';

console.log('Testing PDF Security & Permission Engine...');

// Sample Minimal Valid Unencrypted PDF
function createSamplePdf() {
  const content = `%PDF-1.7
1 0 obj
<<
  /Type /Catalog
  /Pages 2 0 R
>>
endobj
2 0 obj
<<
  /Type /Pages
  /Kids [3 0 R]
  /Count 1
>>
endobj
3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 612 792]
  /Contents 4 0 R
>>
endobj
4 0 obj
<<
  /Length 44
>>
stream
BT
/F1 24 Tf
100 700 Td
(Hello World) Tj
ET
endstream
endobj
trailer
<<
  /Root 1 0 R
  /ID [<1234567890abcdef1234567890abcdef> <1234567890abcdef1234567890abcdef>]
>>
startxref
340
%%EOF
`;
  return new TextEncoder().encode(content);
}

// 1. Test Permission Bitmask Encoding and Decoding
console.log('  Testing Permission bitmask conversion...');
{
  const fullPerm = parsePermissions(-4);
  assert.strictEqual(fullPerm.canPrint, true);
  assert.strictEqual(fullPerm.canPrintHighQuality, true);
  assert.strictEqual(fullPerm.canCopy, true);
  assert.strictEqual(fullPerm.canModify, true);
  assert.strictEqual(fullPerm.canAnnotate, true);
  assert.strictEqual(fullPerm.canFillForms, true);
  assert.strictEqual(fullPerm.canExtractAccessibility, true);
  assert.strictEqual(fullPerm.canAssemble, true);

  // Custom bitmask: No Printing, No Copying
  const p1 = buildPermissions({
    canPrint: false,
    canCopy: false,
    canModify: true
  });
  const parsed1 = parsePermissions(p1);
  assert.strictEqual(parsed1.canPrint, false);
  assert.strictEqual(parsed1.canPrintHighQuality, false);
  assert.strictEqual(parsed1.canCopy, false);
  assert.strictEqual(parsed1.canModify, true);

  // Low-resolution print only (150 dpi)
  const p2 = buildPermissions({
    canPrint: true,
    canPrintHighQuality: false,
    canCopy: true
  });
  const parsed2 = parsePermissions(p2);
  assert.strictEqual(parsed2.canPrint, true);
  assert.strictEqual(parsed2.canPrintHighQuality, false);
  assert.strictEqual(parsed2.canCopy, true);

  console.log('  ✓ Permission bitmask tests passed');
}

// 2. Test Applying Permission Restrictions with AES-128 (Stirling-PDF style)
console.log('  Testing Change Permissions with AES-128...');
{
  const sampleBytes = createSamplePdf();
  const doc = parsePdf(sampleBytes);

  const initialSec = analyzeSecurity(doc);
  assert.strictEqual(initialSec.isEncrypted, false);

  // Apply restrictions: Deny printing & Deny text copying
  const result = changeDocumentPermissions(doc, {
    permissions: {
      canPrint: false,
      canCopy: false,
      canModify: false,
      canAnnotate: true
    },
    ownerPassword: 'SecretOwnerPassword123',
    userPassword: '', // Openable without password, permissions enforced
    algorithm: 'AES-128'
  });

  assert.strictEqual(result.success, true);
  assert.strictEqual(result.permissions.canPrint, false);
  assert.strictEqual(result.permissions.canCopy, false);

  // Serialize to new PDF binary
  const securedBytes = serializePdf(doc);
  assert.ok(securedBytes.length > sampleBytes.length);

  // Parse back the generated PDF and analyze security
  const securedDoc = parsePdf(securedBytes);
  const securedAnalysis = analyzeSecurity(securedDoc);

  assert.strictEqual(securedAnalysis.isEncrypted, true);
  assert.strictEqual(securedAnalysis.requiresPassword, false, 'User password is empty so opening does not require password');
  assert.strictEqual(securedAnalysis.permissions.canPrint, false, 'Printing must be restricted');
  assert.strictEqual(securedAnalysis.permissions.canCopy, false, 'Copying must be restricted');
  assert.strictEqual(securedAnalysis.permissions.canModify, false, 'Modifying must be restricted');
  assert.strictEqual(securedAnalysis.permissions.canAnnotate, true, 'Annotating must be allowed');

  console.log('  ✓ AES-128 Change Permissions passed');
}

// 3. Test Applying Permission Restrictions with RC4-128
console.log('  Testing Change Permissions with RC4-128...');
{
  const sampleBytes = createSamplePdf();
  const doc = parsePdf(sampleBytes);

  const result = changeDocumentPermissions(doc, {
    permissions: {
      canPrint: true,
      canPrintHighQuality: false, // Low-res only
      canCopy: false
    },
    ownerPassword: 'RC4OwnerPass456',
    userPassword: '',
    algorithm: 'RC4-128'
  });

  assert.strictEqual(result.success, true);

  const securedBytes = serializePdf(doc);
  const securedDoc = parsePdf(securedBytes);
  const sec = analyzeSecurity(securedDoc);

  assert.strictEqual(sec.isEncrypted, true);
  assert.strictEqual(sec.permissions.canPrint, true);
  assert.strictEqual(sec.permissions.canPrintHighQuality, false);
  assert.strictEqual(sec.permissions.canCopy, false);

  console.log('  ✓ RC4-128 Change Permissions passed');
}

// 4. Test Re-configuring Permissions on an already protected PDF
console.log('  Testing Re-configuring Permissions on an encrypted PDF...');
{
  const sampleBytes = createSamplePdf();
  const doc = parsePdf(sampleBytes);

  // First lock: No print, No copy
  changeDocumentPermissions(doc, {
    permissions: { canPrint: false, canCopy: false },
    ownerPassword: 'InitialOwnerPassword',
    userPassword: '',
    algorithm: 'AES-128'
  });

  const lockedBytes = serializePdf(doc);

  // Now re-open locked PDF and change permissions: Allow printing, but keep copy forbidden
  const reloadedDoc = parsePdf(lockedBytes);
  const reResult = changeDocumentPermissions(reloadedDoc, {
    permissions: { canPrint: true, canPrintHighQuality: true, canCopy: false },
    ownerPassword: 'NewOwnerPassword999',
    userPassword: '',
    algorithm: 'AES-128'
  });

  assert.strictEqual(reResult.success, true);
  const reSerialized = serializePdf(reloadedDoc);
  const finalDoc = parsePdf(reSerialized);
  const finalSec = analyzeSecurity(finalDoc);

  assert.strictEqual(finalSec.isEncrypted, true);
  assert.strictEqual(finalSec.permissions.canPrint, true);
  assert.strictEqual(finalSec.permissions.canPrintHighQuality, true);
  assert.strictEqual(finalSec.permissions.canCopy, false);

  console.log('  ✓ Re-configuring permissions on protected PDF passed');
}

// 5. Test User Password Protected PDF + Permission Unlock
console.log('  Testing User Password Protection and 1-Click Complete Unlock...');
{
  const sampleBytes = createSamplePdf();
  const doc = parsePdf(sampleBytes);

  // Apply user password
  changeDocumentPermissions(doc, {
    permissions: { canPrint: false },
    ownerPassword: 'MasterPassword',
    userPassword: 'UserSecret123',
    algorithm: 'AES-128'
  });

  const lockedBytes = serializePdf(doc);
  const loadedDoc = parsePdf(lockedBytes);
  const sec = analyzeSecurity(loadedDoc);

  assert.strictEqual(sec.isEncrypted, true);
  assert.strictEqual(sec.requiresPassword, true, 'Must require user password');

  // Attempt unlock with wrong password
  const failUnlock = unlockDocument(loadedDoc, 'WrongPassword');
  assert.strictEqual(failUnlock.success, false);

  // Unlock with correct password
  const successUnlock = unlockDocument(loadedDoc, 'UserSecret123');
  assert.strictEqual(successUnlock.success, true);

  const unlockedBytes = serializePdf(loadedDoc);
  const unlockedDoc = parsePdf(unlockedBytes);
  const unlockedSec = analyzeSecurity(unlockedDoc);

  assert.strictEqual(unlockedSec.isEncrypted, false, 'Document should be completely unencrypted after unlock');
  assert.strictEqual(unlockedSec.permissions.canPrint, true);

  console.log('  ✓ Password Protection and Complete Unlock passed');
}

console.log('✅ All PDF Security & Permission Engine tests passed successfully!');
