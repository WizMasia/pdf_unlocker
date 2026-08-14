/**
 * @file test/generate_fixtures.js
 * @description Generates standard-compliant encrypted/permission-restricted PDF fixtures.
 *              표준 규격을 준수하는 권한 제한/암호화 테스트용 PDF 파일들을 바이너리 레벨에서 직접 생성합니다.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { md5, rc4, aesDecryptCbc } from '../src/core/crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, 'fixtures');

if (!fs.existsSync(fixturesDir)) {
  fs.mkdirSync(fixturesDir, { recursive: true });
}

// Standard 32-byte password padding string per PDF specification (ISO 32000-1)
// PDF 표준 32바이트 패스워드 패딩 바이트
const PAD = new Uint8Array([
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
  0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
  0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
]);

/**
 * Computes PDF encryption key for Rev 2, 3, 4.
 * PDF R2, R3, R4용 문서 암호화 키를 계산합니다.
 */
function computeKey(userPassword, ownerHash, pVal, idFirst, keyLength = 16, rVal = 3, encryptMetadata = true) {
  const pwBytes = Buffer.from(userPassword, 'binary');
  const userPad = new Uint8Array(32);
  const copyLen = Math.min(pwBytes.length, 32);
  for (let i = 0; i < copyLen; i++) userPad[i] = pwBytes[i];
  for (let i = copyLen; i < 32; i++) userPad[i] = PAD[i - copyLen];

  let buf = Buffer.concat([
    Buffer.from(userPad),
    Buffer.from(ownerHash),
    Buffer.from([pVal & 0xff, (pVal >> 8) & 0xff, (pVal >> 16) & 0xff, (pVal >> 24) & 0xff]),
    Buffer.from(idFirst)
  ]);

  if (rVal >= 4 && !encryptMetadata) {
    buf = Buffer.concat([buf, Buffer.from([0xff, 0xff, 0xff, 0xff])]);
  }

  let hash = md5(buf);
  if (rVal >= 3) {
    for (let i = 0; i < 50; i++) {
      hash = md5(hash.subarray(0, keyLength));
    }
  }
  return hash.subarray(0, keyLength);
}

/**
 * Computes Owner Hash (O) for Rev 2 & 3.
 */
function computeOwnerHash(ownerPassword, userPassword, keyLength = 16, rVal = 3) {
  const pw = ownerPassword || userPassword || '';
  const pwBytes = Buffer.from(pw, 'binary');
  const pad = new Uint8Array(32);
  const copyLen = Math.min(pwBytes.length, 32);
  for (let i = 0; i < copyLen; i++) pad[i] = pwBytes[i];
  for (let i = copyLen; i < 32; i++) pad[i] = PAD[i - copyLen];

  let key = md5(pad);
  if (rVal >= 3) {
    for (let i = 0; i < 50; i++) {
      key = md5(key.subarray(0, keyLength));
    }
  }
  key = key.subarray(0, keyLength);

  const userPwBytes = Buffer.from(userPassword || '', 'binary');
  const userPad = new Uint8Array(32);
  const uCopyLen = Math.min(userPwBytes.length, 32);
  for (let i = 0; i < uCopyLen; i++) userPad[i] = userPwBytes[i];
  for (let i = uCopyLen; i < 32; i++) userPad[i] = PAD[i - uCopyLen];

  let encrypted = rc4(key, userPad);
  if (rVal >= 3) {
    for (let i = 1; i <= 19; i++) {
      const iterKey = new Uint8Array(key.length);
      for (let j = 0; j < key.length; j++) iterKey[j] = key[j] ^ i;
      encrypted = rc4(iterKey, encrypted);
    }
  }
  return encrypted;
}

/**
 * Computes User Hash (U) for Rev 2 & 3.
 */
function computeUserHash(fek, idFirst, rVal = 3) {
  if (rVal === 2) {
    return rc4(fek, PAD);
  }
  // R3
  const hash = md5(Buffer.concat([Buffer.from(PAD), Buffer.from(idFirst)]));
  let encrypted = rc4(fek, hash);
  for (let i = 1; i <= 19; i++) {
    const iterKey = new Uint8Array(fek.length);
    for (let j = 0; j < fek.length; j++) iterKey[j] = fek[j] ^ i;
    encrypted = rc4(iterKey, encrypted);
  }
  const result = new Uint8Array(32);
  result.set(encrypted, 0);
  // Pad remaining 16 bytes arbitrarily
  for (let i = 16; i < 32; i++) result[i] = 0x20;
  return result;
}

/**
 * Computes object-specific encryption key.
 */
function computeObjectKey(fek, objNum, genNum, isAes = false) {
  const data = new Uint8Array(fek.length + 5 + (isAes ? 4 : 0));
  data.set(fek, 0);
  data[fek.length + 0] = objNum & 0xff;
  data[fek.length + 1] = (objNum >> 8) & 0xff;
  data[fek.length + 2] = (objNum >> 16) & 0xff;
  data[fek.length + 3] = genNum & 0xff;
  data[fek.length + 4] = (genNum >> 8) & 0xff;
  if (isAes) {
    data[fek.length + 5] = 0x73; // 's'
    data[fek.length + 6] = 0x41; // 'A'
    data[fek.length + 7] = 0x6c; // 'l'
    data[fek.length + 8] = 0x54; // 'T'
  }
  const hash = md5(data);
  const keyLen = Math.min(fek.length + 5, 16);
  return hash.subarray(0, keyLen);
}

/**
 * Builds and encrypts a test PDF document.
 */
function createTestPdf({
  filename,
  pVal = -4, // Default all allowed
  userPassword = '',
  ownerPassword = 'OwnerMasterPassword123',
  vVal = 2,  // 1: RC4-40, 2: RC4-128, 4: AES-128
  rVal = 3,  // 2, 3, 4
  cipherType = 'RC4', // 'RC4' or 'AES'
  isUnencrypted = false
}) {
  const idFirst = crypto.randomBytes(16);
  const idSecond = crypto.randomBytes(16);
  const idStr = `<${idFirst.toString('hex')}><${idSecond.toString('hex')}>`;

  let fek = null;
  let oHash = null;
  let uHash = null;
  const keyLength = (vVal === 1) ? 5 : 16;

  if (!isUnencrypted) {
    oHash = computeOwnerHash(ownerPassword, userPassword, keyLength, rVal);
    fek = computeKey(userPassword, oHash, pVal, idFirst, keyLength, rVal);
    uHash = computeUserHash(fek, idFirst, rVal);
  }

  // Object Contents
  const obj1Content = '<< /Type /Catalog /Pages 2 0 R >>';
  const obj2Content = '<< /Type /Pages /Kids [3 0 R] /Count 1 >>';
  const obj3Content = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>';
  
  const streamPlain = `BT /F1 24 Tf 50 700 Td (PDF Permission Unlocker Test: ${filename}) Tj ET\n` +
                      `BT /F1 14 Tf 50 650 Td (Testing Permission Flags: P=${pVal}) Tj ET\n` +
                      `BT /F1 12 Tf 50 600 Td (Confidential Document Content for Testing Extraction and Print) Tj ET`;

  let streamBytes = Buffer.from(streamPlain, 'utf-8');

  // Encrypt stream 4 0 if encrypted
  if (!isUnencrypted) {
    const objKey = computeObjectKey(fek, 4, 0, cipherType === 'AES');
    if (cipherType === 'AES') {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-128-cbc', objKey, iv);
      const enc = Buffer.concat([cipher.update(streamBytes), cipher.final()]);
      streamBytes = Buffer.concat([iv, enc]);
    } else {
      streamBytes = Buffer.from(rc4(objKey, streamBytes));
    }
  }

  const obj4Content = `<< /Length ${streamBytes.length} >>\nstream\n` + streamBytes.toString('binary') + `\nendstream`;
  const obj5Content = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';

  // Build Objects
  const objects = [
    { num: 1, content: obj1Content },
    { num: 2, content: obj2Content },
    { num: 3, content: obj3Content },
    { num: 4, content: obj4Content, isRaw: true },
    { num: 5, content: obj5Content }
  ];

  if (!isUnencrypted) {
    let encDict = `<< /Filter /Standard /V ${vVal} /R ${rVal} /Length ${keyLength * 8} /P ${pVal} ` +
                  `/O <${Buffer.from(oHash).toString('hex')}> /U <${Buffer.from(uHash).toString('hex')}>`;
    if (vVal === 4) {
      encDict += ` /CF << /StdCF << /Type /CryptFilter /CFM /AESV2 /AuthEvent /DocOpen /Length 16 >> >> /StmF /StdCF /StrF /StdCF`;
    }
    encDict += ` >>`;
    objects.push({ num: 6, content: encDict });
  }

  // Assemble PDF string / PDF 바이너리 조립
  let pdf = `%PDF-1.6\n%\xE2\xE3\xCF\xD3\n`;
  const offsets = [];

  for (const obj of objects) {
    offsets.push({ num: obj.num, offset: Buffer.byteLength(pdf, 'binary') });
    pdf += `${obj.num} 0 obj\n${obj.content}\nendobj\n`;
  }

  const startXref = Buffer.byteLength(pdf, 'binary');
  const maxObjNum = objects.length;
  pdf += `xref\n0 ${maxObjNum + 1}\n`;
  pdf += `0000000000 65535 f \n`;

  for (let i = 1; i <= maxObjNum; i++) {
    const item = offsets.find(o => o.num === i);
    const offStr = String(item ? item.offset : 0).padStart(10, '0');
    pdf += `${offStr} 00000 n \n`;
  }

  pdf += `trailer\n<< /Size ${maxObjNum + 1} /Root 1 0 R /ID [${idStr}]`;
  if (!isUnencrypted) {
    pdf += ` /Encrypt 6 0 R`;
  }
  pdf += ` >>\nstartxref\n${startXref}\n%%EOF\n`;

  const targetPath = path.join(fixturesDir, filename);
  fs.writeFileSync(targetPath, Buffer.from(pdf, 'binary'));
  console.log(`Generated fixture: ${filename} (Size: ${pdf.length} bytes, P: ${pVal})`);
  return targetPath;
}

console.log('Generating test PDF fixtures with various permission restrictions...');

// 1. Restricted Print: Bit 3 clear (P = -3904 + (allow others) -> P = -3908 with bit 3=0)
// Standard P = -3904 is all restricted. Standard P = -4 is all allowed.
// When print (bit 3 / val 4) is disabled: -4 - 4 = -8 (or bitwise: -4 & ~4)
createTestPdf({
  filename: 'restricted_print.pdf',
  pVal: -8, // Bit 3 cleared (Print Forbidden)
  vVal: 2, rVal: 3, cipherType: 'RC4'
});

// 2. Restricted Copy / Clipboard Extraction: Bit 5 clear (val 16)
createTestPdf({
  filename: 'restricted_copy.pdf',
  pVal: -20, // Bit 5 cleared (Copy/Extract Forbidden)
  vVal: 2, rVal: 3, cipherType: 'RC4'
});

// 3. Restricted Modify & Annotations: Bit 4 (val 8) & Bit 6 (val 32) clear
createTestPdf({
  filename: 'restricted_modify.pdf',
  pVal: -44, // Bits 4 and 6 cleared (Modify/Annotations Forbidden)
  vVal: 2, rVal: 3, cipherType: 'RC4'
});

// 4. All Permissions Restricted (RC4-128)
createTestPdf({
  filename: 'restricted_all_rc4.pdf',
  pVal: -3904, // All permissions cleared
  vVal: 2, rVal: 3, cipherType: 'RC4'
});

// 5. All Permissions Restricted (AES-128)
createTestPdf({
  filename: 'restricted_all_aes.pdf',
  pVal: -3904, // All permissions cleared
  vVal: 4, rVal: 4, cipherType: 'AES'
});

// 6. User Password Protected PDF ("secret123")
createTestPdf({
  filename: 'password_open.pdf',
  pVal: -3904,
  userPassword: 'secret123',
  vVal: 2, rVal: 3, cipherType: 'RC4'
});

// 7. Unencrypted Normal PDF
createTestPdf({
  filename: 'unencrypted.pdf',
  isUnencrypted: true
});

console.log('✅ All 7 test PDF fixtures generated successfully in test/fixtures/');
