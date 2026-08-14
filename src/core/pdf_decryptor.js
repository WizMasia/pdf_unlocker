/**
 * @file src/core/pdf_decryptor.js
 * @description Standard Security Handler & Lossless PDF Decryption Engine.
 *              표준 보안 핸들러 및 무손실 PDF 복호화 엔진.
 */

import { md5, rc4, aesDecryptCbc } from './crypto.js';
import { PdfDict, PdfArray, PdfString, PdfStream } from './pdf_parser.js';

// Standard 32-byte password padding string per ISO 32000-1
const PAD = new Uint8Array([
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
  0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
  0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
]);

/**
 * Computes File Encryption Key (FEK) from password and PDF metadata.
 * 비밀번호 및 PDF 메타데이터로부터 파일 암호화 키(FEK)를 계산합니다.
 */
function computeFileEncryptionKey(password, oHash, pVal, idFirst, keyLength = 16, rVal = 3, encryptMetadata = true) {
  const pwBytes = typeof password === 'string' ? new TextEncoder().encode(password) : new Uint8Array(password);
  const userPad = new Uint8Array(32);
  const copyLen = Math.min(pwBytes.length, 32);
  for (let i = 0; i < copyLen; i++) userPad[i] = pwBytes[i];
  for (let i = copyLen; i < 32; i++) userPad[i] = PAD[i - copyLen];

  const pBytes = new Uint8Array([
    pVal & 0xff,
    (pVal >> 8) & 0xff,
    (pVal >> 16) & 0xff,
    (pVal >> 24) & 0xff
  ]);

  const totalLen = 32 + oHash.length + 4 + (idFirst ? idFirst.length : 0) + (rVal >= 4 && !encryptMetadata ? 4 : 0);
  const buf = new Uint8Array(totalLen);
  let offset = 0;

  buf.set(userPad, offset); offset += 32;
  buf.set(oHash, offset); offset += oHash.length;
  buf.set(pBytes, offset); offset += 4;
  if (idFirst && idFirst.length > 0) {
    buf.set(idFirst, offset); offset += idFirst.length;
  }
  if (rVal >= 4 && !encryptMetadata) {
    buf.set([0xff, 0xff, 0xff, 0xff], offset); offset += 4;
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
 * Verifies if the computed FEK is valid against U hash.
 * 계산된 FEK가 U 해시와 일치하는지(인증 성공 여부) 검증합니다.
 */
function verifyFileEncryptionKey(fek, uHash, idFirst, rVal = 3) {
  if (!uHash || uHash.length < 16) return true;

  if (rVal === 2) {
    const testU = rc4(fek, PAD);
    for (let i = 0; i < 32; i++) {
      if (testU[i] !== uHash[i]) return false;
    }
    return true;
  }

  // R3 & R4 verification
  const idBytes = idFirst || new Uint8Array(0);
  const padAndId = new Uint8Array(32 + idBytes.length);
  padAndId.set(PAD, 0);
  padAndId.set(idBytes, 32);

  const hash = md5(padAndId);
  let testU = rc4(fek, hash);
  for (let i = 1; i <= 19; i++) {
    const iterKey = new Uint8Array(fek.length);
    for (let j = 0; j < fek.length; j++) iterKey[j] = fek[j] ^ i;
    testU = rc4(iterKey, testU);
  }

  for (let i = 0; i < 16; i++) {
    if (testU[i] !== uHash[i]) return false;
  }
  return true;
}

/**
 * Computes object-specific decryption key.
 * 객체 번호 및 생성 번호에 따른 객체별 복호화 키를 유도합니다.
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
 * Extracts File ID from trailer.
 * 트레일러로부터 문서 ID 바이트를 추출합니다.
 */
function getFirstFileId(doc) {
  const idArray = doc.trailer.get('/ID');
  if (idArray instanceof PdfArray && idArray.length > 0) {
    const first = idArray.get(0);
    if (first instanceof PdfString) return first.bytes;
    if (typeof first === 'string') return new TextEncoder().encode(first);
  }
  return new Uint8Array(0);
}

/**
 * Analyzes the encryption status and permission flags of a PDF document.
 * PDF 문서의 암호화 상태 및 권한 플래그를 정밀 분석합니다.
 * @param {PdfDocument} doc
 * @returns {object} Security analysis summary / 보안 분석 요약 객체
 */
export function analyzePdfSecurity(doc) {
  const encryptRef = doc.encryptRef || doc.trailer.get('/Encrypt');
  if (!encryptRef) {
    return {
      isEncrypted: false,
      requiresPassword: false,
      permissions: {
        canPrint: true,
        canCopy: true,
        canModify: true,
        canAnnotate: true,
        canFillForms: true,
        canExtractAccessibility: true,
        canAssemble: true,
        canPrintHighQuality: true
      },
      v: 0,
      r: 0,
      filter: null
    };
  }

  let encObj = null;
  if (encryptRef.num) {
    encObj = doc.getObject(encryptRef.num, encryptRef.gen || 0);
  }
  const encDict = encObj && encObj.data instanceof PdfDict ? encObj.data : (encryptRef instanceof PdfDict ? encryptRef : null);

  if (!encDict) {
    return { isEncrypted: true, requiresPassword: false, permissions: {}, v: 0, r: 0, filter: null };
  }

  const vVal = encDict.get('/V') || 0;
  const rVal = encDict.get('/R') || 0;
  const pVal = typeof encDict.get('/P') === 'number' ? encDict.get('/P') : -4;
  const filter = encDict.get('/Filter');

  // Permission flags bitmask (ISO 32000-1 Table 22)
  const permissions = {
    canPrint: (pVal & 4) !== 0,
    canModify: (pVal & 8) !== 0,
    canCopy: (pVal & 16) !== 0,
    canAnnotate: (pVal & 32) !== 0,
    canFillForms: (pVal & 256) !== 0,
    canExtractAccessibility: (pVal & 512) !== 0,
    canAssemble: (pVal & 1024) !== 0,
    canPrintHighQuality: (pVal & 2048) !== 0
  };

  // Check if open password is required (test with empty password "")
  let oHash = new Uint8Array(32);
  let uHash = new Uint8Array(32);
  const oVal = encDict.get('/O');
  if (oVal instanceof PdfString) oHash = oVal.bytes;
  const uVal = encDict.get('/U');
  if (uVal instanceof PdfString) uHash = uVal.bytes;

  const keyLength = encDict.get('/Length') ? encDict.get('/Length') / 8 : (vVal === 1 ? 5 : 16);
  const idFirst = getFirstFileId(doc);
  const encryptMetadata = encDict.get('/EncryptMetadata') !== false;

  const fek = computeFileEncryptionKey('', oHash, pVal, idFirst, keyLength, rVal, encryptMetadata);
  const isAuthenticated = verifyFileEncryptionKey(fek, uHash, idFirst, rVal);

  return {
    isEncrypted: true,
    requiresPassword: !isAuthenticated,
    permissions,
    pVal,
    v: vVal,
    r: rVal,
    filter,
    keyLength
  };
}

/**
 * Decrypts a recursive value (PdfDict, PdfArray, PdfString).
 */
function decryptValue(val, key, isAes) {
  if (val instanceof PdfString) {
    const decBytes = isAes
      ? aesDecryptCbc(key, val.bytes.subarray(0, 16), val.bytes.subarray(16), true)
      : rc4(key, val.bytes);
    return new PdfString(decBytes, val.isHex);
  }
  if (val instanceof PdfDict) {
    for (const [k, v] of val.entries()) {
      val.set(k, decryptValue(v, key, isAes));
    }
    return val;
  }
  if (val instanceof PdfArray) {
    for (let i = 0; i < val.length; i++) {
      val.items[i] = decryptValue(val.get(i), key, isAes);
    }
    return val;
  }
  return val;
}

/**
 * Unlocks PDF document permissions by decrypting all streams and strings.
 * 모든 스트림과 문자열을 무손실 복호화하여 PDF 문서의 권한 제한을 완전히 해제합니다.
 * @param {PdfDocument} doc - Target PDF document / 대상 PDF 문서
 * @param {string} [password=''] - User password (default '') / 사용자 열기 비밀번호
 * @returns {{ success: boolean, message?: string }}
 */
export function unlockPdfDocument(doc, password = '') {
  const encryptRef = doc.encryptRef || doc.trailer.get('/Encrypt');
  if (!encryptRef) {
    return { success: true, message: 'Document is not encrypted' };
  }

  let encObj = null;
  const encNum = encryptRef.num;
  if (encNum) {
    encObj = doc.getObject(encNum, encryptRef.gen || 0);
  }
  const encDict = encObj && encObj.data instanceof PdfDict ? encObj.data : (encryptRef instanceof PdfDict ? encryptRef : null);

  if (!encDict) {
    return { success: false, message: 'Encrypt dictionary not found' };
  }

  const vVal = encDict.get('/V') || 2;
  const rVal = encDict.get('/R') || 3;
  const pVal = typeof encDict.get('/P') === 'number' ? encDict.get('/P') : -4;
  const keyLength = encDict.get('/Length') ? encDict.get('/Length') / 8 : (vVal === 1 ? 5 : 16);
  const encryptMetadata = encDict.get('/EncryptMetadata') !== false;

  let oHash = new Uint8Array(32);
  let uHash = new Uint8Array(32);
  const oVal = encDict.get('/O');
  if (oVal instanceof PdfString) oHash = oVal.bytes;
  const uVal = encDict.get('/U');
  if (uVal instanceof PdfString) uHash = uVal.bytes;

  const idFirst = getFirstFileId(doc);

  // Compute File Encryption Key
  const fek = computeFileEncryptionKey(password, oHash, pVal, idFirst, keyLength, rVal, encryptMetadata);
  const isValid = verifyFileEncryptionKey(fek, uHash, idFirst, rVal);

  if (!isValid) {
    return { success: false, message: 'Invalid password' };
  }

  // Determine cipher algorithm (RC4 vs AES)
  let isAes = (vVal === 4 || vVal === 5);
  const stmF = encDict.get('/StmF');
  if (stmF === '/StdCF') {
    const cf = encDict.get('/CF');
    if (cf instanceof PdfDict) {
      const stdCf = cf.get('/StdCF');
      if (stdCf instanceof PdfDict && stdCf.get('/CFM') === '/AESV2') {
        isAes = true;
      }
    }
  }

  // Decrypt all indirect objects except the Encrypt dictionary itself
  for (const [key, obj] of doc.objects.entries()) {
    if (obj.num === encNum) continue; // Skip Encrypt dictionary

    const objKey = computeObjectKey(fek, obj.num, obj.gen, isAes);

    // 1. Decrypt dictionary/data strings
    if (obj.data) {
      obj.data = decryptValue(obj.data, objKey, isAes);
    }

    // 2. Decrypt stream bytes
    if (obj.stream && obj.stream.bytes && obj.stream.bytes.length > 0) {
      let decStreamBytes;
      if (isAes) {
        // First 16 bytes are IV for AES-CBC
        const iv = obj.stream.bytes.subarray(0, 16);
        const ct = obj.stream.bytes.subarray(16);
        decStreamBytes = aesDecryptCbc(objKey, iv, ct, true);
      } else {
        decStreamBytes = rc4(objKey, obj.stream.bytes);
      }
      obj.stream.bytes = decStreamBytes;
      if (obj.stream.dict instanceof PdfDict) {
        obj.stream.dict.set('/Length', decStreamBytes.length);
      }
    }
  }

  return { success: true };
}
