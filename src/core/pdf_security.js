/**
 * @file src/core/pdf_security.js
 * @description Standalone ISO 32000-1 PDF Security Handler & Permission Engine.
 *              ISO 32000-1 표준 기반 PDF 보안 핸들러 및 권한(인쇄/복사/수정 등) 제어 엔진.
 */

import { md5, rc4, aesEncryptCbc, aesDecryptCbc } from './crypto.js';
import { PdfRef, PdfString, PdfDict, PdfArray, PdfStream, PdfObject, PdfDocument } from './pdf_ast.js';

// Standard 32-byte password padding string per ISO 32000-1 (Table 23)
// ISO 32000-1 표준 32바이트 비밀번호 패딩 상수
export const PDF_PAD = new Uint8Array([
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
  0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
  0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
]);

/**
 * Standard PDF Permission Bitmask Flags (ISO 32000-1 Table 22)
 * 표준 PDF 권한 비트마스크 상수
 */
export const PDF_PERM_FLAGS = {
  PRINT: 4,                   // Bit 3: Print document / 인쇄 (150dpi or basic)
  MODIFY: 8,                  // Bit 4: Modify contents / 내용 수정
  COPY: 16,                   // Bit 5: Copy/extract text & graphics / 텍스트 및 그래픽 복사
  ANNOTATE: 32,               // Bit 6: Add/modify annotations & interactive forms / 주석 및 양식 편집
  FILL_FORMS: 256,            // Bit 9: Fill existing form fields / 양식 필드 채우기
  EXTRACT_ACCESSIBILITY: 512, // Bit 10: Extract for accessibility / 접근성 낭독 추출
  ASSEMBLE: 1024,             // Bit 11: Assemble document (insert/rotate/delete pages) / 문서 조합
  PRINT_HIGH_QUALITY: 2048    // Bit 12: High-resolution printing / 고품질 인쇄
};

/**
 * Parses a 32-bit permission integer into a user-friendly flags object.
 * 32비트 정수 P 값으로부터 세부 권한 플래그 객체를 분석합니다.
 * @param {number} pVal - 32-bit integer / 32비트 권한 정수
 * @returns {object}
 */
export function parsePermissions(pVal) {
  if (typeof pVal !== 'number') {
    pVal = -4; // Default unrestricted / 기본 전체 허용
  }

  return {
    canPrint: (pVal & PDF_PERM_FLAGS.PRINT) !== 0,
    canPrintHighQuality: (pVal & PDF_PERM_FLAGS.PRINT_HIGH_QUALITY) !== 0,
    canModify: (pVal & PDF_PERM_FLAGS.MODIFY) !== 0,
    canCopy: (pVal & PDF_PERM_FLAGS.COPY) !== 0,
    canAnnotate: (pVal & PDF_PERM_FLAGS.ANNOTATE) !== 0,
    canFillForms: (pVal & PDF_PERM_FLAGS.FILL_FORMS) !== 0,
    canExtractAccessibility: (pVal & PDF_PERM_FLAGS.EXTRACT_ACCESSIBILITY) !== 0,
    canAssemble: (pVal & PDF_PERM_FLAGS.ASSEMBLE) !== 0
  };
}

/**
 * Encodes a user-friendly flags object into a standard 32-bit P integer.
 * 세부 권한 플래그 객체를 표준 32비트 P 정수로 인코딩합니다.
 * @param {object} flags - Permission flags / 권한 플래그 설정
 * @returns {number} Signed 32-bit integer / 32비트 부호 있는 정수
 */
export function buildPermissions(flags = {}) {
  let p = 0xfffffffc;

  const canPrint = flags.canPrint !== false;
  const canPrintHighQuality = flags.canPrintHighQuality !== false;
  const canModify = flags.canModify !== false;
  const canCopy = flags.canCopy !== false;
  const canAnnotate = flags.canAnnotate !== false;
  const canFillForms = flags.canFillForms !== false;
  const canExtractAccessibility = flags.canExtractAccessibility !== false;
  const canAssemble = flags.canAssemble !== false;

  if (!canPrint) {
    p &= ~PDF_PERM_FLAGS.PRINT;
    p &= ~PDF_PERM_FLAGS.PRINT_HIGH_QUALITY;
  } else if (!canPrintHighQuality) {
    p |= PDF_PERM_FLAGS.PRINT;
    p &= ~PDF_PERM_FLAGS.PRINT_HIGH_QUALITY;
  } else {
    p |= PDF_PERM_FLAGS.PRINT;
    p |= PDF_PERM_FLAGS.PRINT_HIGH_QUALITY;
  }

  if (!canModify) p &= ~PDF_PERM_FLAGS.MODIFY;
  if (!canCopy) p &= ~PDF_PERM_FLAGS.COPY;
  if (!canAnnotate) p &= ~PDF_PERM_FLAGS.ANNOTATE;
  if (!canFillForms) p &= ~PDF_PERM_FLAGS.FILL_FORMS;
  if (!canExtractAccessibility) p &= ~PDF_PERM_FLAGS.EXTRACT_ACCESSIBILITY;
  if (!canAssemble) p &= ~PDF_PERM_FLAGS.ASSEMBLE;

  return p | 0;
}

/**
 * Computes File Encryption Key (FEK) according to ISO 32000-1 Algorithm 3.2.
 * ISO 32000-1 Algorithm 3.2에 따라 파일 암호화 키(FEK)를 계산합니다.
 */
export function computeFileEncryptionKey(password, oHash, pVal, idFirst, keyLength = 16, rVal = 4, encryptMetadata = true) {
  const pwBytes = typeof password === 'string' ? new TextEncoder().encode(password) : new Uint8Array(password || 0);
  const userPad = new Uint8Array(32);
  const copyLen = Math.min(pwBytes.length, 32);
  for (let i = 0; i < copyLen; i++) userPad[i] = pwBytes[i];
  for (let i = copyLen; i < 32; i++) userPad[i] = PDF_PAD[i - copyLen];

  const pBytes = new Uint8Array([
    pVal & 0xff,
    (pVal >> 8) & 0xff,
    (pVal >> 16) & 0xff,
    (pVal >> 24) & 0xff
  ]);

  const idBytes = idFirst || new Uint8Array(0);
  const totalLen = 32 + oHash.length + 4 + idBytes.length + (rVal >= 4 && !encryptMetadata ? 4 : 0);
  const buf = new Uint8Array(totalLen);
  let offset = 0;

  buf.set(userPad, offset); offset += 32;
  buf.set(oHash, offset); offset += oHash.length;
  buf.set(pBytes, offset); offset += 4;
  if (idBytes.length > 0) {
    buf.set(idBytes, offset); offset += idBytes.length;
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
 * Computes Owner Password Hash (/O) according to ISO 32000-1 Algorithm 3.3.
 * ISO 32000-1 Algorithm 3.3에 따라 권한 관리자 암호 해시(/O)를 계산합니다.
 */
export function computeOwnerPasswordHash(ownerPassword, userPassword, keyLength = 16, rVal = 4) {
  const ownerPwBytes = typeof ownerPassword === 'string' ? new TextEncoder().encode(ownerPassword) : new Uint8Array(ownerPassword || 0);
  const userPwBytes = typeof userPassword === 'string' ? new TextEncoder().encode(userPassword) : new Uint8Array(userPassword || 0);

  // 1. Pad owner password to 32 bytes
  const ownerPad = new Uint8Array(32);
  const copyLen = Math.min(ownerPwBytes.length, 32);
  for (let i = 0; i < copyLen; i++) ownerPad[i] = ownerPwBytes[i];
  for (let i = copyLen; i < 32; i++) ownerPad[i] = PDF_PAD[i - copyLen];

  // 2. MD5 hash padded owner password
  let hash = md5(ownerPad);

  // 3. 50 iterations for R >= 3
  if (rVal >= 3) {
    for (let i = 0; i < 50; i++) {
      hash = md5(hash.subarray(0, keyLength));
    }
  }

  const key = hash.subarray(0, keyLength);

  // 4. Pad user password to 32 bytes
  const userPad = new Uint8Array(32);
  const uCopyLen = Math.min(userPwBytes.length, 32);
  for (let i = 0; i < uCopyLen; i++) userPad[i] = userPwBytes[i];
  for (let i = uCopyLen; i < 32; i++) userPad[i] = PDF_PAD[i - uCopyLen];

  // 5. Encrypt with RC4
  let result = rc4(key, userPad);

  // 6. 19 iterations for R >= 3
  if (rVal >= 3) {
    for (let i = 1; i <= 19; i++) {
      const iterKey = new Uint8Array(keyLength);
      for (let j = 0; j < keyLength; j++) {
        iterKey[j] = key[j] ^ i;
      }
      result = rc4(iterKey, result);
    }
  }

  return result;
}

/**
 * Computes User Password Hash (/U) according to ISO 32000-1 Algorithm 3.4 & 3.5.
 * ISO 32000-1 Algorithm 3.4 및 3.5에 따라 사용자 열람 암호 해시(/U)를 계산합니다.
 */
export function computeUserPasswordHash(fek, idFirst, rVal = 4) {
  if (rVal === 2) {
    return rc4(fek, PDF_PAD);
  }

  const idBytes = idFirst || new Uint8Array(0);
  const padAndId = new Uint8Array(32 + idBytes.length);
  padAndId.set(PDF_PAD, 0);
  padAndId.set(idBytes, 32);

  const hash = md5(padAndId);
  let result = rc4(fek, hash);

  for (let i = 1; i <= 19; i++) {
    const iterKey = new Uint8Array(fek.length);
    for (let j = 0; j < fek.length; j++) {
      iterKey[j] = fek[j] ^ i;
    }
    result = rc4(iterKey, result);
  }

  const out = new Uint8Array(32);
  out.set(result, 0);
  out.set(PDF_PAD.subarray(0, 16), 16);
  return out;
}

/**
 * Authenticates Owner Password according to ISO 32000-1 Algorithm 3.7.
 * ISO 32000-1 Algorithm 3.7에 따라 관리자 암호(Owner Password)를 검증하고 FEK를 복원합니다.
 */
export function authenticateOwnerPassword(ownerPassword, oHash, uHash, pVal, idFirst, keyLength = 16, rVal = 4, encryptMetadata = true) {
  const pwBytes = typeof ownerPassword === 'string' ? new TextEncoder().encode(ownerPassword) : new Uint8Array(ownerPassword || 0);
  const ownerPad = new Uint8Array(32);
  const copyLen = Math.min(pwBytes.length, 32);
  for (let i = 0; i < copyLen; i++) ownerPad[i] = pwBytes[i];
  for (let i = copyLen; i < 32; i++) ownerPad[i] = PDF_PAD[i - copyLen];

  let hash = md5(ownerPad);
  if (rVal >= 3) {
    for (let i = 0; i < 50; i++) {
      hash = md5(hash.subarray(0, keyLength));
    }
  }
  const ownerKey = hash.subarray(0, keyLength);

  let userPad = rc4(ownerKey, oHash);
  if (rVal >= 3) {
    for (let i = 19; i >= 1; i--) {
      const iterKey = new Uint8Array(keyLength);
      for (let j = 0; j < keyLength; j++) {
        iterKey[j] = ownerKey[j] ^ i;
      }
      userPad = rc4(iterKey, userPad);
    }
  }

  const fek = computeFileEncryptionKey(userPad, oHash, pVal, idFirst, keyLength, rVal, encryptMetadata);
  const isAuth = verifyFileEncryptionKey(fek, uHash, idFirst, rVal);
  return { isAuth, fek };
}

/**
 * Computes object-specific encryption/decryption key (Algorithm 3.1).
 * 객체 번호 및 생성 번호 기반의 객체별 파생 암복호화 키를 유도합니다.
 */
export function computeObjectKey(fek, objNum, genNum, isAes = false) {
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
 * Extracts the first File ID from the document trailer.
 * 트레일러로부터 첫 번째 문서 ID 바이트를 추출합니다.
 */
export function getFirstFileId(doc) {
  const idArray = doc.trailer.get('/ID');
  if (idArray instanceof PdfArray && idArray.length > 0) {
    const first = idArray.get(0);
    if (first instanceof PdfString) return first.bytes;
    if (typeof first === 'string') return new TextEncoder().encode(first);
  }
  return new Uint8Array(0);
}

/**
 * Verifies if File Encryption Key (FEK) satisfies /U hash.
 * FEK가 문서의 /U 해시와 일치하는지(비밀번호 인증 성공 여부) 검증합니다.
 */
export function verifyFileEncryptionKey(fek, uHash, idFirst, rVal = 4) {
  if (!uHash || uHash.length < 16) return true;

  if (rVal === 2) {
    const testU = rc4(fek, PDF_PAD);
    for (let i = 0; i < 32; i++) {
      if (testU[i] !== uHash[i]) return false;
    }
    return true;
  }

  const idBytes = idFirst || new Uint8Array(0);
  const padAndId = new Uint8Array(32 + idBytes.length);
  padAndId.set(PDF_PAD, 0);
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
 * Analyzes the security status, required passwords, and permission flags of a PDF document.
 * PDF 문서의 보안 상태, 비밀번호 요구 여부, 세부 권한 플래그를 정밀 분석합니다.
 * @param {PdfDocument} doc
 * @returns {object} Security status summary / 보안 분석 요약 객체
 */
export function analyzeSecurity(doc) {
  const encryptRef = doc.encryptRef || doc.trailer.get('/Encrypt');
  if (!encryptRef) {
    return {
      isEncrypted: false,
      requiresPassword: false,
      permissions: parsePermissions(-4),
      pVal: -4,
      v: 0,
      r: 0,
      filter: null
    };
  }

  let encObj = null;
  if (encryptRef instanceof PdfRef) {
    encObj = doc.getObject(encryptRef.num, encryptRef.gen || 0);
  }
  const encDict = encObj && encObj.data instanceof PdfDict ? encObj.data : (encryptRef instanceof PdfDict ? encryptRef : null);

  if (!encDict) {
    return {
      isEncrypted: true,
      requiresPassword: false,
      permissions: parsePermissions(-4),
      pVal: -4,
      v: 0,
      r: 0,
      filter: null
    };
  }

  const vVal = typeof encDict.get('/V') === 'number' ? encDict.get('/V') : 0;
  const rVal = typeof encDict.get('/R') === 'number' ? encDict.get('/R') : 0;
  const pVal = typeof encDict.get('/P') === 'number' ? encDict.get('/P') : -4;
  const filter = encDict.get('/Filter');

  const permissions = parsePermissions(pVal);

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
 * Decrypts a recursive AST value (PdfDict, PdfArray, PdfString).
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
 * Encrypts a recursive AST value (PdfDict, PdfArray, PdfString).
 */
function encryptValue(val, key, isAes) {
  if (val instanceof PdfString) {
    if (isAes) {
      const iv = new Uint8Array(16);
      for (let i = 0; i < 16; i++) iv[i] = Math.floor(Math.random() * 256);
      const ct = aesEncryptCbc(key, iv, val.bytes, true);
      const combined = new Uint8Array(16 + ct.length);
      combined.set(iv, 0);
      combined.set(ct, 16);
      return new PdfString(combined, val.isHex);
    } else {
      const ct = rc4(key, val.bytes);
      return new PdfString(ct, val.isHex);
    }
  }
  if (val instanceof PdfDict) {
    for (const [k, v] of val.entries()) {
      val.set(k, encryptValue(v, key, isAes));
    }
    return val;
  }
  if (val instanceof PdfArray) {
    for (let i = 0; i < val.length; i++) {
      val.items[i] = encryptValue(val.get(i), key, isAes);
    }
    return val;
  }
  return val;
}

/**
 * Completely unlocks and decrypts all streams and strings in a PDF document.
 * 문서의 모든 객체를 무손실 복호화하여 보안 제한을 완전히 해제합니다.
 * @param {PdfDocument} doc
 * @param {string} [password='']
 * @returns {{ success: boolean, message?: string }}
 */
export function unlockDocument(doc, password = '') {
  const encryptRef = doc.encryptRef || doc.trailer.get('/Encrypt');
  if (!encryptRef) {
    return { success: true, message: 'Document is not encrypted' };
  }

  let encObj = null;
  if (encryptRef instanceof PdfRef) {
    encObj = doc.getObject(encryptRef.num, encryptRef.gen || 0);
  }
  const encDict = encObj && encObj.data instanceof PdfDict ? encObj.data : (encryptRef instanceof PdfDict ? encryptRef : null);

  if (!encDict) {
    doc.trailer.delete('/Encrypt');
    doc.encryptRef = null;
    return { success: true };
  }

  const vVal = typeof encDict.get('/V') === 'number' ? encDict.get('/V') : 0;
  const rVal = typeof encDict.get('/R') === 'number' ? encDict.get('/R') : 0;
  const pVal = typeof encDict.get('/P') === 'number' ? encDict.get('/P') : -4;
  const keyLength = encDict.get('/Length') ? encDict.get('/Length') / 8 : (vVal === 1 ? 5 : 16);
  const idFirst = getFirstFileId(doc);
  const encryptMetadata = encDict.get('/EncryptMetadata') !== false;

  let oHash = new Uint8Array(32);
  let uHash = new Uint8Array(32);
  const oVal = encDict.get('/O');
  if (oVal instanceof PdfString) oHash = oVal.bytes;
  const uVal = encDict.get('/U');
  if (uVal instanceof PdfString) uHash = uVal.bytes;

  // 1. Try User Password
  let fek = computeFileEncryptionKey(password, oHash, pVal, idFirst, keyLength, rVal, encryptMetadata);
  let isAuth = verifyFileEncryptionKey(fek, uHash, idFirst, rVal);

  // 2. If User password failed and a non-empty password was given, try Owner Password
  if (!isAuth && password !== '') {
    const ownerAuth = authenticateOwnerPassword(password, oHash, uHash, pVal, idFirst, keyLength, rVal, encryptMetadata);
    if (ownerAuth.isAuth) {
      isAuth = true;
      fek = ownerAuth.fek;
    }
  }

  if (!isAuth) {
    return { success: false, message: 'Password required or incorrect' };
  }

  // Determine stream and string filter (RC4 or AES)
  const isAes = vVal >= 4 && (encDict.get('/CF') || encDict.get('/StmF') === '/AESV2' || encDict.get('/StrF') === '/AESV2');
  const encObjNum = encObj ? encObj.num : null;

  // Decrypt all document objects
  for (const obj of doc.objects.values()) {
    if (obj.num === encObjNum) continue;

    const objKey = computeObjectKey(fek, obj.num, obj.gen, isAes);

    // 1. Decrypt Data values
    if (obj.data) {
      obj.data = decryptValue(obj.data, objKey, isAes);
    }

    // 2. Decrypt Stream bytes
    if (obj.stream) {
      if (obj.stream.dict) {
        obj.stream.dict = decryptValue(obj.stream.dict, objKey, isAes);
      }
      const rawBytes = obj.stream.bytes;
      if (rawBytes.length > 0) {
        if (isAes) {
          const iv = rawBytes.subarray(0, 16);
          const ct = rawBytes.subarray(16);
          if (ct.length > 0 && ct.length % 16 === 0) {
            obj.stream.bytes = aesDecryptCbc(objKey, iv, ct, true);
          }
        } else {
          obj.stream.bytes = rc4(objKey, rawBytes);
        }
        obj.stream.dict.set('/Length', obj.stream.bytes.length);
      }
    }
  }

  // Delete /Encrypt dictionary and clean trailer
  if (encObjNum) {
    doc.deleteObject(encObjNum);
  }
  doc.trailer.delete('/Encrypt');
  doc.encryptRef = null;

  return { success: true };
}

/**
 * Reconfigures PDF document permissions with ISO 32000-1 Standard Security Handler.
 * PDF 문서의 권한을 세부 재조정하고 표준 암호화 딕셔너리를 새로 생성하여 적용합니다.
 *
 * @param {PdfDocument} doc - Target PDF Document / 대상 PDF 문서
 * @param {object} options - Security configuration options / 보안 설정 옵션
 * @param {object} [options.permissions] - Granular permission flags / 세부 권한 설정
 * @param {string} [options.ownerPassword=''] - Owner Password / 권한 관리자 암호
 * @param {string} [options.userPassword=''] - User/Open Password / 문서 열람 암호
 * @param {string} [options.currentPassword=''] - Current Password if already locked / 기존 비밀번호
 * @param {string} [options.algorithm='AES-128'] - 'AES-128' or 'RC4-128' / 암호화 알고리즘
 * @returns {{ success: boolean, message?: string }}
 */
export function changeDocumentPermissions(doc, options = {}) {
  // 1. Ensure any existing security handler is decrypted first
  const unlockRes = unlockDocument(doc, options.currentPassword || '');
  if (!unlockRes.success) {
    return unlockRes;
  }

  const {
    permissions = {},
    ownerPassword = 'admin_' + Math.random().toString(36).substr(2, 8),
    userPassword = '',
    algorithm = 'AES-128'
  } = options;

  const isAes = algorithm.toUpperCase().includes('AES');
  const rVal = isAes ? 4 : 3;
  const vVal = isAes ? 4 : 2;
  const keyLength = 16; // 128-bit

  // 2. Ensure /ID array exists in trailer
  let idArray = doc.trailer.get('/ID');
  if (!(idArray instanceof PdfArray) || idArray.length === 0) {
    const id1 = new Uint8Array(16);
    const id2 = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      id1[i] = Math.floor(Math.random() * 256);
      id2[i] = Math.floor(Math.random() * 256);
    }
    idArray = new PdfArray([new PdfString(id1, true), new PdfString(id2, true)]);
    doc.trailer.set('/ID', idArray);
  }
  const idFirst = getFirstFileId(doc);

  // 3. Compute Permission bitmask P
  const pVal = buildPermissions(permissions);

  // 4. Compute /O hash (Algorithm 3.3)
  const oHash = computeOwnerPasswordHash(ownerPassword, userPassword, keyLength, rVal);

  // 5. Compute FEK (Algorithm 3.2)
  const fek = computeFileEncryptionKey(userPassword, oHash, pVal, idFirst, keyLength, rVal, true);

  // 6. Compute /U hash (Algorithm 3.4 & 3.5)
  const uHash = computeUserPasswordHash(fek, idFirst, rVal);

  // 7. Find next available Object Number for new /Encrypt object
  let maxObjNum = 0;
  for (const obj of doc.objects.values()) {
    maxObjNum = Math.max(maxObjNum, obj.num);
  }
  const encObjNum = maxObjNum + 1;

  // 8. Encrypt all streams and strings across document objects
  for (const obj of doc.objects.values()) {
    const objKey = computeObjectKey(fek, obj.num, obj.gen, isAes);

    // Encrypt Data
    if (obj.data) {
      obj.data = encryptValue(obj.data, objKey, isAes);
    }

    // Encrypt Stream
    if (obj.stream) {
      if (obj.stream.dict) {
        obj.stream.dict = encryptValue(obj.stream.dict, objKey, isAes);
      }
      const rawBytes = obj.stream.bytes;
      if (rawBytes.length > 0) {
        if (isAes) {
          const iv = new Uint8Array(16);
          for (let i = 0; i < 16; i++) iv[i] = Math.floor(Math.random() * 256);
          const ct = aesEncryptCbc(objKey, iv, rawBytes, true);
          const combined = new Uint8Array(16 + ct.length);
          combined.set(iv, 0);
          combined.set(ct, 16);
          obj.stream.bytes = combined;
        } else {
          obj.stream.bytes = rc4(objKey, rawBytes);
        }
        obj.stream.dict.set('/Length', obj.stream.bytes.length);
      }
    }
  }

  // 9. Build standard /Encrypt dictionary
  const encDict = new PdfDict();
  encDict.set('/Filter', '/Standard');
  encDict.set('/V', vVal);
  encDict.set('/R', rVal);
  encDict.set('/Length', keyLength * 8);
  encDict.set('/P', pVal);
  encDict.set('/O', new PdfString(oHash, true));
  encDict.set('/U', new PdfString(uHash, true));

  if (isAes) {
    encDict.set('/StrF', '/StdCF');
    encDict.set('/StmF', '/StdCF');

    const stdCfDict = new PdfDict();
    stdCfDict.set('/Type', '/CryptFilter');
    stdCfDict.set('/CFM', '/AESV2');
    stdCfDict.set('/Length', 16);
    stdCfDict.set('/AuthEvent', '/DocOpen');

    const cfDict = new PdfDict();
    cfDict.set('/StdCF', stdCfDict);
    encDict.set('/CF', cfDict);
  }

  // 10. Register /Encrypt object in document and update trailer
  doc.setObject(encObjNum, 0, encDict, null);
  const encRef = new PdfRef(encObjNum, 0);
  doc.encryptRef = encRef;
  doc.trailer.set('/Encrypt', encRef);

  return {
    success: true,
    ownerPassword,
    userPassword,
    pVal,
    permissions: parsePermissions(pVal)
  };
}
