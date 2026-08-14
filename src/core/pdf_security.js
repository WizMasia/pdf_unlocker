/**
 * @file src/core/pdf_security.js
 * @description Standard Security Handler (ISO 32000-1 / ISO 32000-2 R2~R6), Permission Bitmask Engine,
 *              and Lossless PDF Cryptographic Processing.
 *              ISO 32000-1 및 ISO 32000-2 표준 보안 핸들러 (R2~R6), 세부 권한 비트마스크 연산 및 무손실 암복호화 엔진.
 */

import { md5, sha256, sha384, sha512, computeHash2A, computeHash2B, rc4, aesEncryptCbc, aesDecryptCbc } from './crypto.js';
import { PdfDict, PdfString, PdfRef, PdfArray, PdfStream, PdfObject } from './pdf_ast.js';

// Standard 32-byte padding specified in ISO 32000-1 Table 23
const STANDARD_ENCRYPT_PADDING = new Uint8Array([
  0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
  0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
]);

/**
 * Parses 32-bit permission integer `P` into granular permission flags (ISO 32000-1 Table 22).
 * PDF 32비트 권한 정수(P)를 세부 권한 플래그 객체로 파싱합니다.
 * @param {number} p - 32-bit permission integer / 32비트 권한 정수
 * @returns {Object}
 */
export function parsePermissions(p) {
  const uP = p >>> 0;
  return {
    canPrint: (uP & 4) !== 0,
    canModify: (uP & 8) !== 0,
    canCopy: (uP & 16) !== 0,
    canAnnotate: (uP & 32) !== 0,
    canFillForms: (uP & 256) !== 0,
    canExtractAccessibility: (uP & 512) !== 0,
    canAssemble: (uP & 1024) !== 0,
    canPrintHighQuality: (uP & 2048) !== 0
  };
}

/**
 * Builds 32-bit two's complement permission integer `P` from granular permission flags.
 * 세부 권한 플래그 객체를 ISO 32000-1 표준 32비트 권한 정수(P)로 조합합니다.
 * @param {Object} perms - Granular permission flags / 세부 권한 설정
 * @returns {number}
 */
export function buildPermissions(perms = {}) {
  let mask = 0xFFFFF0C0; // ISO 32000-1 Reserved Bits (7-8, 13-32 must be 1)

  if (perms.canPrint) mask |= 4;
  if (perms.canModify) mask |= 8;
  if (perms.canCopy) mask |= 16;
  if (perms.canAnnotate) mask |= 32;
  if (perms.canFillForms) mask |= 256;
  if (perms.canExtractAccessibility) mask |= 512;
  if (perms.canAssemble) mask |= 1024;
  if (perms.canPrintHighQuality) mask |= 2048;

  return (mask | 0) - 0x100000000;
}

/**
 * Pads or truncates password to 32 bytes for R2..R4 MD5 hashing.
 * R2..R4 암호화 해싱을 위해 비밀번호를 32바이트로 패딩하거나 자릅니다.
 */
function padOrTruncatePassword(password) {
  const bytes = typeof password === 'string' ? new TextEncoder().encode(password) : password;
  const out = new Uint8Array(32);
  const copyLen = Math.min(bytes.length, 32);
  out.set(bytes.subarray(0, copyLen), 0);
  if (copyLen < 32) {
    out.set(STANDARD_ENCRYPT_PADDING.subarray(0, 32 - copyLen), copyLen);
  }
  return out;
}

/**
 * Checks if provided password is the Owner password in Revision 5 or 6 (AES-256).
 * Revision 5/6 (AES-256)에서 입력한 암호가 Owner 암호인지 검증합니다.
 */
function isOwnerPassword56(passwordBytes, oBytes, uBytes, r) {
  if (!oBytes || oBytes.length < 40) return false;
  const oHash = oBytes.subarray(0, 32);
  const oValidationSalt = oBytes.subarray(32, 40);

  let hash;
  if (r === 5) {
    const input = new Uint8Array(passwordBytes.length + oValidationSalt.length + uBytes.length);
    input.set(passwordBytes, 0);
    input.set(oValidationSalt, passwordBytes.length);
    input.set(uBytes, passwordBytes.length + oValidationSalt.length);
    hash = sha256(input);
  } else {
    hash = computeHash2A(passwordBytes, oValidationSalt, uBytes);
  }

  if (hash.length !== oHash.length) return false;
  for (let i = 0; i < 32; i++) {
    if (hash[i] !== oHash[i]) return false;
  }
  return true;
}

/**
 * Checks if provided password is the User password in Revision 5 or 6 (AES-256).
 * Revision 5/6 (AES-256)에서 입력한 암호가 User 암호인지 검증합니다.
 */
function isUserPassword56(passwordBytes, uBytes, r) {
  if (!uBytes || uBytes.length < 40) return false;
  const uHash = uBytes.subarray(0, 32);
  const uValidationSalt = uBytes.subarray(32, 40);

  let hash;
  if (r === 5) {
    const input = new Uint8Array(passwordBytes.length + uValidationSalt.length);
    input.set(passwordBytes, 0);
    input.set(uValidationSalt, passwordBytes.length);
    hash = sha256(input);
  } else {
    hash = computeHash2A(passwordBytes, uValidationSalt, null);
  }

  if (hash.length !== uHash.length) return false;
  for (let i = 0; i < 32; i++) {
    if (hash[i] !== uHash[i]) return false;
  }
  return true;
}

/**
 * Computes raw unverified FEK for R2..R4 (ISO 32000-1 Algorithm 3.2).
 */
function computeRawFek234(encDict, passwordBytes, docIdBytes) {
  const r = encDict.get('/R') || 2;
  const lengthBits = encDict.get('/Length') || 40;
  const keyLength = lengthBits / 8;
  const pVal = encDict.get('/P') || 0;
  const encryptMetadata = encDict.has('/EncryptMetadata') ? encDict.get('/EncryptMetadata') !== false : true;

  const oObj = encDict.get('/O');
  const oBytes = oObj instanceof PdfString ? oObj.bytes : new Uint8Array(0);

  const passPadded = padOrTruncatePassword(passwordBytes);

  let uP = pVal >>> 0;
  const pBytes = new Uint8Array([
    uP & 0xff,
    (uP >>> 8) & 0xff,
    (uP >>> 16) & 0xff,
    (uP >>> 24) & 0xff
  ]);

  let totalLen = passPadded.length + oBytes.length + 4 + docIdBytes.length;
  if (r >= 4 && !encryptMetadata) totalLen += 4;

  const data = new Uint8Array(totalLen);
  let pos = 0;
  data.set(passPadded, pos); pos += passPadded.length;
  data.set(oBytes, pos); pos += oBytes.length;
  data.set(pBytes, pos); pos += 4;
  data.set(docIdBytes, pos); pos += docIdBytes.length;

  if (r >= 4 && !encryptMetadata) {
    data.set([0xff, 0xff, 0xff, 0xff], pos);
  }

  let hash = md5(data);

  if (r >= 3) {
    for (let i = 0; i < 50; i++) {
      hash = md5(hash.subarray(0, keyLength));
    }
  }

  return hash.subarray(0, keyLength);
}

/**
 * Computes File Encryption Key (FEK) according to ISO 32000-1 Algorithm 3.2 or ISO 32000-2 Algorithm 2.A.
 * ISO 32000 표준에 따라 파일 암호화 키(FEK)를 유도하고 유효성을 검증합니다.
 */
export function computeFileEncryptionKey(encDict, password = '', docIdBytes = new Uint8Array(0)) {
  const r = encDict.get('/R') || 2;
  const lengthBits = encDict.get('/Length') || 40;
  const keyLength = lengthBits / 8;

  const oObj = encDict.get('/O');
  const uObj = encDict.get('/U');
  const oeObj = encDict.get('/OE');
  const ueObj = encDict.get('/UE');

  const oBytes = oObj instanceof PdfString ? oObj.bytes : new Uint8Array(0);
  const uBytes = uObj instanceof PdfString ? uObj.bytes : new Uint8Array(0);
  const oeBytes = oeObj instanceof PdfString ? oeObj.bytes : new Uint8Array(0);
  const ueBytes = ueObj instanceof PdfString ? ueObj.bytes : new Uint8Array(0);

  const passwordBytes = typeof password === 'string' ? new TextEncoder().encode(password) : password;

  // Handle Revision 5 and Revision 6 (AES-256)
  if (r === 5 || r === 6) {
    // 1. Try Owner Password
    if (isOwnerPassword56(passwordBytes, oBytes, uBytes, r) && oeBytes.length >= 32) {
      const oKeySalt = oBytes.subarray(40, 48);
      let hashOE;
      if (r === 5) {
        const input = new Uint8Array(passwordBytes.length + oKeySalt.length + uBytes.length);
        input.set(passwordBytes, 0);
        input.set(oKeySalt, passwordBytes.length);
        input.set(uBytes, passwordBytes.length + oKeySalt.length);
        hashOE = sha256(input);
      } else {
        hashOE = computeHash2A(passwordBytes, oKeySalt, uBytes);
      }
      return aesDecryptCbc(hashOE, new Uint8Array(16), oeBytes.subarray(0, 32), false);
    }

    // 2. Try User Password (or empty password)
    if (isUserPassword56(passwordBytes, uBytes, r) && ueBytes.length >= 32) {
      const uKeySalt = uBytes.subarray(40, 48);
      let hashUE;
      if (r === 5) {
        const input = new Uint8Array(passwordBytes.length + uKeySalt.length);
        input.set(passwordBytes, 0);
        input.set(uKeySalt, passwordBytes.length);
        hashUE = sha256(input);
      } else {
        hashUE = computeHash2A(passwordBytes, uKeySalt, null);
      }
      return aesDecryptCbc(hashUE, new Uint8Array(16), ueBytes.subarray(0, 32), false);
    }

    // 3. Fallback: if password is not empty, also try authenticating with empty string
    if (passwordBytes.length > 0) {
      const emptyPw = new Uint8Array(0);
      if (isUserPassword56(emptyPw, uBytes, r) && ueBytes.length >= 32) {
        const uKeySalt = uBytes.subarray(40, 48);
        const hashUE = r === 5 ? sha256(uKeySalt) : computeHash2A(emptyPw, uKeySalt, null);
        return aesDecryptCbc(hashUE, new Uint8Array(16), ueBytes.subarray(0, 32), false);
      }
    }

    return null; // Password required or invalid
  }

  // Handle Revision 2, 3, 4 (RC4 / AES-128) with authentication
  const fekUser = computeRawFek234(encDict, passwordBytes, docIdBytes);

  // Check if User Password is valid
  if (uBytes.length >= 16) {
    if (r === 2) {
      const testU = rc4(fekUser, STANDARD_ENCRYPT_PADDING);
      let match = true;
      for (let i = 0; i < 32 && i < uBytes.length; i++) {
        if (testU[i] !== uBytes[i]) { match = false; break; }
      }
      if (match) return fekUser;
    } else {
      const testU = computeUserPasswordHash(fekUser, r, docIdBytes);
      let match = true;
      for (let i = 0; i < 16 && i < uBytes.length; i++) {
        if (testU[i] !== uBytes[i]) { match = false; break; }
      }
      if (match) return fekUser;
    }
  }

  // Check if Owner Password is valid (Algorithm 3.7)
  if (oBytes.length >= 32) {
    const ownerPadded = padOrTruncatePassword(passwordBytes);
    let hash = md5(ownerPadded);
    if (r >= 3) {
      for (let i = 0; i < 50; i++) hash = md5(hash.subarray(0, keyLength));
    }
    let recoveredUserPass = rc4(hash.subarray(0, keyLength), oBytes.subarray(0, 32));
    if (r >= 3) {
      for (let i = 19; i >= 1; i--) {
        const iterKey = new Uint8Array(keyLength);
        for (let j = 0; j < keyLength; j++) iterKey[j] = hash[j] ^ i;
        recoveredUserPass = rc4(iterKey, recoveredUserPass);
      }
    }
    const fekOwner = computeRawFek234(encDict, recoveredUserPass, docIdBytes);
    const testU = computeUserPasswordHash(fekOwner, r, docIdBytes);
    let match = true;
    for (let i = 0; i < (r === 2 ? 32 : 16) && i < uBytes.length; i++) {
      if (testU[i] !== uBytes[i]) { match = false; break; }
    }
    if (match) return fekOwner;
  }

  // Fallback: If password was empty but file had no /U (corrupted header)
  if (passwordBytes.length === 0 && uBytes.length === 0) {
    return fekUser;
  }

  return null;
}

/**
 * Computes object-specific derivative key (ISO 32000-1 Algorithm 3.1).
 * 객체별 파생 암호화 키를 계산합니다.
 */
export function computeObjectKey(fek, objNum, genNum, isAes = false) {
  const data = new Uint8Array(fek.length + 5 + (isAes ? 4 : 0));
  data.set(fek, 0);
  data[fek.length] = objNum & 0xff;
  data[fek.length + 1] = (objNum >>> 8) & 0xff;
  data[fek.length + 2] = (objNum >>> 16) & 0xff;
  data[fek.length + 3] = genNum & 0xff;
  data[fek.length + 4] = (genNum >>> 8) & 0xff;

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
 * Computes Owner Password Hash `/O` (ISO 32000-1 Algorithm 3.3).
 */
export function computeOwnerPasswordHash(ownerPassword, userPassword, r, keyLength) {
  const ownerPadded = padOrTruncatePassword(ownerPassword);
  let hash = md5(ownerPadded);

  if (r >= 3) {
    for (let i = 0; i < 50; i++) {
      hash = md5(hash.subarray(0, keyLength));
    }
  }

  const rc4Key = hash.subarray(0, keyLength);
  const userPadded = padOrTruncatePassword(userPassword);
  let result = rc4(rc4Key, userPadded);

  if (r >= 3) {
    for (let i = 1; i <= 19; i++) {
      const iterKey = new Uint8Array(keyLength);
      for (let j = 0; j < keyLength; j++) {
        iterKey[j] = rc4Key[j] ^ i;
      }
      result = rc4(iterKey, result);
    }
  }

  return result;
}

/**
 * Computes User Password Hash `/U` (ISO 32000-1 Algorithm 3.4 & 3.5).
 */
export function computeUserPasswordHash(fek, r, docIdBytes) {
  if (r === 2) {
    return rc4(fek, STANDARD_ENCRYPT_PADDING);
  }

  const totalLen = STANDARD_ENCRYPT_PADDING.length + docIdBytes.length;
  const data = new Uint8Array(totalLen);
  data.set(STANDARD_ENCRYPT_PADDING, 0);
  data.set(docIdBytes, STANDARD_ENCRYPT_PADDING.length);

  let hash = md5(data);
  let result = rc4(fek, hash);

  for (let i = 1; i <= 19; i++) {
    const iterKey = new Uint8Array(fek.length);
    for (let j = 0; j < fek.length; j++) {
      iterKey[j] = fek[j] ^ i;
    }
    result = rc4(iterKey, result);
  }

  const uValue = new Uint8Array(32);
  uValue.set(result, 0);
  uValue.set(STANDARD_ENCRYPT_PADDING.subarray(0, 16), 16);
  return uValue;
}

/**
 * Analyzes the security status and granular permissions of a PdfDocument.
 * PDF 문서의 보안 상태, 암호화 알고리즘, 세부 권한을 종합 분석합니다.
 * @param {PdfDocument} doc - Target PDF Document AST / 대상 PDF AST
 * @returns {Object}
 */
export function analyzeSecurity(doc) {
  if (!doc.encryptRef) {
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

  const encObj = doc.getObject(doc.encryptRef.num, doc.encryptRef.gen);
  if (!encObj || !(encObj.data instanceof PdfDict)) {
    return { isEncrypted: false, requiresPassword: false, permissions: parsePermissions(-4) };
  }

  const encDict = encObj.data;
  const pVal = encDict.get('/P') || -4;
  const v = encDict.get('/V') || 1;
  const r = encDict.get('/R') || 2;
  const filter = encDict.get('/Filter');
  const lengthBits = encDict.get('/Length') || (v === 1 ? 40 : 128);

  const permissions = parsePermissions(pVal);

  // Extract Document ID if available
  let docIdBytes = new Uint8Array(0);
  const idArray = doc.trailer.get('/ID');
  if (idArray instanceof PdfArray && idArray.length > 0) {
    const firstId = idArray.get(0);
    if (firstId instanceof PdfString) docIdBytes = firstId.bytes;
  }

  // Check if openable with empty password
  const fek = computeFileEncryptionKey(encDict, '', docIdBytes);
  const requiresPassword = (fek === null);

  return {
    isEncrypted: true,
    requiresPassword,
    permissions,
    pVal,
    v,
    r,
    filter,
    keyLength: lengthBits / 8
  };
}

/**
 * Decrypts a single PdfString AST object.
 */
function decryptString(strObj, fek, objNum, genNum, v, r) {
  try {
    if (v === 5 || r >= 5) {
      if (strObj.bytes.length <= 16) return strObj.bytes;
      const iv = strObj.bytes.subarray(0, 16);
      const cipherText = strObj.bytes.subarray(16);
      if (cipherText.length % 16 !== 0) return strObj.bytes;
      return aesDecryptCbc(fek, iv, cipherText, true);
    } else if (v === 4) {
      const objKey = computeObjectKey(fek, objNum, genNum, true);
      if (strObj.bytes.length <= 16) return strObj.bytes;
      const iv = strObj.bytes.subarray(0, 16);
      const cipherText = strObj.bytes.subarray(16);
      if (cipherText.length % 16 !== 0) return strObj.bytes;
      return aesDecryptCbc(objKey, iv, cipherText, true);
    } else {
      const objKey = computeObjectKey(fek, objNum, genNum, false);
      return rc4(objKey, strObj.bytes);
    }
  } catch (err) {
    return strObj.bytes;
  }
}

/**
 * Decrypts a single PdfStream AST object.
 */
function decryptStream(streamObj, fek, objNum, genNum, v, r) {
  if (streamObj.dict && streamObj.dict.get('/Type') === '/XRef') {
    return streamObj.bytes; // XRef streams are never encrypted
  }
  try {
    if (v === 5 || r >= 5) {
      if (streamObj.bytes.length <= 16) return streamObj.bytes;
      const iv = streamObj.bytes.subarray(0, 16);
      const cipherText = streamObj.bytes.subarray(16);
      if (cipherText.length % 16 !== 0) return streamObj.bytes;
      return aesDecryptCbc(fek, iv, cipherText, true);
    } else if (v === 4) {
      const objKey = computeObjectKey(fek, objNum, genNum, true);
      if (streamObj.bytes.length <= 16) return streamObj.bytes;
      const iv = streamObj.bytes.subarray(0, 16);
      const cipherText = streamObj.bytes.subarray(16);
      if (cipherText.length % 16 !== 0) return streamObj.bytes;
      return aesDecryptCbc(objKey, iv, cipherText, true);
    } else {
      const objKey = computeObjectKey(fek, objNum, genNum, false);
      return rc4(objKey, streamObj.bytes);
    }
  } catch (err) {
    return streamObj.bytes;
  }
}

/**
 * Recursively decrypts all string and stream objects in the AST.
 */
function decryptAstRecursive(val, fek, objNum, genNum, v, r) {
  if (val instanceof PdfString) {
    val.bytes = decryptString(val, fek, objNum, genNum, v, r);
  } else if (val instanceof PdfDict) {
    for (const [k, child] of val.map.entries()) {
      if (k === '/Encrypt' || k === '/ID') continue;
      decryptAstRecursive(child, fek, objNum, genNum, v, r);
    }
  } else if (val instanceof PdfArray) {
    for (let i = 0; i < val.length; i++) {
      decryptAstRecursive(val.get(i), fek, objNum, genNum, v, r);
    }
  }
}

/**
 * Completely unlocks the document (losslessly decrypts all objects and strips /Encrypt).
 * PDF 문서를 완전히 복호화하고 /Encrypt 보안 딕셔너리를 제거하여 무제한 PDF로 변환합니다.
 * @param {PdfDocument} doc - Target PDF Document AST / 대상 PDF AST
 * @param {string} password - User or Owner password (default: '') / 비밀번호
 * @returns {Object} { success: boolean, message?: string }
 */
export function unlockDocument(doc, password = '') {
  if (!doc.encryptRef) {
    return { success: true, message: 'Document is not encrypted' };
  }

  const encObj = doc.getObject(doc.encryptRef.num, doc.encryptRef.gen);
  if (!encObj || !(encObj.data instanceof PdfDict)) {
    return { success: false, message: 'Invalid /Encrypt dictionary' };
  }

  const encDict = encObj.data;
  const v = encDict.get('/V') || 1;
  const r = encDict.get('/R') || 2;

  let docIdBytes = new Uint8Array(0);
  const idArray = doc.trailer.get('/ID');
  if (idArray instanceof PdfArray && idArray.length > 0) {
    const firstId = idArray.get(0);
    if (firstId instanceof PdfString) docIdBytes = firstId.bytes;
  }

  const fek = computeFileEncryptionKey(encDict, password, docIdBytes);
  if (!fek) {
    return { success: false, message: 'Password required or incorrect' };
  }

  // Decrypt all objects in document
  for (const obj of doc.objects.values()) {
    if (obj.num === doc.encryptRef.num && obj.gen === doc.encryptRef.gen) {
      continue;
    }
    if (obj.stream) {
      obj.stream.bytes = decryptStream(obj.stream, fek, obj.num, obj.gen, v, r);
    }
    decryptAstRecursive(obj.data, fek, obj.num, obj.gen, v, r);
  }

  // Remove /Encrypt from document AST
  doc.objects.delete(`${doc.encryptRef.num}:0`);
  doc.trailer.delete('/Encrypt');

  // Strip any lingering /Encrypt entries across all dictionary objects
  for (const obj of doc.objects.values()) {
    if (obj.data instanceof PdfDict) {
      obj.data.delete('/Encrypt');
    }
  }

  doc.encryptRef = null;
  return { success: true };
}

/**
 * Reconfigures PDF permissions (Stirling-PDF style: Change Permissions).
 * PDF 권한만 세부적으로 재조정합니다.
 * @param {PdfDocument} doc - Target PDF Document AST / 대상 PDF AST
 * @param {Object} options - Configuration options / 권한 재조정 옵션
 * @returns {Object} { success: boolean, message?: string }
 */
export function changeDocumentPermissions(doc, options = {}) {
  const {
    permissions = {},
    ownerPassword = 'master_' + Math.random().toString(36).substr(2, 8),
    userPassword = '',
    currentPassword = '',
    algorithm = 'AES-128'
  } = options;

  // 1. If currently encrypted, decrypt it first using currentPassword
  if (doc.encryptRef) {
    const unlockRes = unlockDocument(doc, currentPassword);
    if (!unlockRes.success) {
      return unlockRes;
    }
  }

  // 2. Set new permissions integer
  const pVal = buildPermissions(permissions);
  const isAes = algorithm === 'AES-128';
  const v = isAes ? 4 : 2;
  const r = isAes ? 4 : 3;
  const keyLength = 16; // 128-bit

  // 3. Generate random Document ID if not present
  let docIdBytes;
  let idArray = doc.trailer.get('/ID');
  if (!idArray || !(idArray instanceof PdfArray) || idArray.length === 0) {
    const id1 = new Uint8Array(16);
    const id2 = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      id1[i] = Math.floor(Math.random() * 256);
      id2[i] = Math.floor(Math.random() * 256);
    }
    docIdBytes = id1;
    idArray = new PdfArray();
    idArray.push(new PdfString(id1, true));
    idArray.push(new PdfString(id2, true));
    doc.trailer.set('/ID', idArray);
  } else {
    docIdBytes = idArray.get(0).bytes;
  }

  // 4. Create new /Encrypt dictionary
  const encDict = new PdfDict();
  encDict.set('/Filter', '/Standard');
  encDict.set('/V', v);
  encDict.set('/R', r);
  encDict.set('/Length', keyLength * 8);
  encDict.set('/P', pVal);

  if (isAes) {
    const cfDict = new PdfDict();
    const stdCf = new PdfDict();
    stdCf.set('/CFM', '/AESV2');
    stdCf.set('/Length', 16);
    stdCf.set('/AuthEvent', '/DocOpen');
    cfDict.set('/StdCF', stdCf);

    encDict.set('/CF', cfDict);
    encDict.set('/StmF', '/StdCF');
    encDict.set('/StrF', '/StdCF');
  }

  // 5. Compute /O and /U hashes
  const oHash = computeOwnerPasswordHash(ownerPassword, userPassword, r, keyLength);
  encDict.set('/O', new PdfString(oHash, false));

  // Compute FEK for user password
  const fek = computeRawFek234(encDict, userPassword, docIdBytes);
  const uHash = computeUserPasswordHash(fek, r, docIdBytes);
  encDict.set('/U', new PdfString(uHash, false));

  // 6. Find available object number for new /Encrypt dictionary
  let maxNum = 0;
  for (const obj of doc.objects.values()) {
    if (obj.num > maxNum) maxNum = obj.num;
  }
  const encObjNum = maxNum + 1;
  doc.setObject(encObjNum, 0, encDict, null);

  doc.encryptRef = new PdfRef(encObjNum, 0);
  doc.trailer.set('/Encrypt', doc.encryptRef);

  // 7. Encrypt all strings and streams in the document AST
  for (const obj of doc.objects.values()) {
    if (obj.num === encObjNum) continue;

    if (obj.stream) {
      if (isAes) {
        const objKey = computeObjectKey(fek, obj.num, obj.gen, true);
        const iv = new Uint8Array(16);
        for (let i = 0; i < 16; i++) iv[i] = Math.floor(Math.random() * 256);
        const encrypted = aesEncryptCbc(objKey, iv, obj.stream.bytes, true);
        const fullStream = new Uint8Array(16 + encrypted.length);
        fullStream.set(iv, 0);
        fullStream.set(encrypted, 16);
        obj.stream.bytes = fullStream;
      } else {
        const objKey = computeObjectKey(fek, obj.num, obj.gen, false);
        obj.stream.bytes = rc4(objKey, obj.stream.bytes);
      }
    }

    encryptAstRecursive(obj.data, fek, obj.num, obj.gen, isAes);
  }

  return { success: true };
}

/**
 * Recursively encrypts all string AST nodes.
 */
function encryptAstRecursive(val, fek, objNum, genNum, isAes) {
  if (val instanceof PdfString) {
    if (isAes) {
      const objKey = computeObjectKey(fek, objNum, genNum, true);
      const iv = new Uint8Array(16);
      for (let i = 0; i < 16; i++) iv[i] = Math.floor(Math.random() * 256);
      const encrypted = aesEncryptCbc(objKey, iv, val.bytes, true);
      const full = new Uint8Array(16 + encrypted.length);
      full.set(iv, 0);
      full.set(encrypted, 16);
      val.bytes = full;
    } else {
      const objKey = computeObjectKey(fek, objNum, genNum, false);
      val.bytes = rc4(objKey, val.bytes);
    }
  } else if (val instanceof PdfDict) {
    for (const [k, child] of val.map.entries()) {
      if (k === '/Encrypt' || k === '/ID') continue;
      encryptAstRecursive(child, fek, objNum, genNum, isAes);
    }
  } else if (val instanceof PdfArray) {
    for (let i = 0; i < val.length; i++) {
      encryptAstRecursive(val.get(i), fek, objNum, genNum, isAes);
    }
  }
}
