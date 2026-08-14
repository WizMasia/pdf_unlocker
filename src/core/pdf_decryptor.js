/**
 * @file src/core/pdf_decryptor.js
 * @description Backward-compatible facade for PDF Security & Decryption engine.
 *              PDF 보안 분석 및 복호화 엔진의 하위 호환 파사드 모듈.
 */

import { analyzeSecurity, unlockDocument, changeDocumentPermissions } from './pdf_security.js';

export {
  analyzeSecurity as analyzePdfSecurity,
  unlockDocument as unlockPdfDocument,
  changeDocumentPermissions
};
