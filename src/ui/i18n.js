/**
 * @file src/ui/i18n.js
 * @description Internationalization dictionary and helper for PDF Permission Unlocker.
 *              PDF 권한 해제 웹 애플리케이션의 다국어(한국어/영어) 리소스 사전 및 헬퍼.
 */

export const translations = {
  ko: {
    appTitle: 'PDF 권한 해제기',
    appSubtitle: '100% 오프라인 무손실 PDF 보안 및 권한(인쇄/복사/수정) 해제 도구',
    offlineBadge: '100% 로컬 & 오프라인',
    dropTitle: 'PDF 파일을 여기에 드래그하거나 클릭하여 선택하세요',
    dropDesc: '인쇄 제한, 텍스트 복사 금지, 수정 제한이 걸린 PDF 파일을 원본 손실 없이 완벽하게 해제합니다',
    privacyNote: '모든 처리는 브라우저 메모리 내에서 로컬로 진행되며 서버로 파일이 전송되지 않습니다',
    queueTitle: '작업 파일 목록',
    clearAllBtn: '전체 지우기',
    unlockAllBtn: '모든 파일 일괄 해제',
    downloadBtn: '권한 해제된 PDF 다운로드',
    alreadyUnlocked: '이미 모든 권한이 허용된 파일입니다',
    statusReady: '대기 중',
    statusAnalyzing: '권한 분석 중...',
    statusDecrypting: '무손실 복호화 중...',
    statusDone: '권한 해제 완료',
    statusError: '해제 실패',
    modalTitle: '문서 열기 비밀번호 필요',
    modalFileDesc: '이 문서는 열람 자체에 비밀번호가 설정되어 있습니다. 비밀번호를 입력하면 모든 권한이 해제된 PDF로 저장됩니다.',
    modalPasswordPlaceholder: '비밀번호를 입력하세요',
    modalCancelBtn: '취소',
    modalConfirmBtn: '권한 해제',
    permPrint: '인쇄',
    permCopy: '복사/추출',
    permModify: '내용 수정',
    permAnnotate: '주석/양식',
    permAllowed: '허용됨',
    permRestricted: '제한됨',
    invalidPassword: '비밀번호가 올바르지 않습니다.',
    footerText: 'PDF Permission Unlocker © 2026 — Zero-dependency, 100% Client-side Security Removal'
  },
  en: {
    appTitle: 'PDF Permission Unlocker',
    appSubtitle: '100% Offline Lossless PDF Security & Permission (Print/Copy/Edit) Removal',
    offlineBadge: '100% Local & Offline',
    dropTitle: 'Drag & Drop PDF files here or click to browse',
    dropDesc: 'Losslessly remove print restrictions, copy protection, and editing locks from PDF files',
    privacyNote: 'Files are processed locally in browser memory and never uploaded to any server',
    queueTitle: 'File Queue',
    clearAllBtn: 'Clear All',
    unlockAllBtn: 'Unlock All Files',
    downloadBtn: 'Download Unlocked PDF',
    alreadyUnlocked: 'Document is already fully unlocked',
    statusReady: 'Ready',
    statusAnalyzing: 'Analyzing security...',
    statusDecrypting: 'Decrypting losslessly...',
    statusDone: 'Unlocked',
    statusError: 'Failed',
    modalTitle: 'Open Password Required',
    modalFileDesc: 'This document requires an open password. Enter the password to unlock all permissions and save as an unrestricted PDF.',
    modalPasswordPlaceholder: 'Enter password',
    modalCancelBtn: 'Cancel',
    modalConfirmBtn: 'Unlock',
    permPrint: 'Print',
    permCopy: 'Copy/Extract',
    permModify: 'Edit Content',
    permAnnotate: 'Annotations',
    permAllowed: 'Allowed',
    permRestricted: 'Restricted',
    invalidPassword: 'Incorrect password.',
    footerText: 'PDF Permission Unlocker © 2026 — Zero-dependency, 100% Client-side Security Removal'
  }
};

let currentLang = 'ko';

export function getLanguage() {
  return currentLang;
}

export function setLanguage(lang) {
  if (translations[lang]) {
    currentLang = lang;
    updateDomTexts();
  }
}

export function t(key) {
  return (translations[currentLang] && translations[currentLang][key]) || translations['en'][key] || key;
}

export function updateDomTexts() {
  const elements = document.querySelectorAll('[data-i18n]');
  elements.forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (key && translations[currentLang][key]) {
      el.textContent = translations[currentLang][key];
    }
  });
}
