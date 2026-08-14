/**
 * @file src/ui/i18n.js
 * @description Internationalization dictionary and helper for PDF Permission Manager.
 *              PDF 권한 관리 및 해제 웹 애플리케이션의 다국어(한국어/영어) 리소스 사전 및 헬퍼.
 */

export const translations = {
  ko: {
    appTitle: 'PDF 권한 관리기',
    appSubtitle: '100% 오프라인 무손실 PDF 권한 재조정(Change Permissions) 및 보안 해제 도구',
    offlineBadge: '100% 로컬 & 오프라인',
    tabChangePerms: '⚙️ 권한 재조정 (Change Permissions)',
    tabUnlockPerms: '🔓 권한 완전 해제 (Unlock)',
    
    // Presets
    presetLabel: '빠른 권한 프리셋',
    presetFull: '모두 허용',
    presetReadPrint: '읽기 및 인쇄 전용',
    presetReadOnly: '엄격한 열람 전용 (인쇄/복사 금지)',
    presetCustom: '사용자 지정',
    
    // Permission Controls
    permSectionTitle: '세부 권한 설정 (Permissions Configuration)',
    permPrintLabel: '인쇄 허용 (Printing)',
    permPrintHigh: '고품질 인쇄 허용',
    permPrintLow: '저해상도(150dpi)만 허용',
    permPrintNone: '인쇄 금지',
    
    permCopyLabel: '내용 복사 및 텍스트 추출 (Copy & Extract)',
    permCopyDesc: '텍스트 및 그래픽의 클립보드 복사를 허용합니다',
    
    permModifyLabel: '문서 내용 수정 (Modify Content)',
    permModifyDesc: '페이지 본문 편집 및 변경을 허용합니다',
    
    permAnnotateLabel: '주석 및 메모 작성 (Annotations & Comments)',
    permAnnotateDesc: '주석, 메모, 서명 필드 수정을 허용합니다',
    
    permFillFormsLabel: '양식 필드 입력 (Form Filling)',
    permFillFormsDesc: '대화형 폼 필드 입력 및 저장을 허용합니다',
    
    permAssembleLabel: '문서 조합 (Document Assembly)',
    permAssembleDesc: '페이지 삽입, 삭제, 회전 및 북마크 생성을 허용합니다',
    
    permExtractAccessibilityLabel: '접근성 낭독 추출 (Accessibility)',
    permExtractAccessibilityDesc: '시각 장애인을 위한 화면 낭독기 텍스트 추출을 허용합니다',
    
    // Security & Passwords
    securitySectionTitle: '암호화 및 비밀번호 설정 (Security & Passwords)',
    ownerPasswordLabel: '권한 관리자 암호 (Owner Password)',
    ownerPasswordDesc: '권한 설정을 보호하고 변경을 제한하는 마스터 암호입니다',
    ownerPasswordPlaceholder: '관리자 암호 (미입력 시 자동 생성)',
    userPasswordLabel: '문서 열람 암호 (User Password - 선택 사항)',
    userPasswordDesc: '문서를 열 때 입력해야 하는 암호입니다 (비워두면 암호 없이 즉시 열림)',
    userPasswordPlaceholder: '열람 암호 (선택 사항)',
    algorithmLabel: '암호화 표준 (Encryption Standard)',
    
    // Drop Zone
    dropTitle: 'PDF 파일을 여기에 드래그하거나 클릭하여 선택하세요',
    dropDesc: '서버 업로드 없이 100% 브라우저 메모리 내에서 안전하고 무손실로 처리됩니다',
    privacyNote: '모든 처리는 브라우저 로컬에서 안전하게 수행되며 파일이 외부로 전송되지 않습니다',
    
    // Queue & Actions
    queueTitle: '작업 파일 목록',
    clearAllBtn: '전체 지우기',
    applyAllBtn: '선택한 권한 일괄 적용',
    unlockAllBtn: '모든 권한 일괄 해제',
    applySingleBtn: '권한 적용 및 다운로드',
    downloadUnlockedBtn: '해제된 PDF 다운로드',
    
    // Status & Badges
    statusReady: '대기 중',
    statusAnalyzing: '권한 분석 중...',
    statusProcessing: '권한 재설정 및 암호화 중...',
    statusDecrypting: '무손실 복호화 중...',
    statusDone: '처리 완료',
    statusError: '처리 실패',
    
    // Current vs New permissions view
    currentPerms: '현재 권한',
    targetPerms: '변경 권한',
    permAllowed: '허용',
    permRestricted: '제한',
    encryptedBadge: '암호화됨',
    unencryptedBadge: '비암호화',
    
    // Password Modal
    modalTitle: '문서 열기 비밀번호 필요',
    modalFileDesc: '이 문서는 열람 암호가 걸려 있습니다. 비밀번호를 입력하면 권한 재조정 또는 해제가 가능합니다.',
    modalPasswordPlaceholder: '비밀번호를 입력하세요',
    modalCancelBtn: '취소',
    modalConfirmBtn: '확인',
    invalidPassword: '비밀번호가 올바르지 않습니다.',
    
    footerText: 'PDF Permission Master © 2026 — Zero-dependency, 100% Client-side Security & Permission Control'
  },
  en: {
    appTitle: 'PDF Permission Master',
    appSubtitle: '100% Offline Lossless PDF Permission Reconfigurer & Security Unlocker',
    offlineBadge: '100% Local & Offline',
    tabChangePerms: '⚙️ Change Permissions',
    tabUnlockPerms: '🔓 Unlock All Permissions',
    
    // Presets
    presetLabel: 'Quick Presets',
    presetFull: 'Full Access',
    presetReadPrint: 'Read & Print Only',
    presetReadOnly: 'Strict Read Only (No Print/Copy)',
    presetCustom: 'Custom',
    
    // Permission Controls
    permSectionTitle: 'Permissions Configuration',
    permPrintLabel: 'Printing Permission',
    permPrintHigh: 'Allow High Quality',
    permPrintLow: 'Allow Low-Res (150 dpi) Only',
    permPrintNone: 'Deny Printing',
    
    permCopyLabel: 'Copy Content & Extract Text',
    permCopyDesc: 'Allow copying text and graphics to clipboard',
    
    permModifyLabel: 'Modify Document Content',
    permModifyDesc: 'Allow editing and modifying page contents',
    
    permAnnotateLabel: 'Annotations & Comments',
    permAnnotateDesc: 'Allow adding annotations, comments, and signatures',
    
    permFillFormsLabel: 'Fill Interactive Forms',
    permFillFormsDesc: 'Allow filling form fields and signing',
    
    permAssembleLabel: 'Document Assembly',
    permAssembleDesc: 'Allow page insertion, deletion, rotation, and bookmarks',
    
    permExtractAccessibilityLabel: 'Extract for Accessibility',
    permExtractAccessibilityDesc: 'Allow screen readers to extract text for users with disabilities',
    
    // Security & Passwords
    securitySectionTitle: 'Security & Passwords',
    ownerPasswordLabel: 'Owner / Master Password',
    ownerPasswordDesc: 'Master password used to enforce and modify permissions',
    ownerPasswordPlaceholder: 'Owner password (auto-generated if blank)',
    userPasswordLabel: 'Open / User Password (Optional)',
    userPasswordDesc: 'Password required to open the PDF (leave blank for password-free viewing)',
    userPasswordPlaceholder: 'User password (optional)',
    algorithmLabel: 'Encryption Standard',
    
    // Drop Zone
    dropTitle: 'Drag & Drop PDF files here or click to browse',
    dropDesc: '100% Client-side in browser memory with zero quality loss or server uploads',
    privacyNote: 'Files are processed locally in your browser and never uploaded anywhere',
    
    // Queue & Actions
    queueTitle: 'File Queue',
    clearAllBtn: 'Clear All',
    applyAllBtn: 'Apply Permissions to All',
    unlockAllBtn: 'Unlock All Files',
    applySingleBtn: 'Apply & Download',
    downloadUnlockedBtn: 'Download Unlocked PDF',
    
    // Status & Badges
    statusReady: 'Ready',
    statusAnalyzing: 'Analyzing security...',
    statusProcessing: 'Applying permissions & encrypting...',
    statusDecrypting: 'Decrypting losslessly...',
    statusDone: 'Completed',
    statusError: 'Failed',
    
    // Current vs New permissions view
    currentPerms: 'Current',
    targetPerms: 'Target',
    permAllowed: 'Allowed',
    permRestricted: 'Restricted',
    encryptedBadge: 'Encrypted',
    unencryptedBadge: 'Unencrypted',
    
    // Password Modal
    modalTitle: 'Open Password Required',
    modalFileDesc: 'This document requires an open password. Please enter the password to process permissions.',
    modalPasswordPlaceholder: 'Enter password',
    modalCancelBtn: 'Cancel',
    modalConfirmBtn: 'Confirm',
    invalidPassword: 'Password is incorrect.',
    
    footerText: 'PDF Permission Master © 2026 — Zero-dependency, 100% Client-side Security & Permission Control'
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
  return (translations[currentLang] && translations[currentLang][key]) || (translations['en'] && translations['en'][key]) || key;
}

export function updateDomTexts() {
  const elements = document.querySelectorAll('[data-i18n]');
  elements.forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (key && translations[currentLang][key]) {
      el.textContent = translations[currentLang][key];
    }
  });

  const placeholders = document.querySelectorAll('[data-i18n-placeholder]');
  placeholders.forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (key && translations[currentLang][key]) {
      el.placeholder = translations[currentLang][key];
    }
  });
}
