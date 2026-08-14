/**
 * @file src/ui/app.js
 * @description Main UI application controller for PDF Permission Unlocker.
 *              PDF 권한 해제 웹 애플리케이션의 메인 UI 컨트롤러.
 */

import { t, setLanguage, getLanguage, updateDomTexts } from './i18n.js';
import { parsePdf } from '../core/pdf_parser.js';
import { analyzePdfSecurity, unlockPdfDocument } from '../core/pdf_decryptor.js';
import { serializePdf } from '../core/pdf_serializer.js';

// State management / 상태 관리
const state = {
  queue: [], // Array of file items
  activePasswordItem: null
};

// DOM Elements / DOM 요소 참조
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const queueSection = document.getElementById('queueSection');
const fileList = document.getElementById('fileList');
const queueCountBadge = document.getElementById('queueCountBadge');
const clearAllBtn = document.getElementById('clearAllBtn');
const unlockAllBtn = document.getElementById('unlockAllBtn');
const langToggleBtn = document.getElementById('langToggleBtn');

const passwordModal = document.getElementById('passwordModal');
const modalPasswordInput = document.getElementById('modalPasswordInput');
const modalCancelBtn = document.getElementById('modalCancelBtn');
const modalConfirmBtn = document.getElementById('modalConfirmBtn');
const modalFileDesc = document.getElementById('modalFileDesc');

/**
 * Format bytes to readable size.
 * 파일 크기를 사람이 읽기 쉬운 형식으로 변환합니다.
 */
function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Initialize event listeners.
 * 이벤트 리스너를 초기화합니다.
 */
function init() {
  updateDomTexts();

  // Language toggle / 다국어 토글
  if (langToggleBtn) {
    langToggleBtn.addEventListener('click', () => {
      const next = getLanguage() === 'ko' ? 'en' : 'ko';
      setLanguage(next);
      renderQueue();
    });
  }

  // File drop & select events / 파일 드롭 및 선택 이벤트
  if (dropZone && fileInput) {
    dropZone.addEventListener('click', () => fileInput.click());

    ['dragenter', 'dragover'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('dragover');
      });
    });

    dropZone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        handleFiles(dt.files);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        handleFiles(e.target.files);
        fileInput.value = ''; // Reset
      }
    });
  }

  // Queue actions / 큐 액션 버튼
  if (clearAllBtn) {
    clearAllBtn.addEventListener('click', () => {
      state.queue = [];
      renderQueue();
    });
  }

  if (unlockAllBtn) {
    unlockAllBtn.addEventListener('click', async () => {
      for (const item of state.queue) {
        if (item.status === 'ready' || item.status === 'error') {
          await processItem(item);
        }
      }
    });
  }

  // Modal actions / 모달 버튼
  if (modalCancelBtn && passwordModal) {
    modalCancelBtn.addEventListener('click', () => {
      passwordModal.classList.add('hidden');
      state.activePasswordItem = null;
    });
  }

  if (modalConfirmBtn && modalPasswordInput) {
    modalConfirmBtn.addEventListener('click', async () => {
      const pw = modalPasswordInput.value;
      const item = state.activePasswordItem;
      if (item) {
        passwordModal.classList.add('hidden');
        await processItem(item, pw);
      }
    });
  }
}

/**
 * Handle added files.
 * 추가된 파일들을 큐에 등록하고 분석합니다.
 */
async function handleFiles(files) {
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    if (file.type !== 'application/pdf' && !file.name.toLowerCase().endsWith('.pdf')) {
      continue;
    }

    const item = {
      id: 'file_' + Math.random().toString(36).substr(2, 9),
      file,
      name: file.name,
      size: file.size,
      status: 'analyzing', // 'analyzing', 'ready', 'processing', 'done', 'error'
      securityInfo: null,
      doc: null,
      resultBlob: null,
      downloadUrl: null,
      errorMsg: null
    };

    state.queue.push(item);
    renderQueue();

    // Read and analyze asynchronously / 비동기로 파일 읽기 및 분석
    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const doc = parsePdf(bytes);
      const sec = analyzePdfSecurity(doc);

      item.doc = doc;
      item.securityInfo = sec;
      item.status = 'ready';
    } catch (err) {
      console.error('PDF Analysis error:', err);
      item.status = 'error';
      item.errorMsg = err.message || 'Failed to parse PDF';
    }
    renderQueue();
  }
}

/**
 * Process unlocking of a single file item.
 * 단일 파일 항목의 권한 해제를 수행합니다.
 */
async function processItem(item, password = '') {
  if (item.securityInfo && item.securityInfo.requiresPassword && !password) {
    // Show password modal / 비밀번호 입력 모달 팝업
    state.activePasswordItem = item;
    if (modalFileDesc) modalFileDesc.textContent = `${item.name}: ${t('modalFileDesc')}`;
    if (modalPasswordInput) modalPasswordInput.value = '';
    if (passwordModal) passwordModal.classList.remove('hidden');
    return;
  }

  item.status = 'processing';
  renderQueue();

  try {
    // 1. Decrypt document / 문서 복호화
    const unlockRes = unlockPdfDocument(item.doc, password);
    if (!unlockRes.success) {
      item.status = 'error';
      item.errorMsg = unlockRes.message || t('invalidPassword');
      renderQueue();
      return;
    }

    // 2. Serialize to unencrypted PDF bytes / 비암호화 PDF로 직렬화
    const unlockedBytes = serializePdf(item.doc);
    const blob = new Blob([unlockedBytes], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);

    item.resultBlob = blob;
    item.downloadUrl = url;
    item.status = 'done';
  } catch (err) {
    console.error('PDF Unlock Error:', err);
    item.status = 'error';
    item.errorMsg = err.message || t('statusError');
  }

  renderQueue();
}

/**
 * Render the entire file queue UI.
 * 전체 파일 큐 UI를 렌더링합니다.
 */
function renderQueue() {
  if (!queueSection || !fileList || !queueCountBadge) return;

  if (state.queue.length === 0) {
    queueSection.classList.add('hidden');
    queueCountBadge.textContent = '0';
    return;
  }

  queueSection.classList.remove('hidden');
  queueCountBadge.textContent = String(state.queue.length);
  fileList.innerHTML = '';

  state.queue.forEach(item => {
    const card = document.createElement('div');
    card.className = 'file-card';

    // File Top Header
    const top = document.createElement('div');
    top.className = 'file-card-top';

    const meta = document.createElement('div');
    meta.className = 'file-meta';

    const icon = document.createElement('div');
    icon.className = 'file-icon';
    icon.textContent = 'PDF';

    const info = document.createElement('div');
    info.className = 'file-info';
    const nameEl = document.createElement('h4');
    nameEl.textContent = item.name;
    const sizeEl = document.createElement('p');
    sizeEl.textContent = `${formatFileSize(item.size)} • PDF ${item.doc ? item.doc.headerVersion : '1.7'}`;
    info.appendChild(nameEl);
    info.appendChild(sizeEl);

    meta.appendChild(icon);
    meta.appendChild(info);

    // Actions
    const actions = document.createElement('div');
    actions.className = 'file-item-actions';

    if (item.status === 'analyzing') {
      const statusEl = document.createElement('span');
      statusEl.className = 'badge';
      statusEl.textContent = t('statusAnalyzing');
      actions.appendChild(statusEl);
    } else if (item.status === 'processing') {
      const statusEl = document.createElement('span');
      statusEl.className = 'badge';
      statusEl.textContent = t('statusDecrypting');
      actions.appendChild(statusEl);
    } else if (item.status === 'done') {
      const dlBtn = document.createElement('a');
      dlBtn.className = 'btn btn-sm btn-success';
      dlBtn.href = item.downloadUrl;
      dlBtn.download = item.name.replace(/\.pdf$/i, '_unlocked.pdf');
      dlBtn.textContent = `📥 ${t('downloadBtn')}`;
      actions.appendChild(dlBtn);
    } else if (item.status === 'error') {
      const errEl = document.createElement('span');
      errEl.className = 'badge';
      errEl.style.color = 'var(--color-danger)';
      errEl.textContent = item.errorMsg || t('statusError');
      actions.appendChild(errEl);

      const retryBtn = document.createElement('button');
      retryBtn.className = 'btn btn-sm btn-secondary';
      retryBtn.textContent = 'Retry';
      retryBtn.addEventListener('click', () => processItem(item));
      actions.appendChild(retryBtn);
    } else if (item.status === 'ready') {
      const isEncrypted = item.securityInfo && item.securityInfo.isEncrypted;
      if (!isEncrypted) {
        const span = document.createElement('span');
        span.className = 'badge security-badge';
        span.textContent = t('alreadyUnlocked');
        actions.appendChild(span);
      } else {
        const unlockBtn = document.createElement('button');
        unlockBtn.className = 'btn btn-sm btn-primary';
        unlockBtn.textContent = t('unlockAllBtn');
        unlockBtn.addEventListener('click', () => processItem(item));
        actions.appendChild(unlockBtn);
      }
    }

    top.appendChild(meta);
    top.appendChild(actions);
    card.appendChild(top);

    // Permission Badges Grid
    if (item.securityInfo && item.securityInfo.isEncrypted) {
      const permGrid = document.createElement('div');
      permGrid.className = 'permission-grid';

      const perms = item.securityInfo.permissions;
      const permItems = [
        { label: t('permPrint'), allowed: perms.canPrint, icon: '🖨️' },
        { label: t('permCopy'), allowed: perms.canCopy, icon: '📋' },
        { label: t('permModify'), allowed: perms.canModify, icon: '✏️' },
        { label: t('permAnnotate'), allowed: perms.canAnnotate, icon: '💬' }
      ];

      permItems.forEach(p => {
        const badge = document.createElement('span');
        const isNowAllowed = (item.status === 'done') ? true : p.allowed;
        badge.className = `perm-item ${isNowAllowed ? 'perm-allowed' : 'perm-restricted'}`;
        badge.textContent = `${p.icon} ${p.label}: ${isNowAllowed ? t('permAllowed') : t('permRestricted')}`;
        permGrid.appendChild(badge);
      });

      card.appendChild(permGrid);
    }

    fileList.appendChild(card);
  });
}

// Auto bootstrap on DOM load / DOM 로드 시 실행
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
}
