/**
 * @file src/ui/app.js
 * @description Main UI Application Controller for PDF Permission Master.
 *              PDF 권한 관리 및 해제 웹 애플리케이션의 메인 UI 컨트롤러.
 */

import { t, setLanguage, getLanguage, updateDomTexts } from './i18n.js';
import { parsePdf } from '../core/pdf_parser.js';
import { analyzeSecurity, unlockDocument, changeDocumentPermissions } from '../core/pdf_security.js';
import { serializePdf } from '../core/pdf_serializer.js';

// Application State / 애플리케이션 상태 관리
const state = {
  currentTab: 'changePerms', // 'changePerms' | 'unlockPerms'
  activePreset: 'readPrint',  // 'full' | 'readPrint' | 'readOnly' | 'custom'
  queue: [],                  // Array of queued file items
  activePasswordItem: null
};

// DOM Element References / DOM 요소 참조
const tabChangePerms = document.getElementById('tabChangePerms');
const tabUnlockPerms = document.getElementById('tabUnlockPerms');
const permConfigPanel = document.getElementById('permConfigPanel');
const langToggleBtn = document.getElementById('langToggleBtn');

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const queueSection = document.getElementById('queueSection');
const fileList = document.getElementById('fileList');
const queueCountBadge = document.getElementById('queueCountBadge');
const clearAllBtn = document.getElementById('clearAllBtn');
const actionAllBtn = document.getElementById('actionAllBtn');

// Permission Controls / 권한 설정 폼 요소
const presetChips = document.querySelectorAll('.chip-btn');
const printRadios = document.querySelectorAll('input[name="permPrint"]');
const permCopy = document.getElementById('permCopy');
const permModify = document.getElementById('permModify');
const permAnnotate = document.getElementById('permAnnotate');
const permFillForms = document.getElementById('permFillForms');
const permAssemble = document.getElementById('permAssemble');
const permExtractAccessibility = document.getElementById('permExtractAccessibility');

const ownerPasswordInput = document.getElementById('ownerPasswordInput');
const userPasswordInput = document.getElementById('userPasswordInput');
const algorithmSelect = document.getElementById('algorithmSelect');

// Password Modal / 비밀번호 모달
const passwordModal = document.getElementById('passwordModal');
const modalPasswordInput = document.getElementById('modalPasswordInput');
const modalCancelBtn = document.getElementById('modalCancelBtn');
const modalConfirmBtn = document.getElementById('modalConfirmBtn');
const modalFileDesc = document.getElementById('modalFileDesc');

/**
 * Format bytes to readable size string.
 * 파일 크기를 사람이 읽기 쉬운 문자열로 변환합니다.
 */
function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Collects current permission options configured in the UI.
 * UI에 설정된 현재 목표 권한 옵션 객체를 반환합니다.
 */
function getTargetPermissions() {
  const selectedPrint = document.querySelector('input[name="permPrint"]:checked')?.value || 'high';
  return {
    canPrint: selectedPrint !== 'none',
    canPrintHighQuality: selectedPrint === 'high',
    canCopy: permCopy.checked,
    canModify: permModify.checked,
    canAnnotate: permAnnotate.checked,
    canFillForms: permFillForms.checked,
    canAssemble: permAssemble.checked,
    canExtractAccessibility: permExtractAccessibility.checked
  };
}

/**
 * Applies a preset configuration to the UI toggles.
 * 선택한 프리셋 설정을 UI 토글 및 컨트롤에 적용합니다.
 */
function applyPreset(presetName) {
  state.activePreset = presetName;
  presetChips.forEach(chip => {
    chip.classList.toggle('active', chip.dataset.preset === presetName);
  });

  if (presetName === 'full') {
    document.querySelector('input[name="permPrint"][value="high"]').checked = true;
    permCopy.checked = true;
    permModify.checked = true;
    permAnnotate.checked = true;
    permFillForms.checked = true;
    permAssemble.checked = true;
    permExtractAccessibility.checked = true;
  } else if (presetName === 'readPrint') {
    document.querySelector('input[name="permPrint"][value="high"]').checked = true;
    permCopy.checked = false;
    permModify.checked = false;
    permAnnotate.checked = false;
    permFillForms.checked = true;
    permAssemble.checked = false;
    permExtractAccessibility.checked = true;
  } else if (presetName === 'readOnly') {
    document.querySelector('input[name="permPrint"][value="none"]').checked = true;
    permCopy.checked = false;
    permModify.checked = false;
    permAnnotate.checked = false;
    permFillForms.checked = false;
    permAssemble.checked = false;
    permExtractAccessibility.checked = true;
  }
}

/**
 * Switch tabs between 'changePerms' and 'unlockPerms'.
 * 탭 전환 처리.
 */
function switchTab(tabName) {
  state.currentTab = tabName;
  tabChangePerms.classList.toggle('active', tabName === 'changePerms');
  tabChangePerms.setAttribute('aria-selected', tabName === 'changePerms');
  tabUnlockPerms.classList.toggle('active', tabName === 'unlockPerms');
  tabUnlockPerms.setAttribute('aria-selected', tabName === 'unlockPerms');

  if (tabName === 'changePerms') {
    permConfigPanel.classList.remove('hidden');
    actionAllBtn.setAttribute('data-i18n', 'applyAllBtn');
    actionAllBtn.textContent = t('applyAllBtn');
  } else {
    permConfigPanel.classList.add('hidden');
    actionAllBtn.setAttribute('data-i18n', 'unlockAllBtn');
    actionAllBtn.textContent = t('unlockAllBtn');
  }

  renderQueue();
}

/**
 * Initializes UI event listeners.
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

  // Mode Tabs / 모드 탭
  if (tabChangePerms && tabUnlockPerms) {
    tabChangePerms.addEventListener('click', () => switchTab('changePerms'));
    tabUnlockPerms.addEventListener('click', () => switchTab('unlockPerms'));
  }

  // Presets / 프리셋 클릭
  presetChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const preset = chip.dataset.preset;
      applyPreset(preset);
    });
  });

  // Custom change detection on toggles
  const allToggles = [permCopy, permModify, permAnnotate, permFillForms, permAssemble, permExtractAccessibility];
  allToggles.forEach(toggle => {
    if (toggle) {
      toggle.addEventListener('change', () => {
        state.activePreset = 'custom';
        presetChips.forEach(chip => chip.classList.toggle('active', chip.dataset.preset === 'custom'));
      });
    }
  });
  printRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      state.activePreset = 'custom';
      presetChips.forEach(chip => chip.classList.toggle('active', chip.dataset.preset === 'custom'));
    });
  });

  // Drag & drop file uploads
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
        fileInput.value = '';
      }
    });
  }

  // Queue actions
  if (clearAllBtn) {
    clearAllBtn.addEventListener('click', () => {
      state.queue = [];
      renderQueue();
    });
  }

  if (actionAllBtn) {
    actionAllBtn.addEventListener('click', async () => {
      for (const item of state.queue) {
        if (item.status === 'ready' || item.status === 'error') {
          await processItem(item);
        }
      }
    });
  }

  // Modal actions
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

  // Apply default preset
  applyPreset('readPrint');
}

/**
 * Handles newly selected PDF files.
 * 추가된 파일들을 큐에 등록하고 보안 분석을 진행합니다.
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
      status: 'analyzing', // 'analyzing' | 'ready' | 'processing' | 'done' | 'error'
      securityInfo: null,
      doc: null,
      resultBlob: null,
      downloadUrl: null,
      errorMsg: null
    };

    state.queue.push(item);
    renderQueue();

    // Analyze security asynchronously
    try {
      const arrayBuffer = await file.arrayBuffer();
      const doc = parsePdf(arrayBuffer);
      const securityInfo = analyzeSecurity(doc);

      item.doc = doc;
      item.securityInfo = securityInfo;
      item.status = 'ready';
    } catch (err) {
      console.error('Failed to parse PDF:', err);
      item.status = 'error';
      item.errorMsg = err.message || 'Corrupted or invalid PDF format';
    }
    renderQueue();
  }
}

/**
 * Processes a single file item (Change Permissions or Unlock).
 * 파일 아이템에 대해 권한 재조정 또는 완전 해제를 실행합니다.
 */
async function processItem(item, providedPassword = '') {
  item.status = 'processing';
  item.errorMsg = null;
  renderQueue();

  try {
    const arrayBuffer = await item.file.arrayBuffer();
    const doc = parsePdf(arrayBuffer);

    if (state.currentTab === 'changePerms') {
      // Change Permissions Mode
      const targetPermissions = getTargetPermissions();
      const ownerPassword = ownerPasswordInput.value.trim() || 'master_' + Math.random().toString(36).substr(2, 8);
      const userPassword = userPasswordInput.value;
      const algorithm = algorithmSelect.value || 'AES-128';

      const res = changeDocumentPermissions(doc, {
        permissions: targetPermissions,
        ownerPassword,
        userPassword,
        currentPassword: providedPassword,
        algorithm
      });

      if (!res.success) {
        if (res.message?.includes('Password required') || res.message?.includes('incorrect')) {
          item.status = 'ready';
          state.activePasswordItem = item;
          modalFileDesc.textContent = `"${item.name}" ` + t('modalFileDesc');
          modalPasswordInput.value = '';
          passwordModal.classList.remove('hidden');
          modalPasswordInput.focus();
          return;
        }
        throw new Error(res.message || 'Permission modification failed');
      }

      const outputBytes = serializePdf(doc);
      const blob = new Blob([outputBytes], { type: 'application/pdf' });
      item.resultBlob = blob;
      item.downloadUrl = URL.createObjectURL(blob);
      item.status = 'done';
    } else {
      // Unlock Mode
      const res = unlockDocument(doc, providedPassword);
      if (!res.success) {
        if (res.message?.includes('Password required') || res.message?.includes('incorrect')) {
          item.status = 'ready';
          state.activePasswordItem = item;
          modalFileDesc.textContent = `"${item.name}" ` + t('modalFileDesc');
          modalPasswordInput.value = '';
          passwordModal.classList.remove('hidden');
          modalPasswordInput.focus();
          return;
        }
        throw new Error(res.message || 'Unlock failed');
      }

      const outputBytes = serializePdf(doc);
      const blob = new Blob([outputBytes], { type: 'application/pdf' });
      item.resultBlob = blob;
      item.downloadUrl = URL.createObjectURL(blob);
      item.status = 'done';
    }
  } catch (err) {
    console.error('Process error:', err);
    item.status = 'error';
    item.errorMsg = err.message || 'Processing error';
  }

  renderQueue();
}

/**
 * Renders the file queue list and status badges.
 * 파일 목록 큐와 상태를 렌더링합니다.
 */
function renderQueue() {
  if (state.queue.length === 0) {
    queueSection.classList.add('hidden');
    return;
  }

  queueSection.classList.remove('hidden');
  queueCountBadge.textContent = state.queue.length;
  fileList.innerHTML = '';

  state.queue.forEach((item, idx) => {
    const el = document.createElement('div');
    el.className = 'file-item';

    // Status text & badge class
    let statusText = t('statusReady');
    let statusClass = 'status-ready';

    if (item.status === 'analyzing') {
      statusText = t('statusAnalyzing');
      statusClass = 'status-analyzing';
    } else if (item.status === 'processing') {
      statusText = state.currentTab === 'changePerms' ? t('statusProcessing') : t('statusDecrypting');
      statusClass = 'status-processing';
    } else if (item.status === 'done') {
      statusText = t('statusDone');
      statusClass = 'status-done';
    } else if (item.status === 'error') {
      statusText = item.errorMsg || t('statusError');
      statusClass = 'status-error';
    }

    // Permission pills summary
    let permsSummaryHtml = '';
    if (item.securityInfo) {
      const p = item.securityInfo.permissions || {};
      const printClass = p.canPrint ? 'allowed' : 'restricted';
      const copyClass = p.canCopy ? 'allowed' : 'restricted';
      const modClass = p.canModify ? 'allowed' : 'restricted';

      permsSummaryHtml = `
        <div class="file-perms-summary">
          <span class="badge ${item.securityInfo.isEncrypted ? 'security-badge' : ''}" style="padding: 2px 6px; font-size: 0.72rem;">
            ${item.securityInfo.isEncrypted ? t('encryptedBadge') : t('unencryptedBadge')}
          </span>
          <span class="perm-pill ${printClass}">🖨️ ${p.canPrint ? (p.canPrintHighQuality ? 'Print (High)' : 'Print (Low)') : 'No Print'}</span>
          <span class="perm-pill ${copyClass}">📋 ${p.canCopy ? 'Copy' : 'No Copy'}</span>
          <span class="perm-pill ${modClass}">✏️ ${p.canModify ? 'Edit' : 'No Edit'}</span>
        </div>
      `;
    }

    // Actions button
    let actionBtnHtml = '';
    if (item.status === 'done' && item.downloadUrl) {
      const filenamePrefix = state.currentTab === 'changePerms' ? 'secured_' : 'unlocked_';
      actionBtnHtml = `
        <a href="${item.downloadUrl}" download="${filenamePrefix}${item.name}" class="btn btn-primary btn-sm">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>
          ${state.currentTab === 'changePerms' ? t('applySingleBtn') : t('downloadUnlockedBtn')}
        </a>
      `;
    } else if (item.status === 'ready' || item.status === 'error') {
      actionBtnHtml = `
        <button class="btn btn-primary btn-sm item-process-btn" data-id="${item.id}">
          ${state.currentTab === 'changePerms' ? t('applySingleBtn') : t('downloadUnlockedBtn')}
        </button>
      `;
    }

    el.innerHTML = `
      <div class="file-item-header">
        <div class="file-meta">
          <div class="file-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          </div>
          <div>
            <div class="file-name" title="${item.name}">${item.name}</div>
            <div class="file-size">${formatFileSize(item.size)}</div>
          </div>
        </div>
        <div class="file-status-badge ${statusClass}">
          ${statusText}
        </div>
      </div>
      ${permsSummaryHtml}
      <div class="file-actions">
        <button class="btn btn-secondary btn-sm item-remove-btn" data-id="${item.id}">✕</button>
        ${actionBtnHtml}
      </div>
    `;

    fileList.appendChild(el);
  });

  // Attach item action handlers
  document.querySelectorAll('.item-remove-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.currentTarget.dataset.id;
      state.queue = state.queue.filter(q => q.id !== id);
      renderQueue();
    });
  });

  document.querySelectorAll('.item-process-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const id = e.currentTarget.dataset.id;
      const item = state.queue.find(q => q.id === id);
      if (item) {
        await processItem(item);
      }
    });
  });
}

// Start application when DOM is loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
