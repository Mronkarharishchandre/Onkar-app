/**
 * StorageOS Enterprise Client Logic & Interactions
 * Features:
 * - Theme Switcher (Light / Dark with local persistence & backend sync)
 * - Mobile Navigation Drawer & Backdrop
 * - File Preview Modal (Image, PDF, Code/Text, Audio, Video)
 * - Three-Dot Context Menus (⋮) with outside-click dismissal
 * - Native Web Share & Tokenized Public Share Link generation
 * - Drag-and-drop file upload with feedback
 * - Toast Notification System
 */

// Active state tracking
let activeShareContext = {
  relativePath: '',
  fileName: '',
  generatedUrl: ''
};

document.addEventListener("DOMContentLoaded", function () {
  initTheme();
  initGlobalListeners();
  initDropzones();
});

/* ==========================================================================
   Theme Management
   ========================================================================== */
function initTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
  updateThemeIcons(currentTheme);
}

function toggleThemeMode() {
  const current = document.documentElement.getAttribute('data-theme');
  const nextTheme = current === 'dark' ? 'light' : 'dark';

  document.documentElement.setAttribute('data-theme', nextTheme);
  localStorage.setItem('storageos_theme', nextTheme);
  updateThemeIcons(nextTheme);

  // Sync with backend asynchronously
  fetch('/set-theme', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ theme: nextTheme })
  }).catch(() => {});

  showToast(`Switched to ${nextTheme === 'dark' ? 'Dark' : 'Light'} theme`, 'info', 2000);
}

function updateThemeIcons(theme) {
  const sunIcon = document.getElementById('theme-icon-sun');
  const moonIcon = document.getElementById('theme-icon-moon');
  if (sunIcon && moonIcon) {
    if (theme === 'dark') {
      sunIcon.style.display = 'none';
      moonIcon.style.display = 'block';
    } else {
      sunIcon.style.display = 'block';
      moonIcon.style.display = 'none';
    }
  }
}

/* ==========================================================================
   Mobile Sidebar Drawer
   ========================================================================== */
function toggleMobileSidebar(show) {
  const sidebar = document.getElementById("app-sidebar");
  const backdrop = document.getElementById("sidebar-backdrop");
  if (!sidebar) return;

  if (typeof show === 'boolean') {
    sidebar.classList.toggle("open", show);
    if (backdrop) backdrop.classList.toggle("open", show);
  } else {
    sidebar.classList.toggle("open");
    if (backdrop) backdrop.classList.toggle("open");
  }
}

/* ==========================================================================
   Dropdowns & Three-Dot (⋮) Menus
   ========================================================================== */
function toggleDropdown(dropdownId) {
  const dropdown = document.getElementById(dropdownId);
  if (!dropdown) return;

  const isOpen = dropdown.classList.contains('show');
  closeAllDropdowns();
  if (!isOpen) {
    dropdown.classList.add('show');
  }
}

function toggleItemMenu(event, menuId) {
  if (event) {
    event.stopPropagation();
    event.preventDefault();
  }
  const menu = document.getElementById(menuId);
  if (!menu) return;

  const isOpen = menu.classList.contains('show');
  closeAllDropdowns();
  if (!isOpen) {
    menu.classList.add('show');
  }
}

function closeAllDropdowns() {
  document.querySelectorAll('.topbar-dropdown.show, .item-dropdown-menu.show').forEach(el => {
    el.classList.remove('show');
  });
}

/* ==========================================================================
   Global Event Listeners
   ========================================================================== */
function initGlobalListeners() {
  // Close dropdowns on outside click
  document.addEventListener('click', function (e) {
    if (!e.target.closest('.dropdown-container') && !e.target.closest('.item-menu-container')) {
      closeAllDropdowns();
    }
  });

  // Close modals or menus on Escape
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeAllDropdowns();
      document.querySelectorAll('.modal-overlay, .modal-backdrop').forEach(modal => {
        modal.style.display = 'none';
        modal.classList.remove('show');
      });
    }
  });
}

/* ==========================================================================
   Modal Operations (Generic & Backwards Compatible)
   ========================================================================== */
window.openModal = function (modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = "flex";
    modal.classList.add("show");
  }
};

window.closeModal = function (modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = "none";
    modal.classList.remove("show");
  }
};

function handleModalBackdropClick(event, modalId) {
  if (event.target.id === modalId) {
    closeModal(modalId);
  }
}

/* Rename modal population */
window.openRenameModal = function (relPath, currentName, itemType) {
  closeAllDropdowns();
  const modal = document.getElementById("renameModal");
  if (!modal) return;
  const relInput = document.getElementById("rename_rel_path");
  const typeInput = document.getElementById("rename_item_type");
  const nameInput = document.getElementById("rename_new_name");
  const titleElem = document.getElementById("rename_modal_title");

  if (relInput) relInput.value = relPath;
  if (typeInput) typeInput.value = itemType;
  if (nameInput) nameInput.value = currentName;
  if (titleElem) titleElem.innerText = itemType === "folder" ? "Rename Folder" : "Rename File";

  openModal("renameModal");
  setTimeout(() => { if (nameInput) nameInput.focus(); }, 100);
};

/* Legacy share modal */
window.openShareModal = function (relPath, fileName) {
  openModernShareModal(relPath, fileName);
};

/* ==========================================================================
   File Preview System
   ========================================================================== */
function openFilePreview(relPath, fileName) {
  closeAllDropdowns();
  activeShareContext.relativePath = relPath;
  activeShareContext.fileName = fileName;

  const modal = document.getElementById("file-preview-modal");
  const title = document.getElementById("preview-modal-title");
  const meta = document.getElementById("preview-modal-meta");
  const content = document.getElementById("preview-modal-content");
  const downloadBtn = document.getElementById("preview-modal-download-btn");

  if (!modal || !content) return;

  title.innerText = fileName;
  meta.innerText = "Querying preview metadata...";
  downloadBtn.href = `/files/download/${encodeURIComponent(relPath)}`;

  content.innerHTML = `
    <div class="preview-loading">
      <div class="spinner"></div>
      <span>Loading preview for ${escapeHtml(fileName)}...</span>
    </div>
  `;

  openModal("file-preview-modal");

  fetch(`/api/preview-info?rel_path=${encodeURIComponent(relPath)}`)
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        renderPreviewError(data.error);
        return;
      }

      meta.innerText = `${data.mime} • ${data.size_formatted} • Modified ${data.modified}`;
      renderPreviewContent(data);
    })
    .catch(err => {
      renderPreviewError("Unable to load preview at this time.");
    });
}

function renderPreviewContent(data) {
  const content = document.getElementById("preview-modal-content");
  if (!content) return;

  if (data.category === 'image') {
    content.innerHTML = `
      <div class="preview-media-container">
        <img src="${data.raw_url}" alt="${escapeHtml(data.filename)}" class="preview-img" />
      </div>
    `;
  } else if (data.category === 'pdf') {
    content.innerHTML = `
      <iframe src="${data.raw_url}" class="preview-iframe" title="PDF Preview"></iframe>
    `;
  } else if (data.category === 'text' || data.category === 'code') {
    // Fetch textual content
    fetch(data.raw_url)
      .then(res => res.text())
      .then(text => {
        content.innerHTML = `
          <pre class="preview-code-container"><code>${escapeHtml(text.slice(0, 100000))}</code></pre>
        `;
      })
      .catch(() => {
        renderPreviewFallback(data);
      });
  } else if (data.category === 'audio') {
    content.innerHTML = `
      <div class="preview-media-container" style="flex-direction: column; gap: 16px;">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--accent-blue);">
          <path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>
        </svg>
        <audio controls class="preview-audio-player" src="${data.raw_url}"></audio>
      </div>
    `;
  } else if (data.category === 'video') {
    content.innerHTML = `
      <div class="preview-media-container">
        <video controls class="preview-video-player" src="${data.raw_url}"></video>
      </div>
    `;
  } else {
    renderPreviewFallback(data);
  }
}

function renderPreviewFallback(data) {
  const content = document.getElementById("preview-modal-content");
  if (!content) return;
  content.innerHTML = `
    <div class="preview-metadata-box">
      <div class="file-icon" style="width: 54px; height: 54px; margin: 0 auto 16px;">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
        </svg>
      </div>
      <h4 style="font-size: 16px; font-weight: 600; margin-bottom: 6px;">${escapeHtml(data.filename)}</h4>
      <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">
        Direct in-browser visual preview is not supported for this file format. You can download and view it locally.
      </p>
      <a href="${data.download_url}" class="btn btn-primary btn-sm">
        Download (${data.size_formatted})
      </a>
    </div>
  `;
}

function renderPreviewError(msg) {
  const content = document.getElementById("preview-modal-content");
  if (content) {
    content.innerHTML = `
      <div class="empty-state">
        <div class="empty-title">Preview Unavailable</div>
        <p style="font-size: 13px;">${escapeHtml(msg)}</p>
      </div>
    `;
  }
}

function openShareFromPreview() {
  closeModal('file-preview-modal');
  openModernShareModal(activeShareContext.relativePath, activeShareContext.fileName);
}

/* ==========================================================================
   Modern Share Modal (Tokenized Links & Peer Invites)
   ========================================================================== */
function openModernShareModal(relPath, fileName) {
  closeAllDropdowns();
  activeShareContext.relativePath = relPath;
  activeShareContext.fileName = fileName;
  activeShareContext.generatedUrl = '';

  const modal = document.getElementById("modern-share-modal");
  const filenameElem = document.getElementById("share-target-filename");
  const linkRelInput = document.getElementById("share-link-rel-path");
  const userRelInput = document.getElementById("share-user-rel-path");
  const resultBox = document.getElementById("share-link-result");

  if (!modal) return;

  if (filenameElem) filenameElem.innerText = fileName;
  if (linkRelInput) linkRelInput.value = relPath;
  if (userRelInput) userRelInput.value = relPath;
  if (resultBox) resultBox.style.display = "none";

  switchShareTab('link');
  openModal("modern-share-modal");
}

function switchShareTab(tab) {
  const btnLink = document.getElementById('tab-btn-link');
  const btnUser = document.getElementById('tab-btn-user');
  const contentLink = document.getElementById('share-tab-link-content');
  const contentUser = document.getElementById('share-tab-user-content');

  if (tab === 'link') {
    if (btnLink) btnLink.classList.add('active');
    if (btnUser) btnUser.classList.remove('active');
    if (contentLink) contentLink.style.display = 'block';
    if (contentUser) contentUser.style.display = 'none';
  } else {
    if (btnLink) btnLink.classList.remove('active');
    if (btnUser) btnUser.classList.add('active');
    if (contentLink) contentLink.style.display = 'none';
    if (contentUser) contentUser.style.display = 'block';
  }
}

function handleCreateShareLink(e) {
  e.preventDefault();
  const form = document.getElementById("create-share-link-form");
  const formData = new FormData(form);
  const btn = document.getElementById("btn-generate-link");

  if (btn) {
    btn.disabled = true;
    btn.innerText = "Generating link...";
  }

  fetch('/share-link/create', {
    method: 'POST',
    body: formData
  })
    .then(res => res.json())
    .then(data => {
      if (btn) {
        btn.disabled = false;
        btn.innerText = "Generate Share Link";
      }

      if (data.success && data.share_url) {
        activeShareContext.generatedUrl = data.share_url;
        const resultBox = document.getElementById("share-link-result");
        const urlInput = document.getElementById("share-link-url-output");

        if (urlInput) urlInput.value = data.share_url;
        if (resultBox) resultBox.style.display = "block";
        showToast("Secure share link created!", "success");
      } else {
        showToast(data.error || "Failed to create share link.", "error");
      }
    })
    .catch(() => {
      if (btn) {
        btn.disabled = false;
        btn.innerText = "Generate Share Link";
      }
      showToast("Network error generating link.", "error");
    });
}

function copyGeneratedShareLink() {
  const urlInput = document.getElementById("share-link-url-output");
  if (!urlInput || !urlInput.value) return;

  navigator.clipboard.writeText(urlInput.value).then(() => {
    showToast("Share link copied to clipboard!", "success");
  }).catch(() => {
    urlInput.select();
    document.execCommand('copy');
    showToast("Share link copied to clipboard!", "success");
  });
}

function shareViaNativeDevice() {
  const url = activeShareContext.generatedUrl || (document.getElementById("share-link-url-output") ? document.getElementById("share-link-url-output").value : "");
  if (!url) {
    showToast("Generate a share link first.", "info");
    return;
  }

  if (navigator.share) {
    navigator.share({
      title: `StorageOS - ${activeShareContext.fileName}`,
      text: `Access file "${activeShareContext.fileName}" securely on StorageOS:`,
      url: url
    }).catch(err => {
      if (err.name !== 'AbortError') {
        copyGeneratedShareLink();
      }
    });
  } else {
    copyGeneratedShareLink();
    showToast("Device share not supported in browser. Copied link instead!", "info");
  }
}

/* ==========================================================================
   File Dropzone Upload Feedback
   ========================================================================== */
function initDropzones() {
  const dropzones = document.querySelectorAll(".dropzone");
  dropzones.forEach(zone => {
    ["dragenter", "dragover"].forEach(name => {
      zone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach(name => {
      zone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.remove("dragover");
      });
    });

    zone.addEventListener("drop", (e) => {
      const fileInput = zone.parentElement.querySelector("input[type=file]");
      if (fileInput && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        handleFileSelected(fileInput);
      }
    });
  });
}

function handleFileSelected(input) {
  if (!input || !input.files || input.files.length === 0) return;
  const file = input.files[0];
  const labelElem = input.parentElement.querySelector("#selected-file-name");
  if (labelElem) {
    labelElem.innerText = `Selected: ${file.name} (${formatBytes(file.size)})`;
    labelElem.style.display = "block";
  }
}

/* ==========================================================================
   Toast Notification System
   ========================================================================== */
function showToast(message, type = 'info', duration = 3500) {
  let container = document.getElementById("storageos-toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "storageos-toast-container";
    container.className = "storageos-toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `storageos-toast ${type}`;

  let iconSvg = '';
  if (type === 'success') {
    iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--success); flex-shrink:0;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
  } else if (type === 'error') {
    iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--danger); flex-shrink:0;"><circle cx="12" cy="12" r="10"/><line x1="15" x2="9" y1="9" y2="15"/><line x1="9" x2="15" y1="9" y2="15"/></svg>';
  } else {
    iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--accent-blue); flex-shrink:0;"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>';
  }

  toast.innerHTML = `
    ${iconSvg}
    <div style="flex: 1; min-width: 0;">${escapeHtml(message)}</div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.25s ease';
    setTimeout(() => toast.remove(), 250);
  }, duration);
}

/* ==========================================================================
   Utilities
   ========================================================================== */
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
