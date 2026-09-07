/**
 * StorageOS Client Interactions & Modals
 */

document.addEventListener("DOMContentLoaded", function () {
  // Mobile sidebar toggle
  const mobileBtn = document.getElementById("mobile-menu-btn");
  const sidebar = document.getElementById("app-sidebar");
  if (mobileBtn && sidebar) {
    mobileBtn.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });
  }

  // Generic modal handlers
  window.openModal = function (modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add("show");
    }
  };

  window.closeModal = function (modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove("show");
    }
  };

  // Close modal when clicking on backdrop
  document.querySelectorAll(".modal-backdrop").forEach((backdrop) => {
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) {
        backdrop.classList.remove("show");
      }
    });
  });

  // Rename modal population
  window.openRenameModal = function (relPath, currentName, itemType) {
    const modal = document.getElementById("renameModal");
    if (!modal) return;
    document.getElementById("rename_rel_path").value = relPath;
    document.getElementById("rename_item_type").value = itemType;
    document.getElementById("rename_new_name").value = currentName;
    document.getElementById("rename_modal_title").innerText = itemType === "folder" ? "Rename Folder" : "Rename File";
    openModal("renameModal");
  };

  // Share modal population
  window.openShareModal = function (relPath, fileName) {
    const modal = document.getElementById("shareModal");
    if (!modal) return;
    document.getElementById("share_rel_path").value = relPath;
    document.getElementById("share_file_display").innerText = fileName;
    openModal("shareModal");
  };

  // Drag and Drop File Upload Handling
  const dropzone = document.getElementById("upload-dropzone");
  const fileInput = document.getElementById("file-input");
  const selectedFileName = document.getElementById("selected-file-name");

  if (dropzone && fileInput) {
    ["dragenter", "dragover"].forEach((eventName) => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach((eventName) => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove("dragover");
      });
    });

    dropzone.addEventListener("drop", (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        updateSelectedFileName(fileInput.files[0].name);
      }
    });

    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files.length > 0) {
        updateSelectedFileName(fileInput.files[0].name);
      }
    });

    function updateSelectedFileName(name) {
      if (selectedFileName) {
        selectedFileName.textContent = `Selected: ${name}`;
        selectedFileName.style.display = "block";
      }
    }
  }
});
