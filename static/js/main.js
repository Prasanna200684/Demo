// TrustVault — Client Interactions & Mobile Navigation

document.addEventListener('DOMContentLoaded', () => {
  // Mobile drawer toggle
  const mobileToggle = document.getElementById('mobileToggle');
  const mobileDrawer = document.getElementById('mobileDrawer');

  if (mobileToggle && mobileDrawer) {
    mobileToggle.addEventListener('click', () => {
      mobileDrawer.classList.toggle('open');
      const isOpen = mobileDrawer.classList.contains('open');
      mobileToggle.innerHTML = isOpen ? '✕' : '☰';
      document.body.style.overflow = isOpen ? 'hidden' : '';
    });
  }

  // File upload input update filename on selection
  const fileInput = document.getElementById('document_file');
  const fileLabel = document.getElementById('file_upload_label');
  if (fileInput && fileLabel) {
    fileInput.addEventListener('change', (e) => {
      if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const sizeKb = (file.size / 1024).toFixed(1);
        fileLabel.innerHTML = `<strong>Selected:</strong> ${file.name} (${sizeKb} KB)`;
      }
    });
  }

  // Auto-hide alert banners after 5 seconds
  const alerts = document.querySelectorAll('.alert');
  alerts.forEach(alert => {
    setTimeout(() => {
      alert.style.transition = 'opacity 0.4s ease';
      alert.style.opacity = '0';
      setTimeout(() => alert.remove(), 400);
    }, 5500);
  });
});
