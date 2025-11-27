document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('blockchain-form');
    const fileInput = document.getElementById('document');
    const dropzone = document.getElementById('upload-dropzone');
    const filenameEl = document.getElementById('dz-filename');
    const previewEl = document.getElementById('dz-preview');
    const progressWrap = document.getElementById('dz-progress');
    const progressBar = document.getElementById('dz-progress-bar');
    const resultEl = document.getElementById('upload-result');
    const submitBtn = document.getElementById('send-blockchain');
    let autoOpened = false; // guard to prevent duplicate auto-opens

    if (!form) return;

    // Auto-open file picker on page load if the user is on the 'send_blockchain' step
    try {
        const container = document.querySelector('.verification-container');
        const step = container ? container.dataset.step : null;
        if (step === 'send_blockchain' && fileInput && !fileInput.files.length) {
            setTimeout(() => {
                if (!autoOpened) {
                    console.debug('[upload.js] Auto-opening file picker for send_blockchain step');
                    fileInput.click();
                    autoOpened = true;
                }
            }, 250);
        }
    } catch (e) {
        console.error('Auto-open file picker check failed:', e);
    }

    // Browse
    const browseBtn = document.getElementById('dz-browse');
    if (browseBtn) browseBtn.addEventListener('click', () => fileInput.click());

    // Click anywhere on dropzone to open file picker
    if (dropzone) {
        dropzone.addEventListener('click', (ev) => {
            // Avoid clicking through if we clicked the 'browse' button itself
            if (ev.target && ev.target.id === 'dz-browse') return;
            fileInput.click();
        });
    }

    // File change
    fileInput.addEventListener('change', () => {
        // mark that a file has been chosen interactively to avoid auto re-open
        autoOpened = true;
        const file = fileInput.files[0];
        if (file && file.size <= 10 * 1024 * 1024) showFile(file);
        else if (file) alert('File too large. Max 10MB.');
    });

    function showFile(file) {
        filenameEl.textContent = `${file.name} • ${(file.size / 1024 / 1024).toFixed(2)} MB`;
        previewEl.innerHTML = '';
        if (file.type.startsWith('image/')) {
            const reader = new FileReader();
            reader.onload = e => previewEl.innerHTML = `<img src="${e.target.result}" class="img-fluid">`;
            reader.readAsDataURL(file);
        }
    }

    // Drag & drop
    ['dragenter', 'dragover'].forEach(e => dropzone.addEventListener(e, ev => {
        ev.preventDefault(); dropzone.classList.add('dragover');
    }));
    ['dragleave', 'drop'].forEach(e => dropzone.addEventListener(e, ev => {
        ev.preventDefault(); dropzone.classList.remove('dragover');
    }));
    dropzone.addEventListener('drop', e => {
        const file = e.dataTransfer.files[0];
        if (file && file.size <= 10 * 1024 * 1024) {
            const dt = new DataTransfer(); dt.items.add(file);
            fileInput.files = dt.files;
            showFile(file);
        } else if (file) alert('File too large.');
    });

    // AJAX Submit
    form.addEventListener('submit', e => {
        e.preventDefault();
        if (!fileInput.files[0]) return alert('Please select a file');

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Uploading...';

        const fd = new FormData();
        fd.append('company_name', document.getElementById('company_name').value);
        fd.append('company_address', document.getElementById('company_address').value);
        fd.append('document', fileInput.files[0]);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', form.action);

        xhr.upload.onprogress = ev => {
            if (ev.lengthComputable) {
                const p = (ev.loaded / ev.total) * 100;
                progressWrap.classList.remove('d-none');
                progressBar.style.width = p + '%';
            }
        };

        xhr.onload = () => {
            submitBtn.disabled = false;
            submitBtn.innerHTML = 'Send to Blockchain';
            progressWrap.classList.add('d-none');
            progressBar.style.width = '0%';

            // Force page reload to show updated session state (phish_info, step, flash)
            location.reload();
        };

        xhr.onerror = () => {
            submitBtn.disabled = false;
            submitBtn.innerHTML = 'Send to Blockchain';
            resultEl.innerHTML = '<div class="alert alert-danger">Upload failed. Try again.</div>';
        };

        xhr.send(fd);
    });
});