// SecureShare Frontend Scripts
document.addEventListener('DOMContentLoaded', () => {
    // 1. Copy Hash to Clipboard
    window.copyToClipboard = function(elementId, btnElement) {
        const textElement = document.getElementById(elementId);
        if (!textElement) return;

        const text = textElement.innerText.trim();
        navigator.clipboard.writeText(text).then(() => {
            const originalHTML = btnElement.innerHTML;
            btnElement.innerHTML = '<i class="bi bi-check-lg"></i> Đã sao chép';
            btnElement.classList.replace('btn-outline-secondary', 'btn-success');
            setTimeout(() => {
                btnElement.innerHTML = originalHTML;
                btnElement.classList.replace('btn-success', 'btn-outline-secondary');
            }, 2000);
        }).catch(err => {
            console.error('Clipboard copy error:', err);
        });
    };

    // 2. Toggle Password Visibility (Eye Icon)
    window.togglePasswordVisibility = function(inputId, btn) {
        const input = document.getElementById(inputId);
        if (!input) return;

        const icon = btn.querySelector('i');
        if (input.type === 'password') {
            input.type = 'text';
            if (icon) {
                icon.classList.remove('bi-eye', 'text-muted');
                icon.classList.add('bi-eye-slash', 'text-primary');
            }
        } else {
            input.type = 'password';
            if (icon) {
                icon.classList.remove('bi-eye-slash', 'text-primary');
                icon.classList.add('bi-eye', 'text-muted');
            }
        }
    };

    // 3. Drag and drop file upload
    const dropzone = document.getElementById('uploadDropzone');
    const fileInput = document.getElementById('fileInput');
    const fileDisplay = document.getElementById('fileDisplayName');
    const fileSizeDisplay = document.getElementById('fileDisplaySize');

    if (dropzone && fileInput) {
        dropzone.addEventListener('click', () => fileInput.click());

        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add('dragover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove('dragover');
            }, false);
        });

        dropzone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                fileInput.files = files;
                updateFileDisplay(files[0]);
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                updateFileDisplay(fileInput.files[0]);
            }
        });

        function updateFileDisplay(file) {
            if (fileDisplay) {
                fileDisplay.innerText = file.name;
                fileDisplay.classList.remove('d-none');
            }
            if (fileSizeDisplay) {
                const sizeKb = (file.size / 1024).toFixed(1);
                const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
                fileSizeDisplay.innerText = file.size > 1024 * 1024 ? `${sizeMb} MB` : `${sizeKb} KB`;
                fileSizeDisplay.classList.remove('d-none');
            }
        }
    }

    // 4. Password Strength Checker & Dynamic Error Removal on Register page
    const passwordInput = document.getElementById('registerPasswordInput');
    const confirmInput = document.getElementById('confirmPasswordInput');
    const usernameInput = document.getElementById('usernameInput');
    const emailInput = document.getElementById('emailInput');

    const passwordErrors = document.getElementById('passwordErrorContainer');
    const confirmErrors = document.getElementById('confirmPasswordErrorContainer');
    const usernameErrors = document.getElementById('usernameErrorContainer');
    const emailErrors = document.getElementById('emailErrorContainer');

    function updateRule(elementId, isValid, labelText) {
        const el = document.getElementById(elementId);
        if (!el) return;
        if (isValid) {
            el.className = 'col-6 text-success fw-semibold';
            el.innerHTML = `<i class="bi bi-check-circle-fill me-1"></i>${labelText}`;
        } else {
            el.className = 'col-6 text-muted';
            el.innerHTML = `<i class="bi bi-circle me-1"></i>${labelText}`;
        }
    }

    function checkPasswordRules() {
        if (!passwordInput) return;
        const val = passwordInput.value;
        const isLen = val.length >= 8;
        const isUpper = /[A-Z]/.test(val);
        const isLower = /[a-z]/.test(val);
        const isNum = /[0-9]/.test(val);

        updateRule('ruleLen', isLen, 'Tối thiểu 8 ký tự');
        updateRule('ruleUpper', isUpper, '1 chữ hoa (A-Z)');
        updateRule('ruleLower', isLower, '1 chữ thường (a-z)');
        updateRule('ruleNum', isNum, '1 chữ số (0-9)');

        // When all 4 rules are satisfied, immediately hide/clear password error message!
        if (isLen && isUpper && isLower && isNum) {
            if (passwordErrors) passwordErrors.classList.add('d-none');
        }

        // Also re-check confirm password if already typed
        checkConfirmPassword();
    }

    function checkConfirmPassword() {
        if (!confirmInput || !passwordInput) return;
        const passVal = passwordInput.value;
        const confirmVal = confirmInput.value;

        // If confirm matches password and is not empty, immediately hide/clear confirm error!
        if (confirmVal.length > 0 && confirmVal === passVal) {
            if (confirmErrors) confirmErrors.classList.add('d-none');
        }
    }

    if (passwordInput) {
        passwordInput.addEventListener('input', checkPasswordRules);
        // Check on initial load if user already typed something
        if (passwordInput.value.length > 0) {
            checkPasswordRules();
        }
    }

    if (confirmInput) {
        confirmInput.addEventListener('input', checkConfirmPassword);
        if (confirmInput.value.length > 0) {
            checkConfirmPassword();
        }
    }

    if (usernameInput) {
        usernameInput.addEventListener('input', () => {
            if (usernameInput.value.trim().length >= 3) {
                if (usernameErrors) usernameErrors.classList.add('d-none');
            }
        });
    }

    if (emailInput) {
        emailInput.addEventListener('input', () => {
            if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput.value.trim())) {
                if (emailErrors) emailErrors.classList.add('d-none');
            }
        });
    }
});
