document.addEventListener('DOMContentLoaded', () => {
    // Form submission logic (index.html)
    const scanForm = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const submitBtn = document.getElementById('submitBtn');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('loadingSpinner');
    const errorMsg = document.getElementById('errorMsg');
    const pasteBtn = document.getElementById('pasteBtn');

    if (scanForm) {
        scanForm.addEventListener('submit', (e) => {
            if (!urlInput.value.trim()) {
                e.preventDefault();
                errorMsg.style.display = 'block';
                urlInput.focus();
                return;
            }
            
            errorMsg.style.display = 'none';
            btnText.style.display = 'none';
            spinner.style.display = 'block';
            submitBtn.style.backgroundColor = '#1f6feb'; // Change to standard blue while loading
            submitBtn.disabled = true;
            
            // Allow form to submit naturally
        });

        urlInput.addEventListener('input', () => {
            if (urlInput.value.trim()) {
                errorMsg.style.display = 'none';
            }
        });

        // Paste button functionality
        if (pasteBtn) {
            pasteBtn.addEventListener('click', async () => {
                try {
                    const text = await navigator.clipboard.readText();
                    urlInput.value = text;
                    urlInput.focus();
                    errorMsg.style.display = 'none';
                } catch (err) {
                    console.error('Failed to read clipboard:', err);
                    // Fallback: prompt user to paste manually
                    urlInput.focus();
                    urlInput.select();
                    document.execCommand('paste');
                }
            });
        }
    }

    // Progress bar animation (result.html)
    const progressBar = document.querySelector('.progress-bar');
    if (progressBar) {
        // Small delay to ensure CSS transition triggers
        setTimeout(() => {
            const width = progressBar.getAttribute('data-width');
            progressBar.style.width = width;
        }, 100);
    }
});
