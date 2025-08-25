class AdvancedEncryptionApp {
    constructor() {
        this.initializeElements();
        this.attachEventListeners();
        this.updateAlgorithmInfo();
        this.updateTextStats();
        this.initializeTheme();
    }

    initializeElements() {
        // Main controls
        this.algorithmSelect = document.getElementById('algorithm');
        this.keyInput = document.getElementById('keyInput');
        this.inputText = document.getElementById('inputText');
        this.outputText = document.getElementById('outputText');
        
        // Buttons
        this.encryptBtn = document.getElementById('encryptBtn');
        this.decryptBtn = document.getElementById('decryptBtn');
        this.generateKeyBtn = document.getElementById('generateKey');
        this.copyBtn = document.getElementById('copyBtn');
        this.downloadBtn = document.getElementById('downloadBtn');
        this.uploadBtn = document.getElementById('uploadBtn');
        this.fileInput = document.getElementById('fileInput');
        this.clearBtn = document.getElementById('clearBtn');
        this.swapBtn = document.getElementById('swapBtn');
        this.themeToggle = document.getElementById('themeToggle');
        
        // UI elements
        this.errorMessage = document.getElementById('errorMessage');
        this.successMessage = document.getElementById('successMessage');
        this.keyInfo = document.getElementById('keyInfo');
        this.algorithmInfo = document.getElementById('algorithmInfo');
        this.algorithmBadge = document.getElementById('algorithmBadge');
        this.toast = document.getElementById('toast');
        this.keySection = document.getElementById('keySection');
        this.inputStats = document.getElementById('inputStats');
        this.outputStats = document.getElementById('outputStats');
        
        // RSA Modal elements
        this.rsaModal = document.getElementById('rsaModal');
        this.showRSAModal = document.getElementById('showRSAModal');
        this.closeModal = document.getElementById('closeModal');
        this.publicKey = document.getElementById('publicKey');
        this.privateKey = document.getElementById('privateKey');
        this.generateRSAKeys = document.getElementById('generateRSAKeys');
        this.copyKeyBtns = document.querySelectorAll('.copy-key-btn');
    }

    attachEventListeners() {
        // Algorithm and key changes
        this.algorithmSelect.addEventListener('change', () => this.updateAlgorithmInfo());
        this.keyInput.addEventListener('input', () => this.debounceEncrypt());
        
        // Text input changes
        this.inputText.addEventListener('input', () => {
            this.updateTextStats();
            this.debounceEncrypt();
        });
        
        // Main action buttons
        this.encryptBtn.addEventListener('click', () => this.performEncryption());
        this.decryptBtn.addEventListener('click', () => this.performDecryption());
        this.generateKeyBtn.addEventListener('click', () => this.generateKey());
        
        // Utility buttons
        this.copyBtn.addEventListener('click', () => this.copyToClipboard());
        this.downloadBtn.addEventListener('click', () => this.downloadResult());
        this.uploadBtn.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => this.handleFileUpload(e));
        this.clearBtn.addEventListener('click', () => this.clearText());
        this.swapBtn.addEventListener('click', () => this.swapTexts());
        this.themeToggle.addEventListener('click', () => this.toggleTheme());
        
        // RSA Modal
        this.showRSAModal.addEventListener('click', () => this.openRSAModal());
        this.closeModal.addEventListener('click', () => this.closeRSAModal());
        this.generateRSAKeys.addEventListener('click', () => this.generateRSAKeyPair());
        
        // Copy key buttons
        this.copyKeyBtns.forEach(btn => {
            btn.addEventListener('click', (e) => this.copyKey(e.target.dataset.target));
        });
        
        // Modal close on outside click
        this.rsaModal.addEventListener('click', (e) => {
            if (e.target === this.rsaModal) {
                this.closeRSAModal();
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => this.handleKeyboardShortcuts(e));
    }

    handleKeyboardShortcuts(e) {
        if (e.ctrlKey || e.metaKey) {
            switch (e.key) {
                case 'e':
                    e.preventDefault();
                    this.performEncryption();
                    break;
                case 'd':
                    e.preventDefault();
                    this.performDecryption();
                    break;
                case 'k':
                    e.preventDefault();
                    this.generateKey();
                    break;
                case 's':
                    e.preventDefault();
                    this.swapTexts();
                    break;
            }
        }
    }

    debounceEncrypt() {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => {
            if (this.inputText.value.trim() && this.shouldAutoEncrypt()) {
                this.performEncryption(true);
            }
        }, 800);
    }

    shouldAutoEncrypt() {
        const algorithm = this.algorithmSelect.value;
        // Only auto-encrypt for simple algorithms
        return ['caesar', 'base64'].includes(algorithm);
    }

    async performEncryption(isPreview = false) {
        const algorithm = this.algorithmSelect.value;
        const text = this.inputText.value.trim();
        const key = this.keyInput.value.trim();

        if (!text) {
            if (!isPreview) this.showError('Please enter text to encrypt');
            return;
        }

        if (this.requiresKey(algorithm) && !key) {
            if (!isPreview) this.showError(`${this.getAlgorithmDisplayName(algorithm)} encryption requires a key`);
            return;
        }

        if (!isPreview) {
            this.setLoading(this.encryptBtn, true);
        }

        try {
            const response = await fetch('/encrypt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    algorithm: algorithm,
                    text: text,
                    key: key
                })
            });

            const data = await response.json();

            if (data.error) {
                if (!isPreview) this.showError(data.error);
                return;
            }

            this.outputText.value = data.result;
            
            // Handle ChaCha20 key generation
            if (data.generated_key) {
                this.keyInput.value = data.generated_key;
                this.showToast('New ChaCha20 key generated!', 'success');
            }
            
            if (!isPreview) {
                this.showSuccess('Text encrypted successfully!');
                this.hideMessages();
            }
            
            this.updateTextStats();
        } catch (error) {
            if (!isPreview) this.showError('Encryption failed: ' + error.message);
        } finally {
            if (!isPreview) {
                this.setLoading(this.encryptBtn, false);
            }
        }
    }

    async performDecryption() {
        const algorithm = this.algorithmSelect.value;
        const text = this.inputText.value.trim();
        const key = this.keyInput.value.trim();

        if (!text) {
            this.showError('Please enter text to decrypt');
            return;
        }

        if (this.requiresKey(algorithm) && !key) {
            this.showError(`${this.getAlgorithmDisplayName(algorithm)} decryption requires a key`);
            return;
        }

        this.setLoading(this.decryptBtn, true);

        try {
            const response = await fetch('/decrypt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    algorithm: algorithm,
                    text: text,
                    key: key
                })
            });

            const data = await response.json();

            if (data.error) {
                this.showError(data.error);
                return;
            }

            this.outputText.value = data.result;
            this.showSuccess('Text decrypted successfully!');
            this.hideMessages();
            this.updateTextStats();
        } catch (error) {
            this.showError('Decryption failed: ' + error.message);
        } finally {
            this.setLoading(this.decryptBtn, false);
        }
    }

    async generateKey() {
        const algorithm = this.algorithmSelect.value;

        if (algorithm === 'rsa') {
            this.openRSAModal();
            return;
        }

        this.setLoading(this.generateKeyBtn, true);

        try {
            const response = await fetch('/generate-key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ algorithm: algorithm })
            });

            const data = await response.json();

            if (data.error) {
                this.showError(data.error);
                return;
            }

            this.keyInput.value = data.key;
            this.showToast('Key generated successfully!', 'success');
        } catch (error) {
            this.showError('Key generation failed: ' + error.message);
        } finally {
            this.setLoading(this.generateKeyBtn, false);
        }
    }

    async generateRSAKeyPair() {
        this.setLoading(this.generateRSAKeys, true);

        try {
            const response = await fetch('/generate-key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ algorithm: 'rsa' })
            });

            const data = await response.json();

            if (data.error) {
                this.showError(data.error);
                return;
            }

            this.publicKey.value = data.keypair.public_key;
            this.privateKey.value = data.keypair.private_key;
            this.showToast('RSA key pair generated successfully!', 'success');
        } catch (error) {
            this.showError('RSA key generation failed: ' + error.message);
        } finally {
            this.setLoading(this.generateRSAKeys, false);
        }
    }

    async copyToClipboard() {
        if (!this.outputText.value) {
            this.showError('No output to copy');
            return;
        }

        try {
            await navigator.clipboard.writeText(this.outputText.value);
            this.showToast('Copied to clipboard!', 'success');
        } catch (error) {
            this.showError('Failed to copy to clipboard');
        }
    }

    async copyKey(target) {
        const textarea = document.getElementById(target);
        if (!textarea.value) {
            this.showError('No key to copy');
            return;
        }

        try {
            await navigator.clipboard.writeText(textarea.value);
            this.showToast('Key copied to clipboard!', 'success');
        } catch (error) {
            this.showError('Failed to copy key');
        }
    }

    async downloadResult() {
        if (!this.outputText.value) {
            this.showError('No output to download');
            return;
        }

        const algorithm = this.algorithmSelect.value;
        const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
        const filename = `encrypted_${algorithm}_${timestamp}.txt`;

        try {
            const response = await fetch('/download', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    content: this.outputText.value,
                    filename: filename
                })
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                this.showToast('File downloaded successfully!', 'success');
            } else {
                this.showError('Download failed');
            }
        } catch (error) {
            this.showError('Download failed: ' + error.message);
        }
    }

    handleFileUpload(event) {
        const file = event.target.files[0];
        if (!file) return;

        if (file.type !== 'text/plain') {
            this.showError('Please select a text file (.txt)');
            return;
        }

        if (file.size > 1024 * 1024) { // 1MB limit
            this.showError('File size must be less than 1MB');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            this.inputText.value = e.target.result;
            this.updateTextStats();
            this.showToast('File uploaded successfully!', 'success');
        };
        reader.onerror = () => {
            this.showError('Failed to read file');
        };
        reader.readAsText(file);
    }

    clearText() {
        this.inputText.value = '';
        this.outputText.value = '';
        this.keyInput.value = '';
        this.hideMessages();
        this.updateTextStats();
    }

    swapTexts() {
        const temp = this.inputText.value;
        this.inputText.value = this.outputText.value;
        this.outputText.value = temp;
        this.updateTextStats();
    }

    toggleTheme() {
        const currentTheme = document.body.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.body.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        const icon = this.themeToggle.querySelector('i');
        icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }

    openRSAModal() {
        this.rsaModal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }

    closeRSAModal() {
        this.rsaModal.style.display = 'none';
        document.body.style.overflow = 'auto';
        
        // Set the public key as the main key if available
        if (this.publicKey.value) {
            this.keyInput.value = this.publicKey.value;
        }
    }

    updateAlgorithmInfo() {
        const algorithm = this.algorithmSelect.value;
        const info = this.getAlgorithmInfo(algorithm);
        
        // Update algorithm badge
        const badgeText = this.algorithmBadge.querySelector('.badge-text');
        const securityLevel = this.algorithmBadge.querySelector('.security-level');
        
        badgeText.textContent = info.name;
        securityLevel.textContent = info.security.charAt(0).toUpperCase() + info.security.slice(1) + ' Security';
        securityLevel.className = `security-level ${info.security}`;
        
        // Update info panel
        this.algorithmInfo.innerHTML = `
            <div class="info-card">
                <h3>${info.name}</h3>
                <p>${info.description}</p>
                <div class="security-level ${info.security}">
                    <span class="level-label">Security Level:</span>
                    <span>${info.security.charAt(0).toUpperCase() + info.security.slice(1)}</span>
                </div>
                ${info.keySize ? `<p><strong>Key Size:</strong> ${info.keySize}</p>` : ''}
                ${info.usage ? `<p><strong>Common Usage:</strong> ${info.usage}</p>` : ''}
            </div>
        `;

        this.keyInfo.textContent = info.keyInfo;
        
        // Show/hide key section and RSA modal button
        const requiresKey = this.requiresKey(algorithm);
        this.keySection.style.display = requiresKey ? 'block' : 'none';
        
        const rsaModalBtn = document.getElementById('showRSAModal');
        if (algorithm === 'rsa') {
            this.generateKeyBtn.style.display = 'none';
            rsaModalBtn.style.display = 'flex';
        } else {
            this.generateKeyBtn.style.display = requiresKey ? 'flex' : 'none';
            rsaModalBtn.style.display = 'none';
        }
    }

    updateTextStats() {
        const inputLength = this.inputText.value.length;
        const outputLength = this.outputText.value.length;
        
        this.inputStats.textContent = `${inputLength} character${inputLength !== 1 ? 's' : ''}`;
        this.outputStats.textContent = `${outputLength} character${outputLength !== 1 ? 's' : ''}`;
    }

    getAlgorithmInfo(algorithm) {
        const algorithms = {
            caesar: {
                name: 'Caesar Cipher',
                description: 'A simple substitution cipher that shifts letters by a fixed number of positions in the alphabet. One of the oldest known encryption techniques, used by Julius Caesar.',
                security: 'low',
                keyInfo: 'Enter a number from 1-25 for the shift amount',
                usage: 'Educational purposes, simple obfuscation'
            },
            vigenere: {
                name: 'Vigenère Cipher',
                description: 'A polyalphabetic substitution cipher that uses a keyword to shift letters by varying amounts. More secure than Caesar cipher due to its use of multiple substitution alphabets.',
                security: 'medium',
                keyInfo: 'Enter a word or phrase as the encryption key (longer keys are more secure)',
                usage: 'Historical encryption, educational cryptography'
            },
            base64: {
                name: 'Base64 Encoding',
                description: 'Binary-to-text encoding scheme that represents binary data in ASCII string format. Not encryption but data encoding - easily reversible.',
                security: 'low',
                keyInfo: 'No key required - standard encoding/decoding algorithm',
                usage: 'Data transmission, email attachments, web APIs'
            },
            aes: {
                name: 'AES-256 (Fernet)',
                description: 'Advanced Encryption Standard with 256-bit keys using Fernet symmetric encryption. Military-grade security with authenticated encryption.',
                security: 'high',
                keyInfo: 'Requires a base64-encoded Fernet key for maximum security',
                keySize: '256-bit',
                usage: 'Secure communications, file encryption, data protection'
            },
            chacha20: {
                name: 'ChaCha20',
                description: 'Modern stream cipher designed by Daniel J. Bernstein. Faster than AES on systems without hardware acceleration and highly secure.',
                security: 'high',
                keyInfo: 'Requires a 256-bit base64-encoded key',
                keySize: '256-bit',
                usage: 'High-performance encryption, mobile devices, IoT'
            },
            rsa: {
                name: 'RSA-2048',
                description: 'Asymmetric encryption algorithm using public-key cryptography. Uses a public key for encryption and a private key for decryption.',
                security: 'high',
                keyInfo: 'Requires RSA public key for encryption, private key for decryption',
                keySize: '2048-bit',
                usage: 'Secure key exchange, digital signatures, HTTPS'
            }
        };

        return algorithms[algorithm] || algorithms.caesar;
    }

    getAlgorithmDisplayName(algorithm) {
        const info = this.getAlgorithmInfo(algorithm);
        return info.name;
    }

    requiresKey(algorithm) {
        return ['caesar', 'vigenere', 'aes', 'chacha20', 'rsa'].includes(algorithm);
    }

    setLoading(button, isLoading) {
        if (isLoading) {
            button.disabled = true;
            button.classList.add('loading');
            const originalText = button.innerHTML;
            button.dataset.originalText = originalText;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        } else {
            button.disabled = false;
            button.classList.remove('loading');
            button.innerHTML = button.dataset.originalText || button.innerHTML;
        }
    }

    showError(message) {
        this.errorMessage.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${message}`;
        this.errorMessage.style.display = 'flex';
        this.successMessage.style.display = 'none';
    }

    showSuccess(message) {
        this.successMessage.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
        this.successMessage.style.display = 'flex';
        this.errorMessage.style.display = 'none';
    }

    hideMessages() {
        setTimeout(() => {
            this.errorMessage.style.display = 'none';
            this.successMessage.style.display = 'none';
        }, 4000);
    }

    showToast(message, type) {
        this.toast.textContent = message;
        this.toast.className = `toast ${type} show`;
        
        setTimeout(() => {
            this.toast.classList.remove('show');
        }, 3000);
    }

    initializeTheme() {
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.body.setAttribute('data-theme', savedTheme);
        
        const icon = this.themeToggle.querySelector('i');
        icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    const app = new AdvancedEncryptionApp();
    
    // Add some nice loading effects
    document.body.style.opacity = '0';
    setTimeout(() => {
        document.body.style.transition = 'opacity 0.5s ease';
        document.body.style.opacity = '1';
    }, 100);
});