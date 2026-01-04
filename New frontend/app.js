// ==================== CONFIGURATION ====================
const CONFIG = {
    API_BASE_URL: 'http://localhost:3000/api', // Change this to your backend URL
    CSRF_TOKEN_HEADER: 'X-CSRF-Token',
    SESSION_CHECK_INTERVAL: 60000, // Check session every 60 seconds
    PASSWORD_MIN_LENGTH: 8,
    RATE_LIMIT_MESSAGE: 'Too many requests. Please try again later.',
};

// ==================== STATE MANAGEMENT ====================
const AppState = {
    currentPage: 'login',
    user: null,
    csrfToken: null,
    isLoading: false,
};

// ==================== UTILITY FUNCTIONS ====================

/**
 * Sanitize HTML to prevent XSS attacks
 * This escapes HTML special characters to prevent script injection
 */
function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Safely set text content to prevent XSS
 */
function setTextSafely(element, text) {
    if (element) {
        element.textContent = text || '';
    }
}

/**
 * Safely set HTML content (only use with trusted, sanitized content)
 */
function setHTMLSafely(element, html) {
    if (element) {
        element.innerHTML = sanitizeHTML(html);
    }
}

/**
 * Generate a CSRF token (in production, this should come from the server)
 */
function generateCSRFToken() {
    return 'csrf_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
}

/**
 * Get CSRF token from cookie or generate new one
 */
function getCSRFToken() {
    if (!AppState.csrfToken) {
        // In production, this should be fetched from a cookie set by the server
        AppState.csrfToken = generateCSRFToken();
        document.cookie = `csrf_token=${AppState.csrfToken}; path=/; SameSite=Strict`;
    }
    return AppState.csrfToken;
}

/**
 * Make authenticated API request with CSRF token
 */
async function apiRequest(endpoint, options = {}) {
    const csrfToken = getCSRFToken();
    
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            [CONFIG.CSRF_TOKEN_HEADER]: csrfToken,
        },
        credentials: 'include', // Include cookies for session management
    };

    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers,
        },
    };

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}${endpoint}`, mergedOptions);
        
        // Check for rate limiting
        if (response.status === 429) {
            throw new Error(CONFIG.RATE_LIMIT_MESSAGE);
        }

        // Check if session is invalid
        if (response.status === 401) {
            handleSessionExpired();
            throw new Error('Session expired. Please login again.');
        }

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'An error occurred');
        }

        return data;
    } catch (error) {
        console.error('API Request Error:', error);
        throw error;
    }
}

/**
 * Handle session expiration
 */
function handleSessionExpired() {
    AppState.user = null;
    localStorage.removeItem('user');
    showPage('login');
    showAlert('loginAlert', 'Your session has expired. Please login again.', 'error');
}

/**
 * Check if user session is still valid
 */
async function checkSession() {
    try {
        const data = await apiRequest('/auth/session', { method: 'GET' });
        if (data.valid) {
            return true;
        } else {
            handleSessionExpired();
            return false;
        }
    } catch (error) {
        console.error('Session check failed:', error);
        return false;
    }
}

// ==================== VALIDATION FUNCTIONS ====================

/**
 * Validate email format
 */
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Validate password strength
 */
function validatePassword(password) {
    const errors = [];
    
    if (password.length < CONFIG.PASSWORD_MIN_LENGTH) {
        errors.push(`Password must be at least ${CONFIG.PASSWORD_MIN_LENGTH} characters long`);
    }
    
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors,
    };
}

/**
 * Calculate password strength
 */
function calculatePasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= CONFIG.PASSWORD_MIN_LENGTH) strength++;
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) strength++;
    
    if (strength <= 2) return 'weak';
    if (strength <= 4) return 'medium';
    return 'strong';
}

/**
 * Validate name (no special characters, XSS prevention)
 */
function validateName(name) {
    // Remove any HTML tags and check for valid characters
    const sanitized = name.replace(/<[^>]*>/g, '').trim();
    
    if (sanitized.length < 2) {
        return { isValid: false, error: 'Name must be at least 2 characters long' };
    }
    
    if (sanitized.length > 50) {
        return { isValid: false, error: 'Name must not exceed 50 characters' };
    }
    
    if (!/^[a-zA-Z\s'-]+$/.test(sanitized)) {
        return { isValid: false, error: 'Name can only contain letters, spaces, hyphens, and apostrophes' };
    }
    
    return { isValid: true, sanitized: sanitized };
}

// ==================== UI FUNCTIONS ====================

/**
 * Show/hide loading state on buttons
 */
function setButtonLoading(button, isLoading) {
    const btnText = button.querySelector('.btn-text');
    const btnLoader = button.querySelector('.btn-loader');
    
    if (isLoading) {
        btnText.style.display = 'none';
        btnLoader.style.display = 'flex';
        button.disabled = true;
    } else {
        btnText.style.display = 'block';
        btnLoader.style.display = 'none';
        button.disabled = false;
    }
}

/**
 * Show alert message
 */
function showAlert(alertId, message, type = 'info') {
    const alert = document.getElementById(alertId);
    if (!alert) return;
    
    // Remove existing type classes
    alert.className = 'alert';
    alert.classList.add(`alert-${type}`);
    
    // Safely set the message (prevent XSS)
    setTextSafely(alert, message);
    
    alert.style.display = 'block';
    
    // Auto-hide success messages after 5 seconds
    if (type === 'success') {
        setTimeout(() => {
            alert.style.display = 'none';
        }, 5000);
    }
}

/**
 * Hide alert message
 */
function hideAlert(alertId) {
    const alert = document.getElementById(alertId);
    if (alert) {
        alert.style.display = 'none';
    }
}

/**
 * Show error message for form field
 */
function showFieldError(fieldId, message) {
    const errorElement = document.getElementById(`${fieldId}Error`);
    const inputElement = document.getElementById(fieldId);
    
    if (errorElement) {
        setTextSafely(errorElement, message);
    }
    
    if (inputElement) {
        inputElement.classList.add('error');
    }
}

/**
 * Clear error message for form field
 */
function clearFieldError(fieldId) {
    const errorElement = document.getElementById(`${fieldId}Error`);
    const inputElement = document.getElementById(fieldId);
    
    if (errorElement) {
        errorElement.textContent = '';
    }
    
    if (inputElement) {
        inputElement.classList.remove('error');
    }
}

/**
 * Clear all form errors
 */
function clearAllErrors(formId) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    const errorElements = form.querySelectorAll('.error-message');
    errorElements.forEach(el => el.textContent = '');
    
    const inputElements = form.querySelectorAll('.form-input');
    inputElements.forEach(el => el.classList.remove('error'));
}

/**
 * Show page and hide others
 */
function showPage(pageName) {
    const pages = document.querySelectorAll('.page');
    pages.forEach(page => {
        page.classList.remove('active');
    });
    
    const targetPage = document.getElementById(`${pageName}Page`);
    if (targetPage) {
        targetPage.classList.add('active');
        AppState.currentPage = pageName;
    }
}

/**
 * Update password strength indicator
 */
function updatePasswordStrength(password) {
    const strengthFill = document.getElementById('strengthFill');
    const strengthText = document.getElementById('strengthText');
    
    if (!strengthFill || !strengthText) return;
    
    if (password.length === 0) {
        strengthFill.className = 'strength-fill';
        setTextSafely(strengthText, 'Password strength');
        return;
    }
    
    const strength = calculatePasswordStrength(password);
    strengthFill.className = `strength-fill ${strength}`;
    
    const strengthLabels = {
        weak: 'Weak password',
        medium: 'Medium password',
        strong: 'Strong password',
    };
    
    setTextSafely(strengthText, strengthLabels[strength]);
}

// ==================== LOGIN FUNCTIONALITY ====================

/**
 * Handle login form submission
 */
async function handleLogin(event) {
    event.preventDefault();
    
    if (AppState.isLoading) return;
    
    // Clear previous errors
    clearAllErrors('loginForm');
    hideAlert('loginAlert');
    
    // Get form values
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    
    // Validate inputs
    let hasErrors = false;
    
    if (!email) {
        showFieldError('loginEmail', 'Email is required');
        hasErrors = true;
    } else if (!validateEmail(email)) {
        showFieldError('loginEmail', 'Please enter a valid email address');
        hasErrors = true;
    }
    
    if (!password) {
        showFieldError('loginPassword', 'Password is required');
        hasErrors = true;
    }
    
    if (hasErrors) return;
    
    // Set loading state
    const loginBtn = document.getElementById('loginBtn');
    setButtonLoading(loginBtn, true);
    AppState.isLoading = true;
    
    try {
        // Make API request
        const data = await apiRequest('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        });
        
        // Store user data (sanitize before storing)
        AppState.user = {
            id: data.user.id,
            name: sanitizeHTML(data.user.name),
            email: sanitizeHTML(data.user.email),
        };
        
        // Store in localStorage for persistence
        localStorage.setItem('user', JSON.stringify(AppState.user));
        
        // Show success message
        showAlert('loginAlert', 'Login successful! Redirecting...', 'success');
        
        // Redirect to dashboard after short delay
        setTimeout(() => {
            showDashboard();
        }, 1000);
        
    } catch (error) {
        showAlert('loginAlert', error.message || 'Login failed. Please try again.', 'error');
    } finally {
        setButtonLoading(loginBtn, false);
        AppState.isLoading = false;
    }
}

// ==================== REGISTRATION FUNCTIONALITY ====================

/**
 * Handle registration form submission
 */
async function handleRegister(event) {
    event.preventDefault();
    
    if (AppState.isLoading) return;
    
    // Clear previous errors
    clearAllErrors('registerForm');
    hideAlert('registerAlert');
    
    // Get form values
    const name = document.getElementById('registerName').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('registerConfirmPassword').value;
    
    // Validate inputs
    let hasErrors = false;
    
    // Validate name
    const nameValidation = validateName(name);
    if (!name) {
        showFieldError('registerName', 'Name is required');
        hasErrors = true;
    } else if (!nameValidation.isValid) {
        showFieldError('registerName', nameValidation.error);
        hasErrors = true;
    }
    
    // Validate email
    if (!email) {
        showFieldError('registerEmail', 'Email is required');
        hasErrors = true;
    } else if (!validateEmail(email)) {
        showFieldError('registerEmail', 'Please enter a valid email address');
        hasErrors = true;
    }
    
    // Validate password
    const passwordValidation = validatePassword(password);
    if (!password) {
        showFieldError('registerPassword', 'Password is required');
        hasErrors = true;
    } else if (!passwordValidation.isValid) {
        showFieldError('registerPassword', passwordValidation.errors[0]);
        hasErrors = true;
    }
    
    // Validate confirm password
    if (!confirmPassword) {
        showFieldError('registerConfirmPassword', 'Please confirm your password');
        hasErrors = true;
    } else if (password !== confirmPassword) {
        showFieldError('registerConfirmPassword', 'Passwords do not match');
        hasErrors = true;
    }
    
    if (hasErrors) return;
    
    // Set loading state
    const registerBtn = document.getElementById('registerBtn');
    setButtonLoading(registerBtn, true);
    AppState.isLoading = true;
    
    try {
        // Make API request
        const data = await apiRequest('/auth/register', {
            method: 'POST',
            body: JSON.stringify({
                name: nameValidation.sanitized, // Use sanitized name
                email,
                password,
            }),
        });
        
        // Show success message
        showAlert('registerAlert', 'Account created successfully! Redirecting to login...', 'success');
        
        // Redirect to login after short delay
        setTimeout(() => {
            showPage('login');
            // Pre-fill email on login page
            document.getElementById('loginEmail').value = email;
        }, 2000);
        
    } catch (error) {
        showAlert('registerAlert', error.message || 'Registration failed. Please try again.', 'error');
    } finally {
        setButtonLoading(registerBtn, false);
        AppState.isLoading = false;
    }
}

// ==================== DASHBOARD FUNCTIONALITY ====================

/**
 * Show dashboard with user data
 */
function showDashboard() {
    if (!AppState.user) {
        // Try to restore from localStorage
        const storedUser = localStorage.getItem('user');
        if (storedUser) {
            try {
                AppState.user = JSON.parse(storedUser);
            } catch (e) {
                console.error('Failed to parse stored user:', e);
                showPage('login');
                return;
            }
        } else {
            showPage('login');
            return;
        }
    }
    
    // Update user info in UI (using safe methods to prevent XSS)
    setTextSafely(document.getElementById('userName'), AppState.user.name);
    setTextSafely(document.getElementById('userEmail'), AppState.user.email);
    setTextSafely(document.getElementById('welcomeName'), AppState.user.name.split(' ')[0]);
    
    // Set user initials
    const initials = AppState.user.name
        .split(' ')
        .map(n => n[0])
        .join('')
        .toUpperCase()
        .substring(0, 2);
    setTextSafely(document.getElementById('userInitials'), initials);
    
    // Update session info
    updateSessionInfo();
    
    // Show dashboard page
    showPage('dashboard');
    
    // Start session check interval
    startSessionCheck();
}

/**
 * Update session information in dashboard
 */
function updateSessionInfo() {
    // Session ID (in production, this should come from backend)
    const sessionId = 'sess_' + Math.random().toString(36).substring(2, 10);
    setTextSafely(document.getElementById('sessionId'), sessionId);
    
    // IP Address (in production, this should come from backend)
    fetch('https://api.ipify.org?format=json')
        .then(res => res.json())
        .then(data => {
            setTextSafely(document.getElementById('ipAddress'), data.ip);
        })
        .catch(() => {
            setTextSafely(document.getElementById('ipAddress'), 'Unable to fetch');
        });
    
    // Browser info
    const browserInfo = navigator.userAgent.split(' ').pop().split('/')[0];
    setTextSafely(document.getElementById('browserInfo'), browserInfo);
    
    // Session expiry (example: 30 minutes from now)
    const expiryTime = new Date(Date.now() + 30 * 60 * 1000);
    setTextSafely(document.getElementById('sessionExpiry'), expiryTime.toLocaleTimeString());
    
    // Last login time
    setTextSafely(document.getElementById('lastLogin'), new Date().toLocaleString());
}

/**
 * Start periodic session checks
 */
let sessionCheckInterval = null;

function startSessionCheck() {
    if (sessionCheckInterval) {
        clearInterval(sessionCheckInterval);
    }
    
    sessionCheckInterval = setInterval(() => {
        if (AppState.currentPage === 'dashboard') {
            checkSession();
        }
    }, CONFIG.SESSION_CHECK_INTERVAL);
}

/**
 * Handle logout
 */
async function handleLogout() {
    try {
        // Make API request to logout
        await apiRequest('/auth/logout', { method: 'POST' });
    } catch (error) {
        console.error('Logout API error:', error);
        // Continue with logout even if API fails
    }
    
    // Clear user data
    AppState.user = null;
    localStorage.removeItem('user');
    
    // Clear session check interval
    if (sessionCheckInterval) {
        clearInterval(sessionCheckInterval);
        sessionCheckInterval = null;
    }
    
    // Redirect to login
    showPage('login');
    showAlert('loginAlert', 'You have been logged out successfully.', 'success');
}

// ==================== PASSWORD VISIBILITY TOGGLE ====================

/**
 * Toggle password visibility
 */
function setupPasswordToggle(toggleButtonId, inputId) {
    const toggleButton = document.getElementById(toggleButtonId);
    const passwordInput = document.getElementById(inputId);
    
    if (!toggleButton || !passwordInput) return;
    
    toggleButton.addEventListener('click', () => {
        const eyeOpen = toggleButton.querySelector('.eye-open');
        const eyeClosed = toggleButton.querySelector('.eye-closed');
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            eyeOpen.style.display = 'none';
            eyeClosed.style.display = 'block';
        } else {
            passwordInput.type = 'password';
            eyeOpen.style.display = 'block';
            eyeClosed.style.display = 'none';
        }
    });
}

// ==================== INITIALIZATION ====================

/**
 * Initialize the application
 */
function initApp() {
    // Setup form handlers
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    // Setup navigation links
    const goToRegister = document.getElementById('goToRegister');
    if (goToRegister) {
        goToRegister.addEventListener('click', (e) => {
            e.preventDefault();
            showPage('register');
            clearAllErrors('loginForm');
            hideAlert('loginAlert');
        });
    }
    
    const goToLogin = document.getElementById('goToLogin');
    if (goToLogin) {
        goToLogin.addEventListener('click', (e) => {
            e.preventDefault();
            showPage('login');
            clearAllErrors('registerForm');
            hideAlert('registerAlert');
        });
    }
    
    // Setup logout button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
    
    // Setup password toggles
    setupPasswordToggle('toggleLoginPassword', 'loginPassword');
    setupPasswordToggle('toggleRegisterPassword', 'registerPassword');
    
    // Setup password strength indicator
    const registerPassword = document.getElementById('registerPassword');
    if (registerPassword) {
        registerPassword.addEventListener('input', (e) => {
            updatePasswordStrength(e.target.value);
        });
    }
    
    // Check if user is already logged in
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
        try {
            AppState.user = JSON.parse(storedUser);
            showDashboard();
        } catch (e) {
            console.error('Failed to restore user session:', e);
            localStorage.removeItem('user');
            showPage('login');
        }
    } else {
        showPage('login');
    }
    
    // Initialize CSRF token
    getCSRFToken();
}

// ==================== START APPLICATION ====================

// Wait for DOM to be fully loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

// ==================== EXPORT FOR TESTING ====================
// Only export if in a module environment
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        sanitizeHTML,
        validateEmail,
        validatePassword,
        validateName,
        calculatePasswordStrength,
    };
}
