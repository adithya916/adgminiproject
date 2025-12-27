document.addEventListener('DOMContentLoaded', () => {
    const app = {
        user: null,
        csrfToken: null,

        init: async () => {
            app.csrfToken = app.getCookie('XSRF-TOKEN');
            await app.checkAuth();
            app.render();
        },

        getCookie: (name) => {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
            return null;
        },

        checkAuth: async () => {
            try {
                const res = await fetch('/api/users/me', {
                    headers: {
                        'CSRF-Token': app.csrfToken
                    }
                });
                const data = await res.json();
                if (data.success) {
                    app.user = data.user;
                } else {
                    app.user = null;
                }
            } catch (err) {
                console.error('Auth check failed', err);
                app.user = null;
            }
        },

        logout: async () => {
            try {
                const res = await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': app.csrfToken
                    }
                });
                const data = await res.json();
                if (data.success) {
                    app.user = null;
                    app.render();
                    app.showAlert('Logged out successfully', 'success');
                }
            } catch (err) {
                console.error('Logout failed', err);
            }
        },

        login: async (email, password) => {
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': app.csrfToken
                    },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();
                if (data.success) {
                    app.user = data.user;
                    // Update CSRF token if rotated
                    app.csrfToken = app.getCookie('XSRF-TOKEN'); 
                    app.render();
                } else {
                    app.showAlert(data.error || 'Login failed', 'error');
                }
            } catch (err) {
                app.showAlert('Network error', 'error');
            }
        },

        register: async (email, password) => {
            try {
                const res = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': app.csrfToken
                    },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();
                if (data.success) {
                    app.showAlert('Registration successful! Please login.', 'success');
                    app.render('login');
                } else {
                    app.showAlert(data.error || 'Registration failed', 'error');
                }
            } catch (err) {
                app.showAlert('Network error', 'error');
            }
        },

        showAlert: (msg, type) => {
            const container = document.getElementById('alert-container');
            const div = document.createElement('div');
            div.className = `alert alert-${type}`;
            div.textContent = msg;
            container.innerHTML = '';
            container.appendChild(div);
            setTimeout(() => {
                div.remove();
            }, 5000);
        },

        render: (viewName = null) => {
            const content = document.getElementById('content');
            const navLinks = document.getElementById('nav-links');
            content.innerHTML = '';
            navLinks.innerHTML = '';

            // Render Nav
            if (app.user) {
                const logoutLi = document.createElement('li');
                const logoutLink = document.createElement('a');
                logoutLink.textContent = 'Logout';
                logoutLink.onclick = (e) => { e.preventDefault(); app.logout(); };
                logoutLi.appendChild(logoutLink);
                navLinks.appendChild(logoutLi);
            } else {
                const loginLi = document.createElement('li');
                const loginLink = document.createElement('a');
                loginLink.textContent = 'Login';
                loginLink.onclick = (e) => { e.preventDefault(); app.render('login'); };
                loginLi.appendChild(loginLink);
                
                const regLi = document.createElement('li');
                const regLink = document.createElement('a');
                regLink.textContent = 'Register';
                regLink.onclick = (e) => { e.preventDefault(); app.render('register'); };
                regLi.appendChild(regLink);
                
                navLinks.appendChild(loginLi);
                navLinks.appendChild(regLi);
            }

            // Determine view
            if (!viewName) {
                if (app.user) viewName = 'dashboard';
                else viewName = 'login';
            }

            // Render View
            if (viewName === 'dashboard' && app.user) {
                const tmpl = document.getElementById('dashboard-template').content.cloneNode(true);
                tmpl.getElementById('user-email').textContent = app.user.email;
                tmpl.getElementById('user-id').textContent = app.user.id;
                tmpl.getElementById('user-role').textContent = app.user.role;
                content.appendChild(tmpl);
            } else if (viewName === 'register') {
                const tmpl = document.getElementById('register-template').content.cloneNode(true);
                const form = tmpl.getElementById('register-form');
                form.onsubmit = (e) => {
                    e.preventDefault();
                    app.register(
                        tmpl.getElementById('register-email').value,
                        tmpl.getElementById('register-password').value
                    );
                };
                tmpl.getElementById('link-login').onclick = (e) => {
                    e.preventDefault();
                    app.render('login');
                };
                content.appendChild(tmpl);
            } else {
                // Default to login
                const tmpl = document.getElementById('login-template').content.cloneNode(true);
                const form = tmpl.getElementById('login-form');
                form.onsubmit = (e) => {
                    e.preventDefault();
                    app.login(
                        tmpl.getElementById('login-email').value,
                        tmpl.getElementById('login-password').value
                    );
                };
                tmpl.getElementById('link-register').onclick = (e) => {
                    e.preventDefault();
                    app.render('register');
                };
                content.appendChild(tmpl);
            }
        }
    };

    app.init();
});

