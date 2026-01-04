# ASTRA DYNE GLOBAL - User Management System Frontend

## 📋 Overview

This is a secure, production-ready frontend for the ASTRA DYNE GLOBAL User Management System. Built with vanilla HTML, CSS, and JavaScript, it provides a modern authentication interface with comprehensive security features.

## ✨ Features

### 🔐 Security Features

1. **CSRF Protection**
   - Generates and includes CSRF tokens in all API requests
   - Tokens are stored in cookies with SameSite=Strict
   - Custom header `X-CSRF-Token` for API communication

2. **XSS Prevention**
   - All user input is sanitized before rendering
   - Uses `textContent` instead of `innerHTML` for user data
   - HTML special characters are escaped
   - Safe rendering functions throughout the codebase

3. **Input Validation**
   - Client-side validation for all form fields
   - Email format validation
   - Strong password requirements (min 8 chars, uppercase, lowercase, number, special char)
   - Name validation to prevent injection attacks
   - Real-time password strength indicator

4. **Session Management**
   - Cookie-based session handling
   - Automatic session expiration detection
   - Periodic session validity checks (every 60 seconds)
   - Secure credential storage

5. **Rate Limiting Feedback**
   - Handles 429 status codes from backend
   - User-friendly error messages for rate limit violations
   - Prevents multiple simultaneous submissions

### 🎨 User Interface Features

1. **Authentication Pages**
   - Modern login page with email/password fields
   - Registration page with name, email, and password confirmation
   - Secure dashboard after successful authentication

2. **User Experience**
   - Smooth page transitions with animations
   - Loading states on all buttons
   - Real-time form validation feedback
   - Password visibility toggle
   - Password strength indicator
   - Responsive design for all screen sizes

3. **Dashboard**
   - User profile display
   - Session information (ID, IP, browser, expiry)
   - Security status indicators
   - Logout functionality

### 🎯 Design Features

- **Distinctive Aesthetic**: Cybersecurity-inspired dark theme with cyan accents
- **Modern Typography**: Outfit font for UI, JetBrains Mono for technical elements
- **Glassmorphism**: Frosted glass effects with backdrop blur
- **Smooth Animations**: Professional transitions and micro-interactions
- **Accessible**: Focus states, keyboard navigation, reduced motion support

## 🗂️ File Structure

```
frontend/
├── index.html          # Main HTML structure
├── styles.css          # All styling and animations
├── app.js             # Client-side logic and API integration
└── README.md          # This file
```

## 🚀 Getting Started

### Prerequisites

- A modern web browser (Chrome, Firefox, Safari, Edge)
- A backend API server (see Backend Integration section)

### Installation

1. Clone or download the frontend files
2. Open `app.js` and update the `API_BASE_URL` in the CONFIG object:
   ```javascript
   const CONFIG = {
       API_BASE_URL: 'http://your-backend-url/api', // Update this
       // ...
   };
   ```
3. Serve the files using any web server (e.g., Python's http.server, Node's http-server, or any static hosting)

### Running Locally

Using Python:
```bash
py -3 -m http.server 8000
```

Using Node.js:
```bash
npx http-server -p 8000
```

Then open `http://localhost:8000` in your browser.

## 🔌 Backend Integration

### Required API Endpoints

The frontend expects the following REST API endpoints:

#### 1. **POST /api/auth/register**
Register a new user account.

**Request:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

**Response (Success - 201):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "id": "user123",
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

**Response (Error - 400/409):**
```json
{
  "success": false,
  "message": "Email already exists"
}
```

#### 2. **POST /api/auth/login**
Authenticate a user and create a session.

**Request:**
```json
{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

**Response (Success - 200):**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": "user123",
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

**Response (Error - 401):**
```json
{
  "success": false,
  "message": "Invalid email or password"
}
```

**Important:** Set a secure HTTP-only cookie with the session ID in the response headers.

#### 3. **GET /api/auth/session**
Check if the current session is valid.

**Response (Valid - 200):**
```json
{
  "valid": true,
  "user": {
    "id": "user123",
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

**Response (Invalid - 401):**
```json
{
  "valid": false,
  "message": "Session expired or invalid"
}
```

#### 4. **POST /api/auth/logout**
Invalidate the current session.

**Response (Success - 200):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

### CSRF Token Handling

The frontend sends a CSRF token with every request in the `X-CSRF-Token` header. Your backend should:

1. Generate a CSRF token when the user first visits the site
2. Set it in a cookie: `csrf_token=<token>; HttpOnly; SameSite=Strict`
3. Validate the token from the header against the cookie on protected routes
4. Reject requests with missing or invalid CSRF tokens (return 403)

### CORS Configuration

If your backend is on a different domain, configure CORS:

```javascript
// Express.js example
app.use(cors({
  origin: 'http://frontend-domain.com',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token']
}));
```

### Rate Limiting

Implement rate limiting on your backend and return a 429 status code when limits are exceeded. The frontend will display an appropriate message to the user.

Example rate limits:
- Login attempts: 5 per 15 minutes per IP
- Registration: 3 per hour per IP
- General API calls: 100 per hour per user

## 🛡️ Security Best Practices

### Frontend Security

1. **Always sanitize user input** before displaying it
2. **Never trust client-side validation alone** - always validate on the server
3. **Use HTTPS** in production
4. **Implement Content Security Policy (CSP)** headers
5. **Keep dependencies updated**

### Backend Security Requirements

Your backend MUST implement:

1. **Password Hashing**: Use bcrypt, argon2, or similar (never store plain text)
2. **SQL Injection Prevention**: Use parameterized queries
3. **Session Security**: 
   - HttpOnly cookies
   - Secure flag in production
   - SameSite=Strict
   - Short expiration times
4. **Rate Limiting**: Prevent brute force attacks
5. **Input Validation**: Validate all inputs on the server
6. **HTTPS**: Always use HTTPS in production

## 📱 Responsive Design

The interface is fully responsive and works on:
- Desktop (1920px+)
- Laptop (1366px - 1920px)
- Tablet (768px - 1366px)
- Mobile (320px - 768px)

## 🎨 Customization

### Changing Colors

Edit the CSS variables in `styles.css`:

```css
:root {
    --color-primary: #00f5d4;      /* Primary accent color */
    --color-secondary: #00bbf9;    /* Secondary accent color */
    --bg-primary: #0a0e27;         /* Main background */
    --bg-card: rgba(19, 24, 53, 0.8); /* Card background */
    /* ... */
}
```

### Changing Configuration

Edit the CONFIG object in `app.js`:

```javascript
const CONFIG = {
    API_BASE_URL: 'http://localhost:3000/api',
    CSRF_TOKEN_HEADER: 'X-CSRF-Token',
    SESSION_CHECK_INTERVAL: 60000,
    PASSWORD_MIN_LENGTH: 8,
    RATE_LIMIT_MESSAGE: 'Too many requests. Please try again later.',
};
```

## 🧪 Testing

### Manual Testing Checklist

- [ ] Register new account with valid details
- [ ] Register with invalid email format
- [ ] Register with weak password
- [ ] Register with mismatched passwords
- [ ] Login with correct credentials
- [ ] Login with incorrect credentials
- [ ] View dashboard after login
- [ ] Logout and return to login page
- [ ] Test password visibility toggle
- [ ] Test responsive design on different devices
- [ ] Test form validation messages
- [ ] Test session expiration handling

### Browser Testing

Test on:
- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## 🐛 Troubleshooting

### Issue: CORS errors in console

**Solution**: Configure CORS on your backend to allow your frontend origin.

### Issue: Login succeeds but redirects to login page

**Solution**: Check that cookies are being set correctly. Ensure `credentials: 'include'` is in fetch requests and backend sets cookies properly.

### Issue: CSRF token errors

**Solution**: Ensure your backend is validating CSRF tokens correctly and that the cookie is set with the right SameSite and path settings.

### Issue: Session keeps expiring

**Solution**: Check session timeout settings in your backend. Adjust `SESSION_CHECK_INTERVAL` in frontend config.

## 📝 Code Quality

The codebase follows these standards:

- **No hardcoded credentials** anywhere in the code
- **Commented functions** for clarity
- **Consistent naming conventions** (camelCase for JavaScript)
- **Modular structure** with separate concerns
- **Security-first approach** throughout

## 🔄 Future Enhancements

Potential features for future versions:

1. Two-factor authentication (2FA)
2. Password reset functionality
3. Email verification
4. Remember me option
5. Social login (Google, GitHub)
6. Profile editing
7. Activity log
8. Dark/light theme toggle
9. Multi-language support
10. Biometric authentication

## 👥 Team Roles

### Cyril Rene Philip (Frontend Developer)
- UI/UX design and implementation
- Client-side validation
- API integration
- Security features (XSS prevention, CSRF handling)
- State management

### Integration Points with Team Members

**With Adhitya (Database):**
- User data structure must match database schema
- Session data format coordination

**With Sri Krishna Adithya (Backend):**
- API endpoint contracts
- Authentication flow
- Session management strategy
- Error handling conventions

## 📄 License

This project is part of the ASTRA DYNE GLOBAL User Management System.

## 🤝 Contributing

When making changes:

1. Test all authentication flows
2. Verify security features still work
3. Test on multiple browsers
4. Check responsive design
5. Update this README if adding features

## 📞 Support

For issues or questions:
- Check the Troubleshooting section
- Review the Backend Integration guide
- Contact the development team

---

**Built with security and user experience in mind** 🔒✨
