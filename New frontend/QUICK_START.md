# Quick Start Guide - ASTRA DYNE Frontend

## 🚀 Get Started in 5 Minutes

### Step 1: Configure the Backend URL

Open `app.js` and find line 2-6:

```javascript
const CONFIG = {
    API_BASE_URL: 'http://localhost:3000/api', // ← CHANGE THIS
    // ...
};
```

Replace with your backend URL:
- Development: `http://localhost:3000/api`
- Production: `https://api.yourdomain.com/api`

### Step 2: Start a Local Server

Choose one method:

**Option A: Python (Recommended for quick testing)**
```bash
python3 -m http.server 8000
```

**Option B: Node.js**
```bash
npx http-server -p 8000
```

**Option C: VS Code Live Server**
- Install "Live Server" extension
- Right-click `index.html` → "Open with Live Server"

### Step 3: Open in Browser

Navigate to: `http://localhost:8000`

### Step 4: Test the UI

You can test the frontend without a backend! The UI will work, but API calls will fail (as expected). To see the full flow, you need the backend running.

## 📁 File Overview

```
frontend/
├── index.html                  # Main HTML (login, register, dashboard)
├── styles.css                 # All styling and animations
├── app.js                     # Client logic, validation, API calls
├── README.md                  # Complete documentation
└── BACKEND_INTEGRATION.md     # Backend setup guide
```

## 🔧 What Your Teammates Need to Do

### For Adhitya (Database)

Create these tables in your database:

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);
```

### For Sri Krishna Adithya (Backend)

Implement these 4 endpoints:

1. **POST /api/auth/register** - Create new user
2. **POST /api/auth/login** - Authenticate user
3. **GET /api/auth/session** - Check session validity
4. **POST /api/auth/logout** - End session

See `BACKEND_INTEGRATION.md` for complete examples!

## ✅ Features Already Implemented

Your frontend has:

- ✅ **Login page** with email/password
- ✅ **Registration page** with validation
- ✅ **Dashboard** showing user info
- ✅ **Password strength indicator**
- ✅ **Password visibility toggle**
- ✅ **Client-side validation**
- ✅ **XSS prevention** (all user data sanitized)
- ✅ **CSRF token handling**
- ✅ **Session management**
- ✅ **Rate limit feedback**
- ✅ **Loading states**
- ✅ **Error messages**
- ✅ **Responsive design**
- ✅ **Modern animations**
- ✅ **Security best practices**

## 🎨 Customization

### Change Colors

Edit `styles.css` lines 3-7:

```css
:root {
    --color-primary: #00f5d4;      /* Cyan - main accent */
    --color-secondary: #00bbf9;    /* Blue - secondary */
    --bg-primary: #0a0e27;         /* Dark background */
}
```

### Change Password Requirements

Edit `app.js` line 6:

```javascript
const CONFIG = {
    PASSWORD_MIN_LENGTH: 8, // ← Change this
};
```

## 🐛 Common Issues & Fixes

### Issue: "CORS Error" in console

**Cause**: Backend not configured for CORS

**Fix**: Add CORS middleware in your backend:
```javascript
app.use(cors({
    origin: 'http://localhost:8000',
    credentials: true
}));
```

### Issue: Login works but immediately logs out

**Cause**: Cookies not being set properly

**Fix**: Ensure backend sets cookies with correct settings:
```javascript
cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: false // true only for HTTPS
}
```

### Issue: "Too many requests" message

**Cause**: Rate limiting is working! (This is good)

**Fix**: Wait 15 minutes or implement rate limiting on backend

## 📱 Testing Checklist

Open the app and test:

- [ ] Navigate to registration page
- [ ] Fill out registration form
- [ ] See password strength indicator change
- [ ] Toggle password visibility
- [ ] Submit with invalid email (should show error)
- [ ] Submit with weak password (should show error)
- [ ] Submit with mismatched passwords (should show error)
- [ ] Navigate to login page
- [ ] Try to login
- [ ] See dashboard (if backend connected)
- [ ] Logout
- [ ] Test on mobile (resize browser)

## 🌐 Deployment to Production

### Option 1: Static Hosting (Netlify, Vercel)

1. Push code to GitHub
2. Connect repository to Netlify/Vercel
3. Deploy!
4. Update `API_BASE_URL` to production backend

### Option 2: Traditional Hosting

1. Upload files to web server
2. Configure web server (Nginx/Apache)
3. Set up HTTPS certificate
4. Update `API_BASE_URL`

### Option 3: With Backend (Full Stack)

1. Deploy backend first
2. Get backend URL
3. Update `API_BASE_URL` in frontend
4. Deploy frontend
5. Test end-to-end

## 🔒 Security Reminders

Before going live:

- [ ] Backend uses HTTPS
- [ ] Passwords are hashed (bcrypt/argon2)
- [ ] CSRF protection enabled
- [ ] Rate limiting configured
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (already done in frontend)
- [ ] Secure cookies (HttpOnly, SameSite, Secure)
- [ ] Input validation on backend
- [ ] Error messages don't leak sensitive info

## 📞 Need Help?

1. **Read the docs**: `README.md` has everything
2. **Backend setup**: See `BACKEND_INTEGRATION.md`
3. **Check console**: Look for errors in browser DevTools (F12)
4. **Test API**: Use Postman or curl to test backend
5. **Ask teammate**: Coordinate with backend developer

## 🎯 Next Steps

1. ✅ **You**: Frontend is done! Test the UI
2. 🔨 **Sri Krishna**: Build the 4 API endpoints
3. 📊 **Adhitya**: Set up database tables
4. 🔗 **Together**: Connect frontend + backend
5. 🧪 **Team**: Test everything end-to-end
6. 🚀 **Deploy**: Launch the system!

## 💡 Pro Tips

- Use Chrome DevTools (F12) → Network tab to debug API calls
- Use Redux DevTools if you add Redux later
- Keep `README.md` updated as you add features
- Write tests for critical functions
- Document any changes you make
- Use Git for version control

---

**You're all set!** 🎉

Your frontend is production-ready and secure. Now coordinate with your teammates to connect everything together!

**Questions?** Check the detailed docs or ask your team! 👥
