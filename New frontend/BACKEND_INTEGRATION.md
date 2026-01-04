# Backend Integration Guide

This document provides example code for integrating the frontend with your backend API.

## Table of Contents
1. [Express.js Example](#expressjs-example)
2. [Security Middleware](#security-middleware)
3. [CSRF Token Implementation](#csrf-token-implementation)
4. [Session Management](#session-management)
5. [Rate Limiting](#rate-limiting)

## Express.js Example

### Basic Server Setup

```javascript
// server.js
const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet()); // Security headers
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:8000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token']
}));
app.use(express.json());
app.use(cookieParser());

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'strict',
        maxAge: 1800000 // 30 minutes
    }
}));

// Routes
app.use('/api/auth', require('./routes/auth'));

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

### Authentication Routes

```javascript
// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const csrf = require('csurf');

// Database connection (example using PostgreSQL)
const db = require('../database/db');

// CSRF protection
const csrfProtection = csrf({ 
    cookie: { 
        httpOnly: true, 
        sameSite: 'strict' 
    } 
});

// Rate limiters
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts. Please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 registrations
    message: 'Too many registration attempts. Please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// ========== REGISTER ENDPOINT ==========
router.post('/register',
    registerLimiter,
    csrfProtection,
    [
        body('name')
            .trim()
            .isLength({ min: 2, max: 50 })
            .matches(/^[a-zA-Z\s'-]+$/)
            .withMessage('Invalid name format'),
        body('email')
            .isEmail()
            .normalizeEmail()
            .withMessage('Invalid email address'),
        body('password')
            .isLength({ min: 8 })
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
            .withMessage('Password must contain uppercase, lowercase, number, and special character')
    ],
    async (req, res) => {
        try {
            // Validate input
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    success: false, 
                    message: errors.array()[0].msg 
                });
            }

            const { name, email, password } = req.body;

            // Check if user already exists
            const existingUser = await db.query(
                'SELECT id FROM users WHERE email = $1',
                [email]
            );

            if (existingUser.rows.length > 0) {
                return res.status(409).json({ 
                    success: false, 
                    message: 'Email already registered' 
                });
            }

            // Hash password
            const saltRounds = 12;
            const passwordHash = await bcrypt.hash(password, saltRounds);

            // Insert user into database
            const result = await db.query(
                'INSERT INTO users (name, email, password_hash, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, name, email',
                [name, email, passwordHash]
            );

            const newUser = result.rows[0];

            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                user: {
                    id: newUser.id,
                    name: newUser.name,
                    email: newUser.email
                }
            });

        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Registration failed. Please try again.' 
            });
        }
    }
);

// ========== LOGIN ENDPOINT ==========
router.post('/login',
    loginLimiter,
    csrfProtection,
    [
        body('email').isEmail().normalizeEmail(),
        body('password').notEmpty()
    ],
    async (req, res) => {
        try {
            // Validate input
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid input' 
                });
            }

            const { email, password } = req.body;

            // Get user from database
            const result = await db.query(
                'SELECT id, name, email, password_hash FROM users WHERE email = $1',
                [email]
            );

            if (result.rows.length === 0) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid email or password' 
                });
            }

            const user = result.rows[0];

            // Verify password
            const isValidPassword = await bcrypt.compare(password, user.password_hash);

            if (!isValidPassword) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid email or password' 
                });
            }

            // Create session
            req.session.userId = user.id;
            req.session.email = user.email;

            // Store session in database
            await db.query(
                'INSERT INTO sessions (user_id, session_id, created_at, expires_at) VALUES ($1, $2, NOW(), NOW() + INTERVAL \'30 minutes\')',
                [user.id, req.sessionID]
            );

            res.status(200).json({
                success: true,
                message: 'Login successful',
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email
                }
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Login failed. Please try again.' 
            });
        }
    }
);

// ========== SESSION CHECK ENDPOINT ==========
router.get('/session', csrfProtection, async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ 
                valid: false, 
                message: 'No active session' 
            });
        }

        // Check if session exists in database
        const result = await db.query(
            'SELECT user_id FROM sessions WHERE session_id = $1 AND expires_at > NOW()',
            [req.sessionID]
        );

        if (result.rows.length === 0) {
            req.session.destroy();
            return res.status(401).json({ 
                valid: false, 
                message: 'Session expired' 
            });
        }

        // Get user data
        const userResult = await db.query(
            'SELECT id, name, email FROM users WHERE id = $1',
            [req.session.userId]
        );

        const user = userResult.rows[0];

        res.status(200).json({
            valid: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error('Session check error:', error);
        res.status(500).json({ 
            valid: false, 
            message: 'Session check failed' 
        });
    }
});

// ========== LOGOUT ENDPOINT ==========
router.post('/logout', csrfProtection, async (req, res) => {
    try {
        if (req.session.userId) {
            // Delete session from database
            await db.query(
                'DELETE FROM sessions WHERE session_id = $1',
                [req.sessionID]
            );

            // Destroy session
            req.session.destroy((err) => {
                if (err) {
                    console.error('Session destroy error:', err);
                }
            });
        }

        res.clearCookie('connect.sid'); // Clear session cookie
        res.status(200).json({ 
            success: true, 
            message: 'Logged out successfully' 
        });

    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Logout failed' 
        });
    }
});

module.exports = router;
```

## Security Middleware

### Authentication Middleware

```javascript
// middleware/auth.js

/**
 * Middleware to check if user is authenticated
 */
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    return res.status(401).json({ 
        success: false, 
        message: 'Unauthorized. Please login.' 
    });
}

/**
 * Middleware for SQL injection prevention
 * (Using parameterized queries is the primary defense)
 */
function sanitizeInput(req, res, next) {
    // Additional validation can be added here
    // But parameterized queries are the main defense
    next();
}

module.exports = {
    isAuthenticated,
    sanitizeInput
};
```

## CSRF Token Implementation

The example above uses the `csurf` package. Here's how it works:

1. **Frontend sends request** with CSRF token in header
2. **Backend validates** token against cookie
3. **If valid**, process request
4. **If invalid**, return 403 Forbidden

### Alternative: Manual CSRF Implementation

```javascript
// utils/csrf.js
const crypto = require('crypto');

/**
 * Generate CSRF token
 */
function generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * CSRF validation middleware
 */
function validateCSRF(req, res, next) {
    const tokenFromHeader = req.headers['x-csrf-token'];
    const tokenFromCookie = req.cookies.csrf_token;

    if (!tokenFromHeader || !tokenFromCookie) {
        return res.status(403).json({ 
            success: false, 
            message: 'CSRF token missing' 
        });
    }

    if (tokenFromHeader !== tokenFromCookie) {
        return res.status(403).json({ 
            success: false, 
            message: 'Invalid CSRF token' 
        });
    }

    next();
}

// Set CSRF token on first visit
app.get('/api/csrf-token', (req, res) => {
    const token = generateCSRFToken();
    res.cookie('csrf_token', token, {
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production'
    });
    res.json({ token });
});

module.exports = {
    generateCSRFToken,
    validateCSRF
};
```

## Session Management

### Database Schema for Sessions

```sql
-- sessions table
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

### Session Cleanup (Cron Job)

```javascript
// utils/sessionCleanup.js
const db = require('../database/db');

/**
 * Clean up expired sessions
 * Run this periodically (e.g., every hour)
 */
async function cleanupExpiredSessions() {
    try {
        const result = await db.query(
            'DELETE FROM sessions WHERE expires_at < NOW()'
        );
        console.log(`Cleaned up ${result.rowCount} expired sessions`);
    } catch (error) {
        console.error('Session cleanup error:', error);
    }
}

// Run every hour
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

module.exports = { cleanupExpiredSessions };
```

## Rate Limiting

### IP-Based Rate Limiting

```javascript
// middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');

// For production, use Redis
const redisClient = redis.createClient({
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379
});

// General API rate limiter
const apiLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:api:'
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            message: 'Too many requests. Please try again later.',
            retryAfter: Math.ceil(req.rateLimit.resetTime.getTime() / 1000)
        });
    }
});

// Strict limiter for authentication endpoints
const authLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:auth:'
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    skipSuccessfulRequests: true, // Don't count successful logins
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            message: 'Too many authentication attempts. Please try again later.',
            retryAfter: Math.ceil(req.rateLimit.resetTime.getTime() / 1000)
        });
    }
});

module.exports = {
    apiLimiter,
    authLimiter
};
```

## Environment Variables

Create a `.env` file:

```env
# Server
NODE_ENV=development
PORT=3000
FRONTEND_URL=http://localhost:8000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=astra_dyne
DB_USER=postgres
DB_PASSWORD=your_password

# Session
SESSION_SECRET=your-super-secret-session-key-change-in-production

# Redis (for rate limiting)
REDIS_HOST=localhost
REDIS_PORT=6379

# Security
BCRYPT_ROUNDS=12
```

## Testing the Integration

### Using cURL

```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: your-token" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: your-token" \
  -c cookies.txt \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'

# Check session
curl -X GET http://localhost:3000/api/auth/session \
  -H "X-CSRF-Token: your-token" \
  -b cookies.txt

# Logout
curl -X POST http://localhost:3000/api/auth/logout \
  -H "X-CSRF-Token: your-token" \
  -b cookies.txt
```

## Deployment Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Use strong `SESSION_SECRET`
- [ ] Enable HTTPS (set `secure: true` for cookies)
- [ ] Configure proper CORS origins
- [ ] Set up Redis for rate limiting
- [ ] Enable database connection pooling
- [ ] Set up logging (Winston, Morgan)
- [ ] Configure error handling
- [ ] Set up monitoring (PM2, New Relic)
- [ ] Regular security audits
- [ ] Keep dependencies updated

## Additional Security Measures

1. **Helmet Configuration**:
```javascript
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));
```

2. **Input Sanitization**:
```javascript
const xss = require('xss-clean');
app.use(xss()); // Sanitize user input
```

3. **SQL Injection Prevention**: Always use parameterized queries
4. **Password Policy**: Enforce strong passwords
5. **Account Lockout**: Lock account after 5 failed attempts
6. **Email Verification**: Verify email before full access
7. **Audit Logging**: Log all authentication events

---

**Remember**: Security is a continuous process. Regularly update dependencies, monitor logs, and stay informed about new vulnerabilities.
