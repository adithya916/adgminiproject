const connectDB = require('./config/db');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

// Import our custom logic
const { sessionMiddleware } = require('./middleware/authMiddleware');
const errorHandler = require('./middleware/errorMiddleware');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

// 1. Connect to our Database
connectDB();

const app = express();
const PORT = process.env.PORT || 3000;

// 2. Set up Global Security Middleware
// Helmet sets various HTTP headers to make things harder for attackers
app.use(helmet());

// Limit body size to prevent DoS attacks with huge payloads
app.use(express.json({ limit: '10kb' })); 

// We need to parse cookies because that's where our session ID lives
app.use(cookieParser());

// 3. Serve Frontend Files
// Since this is a simple prototype, we serve the HTML/JS directly from here
app.use(express.static(path.join(__dirname, '../../frontend/public')));
app.use('/src', express.static(path.join(__dirname, '../../frontend/src')));

// 4. Custom Session Handling
// This middleware checks the cookie on every request to see if you're logged in
app.use(sessionMiddleware);

// 5. CSRF Protection
// This is tricky! We need to protect against Cross-Site Request Forgery.
// The server sets a secret cookie (HttpOnly) and verifies a token sent in headers.
const csrfProtection = csurf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
    }
});

// Apply CSRF check to all write methods (POST, PUT, DELETE)
app.use(csrfProtection);

// Helper to let the frontend know what the CSRF token is.
// We set a separate cookie 'XSRF-TOKEN' that the frontend JS *can* read.
app.use((req, res, next) => {
    res.cookie('XSRF-TOKEN', req.csrfToken(), {
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
    });
    next();
});

// 6. Define API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Catch-all route to serve the main HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../../frontend/public/index.html'));
});

// 7. Global Error Handler
// If anything breaks, this catches it and sends a clean response
app.use(errorHandler);

// Start the server!
app.listen(PORT, () => {
    console.log(`Server is up and running on port ${PORT}`);
});
