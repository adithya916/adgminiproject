const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs for login/register
    message: {
        success: false,
        error: 'Too many attempts, please try again after 15 minutes',
    },
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100, // Limit each IP to 100 requests per windowMs for other APIs
    message: {
        success: false,
        error: 'Too many requests, please try again later',
    },
});

module.exports = { authLimiter, apiLimiter };

