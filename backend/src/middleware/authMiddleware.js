const Session = require('../models/Session');
const User = require('../models/User');

/**
 * Middleware: Session Checker
 * This runs on every request to see if the user is logged in.
 */
const sessionMiddleware = async (req, res, next) => {
    // 1. Try to get the session ID from the cookie
    const sessionId = req.cookies.session_id;

    if (!sessionId) {
        req.user = null; // No session? No user.
        return next();
    }

    try {
        // 2. Look up the session in the database
        // Also check if it has expired!
        const session = await Session.findOne({ 
            session_id: sessionId, 
            expires_at: { $gt: new Date() } // "Greater than now" means not expired
        });

        if (session) {
            // 3. If session is valid, find the user who owns it
            // We exclude the password hash so we don't accidentally leak it
            const user = await User.findById(session.user_id).select('-password_hash');
            
            if (user) {
                // Attach the user to the request object so other routes can use it
                req.user = {
                    id: user._id,
                    email: user.email,
                    role: user.role
                };
            } else {
                 // User might have been deleted?
                 req.user = null;
                 res.clearCookie('session_id');
            }
        } else {
            // Session not found or expired
            req.user = null;
            // Clean up the invalid cookie
            res.clearCookie('session_id');
        }
    } catch (err) {
        console.error('Session middleware error:', err);
        req.user = null;
    }

    // Move on to the next middleware/route
    next();
};

/**
 * Middleware: Require Authentication
 * Blocks access to routes if the user isn't logged in.
 */
const requireAuth = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ success: false, error: 'Unauthorized: You need to log in first.' });
    }
    next();
};

module.exports = { sessionMiddleware, requireAuth };
