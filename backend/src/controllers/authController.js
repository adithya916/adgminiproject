const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const Session = require('../models/Session');
const { registerSchema, loginSchema } = require('../utils/validation');

/**
 * Handle User Registration
 */
const register = async (req, res, next) => {
    try {
        // 1. Validate the input data first!
        const { error } = registerSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ success: false, error: error.details[0].message });
        }

        const { email, password } = req.body;

        // 2. Check if this email is already taken
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ success: false, error: 'Email already registered' });
        }

        // 3. Securely hash the password
        // We add "salt" to make it unique even if two users have the same password
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // 4. Save the new user to MongoDB
        const newUser = await User.create({
            email,
            password_hash: passwordHash
        });

        // 5. Respond with success (but don't send back the password!)
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: {
                id: newUser._id,
                email: newUser.email,
                role: newUser.role,
                created_at: newUser.created_at
            },
        });
    } catch (err) {
        // Pass any errors to our global error handler
        next(err);
    }
};

/**
 * Handle User Login
 */
const login = async (req, res, next) => {
    try {
        // 1. Validate inputs
        const { error } = loginSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ success: false, error: error.details[0].message });
        }

        const { email, password } = req.body;

        // 2. Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            // Generic error message for security (don't say "User not found")
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        // 3. Compare the provided password with the stored hash
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        // 4. Create a new Session
        // We generate a random unique ID for this session
        const sessionId = uuidv4();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // Expires in 1 day

        await Session.create({
            session_id: sessionId,
            user_id: user._id,
            expires_at: expiresAt
        });

        // 5. Send the session ID in a secure HTTP-Only cookie
        res.cookie('session_id', sessionId, {
            httpOnly: true, // JavaScript can't read this (Protects against XSS)
            secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
            sameSite: 'Strict', // Prevents sending cookie on cross-site requests (CSRF protection)
            expires: expiresAt,
        });

        res.json({
            success: true,
            message: 'Logged in successfully',
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
            },
        });
    } catch (err) {
        next(err);
    }
};

/**
 * Handle User Logout
 */
const logout = async (req, res, next) => {
    try {
        const sessionId = req.cookies.session_id;

        // 1. Remove the session from the database
        if (sessionId) {
            await Session.findOneAndDelete({ session_id: sessionId });
        }

        // 2. Clear the cookie from the browser
        res.clearCookie('session_id');
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (err) {
        next(err);
    }
};

module.exports = {
    register,
    login,
    logout,
};
