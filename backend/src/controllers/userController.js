const getMe = (req, res) => {
    // req.user is set by authMiddleware
    if (!req.user) {
        // Should catch by middleware, but safe check
        return res.status(401).json({ success: false, error: 'Not authenticated' });
    }

    res.json({
        success: true,
        user: req.user,
    });
};

module.exports = {
    getMe,
};

