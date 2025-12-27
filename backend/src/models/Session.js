const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
    session_id: {
        type: String,
        required: true,
        unique: true
    },
    user_id: {
        type: String, // References User._id (UUID string)
        ref: 'User',
        required: true
    },
    expires_at: {
        type: Date,
        required: true
    }
}, {
    timestamps: { createdAt: 'created_at', updatedAt: false }
});

// Index for automatic expiration (TTL)
// Note: We are handling expiration manually in middleware logic to match previous SQL logic, 
// but MongoDB has built-in TTL. Let's rely on manual check for consistency with the controller logic 
// or use TTL. For this port, we'll keep the manual check but index for performance.
sessionSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 }); 

module.exports = mongoose.model('Session', sessionSchema);

