const mongoose = require('mongoose');

const accessTokenSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    access_token: { type: String, required: true, unique: true },
    expiry: { type: Date, required: true }
});

module.exports = mongoose.model('AccessToken', accessTokenSchema);
