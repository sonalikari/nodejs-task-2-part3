const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    isEmailVerified: { type: Boolean, default: false },
    addresses: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Address'
    }]
});

module.exports = mongoose.model('User', userSchema);



