const AccessToken = require('../models/access_token');

exports.validateAccessToken = async (req, res, next) => {
    try {
        const accessToken = req.headers['access_token'];
        if (!accessToken) {
            return res.status(400).json({ error: 'Access token is required' });
        }
        const token = await AccessToken.findOne({ access_token: accessToken }).populate('user_id');

        if (!token || token.expiry < Date.now()) {
            return res.status(400).json({ error: 'Invalid access token or token expired' });
        }
        req.user = token.user_id;
        next();
    } catch (error) {
        console.error('Error validating access token:', error);
        res.status(500).json({ error: 'Error validating access token' });
    }
};
