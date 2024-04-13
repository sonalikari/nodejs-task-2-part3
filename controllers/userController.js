const bcrypt = require('bcrypt');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const AccessToken = require('../models/access_token');
const Address = require('../models/Address');
const PasswordResetToken = require('../models/passwordResetToken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_ID,
        pass: process.env.EMAIL_PASSWORD
    }
});
exports.registerUser = async (req, res) => {
    try {
        const { username, password, confirmPassword, email, firstname, lastname } = req.body;

        if (password !== confirmPassword) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }
        const hashedPassword = await bcrypt.hash(password, 8);

        const verificationToken = jwt.sign({ email }, process.env.VERIFICATION_SECRET, { expiresIn: '1d' });

        const newUser = new User({
            username,
            password: hashedPassword,
            email,
            firstname,
            lastname,
            verificationToken
        });
        await newUser.save(); 
        await sendRegistrationEmail(email, verificationToken);
        res.status(200).json({ message: 'Registration email sent. Please verify your email address.' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(400).json({ error: "Error occurred! Try Again", details: error.message });
    }
};

exports.verifyEmail = async (req, res) => {
    try {
        const { token } = req.query;

        const decodedToken = jwt.verify(token, process.env.VERIFICATION_SECRET);
        const email = decodedToken.email;

        await User.findOneAndUpdate({ email }, { isEmailVerified: true });

        res.status(200).json({ message: 'Email verified successfully. You can now login.' });
    } catch (error) {
        console.error('Error verifying email:', error);
        res.status(400).json({ error: 'Invalid or expired verification token' });
    }
};

exports.loginUser = async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        if (!user.isEmailVerified) {
            return res.status(400).json({ error: 'Email not verified. Please verify your email address.' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.KEY, { expiresIn: '1h' });

        await AccessToken.create({
            user_id: user._id,
            access_token: token,
            expiry: Date.now() + 3600000 
        });
       
        res.status(200).json({ access_token: token });
    } catch (error) {
        res.status(500).json({ error: 'Error while logging in the user' });
    }
};

exports.getUserData = async (req, res) => {
    try {
        const accessToken = req.headers['access_token'];
        const token = await AccessToken.findOne({ access_token: accessToken });

        if (!token || token.expiry < Date.now()) {
            return res.status(400).json({ error: 'Invalid access token or token expired' });
        }
        const user = await User.findById(token.user_id);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Error while fetching user data' });
    }
};

exports.deleteUserData = async (req, res) => {
    try {
        const accessToken = req.headers['access_token'];
        const token = await AccessToken.findOne({ access_token: accessToken });

        if (!token || token.expiry < Date.now()) {
            return res.status(400).json({ error: 'Invalid access token or token expired' });
        }
        const user = await User.findById(token.user_id);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        await User.findByIdAndDelete(token.user_id);
        res.json({ message: 'User deleted' });
    } catch (error) {
        res.status(500).json({ error: 'An error occurred while deleting user data' });
    }
};

exports.getUserList = async (req, res) => {
    try {
        const page = parseInt(req.params.page);
        if (isNaN(page) || page <= 0) {
            return res.status(400).json({ error: 'Invalid page number' });
        }
        const limit = 10;
        const skip = (page - 1) * limit;
        const userList = await User.find().skip(skip).limit(limit);

        res.json(userList);
    } catch (error) {
        res.status(500).json({ error: 'Error while fetching user list' });
    }
};

exports.addUserAddress = async (req, res) => {
    try {
        const { address, city, state, pincode, phone } = req.body;
        const userId = req.user._id; 

        const newAddress = new Address({
            userId: userId,
            address,
            city,
            state,
            pincode,
            phone
        });

        await newAddress.save();

        const user = await User.findById(userId);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        user.addresses.push(newAddress._id);
        await user.save();

        res.status(200).json({ message: 'Address added successfully' });
    } catch (error) {
        console.error('Error adding user address:', error);
        res.status(500).json({ error: 'Error while adding user address' });
    }
};

exports.getUserById = async (req, res) => {
    try {
        const userId = req.params.id;

        const user = await User.findById(userId).populate('addresses');

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ error: 'Error while fetching user data' });
    }
};

exports.deleteUserAddress = async (req, res) => {
    try {
        const userId = req.user._id;
        const addressIds = req.body.addressIds; 

        if (!Array.isArray(addressIds) || addressIds.length === 0) {
            return res.status(400).json({ error: 'Invalid address ids' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        user.addresses = user.addresses.filter(addressId => !addressIds.includes(addressId));

        await user.save();

        await Address.deleteMany({ _id: { $in: addressIds } });

        res.status(200).json({ message: 'Addresses deleted successfully' });
    } catch (error) {
        console.error('Error deleting user addresses:', error);
        res.status(500).json({ error: 'Error while deleting user addresses' });
    }
};

exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.PASSWORD_RESET_KEY, { expiresIn: '15m' });
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000); 

        await PasswordResetToken.create({ userId: user._id, token, expiresAt });
        await sendPasswordResetEmail(email, token);
        res.status(200).json({ message: 'Password reset token sent successfully', token });
    } catch (error) {
        console.error('Error generating password reset token:', error);
        res.status(500).json({ error: 'Error generating password reset token' });
    }
};

exports.verifyResetPassword = async (req, res) => {
    try {
        const { password, confirmPassword } = req.body;
        const resetToken = req.params.passwordResetToken;

        if (!resetToken) {
            return res.status(400).json({ error: 'Reset token is required' });
        }

        const tokenRecord = await PasswordResetToken.findOne({ token: resetToken });
        if (!tokenRecord) {
            return res.status(400).json({ error: 'Invalid reset token' });
        }

        const decodedToken = jwt.verify(resetToken, process.env.PASSWORD_RESET_KEY);
        const userId = decodedToken.userId;

        const currentTime = new Date();
        if (currentTime > tokenRecord.expiresAt) {
            return res.status(400).json({ error: 'Password reset token has expired' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        const email = user.email;
        if (password !== confirmPassword) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }

        const hashedPassword = await bcrypt.hash(password, 8);
        user.password = hashedPassword;
        await user.save();

        await PasswordResetToken.deleteOne({ token: resetToken });
        await sendPasswordResetSuccessEmail(email);
        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Error resetting password' });
    }
};


const sendRegistrationEmail = async (email, verificationToken) => {
    const verificationLink = `http://localhost:8000/user/verify-email?token=${verificationToken}`;

    const mailOptions = {
        from: process.env.EMAIL_ID,
        to: email,
        subject: 'Welcome to Our Application!',
        html: `
        <p>Thank you for registering with us!</p>
        <p>Please verify your email address by clicking <a href="${verificationLink}">here</a>.</p>`
    };
    await transporter.sendMail(mailOptions);
};


const sendPasswordResetEmail = async (email, resetToken) => {
    const resetLink = `http://localhost:8000/user/verify_reset_password/${resetToken}`;

    const mailOptions = {
        from: process.env.EMAIL_ID,
        to: email,
        subject: 'Password Reset Request',
        html: `<p>You have requested to reset your password. Please click <a href="${resetLink}">here</a> to reset your password.</p>`
    };
    await transporter.sendMail(mailOptions);
};

const sendPasswordResetSuccessEmail = async (email) => {
    const mailOptions = {
        from: process.env.EMAIL_ID,
        to: email,
        subject: 'Password Reset Successful',
        text: 'Your password has been successfully reset.'
    };
    await transporter.sendMail(mailOptions);
};

exports.uploadProfileImage = async (req, res) => {
    try {
        const { flag } = req.body;
        const file = req.file;

        if (!flag) {
            return res.status(400).json({ error: 'Flag is required' });
        }

        if (flag === 'online') {
            const result = await cloudinary.uploader.upload(file.path);
            return res.status(200).json({ imageUrl: result.secure_url });
        } else if (flag === 'local') {
            return res.status(200).json({ imagePath: file.path });
        } else {
            return res.status(400).json({ error: 'Invalid flag' });
        }
    } catch (error) {
        console.error('Error uploading profile image:', error);
        res.status(500).json({ error: 'Error uploading profile image' });
    }
};