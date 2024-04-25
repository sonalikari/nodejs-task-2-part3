const express = require('express');
const router = express.Router();
const passport = require('../middleware/passport');
const userController = require('../controllers/userController');
const validationMiddleware = require('../middleware/validationMiddleware');
const authMiddleware = require('../middleware/authMiddleware');
const multerMiddleware = require('../middleware/multer');

// Routes
router.post('/register', validationMiddleware.validateRegistration, userController.registerUser);
router.get('/verify-email', userController.verifyEmail);

router.post('/login', passport.authenticate('local', { session: false }), userController.loginUser);

router.get('/get', authMiddleware.validateAccessToken, userController.getUserData);
router.delete('/delete', authMiddleware.validateAccessToken, userController.deleteUserData);

router.get('/list/:page', userController.getUserList);

router.post('/address', validationMiddleware.validateAddress, authMiddleware.validateAccessToken, userController.addUserAddress);
router.get('/get/:id', authMiddleware.validateAccessToken, userController.getUserById);
router.delete('/address/delete', authMiddleware.validateAccessToken, userController.deleteUserAddress);

router.post('/forgot-password', userController.forgotPassword); 
router.put('/verify-reset-password/:passwordResetToken', userController.verifyResetPassword); 

router.put('/profile-image', authMiddleware.validateAccessToken, multerMiddleware.single('image'), userController.uploadProfileImage);

module.exports = router;