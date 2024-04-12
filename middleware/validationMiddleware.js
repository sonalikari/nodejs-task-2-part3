const { validationResult, body } = require('express-validator');
const bcrypt = require('bcrypt');
const User = require('../models/user');

exports.validateRegistration = [
    body('username').notEmpty().isString(),
    body('password').notEmpty().isString(),
    body('email').notEmpty().isEmail(),
    body('firstname').notEmpty().isString(),
    body('lastname').notEmpty().isString(),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];

exports.validateAddress=[
    body('address').notEmpty().isString(),
    body('city').notEmpty().isString(),
    body('state').notEmpty().isString(),
    body('pincode').notEmpty().isString().matches(/^\d{6}$/).withMessage('Invalid pincode format'),
    body('phone').notEmpty().isString().matches(/^\d{10}$/).withMessage('Invalid phone number format'),
];