const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const allowedExtensions = ['.jpg', '.jpeg', '.png'];
        const fileExtension = path.extname(file.originalname).toLowerCase();

        if (allowedExtensions.includes(fileExtension)) {
            cb(null, Date.now() + '-' + file.originalname);
        } else {
            cb(new Error('Filetype not supported'), false);
        }
    }
});
const multerMiddleware = multer({ storage: storage });

module.exports = multerMiddleware;
