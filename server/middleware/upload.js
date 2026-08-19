const multer = require('multer');

// Use memoryStorage for serverless runtime compatibility
const storage = multer.memoryStorage();

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 4.5 * 1024 * 1024 // 4.5 MB maximum file upload size (Vercel Serverless payload limit)
    }
});

module.exports = upload;

