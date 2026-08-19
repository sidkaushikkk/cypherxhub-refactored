const express = require('express');
const router = express.Router();
const upload = require('../middleware/upload');
const { scanLimiter } = require('../middleware/rateLimiter');
const { scanUrl } = require('../services/urlScanner');
const { scanFile } = require('../services/fileScanner');

// Apply scan rate limiter
router.use('/scan-url', scanLimiter);
router.use('/scan-file', scanLimiter);

/**
 * POST /api/scan-url
 */
router.post('/scan-url', async (req, res, next) => {
    try {
        const { url, source = 'URL Scanner' } = req.body || {};
        
        if (!url) {
            return res.status(400).json({
                error: {
                    code: 'MISSING_URL',
                    message: 'URL parameter is required.'
                },
                status: 'ERROR',
                riskScore: 0,
                reasons: ['URL parameter is required.']
            });
        }

        const verdict = await scanUrl(url, source);
        return res.json(verdict);
    } catch (err) {
        if (err.code && err.status) {
            return res.status(err.status).json({
                error: {
                    code: err.code,
                    message: err.message
                },
                status: 'ERROR',
                riskScore: 0,
                reasons: [err.message]
            });
        }
        next(err);
    }
});

/**
 * POST /api/scan-file
 * Supports multipart/form-data (file upload) and JSON payload fallback
 */
router.post('/scan-file', upload.single('file'), async (req, res, next) => {
    try {
        let targetFile = req.file;

        // Fallback for JSON body { filename }
        if (!targetFile && req.body && req.body.filename) {
            targetFile = {
                originalname: req.body.filename,
                size: 0,
                path: null
            };
        }

        if (!targetFile) {
            return res.status(400).json({
                error: {
                    code: 'MISSING_FILE',
                    message: 'Please provide a file to scan.'
                },
                status: 'ERROR',
                riskScore: 0,
                reasons: ['No file was uploaded or specified.']
            });
        }

        const verdict = await scanFile(targetFile);
        return res.json(verdict);
    } catch (err) {
        if (err.code && err.status) {
            return res.status(err.status).json({
                error: {
                    code: err.code,
                    message: err.message
                },
                status: 'ERROR',
                riskScore: 0,
                reasons: [err.message]
            });
        }
        next(err);
    }
});

module.exports = router;
