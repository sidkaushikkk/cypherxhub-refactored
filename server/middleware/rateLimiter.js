const rateLimit = require('express-rate-limit');
const config = require('../config/env');

const generalLimiter = rateLimit({
    windowMs: config.rateLimitWindowMs,
    max: config.rateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            error: {
                code: 'TOO_MANY_REQUESTS',
                message: 'General API rate limit exceeded. Please try again later.'
            }
        });
    }
});

const scanLimiter = rateLimit({
    windowMs: config.rateLimitWindowMs,
    max: config.scanRateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            error: {
                code: 'SCAN_RATE_LIMIT_EXCEEDED',
                message: 'Security scanner rate limit exceeded. Max 30 scans allowed per 15-minute window.'
            }
        });
    }
});

module.exports = {
    generalLimiter,
    scanLimiter
};
