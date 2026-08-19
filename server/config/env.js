const path = require('path');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config({ path: path.join(__dirname, '../../.env') });

const config = {
    port: parseInt(process.env.PORT || '3000', 10),
    nodeEnv: process.env.NODE_ENV || 'development',
    frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
    
    // Security & Limits
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 mins
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
    scanRateLimitMax: parseInt(process.env.SCAN_RATE_LIMIT_MAX || '30', 10),
    
    // External APIs
    googleSafeBrowsingApiKey: process.env.GOOGLE_SAFE_BROWSING_API_KEY || '',
    safeBrowsingTimeoutMs: 5000 // 5 seconds maximum
};

module.exports = config;
