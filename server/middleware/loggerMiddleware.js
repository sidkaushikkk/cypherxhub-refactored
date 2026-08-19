const logger = require('../utils/logger');

/**
 * Express middleware to attach request correlation ID and log HTTP request details
 */
function requestLogger(req, res, next) {
    const startTime = Date.now();

    // Use incoming header or generate unique request ID
    const requestId = req.headers['x-request-id'] || 
        `${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 7)}`;
    
    req.id = requestId;
    res.setHeader('X-Request-ID', requestId);

    // Intercept finish event to log timing and status
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        // Avoid noisy logging for standard static files if needed, focus on API routes
        if (req.originalUrl.startsWith('/api')) {
            logger.http(requestId, req.method, req.originalUrl, res.statusCode, duration);
        }
    });

    next();
}

module.exports = requestLogger;
