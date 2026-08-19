const logger = require('../utils/logger');

function errorHandler(err, req, res, next) {
    logger.error('Unhandled server error', {
        error: err.message || err,
        code: err.code,
        path: req.path
    });

    const status = err.status || (err.code === 'LIMIT_FILE_SIZE' ? 413 : 500);
    const code = err.code || 'INTERNAL_SERVER_ERROR';
    const message = err.message || 'An unexpected internal server error occurred.';

    res.status(status).json({
        error: {
            code,
            message
        }
    });
}

module.exports = errorHandler;
