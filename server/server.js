const express = require('express');
const config = require('./config/env');
const setupSecurity = require('./middleware/security');
const { generalLimiter } = require('./middleware/rateLimiter');
const requestLogger = require('./middleware/loggerMiddleware');
const errorHandler = require('./middleware/errorHandler');
const logger = require('./utils/logger');
const healthRoutes = require('./routes/health.routes');
const scanRoutes = require('./routes/scan.routes');

const app = express();

// 1. Structured HTTP Request Logging & Tracing
app.use(requestLogger);

// 2. Security Middleware (Helmet + CORS)
setupSecurity(app);

// 3. Request body parsers with explicit limits
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// 4. Apply general rate limiter
app.use(generalLimiter);

// 5. Register API Routes
app.use('/api', healthRoutes);
app.use('/api', scanRoutes);

const path = require('path');

// 6. Serve static frontend files from public directory or root
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.static(path.join(__dirname, '..')));

// 7. Centralized Error Handler
app.use(errorHandler);

// Listener for direct execution
if (require.main === module) {
    app.listen(config.port, () => {
        logger.info(`CypherX Security Backend running on http://localhost:${config.port}`);
    });
}

module.exports = app;
