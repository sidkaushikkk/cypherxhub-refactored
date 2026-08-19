const helmet = require('helmet');
const cors = require('cors');
const config = require('../config/env');

/**
 * Configure Security Middleware (Helmet + CORS)
 */
function setupSecurity(app) {
    // Configure Helmet with safe defaults for modern web apps & script tags
    app.use(helmet({
        contentSecurityPolicy: false, // Disabled CSP header so local scripts/CDNs work seamlessly
        crossOriginResourcePolicy: { policy: "cross-origin" }
    }));

    // Configurable CORS
    const corsOptions = {
        origin: (origin, callback) => {
            // Allow requests with no origin (mobile apps, curl, local static files)
            if (!origin) return callback(null, true);
            
            if (config.nodeEnv === 'development' || origin === config.frontendUrl || origin.includes('localhost') || origin.includes('127.0.0.1')) {
                return callback(null, true);
            }
            
            callback(new Error(`CORS origin ${origin} not permitted by CypherX security policy.`));
        },
        credentials: true,
        methods: ['GET', 'POST', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    };

    app.use(cors(corsOptions));
}

module.exports = setupSecurity;
