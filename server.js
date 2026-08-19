/**
 * CypherX Backend Entrypoint
 */
const app = require('./server/server');
const config = require('./server/config/env');
const logger = require('./server/utils/logger');

if (require.main === module) {
    app.listen(config.port, () => {
        logger.info(`CypherX Security Backend running on http://localhost:${config.port}`);
    });
}

module.exports = app;
