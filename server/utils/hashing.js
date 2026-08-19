const crypto = require('crypto');
const fs = require('fs');

/**
 * Calculate SHA-256 hash of a buffer or string
 */
function calculateHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Calculate SHA-256 hash of a file on disk
 */
function calculateFileHash(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);

        stream.on('data', chunk => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', err => reject(err));
    });
}

module.exports = {
    calculateHash,
    calculateFileHash
};
