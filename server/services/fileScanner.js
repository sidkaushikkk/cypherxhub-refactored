const fs = require('fs');
const path = require('path');
const { calculateFileHash } = require('../utils/hashing');
const { INDICATOR_DEFINITIONS } = require('../engine/indicators');
const { evaluateRisk } = require('../engine/riskEngine');
const logger = require('../utils/logger');

/**
 * Inspect magic header bytes of a file buffer to determine actual binary payload type
 * 
 * @param {Buffer} buffer File header bytes
 * @returns {string} Detected binary classification
 */
function detectMagicByteType(buffer) {
    if (!buffer || buffer.length < 4) return 'UNKNOWN';

    // Windows PE Executable (MZ)
    if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
        return 'EXECUTABLE_PE';
    }

    // Linux ELF Executable (\x7fELF)
    if (buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
        return 'EXECUTABLE_ELF';
    }

    // PDF Document (%PDF)
    if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
        return 'DOCUMENT_PDF';
    }

    // ZIP Archive / DOCX / XLSX (PK\x03\x04)
    if (buffer[0] === 0x50 && buffer[1] === 0x4B && buffer[2] === 0x03 && buffer[3] === 0x04) {
        return 'ARCHIVE_ZIP';
    }

    // PNG Image (\x89PNG)
    if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
        return 'IMAGE_PNG';
    }

    // JPEG Image (\xFF\xD8\xFF)
    if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
        return 'IMAGE_JPEG';
    }

    return 'UNKNOWN';
}

/**
 * Perform real file payload inspection
 * 
 * @param {Object} fileObject Multer file object or fallback metadata
 * @returns {Promise<Object>} Unified risk verdict with SHA-256 hash
 */
async function scanFile(fileObject) {
    const startTime = Date.now();

    if (!fileObject) {
        throw { code: 'MISSING_FILE', message: 'No file was uploaded for inspection.', status: 400 };
    }

    const filePath = fileObject.path;
    const originalName = fileObject.originalname || fileObject.filename || 'unknown';
    const fileSize = fileObject.size || 0;

    let indicators = [];
    let sha256 = '';
    let detectedType = 'UNKNOWN';

    try {
        // 1. Calculate SHA-256 Hash & Read Magic Bytes
        if (filePath && fs.existsSync(filePath)) {
            sha256 = await calculateFileHash(filePath);

            const fd = fs.openSync(filePath, 'r');
            const buffer = Buffer.alloc(16);
            fs.readSync(fd, buffer, 0, 16, 0);
            fs.closeSync(fd);

            detectedType = detectMagicByteType(buffer);
        } else if (fileObject.buffer) {
            const crypto = require('crypto');
            sha256 = crypto.createHash('sha256').update(fileObject.buffer).digest('hex');
            detectedType = detectMagicByteType(fileObject.buffer);
        }

        const lowerName = originalName.toLowerCase();
        const ext = path.extname(lowerName);

        // 2. Extension vs Magic Byte Mismatch Check (Extension Spoofing)
        const isDeclaredDocumentOrMedia = ['.pdf', '.jpg', '.jpeg', '.png', '.txt', '.csv', '.docx'].includes(ext);
        if (isDeclaredDocumentOrMedia && ['EXECUTABLE_PE', 'EXECUTABLE_ELF'].includes(detectedType)) {
            indicators.push({
                ...INDICATOR_DEFINITIONS.MAGIC_BYTE_MISMATCH,
                message: `Extension mismatch: File claims to be ${ext} but contains executable binary header signature (${detectedType}).`
            });
        }

        // 3. Double Extension Trick (e.g. document.pdf.exe)
        const nameParts = lowerName.split('.');
        if (nameParts.length > 2) {
            const lastExt = '.' + nameParts[nameParts.length - 1];
            const secondLastExt = '.' + nameParts[nameParts.length - 2];
            const executableExtensions = ['.exe', '.bat', '.vbs', '.sh', '.apk', '.cmd', '.ps1', '.scr'];
            
            if (executableExtensions.includes(lastExt) && ['.pdf', '.doc', '.png', '.jpg', '.txt'].includes(secondLastExt)) {
                indicators.push({
                    ...INDICATOR_DEFINITIONS.DOUBLE_EXTENSION_EVASION,
                    message: `File uses double extension pattern (${secondLastExt}${lastExt}) commonly used to disguise executable payloads.`
                });
            }
        }

        // 4. Direct Executable & Script Payloads
        const directExecutables = ['.exe', '.bat', '.vbs', '.sh', '.apk', '.cmd', '.ps1', '.scr', '.msi'];
        if (directExecutables.includes(ext) || ['EXECUTABLE_PE', 'EXECUTABLE_ELF'].includes(detectedType)) {
            indicators.push({
                ...INDICATOR_DEFINITIONS.SUSPICIOUS_EXECUTABLE_BINARY,
                message: `File is a direct binary executable or script payload (${ext || detectedType}).`
            });
        }

        // 5. Macro-enabled Documents
        if (['.docm', '.xlsm', '.pptm'].includes(ext)) {
            indicators.push(INDICATOR_DEFINITIONS.MACRO_ENABLED_DOCUMENT);
        }

        // 6. Archives
        if (['.zip', '.rar', '.7z', '.tar', '.gz'].includes(ext) || detectedType === 'ARCHIVE_ZIP') {
            indicators.push(INDICATOR_DEFINITIONS.ARCHIVE_PAYLOAD);
        }

        // 7. Known Malware Filename Heuristics
        if (lowerName.includes('crack') || lowerName.includes('keygen') || lowerName.includes('autokms') || lowerName.includes('trojan')) {
            indicators.push({
                ...INDICATOR_DEFINITIONS.KNOWN_MALWARE_SIGNATURE,
                message: `Filename matches known malware or piracy tool keywords (${originalName}).`
            });
        }

        const threatIntelSummary = {
            magicByteAnalysis: {
                detectedType,
                declaredExtension: ext,
                isMatch: !indicators.some(i => i.type === 'MAGIC_BYTE_MISMATCH')
            },
            reputationDatabase: {
                status: 'UNVERIFIED',
                reason: 'Local binary heuristics performed. External malware hash lookup not connected.'
            }
        };

        const targetContext = {
            type: 'FILE',
            filename: originalName,
            sha256,
            fileSize,
            detectedType,
            scanType: 'FILE'
        };

        const verdict = evaluateRisk(indicators, threatIntelSummary, targetContext);

        const duration = Date.now() - startTime;
        logger.scan(Date.now().toString(36), 'FILE', originalName, verdict.status, verdict.riskScore, duration);

        return verdict;

    } finally {
        // Cleanup temp file immediately
        if (filePath && fs.existsSync(filePath)) {
            fs.unlink(filePath, (err) => {
                if (err) logger.warn(`Failed to clean up temp file ${filePath}: ${err.message}`);
            });
        }
    }
}

module.exports = {
    scanFile,
    detectMagicByteType
};
