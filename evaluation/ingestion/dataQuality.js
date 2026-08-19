/**
 * CypherX Dataset Quality Control, Deduplication, Conflict Detection & Splitting
 */

const { validateRecord } = require('./normalize');

/**
 * Process a raw list of records through validation, deduplication, and conflict resolution
 * 
 * @param {Array<Object>} rawRecords 
 * @returns {Object} { cleanRecords, qualityReport, conflicts, invalidRecords }
 */
function processDatasetQuality(rawRecords = []) {
    let importedCount = rawRecords.length;
    let validRecords = [];
    let invalidRecords = [];

    // 1. Validation
    for (const raw of rawRecords) {
        const valResult = validateRecord(raw);
        if (valResult.isValid) {
            validRecords.push(valResult.record);
        } else {
            invalidRecords.push({
                record: raw,
                error: valResult.error
            });
        }
    }

    // 2. Conflict Detection (URL present in both BENIGN and MALICIOUS)
    const labelByUrl = new Map();
    const conflictUrls = new Set();

    for (const rec of validRecords) {
        const existingLabel = labelByUrl.get(rec.url);
        if (existingLabel && existingLabel !== rec.label) {
            conflictUrls.add(rec.url);
        } else {
            labelByUrl.set(rec.url, rec.label);
        }
    }

    const nonConflictingRecords = [];
    const conflictRecords = [];

    for (const rec of validRecords) {
        if (conflictUrls.has(rec.url)) {
            conflictRecords.push(rec);
        } else {
            nonConflictingRecords.push(rec);
        }
    }

    // 3. Deduplication (Merge identical URLs from same or multiple sources)
    const recordMap = new Map();
    let duplicatesRemoved = 0;

    for (const rec of nonConflictingRecords) {
        if (recordMap.has(rec.url)) {
            duplicatesRemoved++;
            const existing = recordMap.get(rec.url);
            
            // Merge source metadata
            const sources = Array.isArray(existing.sources) ? existing.sources : [existing.source];
            if (rec.source && !sources.includes(rec.source)) {
                sources.push(rec.source);
            }
            existing.sources = sources;
            existing.source = sources.join('+');

            // Keep earlier/most complete timestamp
            if (!existing.collectedAt && rec.collectedAt) existing.collectedAt = rec.collectedAt;
            if (!existing.verifiedAt && rec.verifiedAt) existing.verifiedAt = rec.verifiedAt;
        } else {
            recordMap.set(rec.url, {
                ...rec,
                sources: [rec.source]
            });
        }
    }

    const cleanRecords = Array.from(recordMap.values());

    // 4. Quality Statistics
    let benignCount = 0;
    let maliciousCount = 0;
    const sourceDistribution = {};
    const categoryDistribution = {};
    let timestampsPresent = 0;
    let earliestDate = null;
    let latestDate = null;

    for (const rec of cleanRecords) {
        if (rec.label === 'BENIGN') benignCount++;
        else if (rec.label === 'MALICIOUS') maliciousCount++;

        // Source counts
        const src = rec.source || 'unknown';
        sourceDistribution[src] = (sourceDistribution[src] || 0) + 1;

        // Category counts
        const cat = rec.category || 'unknown';
        categoryDistribution[cat] = (categoryDistribution[cat] || 0) + 1;

        // Date tracking
        const dateStr = rec.collectedAt || rec.verifiedAt;
        if (dateStr) {
            const date = new Date(dateStr);
            if (!isNaN(date.getTime())) {
                timestampsPresent++;
                if (!earliestDate || date < earliestDate) earliestDate = date;
                if (!latestDate || date > latestDate) latestDate = date;
            }
        }
    }

    const qualityReport = {
        imported: importedCount,
        valid: validRecords.length,
        invalid: invalidRecords.length,
        duplicatesRemoved,
        conflictsExcluded: conflictUrls.size,
        cleanTotal: cleanRecords.length,
        benignCount,
        maliciousCount,
        sourceDistribution,
        categoryDistribution,
        temporalCoverage: {
            timestampsPresent,
            earliestDate: earliestDate ? earliestDate.toISOString() : null,
            latestDate: latestDate ? latestDate.toISOString() : null,
            temporalSplitSupported: timestampsPresent >= cleanRecords.length * 0.5
        }
    };

    return {
        cleanRecords,
        qualityReport,
        conflicts: conflictRecords,
        invalidRecords
    };
}

/**
 * Split dataset into Development, Validation, and Test partitions
 * 
 * @param {Array<Object>} cleanRecords 
 * @returns {Object} { dev, val, test, isTemporal }
 */
function createDatasetSplits(cleanRecords = []) {
    const withDates = cleanRecords.filter(r => r.collectedAt || r.verifiedAt);
    const isTemporal = withDates.length >= cleanRecords.length * 0.5;

    let sortedRecords;
    if (isTemporal) {
        // Chronological sort: oldest to newest
        sortedRecords = [...cleanRecords].sort((a, b) => {
            const dateA = new Date(a.collectedAt || a.verifiedAt || 0).getTime();
            const dateB = new Date(b.collectedAt || b.verifiedAt || 0).getTime();
            return dateA - dateB;
        });
    } else {
        // Stable deterministic sort by URL
        sortedRecords = [...cleanRecords].sort((a, b) => a.url.localeCompare(b.url));
    }

    const total = sortedRecords.length;
    const devEnd = Math.floor(total * 0.6);
    const valEnd = Math.floor(total * 0.8);

    return {
        isTemporal,
        development: sortedRecords.slice(0, devEnd),
        validation: sortedRecords.slice(devEnd, valEnd),
        test: sortedRecords.slice(valEnd)
    };
}

/**
 * Generate balanced subset from clean records (50% benign, 50% malicious)
 * 
 * @param {Array<Object>} cleanRecords 
 * @returns {Array<Object>}
 */
function createBalancedDataset(cleanRecords = []) {
    const benign = cleanRecords.filter(r => r.label === 'BENIGN');
    const malicious = cleanRecords.filter(r => r.label === 'MALICIOUS');

    const sampleSize = Math.min(benign.length, malicious.length);
    const balancedBenign = benign.slice(0, sampleSize);
    const balancedMalicious = malicious.slice(0, sampleSize);

    return [...balancedBenign, ...balancedMalicious];
}

module.exports = {
    processDatasetQuality,
    createDatasetSplits,
    createBalancedDataset
};
