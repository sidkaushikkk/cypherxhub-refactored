const { SEVERITY } = require('./indicators');

/**
 * Evaluate structured indicators using evidence weighting and return a unified threat verdict
 * 
 * @param {Array} indicatorList List of indicator objects
 * @param {Object} threatIntel Intelligence status (e.g. googleSafeBrowsing)
 * @param {Object} targetContext Target metadata (e.g. { type: 'URL', value: '...' } or { type: 'FILE', filename: '...' })
 * @returns {Object} Unified risk verdict response
 */
function evaluateRisk(indicatorList = [], threatIntel = {}, targetContext = {}) {
    let rawScore = 0;
    let reasons = [];
    let structuredIndicators = [];

    let hasCritical = false;
    let hasHigh = false;
    let mediumCount = 0;
    let lowCount = 0;

    for (const ind of indicatorList) {
        if (!ind) continue;

        const severity = ind.severity || SEVERITY.INFO;
        const score = ind.score || 0;

        structuredIndicators.push({
            type: ind.type,
            severity: severity,
            score: score,
            message: ind.message
        });

        if (ind.message) {
            reasons.push(ind.message);
        }

        if (severity === SEVERITY.CRITICAL) {
            hasCritical = true;
            rawScore += score;
        } else if (severity === SEVERITY.HIGH) {
            hasHigh = true;
            rawScore += score;
        } else if (severity === SEVERITY.MEDIUM) {
            mediumCount++;
            rawScore += score;
        } else if (severity === SEVERITY.LOW) {
            lowCount++;
            // Apply non-linear dampening for weak LOW signals so multiple weak signals don't falsely trigger DANGEROUS
            rawScore += Math.min(score, 10);
        }
    }

    // Cap total score strictly between 0 and 100
    const riskScore = Math.min(Math.max(Math.round(rawScore), 0), 100);

    // Status classification: SAFE, SUSPICIOUS, DANGEROUS
    let status = 'SAFE';
    if (hasCritical || riskScore >= 70) {
        status = 'DANGEROUS';
        if (reasons.length === 0) reasons.push('Critical security risk indicators discovered.');
    } else if (hasHigh || riskScore > 25 || mediumCount >= 2) {
        status = 'SUSPICIOUS';
        if (reasons.length === 0) reasons.push('Suspicious threat patterns or domain heuristics observed.');
    } else {
        if (reasons.length === 0) reasons.push('No obvious threats detected. Target appears clean based on active checks.');
    }

    // Confidence classification: LOW, MEDIUM, HIGH
    let confidence = 'LOW';
    if (hasCritical || threatIntel.googleSafeBrowsing?.status === 'MALICIOUS' || (hasHigh && mediumCount >= 1) || structuredIndicators.length >= 3) {
        confidence = 'HIGH';
    } else if (hasHigh || mediumCount >= 1 || riskScore > 20) {
        confidence = 'MEDIUM';
    }

    // Recommended action guidance
    let recommendation = '';
    if (status === 'DANGEROUS') {
        recommendation = 'DO NOT ACCESS OR EXECUTE: Target matches known malware signatures, phishing blacklists, or deceptive payload structures.';
    } else if (status === 'SUSPICIOUS') {
        recommendation = 'PROCEED WITH CAUTION: Target exhibits suspicious evasion or domain patterns. Verify destination identity before entering credentials.';
    } else {
        recommendation = 'CLEAN VERDICT: Target passed threat heuristics and threat intelligence evaluation. No suspicious indicators detected.';
    }

    // Construct unified response schema
    const scanType = targetContext.scanType || (targetContext.type === 'FILE' ? 'FILE' : 'URL');

    return {
        scanType,
        status,
        riskScore,
        confidence,
        target: {
            type: targetContext.type || (scanType === 'FILE' ? 'FILE' : 'URL'),
            value: targetContext.value || targetContext.filename || targetContext.rawUrl || 'unknown',
            filename: targetContext.filename || undefined,
            sha256: targetContext.sha256 || undefined
        },
        indicators: structuredIndicators,
        reasons,
        recommendation,
        threatIntelligence: threatIntel,
        timestamp: new Date().toISOString(),
        // Legacy top-level properties for frontend compatibility
        sha256: targetContext.sha256 || undefined,
        filename: targetContext.filename || undefined,
        fileSize: targetContext.fileSize || undefined,
        detectedType: targetContext.detectedType || undefined
    };
}

module.exports = {
    evaluateRisk
};
