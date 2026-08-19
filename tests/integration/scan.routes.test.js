const test = require('node:test');
const assert = require('node:assert/strict');
const axios = require('axios');
const config = require('../../server/config/env');
const app = require('../../server/server');

test('Scan API Routes Integration Suite', async (t) => {
    let server;
    let baseUrl;
    let originalApiKey;
    let originalAxiosPost;

    t.before(async () => {
        originalApiKey = config.googleSafeBrowsingApiKey;
        config.googleSafeBrowsingApiKey = 'test_mock_key';

        originalAxiosPost = axios.post;
        axios.post = async () => ({
            data: { matches: [] } // Mock clean response
        });

        await new Promise((resolve) => {
            server = app.listen(0, () => {
                const port = server.address().port;
                baseUrl = `http://localhost:${port}`;
                resolve();
            });
        });
    });

    t.after(async () => {
        config.googleSafeBrowsingApiKey = originalApiKey;
        axios.post = originalAxiosPost;
        await new Promise((resolve) => server.close(resolve));
    });

    await t.test('POST /api/scan-url with safe URL and CLEAN Safe Browsing returns 200 OK SAFE', async () => {
        const response = await fetch(`${baseUrl}/api/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: 'https://github.com', source: 'Integration Test' })
        });

        assert.equal(response.status, 200);
        const data = await response.json();
        assert.equal(data.status, 'SAFE');
        assert.equal(data.riskScore, 0);
        assert.ok(Array.isArray(data.indicators));
        assert.ok(Array.isArray(data.reasons));
        assert.ok(data.recommendation);
    });

    await t.test('POST /api/scan-url with safe URL and UNAVAILABLE Safe Browsing returns UNVERIFIED', async () => {
        config.googleSafeBrowsingApiKey = ''; // Trigger UNAVAILABLE

        const response = await fetch(`${baseUrl}/api/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: 'https://github.com', source: 'Integration Test' })
        });

        assert.equal(response.status, 200);
        const data = await response.json();
        assert.equal(data.status, 'UNVERIFIED');
        assert.notEqual(data.status, 'SAFE');

        config.googleSafeBrowsingApiKey = 'test_mock_key'; // Reset
    });

    await t.test('POST /api/scan-url with IP host returns 200 OK suspicious verdict', async () => {
        const response = await fetch(`${baseUrl}/api/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: 'http://192.168.1.1/login', source: 'Integration Test' })
        });

        assert.equal(response.status, 200);
        const data = await response.json();
        assert.equal(data.status, 'SUSPICIOUS');
        assert.ok(data.riskScore >= 30);
    });

    await t.test('POST /api/scan-url with missing URL returns 400 Bad Request', async () => {
        const response = await fetch(`${baseUrl}/api/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });

        assert.equal(response.status, 400);
        const data = await response.json();
        assert.equal(data.status, 'ERROR');
        assert.equal(data.error.code, 'MISSING_URL');
    });

    await t.test('POST /api/scan-url with unsafe protocol returns 400 Bad Request', async () => {
        const response = await fetch(`${baseUrl}/api/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: 'javascript:alert(1)' })
        });

        assert.equal(response.status, 400);
        const data = await response.json();
        assert.equal(data.status, 'ERROR');
        assert.equal(data.error.code, 'UNSUPPORTED_PROTOCOL');
    });

    await t.test('POST /api/scan-file with JSON filename fallback returns 200 OK file verdict', async () => {
        const response = await fetch(`${baseUrl}/api/scan-file`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: 'document.pdf' })
        });

        assert.equal(response.status, 200);
        const data = await response.json();
        assert.equal(data.scanType, 'FILE');
        assert.ok(data.status);
        assert.equal(data.target.filename, 'document.pdf');
    });

    await t.test('POST /api/scan-file with multipart upload returns 200 OK file verdict', async () => {
        const formData = new FormData();
        const blob = new Blob(['%PDF-1.4 test document content'], { type: 'application/pdf' });
        formData.append('file', blob, 'sample.pdf');

        const response = await fetch(`${baseUrl}/api/scan-file`, {
            method: 'POST',
            body: formData
        });

        assert.equal(response.status, 200);
        const data = await response.json();
        assert.equal(data.scanType, 'FILE');
        assert.equal(data.status, 'SAFE');
        assert.ok(data.sha256);
        assert.equal(data.detectedType, 'DOCUMENT_PDF');
    });

    await t.test('POST /api/scan-file without file returns 400 Bad Request', async () => {
        const response = await fetch(`${baseUrl}/api/scan-file`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });

        assert.equal(response.status, 400);
        const data = await response.json();
        assert.equal(data.status, 'ERROR');
        assert.equal(data.error.code, 'MISSING_FILE');
    });
});
