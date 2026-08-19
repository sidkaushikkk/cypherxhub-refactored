const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../../server/server');

test('Health Routes Integration Suite', async (t) => {
    let server;
    let baseUrl;

    t.before(async () => {
        await new Promise((resolve) => {
            server = app.listen(0, () => {
                const port = server.address().port;
                baseUrl = `http://localhost:${port}`;
                resolve();
            });
        });
    });

    t.after(async () => {
        await new Promise((resolve) => server.close(resolve));
    });

    await t.test('GET /api/health returns 200 OK with health status metadata', async () => {
        const response = await fetch(`${baseUrl}/api/health`);
        assert.equal(response.status, 200);

        const data = await response.json();
        assert.equal(data.status, 'ok');
        assert.ok(data.service);
        assert.ok(data.timestamp);
    });
});
