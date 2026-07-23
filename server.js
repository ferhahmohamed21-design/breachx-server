const express = require('express');
const { createClient } = require('@libsql/client');
const crypto = require('crypto');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = '553558187438-il1bdg8rru2o1sedpur96ng0lv5takqb.apps.googleusercontent.com';
const oAuth2Client = new OAuth2Client(GOOGLE_CLIENT_ID);
const HMAC_SECRET = process.env.HMAC_SECRET || 'bx-' + (process.env.RENDER_SERVICE_ID || 'local-secret-key-2026');
const SESSION_EXPIRY = 30 * 24 * 60 * 60 * 1000;

const turso = createClient({
    url: process.env.TURSO_DATABASE_URL || 'file:local.db',
    authToken: process.env.TURSO_AUTH_TOKEN || undefined,
});

async function initDB() {
    await turso.execute(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_code TEXT UNIQUE NOT NULL,
        hwid TEXT DEFAULT '',
        is_used INTEGER DEFAULT 0,
        locked INTEGER DEFAULT 0,
        expire_at TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now')),
        used_at TEXT DEFAULT ''
    )`);
}

function generateKeyCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
}

function createSessionToken(email) {
    const payload = JSON.stringify({ email, exp: Date.now() + SESSION_EXPIRY });
    const encoded = Buffer.from(payload).toString('base64url');
    const sig = crypto.createHmac('sha256', HMAC_SECRET).update(encoded).digest('base64url');
    return encoded + '.' + sig;
}

function verifySessionToken(token) {
    try {
        const [encoded, sig] = token.split('.');
        if (!encoded || !sig) return null;
        const expected = crypto.createHmac('sha256', HMAC_SECRET).update(encoded).digest('base64url');
        if (sig !== expected) return null;
        const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString());
        if (Date.now() > payload.exp) return null;
        return payload;
    } catch (e) {
        return null;
    }
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/auth/google', async (req, res) => {
    try {
        const { credential } = req.body;
        if (!credential) return res.json({ success: false, message: 'No credential' });
        const ticket = await oAuth2Client.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        const token = createSessionToken(payload.email);
        return res.json({ success: true, token, email: payload.email, name: payload.name });
    } catch (e) {
        return res.json({ success: false, message: 'Invalid Google token' });
    }
});

app.post('/api/auth/check', (req, res) => {
    const { token } = req.body;
    if (!token) return res.json({ success: false });
    const payload = verifySessionToken(token);
    if (!payload) return res.json({ success: false });
    return res.json({ success: true, email: payload.email });
});

app.post('/api/auth/logout', (req, res) => {
    return res.json({ success: true });
});

function requireSession(req) {
    const token = req.headers['x-session-token'];
    if (!token) return null;
    return verifySessionToken(token);
}

app.post('/api/validate', async (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ valid: false, message: 'Missing key or hwid' });
    if (!/^BreachX-Safe-OB54-[A-Z0-9]{4}-$/.test(key)) return res.json({ valid: false, message: 'Invalid format' });

    const result = await turso.execute({ sql: 'SELECT * FROM keys WHERE key_code = ?', args: [key] });
    const row = result.rows[0];
    if (!row) return res.json({ valid: false, message: 'Key not found' });

    if (row.expire_at && row.expire_at !== '') {
        const expireTime = new Date(row.expire_at).getTime();
        if (Date.now() > expireTime)
            return res.json({ valid: false, message: 'Key expired' });
    }

    if (row.locked === 1) {
        if (row.is_used && row.hwid !== hwid)
            return res.json({ valid: false, message: 'Key used on another device' });
        if (!row.is_used)
            await turso.execute({ sql: "UPDATE keys SET is_used = 1, hwid = ?, used_at = datetime('now') WHERE key_code = ?", args: [hwid, key] });
        return res.json({ valid: true, message: 'Key accepted' });
    } else {
        return res.json({ valid: true, message: 'Key accepted' });
    }
});

app.post('/api/generate', async (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const { count, mode, expireValue, expireUnit } = req.body;
    const n = Math.min(Math.max(parseInt(count) || 1, 1), 500);
    const locked = mode === 'hwid' ? 1 : 0;
    const keys = [];

    let expireAt = '';
    if (expireValue && expireUnit) {
        const ms = parseInt(expireValue) * ({
            seconds: 1000, minutes: 60000, hours: 3600000, days: 86400000
        }[expireUnit] || 0);
        if (ms > 0) expireAt = new Date(Date.now() + ms).toISOString();
    }

    for (let i = 0; i < n; i++) {
        let code;
        let unique = false;
        while (!unique) {
            code = 'BreachX-Safe-OB54-' + generateKeyCode() + '-';
            const exists = await turso.execute({ sql: 'SELECT 1 FROM keys WHERE key_code = ?', args: [code] });
            if (exists.rows.length === 0) unique = true;
        }
        await turso.execute({ sql: 'INSERT INTO keys (key_code, hwid, locked, expire_at) VALUES (?, ?, ?, ?)', args: [code, '', locked, expireAt] });
        keys.push(code);
    }

    return res.json({ success: true, keys, mode: locked ? 'hwid' : 'all' });
});

app.post('/api/generate-custom', async (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const { key, mode, expireValue, expireUnit } = req.body;
    if (!key || !key.trim()) return res.json({ success: false, message: 'No key provided' });

    const code = key.trim().toUpperCase();
    const exists = await turso.execute({ sql: 'SELECT 1 FROM keys WHERE key_code = ?', args: [code] });
    if (exists.rows.length > 0) return res.json({ success: false, message: 'Key already exists' });

    let expireAt = '';
    if (expireValue && expireUnit) {
        const ms = parseInt(expireValue) * ({
            seconds: 1000, minutes: 60000, hours: 3600000, days: 86400000
        }[expireUnit] || 0);
        if (ms > 0) expireAt = new Date(Date.now() + ms).toISOString();
    }

    const locked = mode === 'hwid' ? 1 : 0;
    await turso.execute({ sql: 'INSERT INTO keys (key_code, hwid, locked, expire_at) VALUES (?, ?, ?, ?)', args: [code, '', locked, expireAt] });
    return res.json({ success: true, keys: [code], mode: locked ? 'hwid' : 'all' });
});

app.post('/api/revoke', async (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const { key_code } = req.body;
    await turso.execute({ sql: 'UPDATE keys SET is_used = 0, hwid = "", used_at = "" WHERE key_code = ?', args: [key_code] });
    return res.json({ success: true, message: 'Key revoked' });
});

app.post('/api/delete', async (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const { key_code } = req.body;
    await turso.execute({ sql: 'DELETE FROM keys WHERE key_code = ?', args: [key_code] });
    return res.json({ success: true, message: 'Key deleted' });
});

app.post('/api/delete-all-unused', async (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const before = await turso.execute('SELECT COUNT(*) as c FROM keys WHERE is_used = 0');
    await turso.execute('DELETE FROM keys WHERE is_used = 0');
    return res.json({ success: true, message: `Deleted ${before.rows[0]?.c || 0} unused keys` });
});

app.get('/api/keys', async (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const result = await turso.execute('SELECT * FROM keys ORDER BY id DESC');
    return res.json({ success: true, keys: result.rows });
});

app.get('/api/stats', async (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const total = await turso.execute('SELECT COUNT(*) as c FROM keys');
    const used = await turso.execute('SELECT COUNT(*) as c FROM keys WHERE is_used = 1');
    const locked = await turso.execute('SELECT COUNT(*) as c FROM keys WHERE locked = 1');
    const unlocked = await turso.execute('SELECT COUNT(*) as c FROM keys WHERE locked = 0');
    return res.json({
        success: true,
        total: total.rows[0]?.c || 0,
        used: used.rows[0]?.c || 0,
        unused: (total.rows[0]?.c || 0) - (used.rows[0]?.c || 0),
        locked: locked.rows[0]?.c || 0,
        unlocked: unlocked.rows[0]?.c || 0
    });
});

initDB().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log('========================================');
        console.log('  Breach X Key Server');
        console.log('  Port: ' + PORT);
        console.log('  Database: Turso (persistent)');
        console.log('========================================');
    });
}).catch(err => {
    console.error('Failed to init DB:', err);
    process.exit(1);
});
