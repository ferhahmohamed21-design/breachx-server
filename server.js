const express = require('express');
const initSqlJs = require('sql.js');
const crypto = require('crypto');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = '553558187438-il1bdg8rru2o1sedpur96ng0lv5takqb.apps.googleusercontent.com';
const oAuth2Client = new OAuth2Client(GOOGLE_CLIENT_ID);
const DB_PATH = path.join(__dirname, 'keys.db');

let db;

function saveDB() {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
}

setInterval(saveDB, 30000);

process.on('SIGINT', () => { saveDB(); process.exit(); });
process.on('SIGTERM', () => { saveDB(); process.exit(); });

async function initDB() {
    const SQL = await initSqlJs();
    if (fs.existsSync(DB_PATH)) {
        const fileBuffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(fileBuffer);
    } else {
        db = new SQL.Database();
    }
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_code TEXT UNIQUE NOT NULL,
        hwid TEXT DEFAULT '',
        is_used INTEGER DEFAULT 0,
        locked INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        used_at TEXT DEFAULT ''
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )`);
    saveDB();
}

function generateKeyCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function dbGet(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    if (stmt.step()) {
        const cols = stmt.getColumnNames();
        const vals = stmt.get();
        stmt.free();
        const row = {};
        cols.forEach((c, i) => row[c] = vals[i]);
        return row;
    }
    stmt.free();
    return null;
}

function dbAll(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) {
        const cols = stmt.getColumnNames();
        const vals = stmt.get();
        const row = {};
        cols.forEach((c, i) => row[c] = vals[i]);
        rows.push(row);
    }
    stmt.free();
    return rows;
}

function dbRun(sql, params = []) {
    db.run(sql, params);
    saveDB();
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/auth/google', async (req, res) => {
    try {
        const { credential } = req.body;
        if (!credential) return res.json({ success: false, message: 'No credential' });
        const ticket = await oAuth2Client.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        const token = generateSessionToken();
        dbRun('INSERT INTO sessions (token, email) VALUES (?, ?)', [token, payload.email]);
        return res.json({ success: true, token, email: payload.email, name: payload.name });
    } catch (e) {
        return res.json({ success: false, message: 'Invalid Google token' });
    }
});

app.post('/api/auth/check', (req, res) => {
    const { token } = req.body;
    if (!token) return res.json({ success: false });
    const row = dbGet('SELECT * FROM sessions WHERE token = ?', [token]);
    if (!row) return res.json({ success: false });
    return res.json({ success: true, email: row.email });
});

app.post('/api/auth/logout', (req, res) => {
    const { token } = req.body;
    if (token) dbRun('DELETE FROM sessions WHERE token = ?', [token]);
    return res.json({ success: true });
});

function requireSession(req) {
    const token = req.headers['x-session-token'];
    if (!token) return null;
    return dbGet('SELECT * FROM sessions WHERE token = ?', [token]) || null;
}

app.post('/api/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ valid: false, message: 'Missing key or hwid' });
    if (!/^BreachX-Safe-OB54-[A-Z0-9]{4}-$/.test(key)) return res.json({ valid: false, message: 'Invalid format' });

    const row = dbGet('SELECT * FROM keys WHERE key_code = ?', [key]);
    if (!row) return res.json({ valid: false, message: 'Key not found' });

    if (row.locked === 1) {
        if (row.is_used && row.hwid !== hwid)
            return res.json({ valid: false, message: 'Key used on another device' });
        if (!row.is_used)
            dbRun("UPDATE keys SET is_used = 1, hwid = ?, used_at = datetime('now') WHERE key_code = ?", [hwid, key]);
        return res.json({ valid: true, message: 'Key accepted' });
    } else {
        return res.json({ valid: true, message: 'Key accepted' });
    }
});

app.post('/api/generate', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const { count, mode } = req.body;
    const n = Math.min(Math.max(parseInt(count) || 1, 1), 500);
    const locked = mode === 'hwid' ? 1 : 0;
    const keys = [];

    for (let i = 0; i < n; i++) {
        let code;
        do { code = 'BreachX-Safe-OB54-' + generateKeyCode() + '-'; }
        while (dbGet('SELECT 1 FROM keys WHERE key_code = ?', [code]));
        dbRun('INSERT INTO keys (key_code, hwid, locked) VALUES (?, ?, ?)', [code, '', locked]);
        keys.push(code);
    }

    return res.json({ success: true, keys, mode: locked ? 'hwid' : 'all' });
});

app.post('/api/generate-custom', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const { key, mode } = req.body;
    if (!key || !key.trim()) return res.json({ success: false, message: 'No key provided' });

    const code = key.trim().toUpperCase();
    if (dbGet('SELECT 1 FROM keys WHERE key_code = ?', [code]))
        return res.json({ success: false, message: 'Key already exists' });

    const locked = mode === 'hwid' ? 1 : 0;
    dbRun('INSERT INTO keys (key_code, hwid, locked) VALUES (?, ?, ?)', [code, '', locked]);
    return res.json({ success: true, keys: [code], mode: locked ? 'hwid' : 'all' });
});

app.post('/api/revoke', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const { key_code } = req.body;
    dbRun('UPDATE keys SET is_used = 0, hwid = "", used_at = "" WHERE key_code = ?', [key_code]);
    return res.json({ success: true, message: 'Key revoked' });
});

app.post('/api/delete', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const { key_code } = req.body;
    dbRun('DELETE FROM keys WHERE key_code = ?', [key_code]);
    return res.json({ success: true, message: 'Key deleted' });
});

app.post('/api/delete-all-unused', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const before = dbGet('SELECT COUNT(*) as c FROM keys WHERE is_used = 0');
    dbRun('DELETE FROM keys WHERE is_used = 0');
    return res.json({ success: true, message: `Deleted ${before ? before.c : 0} unused keys` });
});

app.get('/api/keys', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const rows = dbAll('SELECT * FROM keys ORDER BY id DESC');
    return res.json({ success: true, keys: rows });
});

app.get('/api/stats', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });
    const total = dbGet('SELECT COUNT(*) as c FROM keys');
    const used = dbGet('SELECT COUNT(*) as c FROM keys WHERE is_used = 1');
    const locked = dbGet('SELECT COUNT(*) as c FROM keys WHERE locked = 1');
    const unlocked = dbGet('SELECT COUNT(*) as c FROM keys WHERE locked = 0');
    return res.json({
        success: true,
        total: total ? total.c : 0,
        used: used ? used.c : 0,
        unused: total ? total.c - (used ? used.c : 0) : 0,
        locked: locked ? locked.c : 0,
        unlocked: unlocked ? unlocked.c : 0
    });
});

initDB().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log('========================================');
        console.log('  Breach X Key Server');
        console.log('  Port: ' + PORT);
        console.log('  Database: sql.js (no native deps)');
        console.log('========================================');
    });
}).catch(err => {
    console.error('Failed to init DB:', err);
    process.exit(1);
});
