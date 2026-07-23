const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = 3000;
const GOOGLE_CLIENT_ID = '553558187438-il1bdg8rru2o1sedpur96ng0lv5takqb.apps.googleusercontent.com';
const oAuth2Client = new OAuth2Client(GOOGLE_CLIENT_ID);

const db = new Database(path.join(__dirname, 'keys.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code TEXT UNIQUE NOT NULL,
    hwid TEXT DEFAULT '',
    is_used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    used_at TEXT DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

function generateKeyCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function isAdminEmail(email) {
    if (ADMIN_GOOGLE_EMAILS.length === 0) return true;
    return ADMIN_GOOGLE_EMAILS.includes(email);
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- Google Auth ----
app.post('/api/auth/google', async (req, res) => {
    try {
        const { credential } = req.body;
        if (!credential) return res.json({ success: false, message: 'No credential' });

        const ticket = await oAuth2Client.verifyIdToken({
            idToken: credential,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const email = payload.email;
        const name = payload.name;

        const token = generateSessionToken();
        db.prepare('INSERT INTO sessions (token, email) VALUES (?, ?)').run(token, email);

        return res.json({ success: true, token, email, name });
    } catch (e) {
        return res.json({ success: false, message: 'Invalid Google token: ' + e.message });
    }
});

app.post('/api/auth/check', (req, res) => {
    const { token } = req.body;
    if (!token) return res.json({ success: false });

    const row = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (!row) return res.json({ success: false });

    return res.json({ success: true, email: row.email });
});

app.post('/api/auth/logout', (req, res) => {
    const { token } = req.body;
    if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return res.json({ success: true });
});

// ---- Key Management (requires session) ----
function requireSession(req) {
    const token = req.headers['x-session-token'];
    if (!token) return null;
    const row = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    return row || null;
}

app.post('/api/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ valid: false, message: 'Missing key or hwid' });

    const format = /^BreachX-Safe-OB54-[A-Z0-9]{4}-$/;
    if (!format.test(key)) return res.json({ valid: false, message: 'Invalid key format' });

    const row = db.prepare('SELECT * FROM keys WHERE key_code = ?').get(key);
    if (!row) return res.json({ valid: false, message: 'Key not found' });

    if (row.is_used && row.hwid !== hwid) {
        return res.json({ valid: false, message: 'Key used on another device' });
    }

    if (!row.is_used) {
        db.prepare("UPDATE keys SET is_used = 1, hwid = ?, used_at = datetime('now') WHERE key_code = ?").run(hwid, key);
    }

    return res.json({ valid: true, message: 'Key accepted' });
});

app.post('/api/generate', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const { count } = req.body;
    const n = Math.min(Math.max(parseInt(count) || 1, 1), 500);
    const keys = [];
    const insert = db.prepare('INSERT INTO keys (key_code) VALUES (?)');

    for (let i = 0; i < n; i++) {
        let code;
        do { code = 'BreachX-Safe-OB54-' + generateKeyCode() + '-'; }
        while (db.prepare('SELECT 1 FROM keys WHERE key_code = ?').get(code));
        insert.run(code);
        keys.push(code);
    }

    return res.json({ success: true, keys });
});

app.post('/api/revoke', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const { key_code } = req.body;
    db.prepare('UPDATE keys SET is_used = 0, hwid = "", used_at = "" WHERE key_code = ?').run(key_code);
    return res.json({ success: true, message: 'Key revoked' });
});

app.post('/api/delete', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const { key_code } = req.body;
    db.prepare('DELETE FROM keys WHERE key_code = ?').run(key_code);
    return res.json({ success: true, message: 'Key deleted' });
});

app.post('/api/delete-all-unused', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const result = db.prepare('DELETE FROM keys WHERE is_used = 0').run();
    return res.json({ success: true, message: `Deleted ${result.changes} unused keys` });
});

app.get('/api/keys', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const rows = db.prepare('SELECT * FROM keys ORDER BY id DESC').all();
    return res.json({ success: true, keys: rows });
});

app.get('/api/stats', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.json({ success: false, message: 'Not logged in' });

    const total = db.prepare('SELECT COUNT(*) as c FROM keys').get().c;
    const used = db.prepare('SELECT COUNT(*) as c FROM keys WHERE is_used = 1').get().c;
    return res.json({ success: true, total, used, unused: total - used });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log('========================================');
    console.log('  Breach X Key Server');
    console.log('  Port: ' + PORT);
    console.log('  Admin Panel: http://localhost:' + PORT);
    console.log('  Google OAuth Client ID: ' + GOOGLE_CLIENT_ID);
    console.log('========================================');
});
