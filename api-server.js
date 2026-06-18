# Earth Online — API Server
# Cloudflare Tunnel backend for yswy.club
# Usage: node api-server.js

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// ── Helpers ────────────────────────────────────────────────

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}', 'utf-8');
}

function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8')); }
  catch { return {}; }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
}

function hashPassword(pw) {
  return crypto.createHash('sha256').update('earth_online_salt_' + pw + '_v2').digest('hex');
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch { resolve(null); }
    });
  });
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data));
}

function getUrlParams(url) {
  // Extract path params like /api/user/:username
  return url.split('/').filter(Boolean);
}

// ── Routes ─────────────────────────────────────────────────

async function handleRequest(req, res) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    sendJSON(res, 204, {});
    return;
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const parts = getUrlParams(req.url);
  const method = req.method;

  try {
    // GET /health
    if (method === 'GET' && url.pathname === '/health') {
      const users = readUsers();
      sendJSON(res, 200, {
        status: 'ok',
        uptime: process.uptime(),
        users: Object.keys(users).length,
        timestamp: new Date().toISOString()
      });
      return;
    }

    // POST /api/register
    if (method === 'POST' && url.pathname === '/api/register') {
      const body = await parseBody(req);
      if (!body || !body.username || !body.password) {
        sendJSON(res, 400, { error: 'Missing username or password' });
        return;
      }
      const username = body.username.trim();
      if (!/^[a-zA-Z0-9_\-\u4e00-\u9fff]{2,30}$/.test(username)) {
        sendJSON(res, 400, { error: 'Invalid username format' });
        return;
      }
      if (body.password.length < 3) {
        sendJSON(res, 400, { error: 'Password too short' });
        return;
      }

      const users = readUsers();
      if (users[username]) {
        sendJSON(res, 409, { error: 'Username already exists' });
        return;
      }

      const isFirstUser = Object.keys(users).length === 0;
      users[username] = {
        username,
        passwordHash: hashPassword(body.password),
        isAdmin: isFirstUser || body.isAdmin === true,
        createdAt: new Date().toISOString(),
        state: {
          level: 1, xp: 0, xpToNext: 100,
          hp: 100, maxHp: 100, mp: 50, maxMp: 50,
          stamina: 80, maxStamina: 80, gold: 0, attrPoints: 3,
          attrs: { str: 5, dex: 5, con: 5, int: 5, wis: 5, cha: 5 },
          quests: [], skills: [], log: []
        }
      };
      writeUsers(users);

      const { passwordHash, ...safeUser } = users[username];
      sendJSON(res, 201, { ok: true, user: safeUser });
      return;
    }

    // POST /api/login
    if (method === 'POST' && url.pathname === '/api/login') {
      const body = await parseBody(req);
      if (!body || !body.username || !body.password) {
        sendJSON(res, 400, { error: 'Missing username or password' });
        return;
      }

      const users = readUsers();
      const user = users[body.username.trim()];
      if (!user) { sendJSON(res, 401, { error: 'User not found' }); return; }
      if (user.passwordHash !== hashPassword(body.password)) {
        sendJSON(res, 401, { error: 'Wrong password' });
        return;
      }

      const { passwordHash, ...safeUser } = user;
      sendJSON(res, 200, { ok: true, user: safeUser });
      return;
    }

    // GET /api/user/:username
    if (method === 'GET' && parts[0] === 'api' && parts[1] === 'user' && parts[2]) {
      const username = parts[2];
      const users = readUsers();
      const user = users[username];
      if (!user) { sendJSON(res, 404, { error: 'User not found' }); return; }
      const { passwordHash, ...safeUser } = user;
      sendJSON(res, 200, { ok: true, user: safeUser });
      return;
    }

    // PUT /api/user/:username
    if (method === 'PUT' && parts[0] === 'api' && parts[1] === 'user' && parts[2]) {
      const username = parts[2];
      const body = await parseBody(req);
      if (!body || !body.state) {
        sendJSON(res, 400, { error: 'Missing state in body' });
        return;
      }

      const users = readUsers();
      if (!users[username]) { sendJSON(res, 404, { error: 'User not found' }); return; }
      users[username].state = body.state;
      writeUsers(users);
      sendJSON(res, 200, { ok: true });
      return;
    }

    // GET /api/users (admin: list all)
    if (method === 'GET' && url.pathname === '/api/users') {
      const users = readUsers();
      const safeUsers = {};
      for (const [name, u] of Object.entries(users)) {
        const { passwordHash, ...safe } = u;
        safeUsers[name] = safe;
      }
      sendJSON(res, 200, { ok: true, users: safeUsers });
      return;
    }

    // DELETE /api/user/:username
    if (method === 'DELETE' && parts[0] === 'api' && parts[1] === 'user' && parts[2]) {
      const username = parts[2];
      const users = readUsers();
      if (!users[username]) { sendJSON(res, 404, { error: 'User not found' }); return; }
      if (users[username].isAdmin) {
        sendJSON(res, 403, { error: 'Cannot delete admin user' });
        return;
      }
      delete users[username];
      writeUsers(users);
      sendJSON(res, 200, { ok: true });
      return;
    }

    // 404
    sendJSON(res, 404, { error: 'Not found' });

  } catch (err) {
    console.error('Request error:', err);
    sendJSON(res, 500, { error: 'Internal server error' });
  }
}

// ── Start ──────────────────────────────────────────────────

ensureDataDir();

const server = http.createServer(handleRequest);

server.listen(PORT, () => {
  console.log(`🌍 Earth Online API running on http://localhost:${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
  console.log(`   Ready for Cloudflare Tunnel → api.yswy.club`);
});
