/**
 * ssh-updater v2 - MongoDB storage + JWT auth + SSE streaming
 */
const express = require('express');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { Client } = require('ssh2');
const { EventEmitter } = require('events');

const PORT = 8080;
const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017/sshupdater';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

// ─────────────────────────────────────────────────────────────────────────────
// Schemas & Models
// ─────────────────────────────────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, index: true },
  passwordHash: String,
  createdAt: { type: Date, default: Date.now }
});

const HostSchema = new mongoose.Schema({
  name: String,
  ip: String,
  user: String,
  password: String, // plaintext for demo; prefer key auth or encryption in production
  port: { type: Number, default: 22 },
  isRoot: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Host = mongoose.model('Host', HostSchema);

// ─────────────────────────────────────────────────────────────────────────────
// App Setup
// ─────────────────────────────────────────────────────────────────────────────
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// UI (protected root)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  const token = req.cookies?.token;
  if (!token) return res.redirect('/login.html');
  try {
    jwt.verify(token, JWT_SECRET);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } catch {
    res.clearCookie('token');
    res.redirect('/login.html');
  }
});
app.use('/public', express.static(path.join(__dirname, 'public')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// ─────────────────────────────────────────────────────────────────────────────
/* Auth */
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' });
  const count = await User.countDocuments();
  if (count > 0) {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Auth required to add users' });
    try { jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: 'Invalid token' }); }
  }
  const exists = await User.findOne({ username });
  if (exists) return res.status(409).json({ error: 'username already exists' });
  const passwordHash = await bcrypt.hash(password, 12);
  const user = await User.create({ username, passwordHash });
  res.json({ ok: true, id: user._id });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' });
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ uid: user._id, u: user.username }, JWT_SECRET, { expiresIn: '12h' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 12 * 60 * 60 * 1000 });
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/hasUsers', async (req, res) => {
  const count = await User.countDocuments();
  res.json({ hasUsers: count > 0 });
});

// ─────────────────────────────────────────────────────────────────────────────
/* Hosts CRUD */
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/hosts', requireAuth, async (req, res) => {
  const hosts = await Host.find({}).sort({ createdAt: -1 }).lean();
  res.json(hosts);
});

app.post('/api/hosts', requireAuth, async (req, res) => {
  const { name, ip, user, password, port, isRoot } = req.body || {};
  if (!ip || !user || !password) return res.status(400).json({ error: 'ip, user, password are required' });
  const host = await Host.create({
    name: name || ip, ip, user, password, port: Number(port) || 22, isRoot: !!isRoot
  });
  res.json(host);
});

app.put('/api/hosts/:id', requireAuth, async (req, res) => {
  const { name, ip, user, password, port, isRoot } = req.body || {};
  const update = { name, ip, user, port: Number(port) || 22, isRoot: !!isRoot };
  if (!password) delete update.password;
  const doc = await Host.findByIdAndUpdate(req.params.id, update, { new: true });
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json(doc);
});

app.delete('/api/hosts/:id', requireAuth, async (req, res) => {
  const removed = await Host.findByIdAndDelete(req.params.id);
  if (!removed) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SSH helpers (ALWAYS via bash -lc with safe single-quote escaping)
// ─────────────────────────────────────────────────────────────────────────────
function escSingle(s) { return String(s).replace(/'/g, "'\\''"); }
const DEFAULT_ENV = { LC_ALL: 'C', PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' };

function runAptOnHost(host) {
  return new Promise((resolve) => {
    const conn = new Client();
    const start = Date.now();
    let stdout = '', stderr = '';

    conn.on('ready', () => {
      const nonInteractive = "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get upgrade -y";
      const ni = escSingle(nonInteractive);
      const pw = escSingle(host.password || '');

      const cmd = (host.isRoot || host.user === 'root')
        ? `bash -lc '${ni}'`
        : `echo '${pw}' | sudo -S -p '' bash -lc '${ni}'`;

      conn.exec(cmd, { env: DEFAULT_ENV }, (err, stream) => {
        if (err) { conn.end(); return resolve({ host: host.name, ip: host.ip, ok: false, error: 'exec: ' + err.message }); }
        stream.on('close', (code, signal) => {
          conn.end();
          resolve({
            host: host.name, ip: host.ip, ok: code === 0, exitCode: code, signal,
            durationMs: Date.now() - start,
            stdout: stdout.slice(-20000), stderr: stderr.slice(-20000)
          });
        }).on('data', d => { stdout += d.toString(); })
          .stderr.on('data', d => { stderr += d.toString(); });
      });
    }).on('error', (err) => {
      resolve({ host: host.name, ip: host.ip, ok: false, error: 'ssh: ' + err.message, durationMs: Date.now() - start });
    }).connect({
      host: host.ip, port: host.port || 22, username: host.user, password: host.password, readyTimeout: 20000
    });
  });
}

function streamAptOnHost(host, onEvent) {
  const conn = new Client();
  const start = Date.now();

  conn.on('ready', () => {
    const nonInteractive = "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get upgrade -y";
    const ni = escSingle(nonInteractive);
    const pw = escSingle(host.password || '');

    const cmd = (host.isRoot || host.user === 'root')
      ? `bash -lc '${ni}'`
      : `echo '${pw}' | sudo -S -p '' bash -lc '${ni}'`;

    onEvent({ type: 'hostStart', host: host.name, ip: host.ip });

    conn.exec(cmd, { env: DEFAULT_ENV }, (err, stream) => {
      if (err) {
        onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'exec: ' + err.message, durationMs: Date.now() - start, exitCode: null });
        conn.end();
        return;
      }
      stream.on('close', (code) => {
        onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: code === 0, exitCode: code, durationMs: Date.now() - start });
        conn.end();
      }).on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }))
        .stderr.on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }));
    });
  }).on('error', (err) => {
    onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'ssh: ' + err.message, durationMs: Date.now() - start, exitCode: null });
  }).connect({
    host: host.ip, port: host.port || 22, username: host.user, password: host.password, readyTimeout: 20000
  });
}

/** Execute custom script as root, streaming logs */
function streamScriptOnHost(host, script, onEvent) {
  const conn = new Client();
  const start = Date.now();

  // Encode script and execute from a temp file
  const b64 = Buffer.from(String(script), 'utf8').toString('base64');
  const remote = `TMP=$(mktemp) && printf '%s' '${b64}' | base64 -d > "$TMP" && chmod +x "$TMP" && bash "$TMP"; rc=$?; rm -f "$TMP"; exit $rc`;
  const remoteEsc = escSingle(remote);
  const pw = escSingle(host.password || '');

  const cmd = (host.isRoot || host.user === 'root')
    ? `bash -lc '${remoteEsc}'`
    : `echo '${pw}' | sudo -S -p '' bash -lc '${remoteEsc}'`;

  conn.on('ready', () => {
    onEvent({ type: 'hostStart', host: host.name, ip: host.ip });

    conn.exec(cmd, { env: DEFAULT_ENV }, (err, stream) => {
      if (err) {
        onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'exec: ' + err.message, durationMs: Date.now() - start, exitCode: null });
        conn.end();
        return;
      }
      stream.on('close', (code) => {
        onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: code === 0, exitCode: code, durationMs: Date.now() - start });
        conn.end();
      }).on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }))
        .stderr.on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }));
    });
  }).on('error', (err) => {
    onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'ssh: ' + err.message, durationMs: Date.now() - start, exitCode: null });
  }).connect({
    host: host.ip, port: host.port || 22, username: host.user, password: host.password, readyTimeout: 20000
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-stream JSON endpoints (compatibility)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/run/:id', requireAuth, async (req, res) => {
  const host = await Host.findById(req.params.id).lean();
  if (!host) return res.status(404).json({ error: 'Host not found' });
  const result = await runAptOnHost(host);
  res.json(result);
});

app.post('/api/runAll', requireAuth, async (req, res) => {
  const hosts = await Host.find({}).lean();
  const results = await Promise.all(hosts.map(h => runAptOnHost(h)));
  res.json({ count: hosts.length, results });
});

app.post('/api/runCustom', requireAuth, async (req, res) => {
  try {
    const { hostIds, scriptB64 } = req.body || {};
    if (!Array.isArray(hostIds) || hostIds.length === 0) {
      return res.status(400).json({ error: 'hostIds is required' });
    }
    if (!scriptB64) return res.status(400).json({ error: 'scriptB64 required' });

    const script = Buffer.from(String(scriptB64), 'base64').toString('utf8');
    if (!script.trim()) return res.status(400).json({ error: 'Empty script' });
    if (script.length > 200 * 1024) return res.status(413).json({ error: 'Script too large (max 200 KB)' });

    const hosts = await Host.find({ _id: { $in: hostIds } }).lean();

    // run sequentially to keep response deterministic
    const results = [];
    for (const h of hosts) {
      results.push(await new Promise((resolve) => {
        let out = '', errTxt = '';
        streamScriptOnHost(h, script, ev => {
          if (ev.type === 'log') out += ev.chunk;
          else if (ev.type === 'hostEnd') {
            resolve({
              host: h.name, ip: h.ip, ok: ev.ok, exitCode: ev.exitCode, durationMs: ev.durationMs,
              stdout: out.slice(-20000), stderr: errTxt.slice(-20000), error: ev.error
            });
          }
        });
      }));
    }
    res.json({ count: hosts.length, results });
  } catch (e) {
    console.error('runCustom error:', e);
    res.status(500).json({ error: e.message || 'runCustom failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SSE helpers
// ─────────────────────────────────────────────────────────────────────────────
function sseInit(res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
  });
  res.write('\n');
}
function sseSend(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming: apt (single + all)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/stream/run/:id', requireAuth, async (req, res) => {
  const host = await Host.findById(req.params.id).lean();
  if (!host) return res.status(404).end();

  sseInit(res);
  streamAptOnHost(host, (ev) => {
    if (ev.type === 'hostStart') sseSend(res, 'hostStart', ev);
    else if (ev.type === 'log') sseSend(res, 'log', ev);
    else if (ev.type === 'hostEnd') { sseSend(res, 'hostEnd', ev); sseSend(res, 'done', {}); res.end(); }
  });
});

app.get('/api/stream/runAll', requireAuth, async (req, res) => {
  const hosts = await Host.find({}).lean();
  sseInit(res);
  let remaining = hosts.length;
  hosts.forEach(h => {
    streamAptOnHost(h, (ev) => {
      if (ev.type === 'hostStart') sseSend(res, 'hostStart', ev);
      else if (ev.type === 'log') sseSend(res, 'log', ev);
      else if (ev.type === 'hostEnd') {
        sseSend(res, 'hostEnd', ev);
        remaining -= 1;
        if (remaining === 0) { sseSend(res, 'done', {}); res.end(); }
      }
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
/* Streaming: custom (job + stream) */
// ─────────────────────────────────────────────────────────────────────────────
const jobs = new Map(); // jobId -> EventEmitter
function newJob() {
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  const ee = new EventEmitter();
  ee.setMaxListeners(0);
  jobs.set(id, ee);
  setTimeout(() => jobs.delete(id), 60 * 60 * 1000); // auto-clean after 1h
  return { id, ee };
}

app.post('/api/runCustomStream', requireAuth, async (req, res) => {
  try {
    const { hostIds, scriptB64 } = req.body || {};
    if (!Array.isArray(hostIds) || hostIds.length === 0) {
      return res.status(400).json({ error: 'hostIds is required' });
    }
    if (!scriptB64) return res.status(400).json({ error: 'scriptB64 required' });

    const script = Buffer.from(String(scriptB64), 'base64').toString('utf8');
    if (!script.trim()) return res.status(400).json({ error: 'Empty script' });
    if (script.length > 200 * 1024) return res.status(413).json({ error: 'Script too large (max 200 KB)' });

    const hosts = await Host.find({ _id: { $in: hostIds } }).lean();
    const { id: jobId, ee } = newJob();

    // kick work on next tick; respond immediately with jobId
    process.nextTick(() => {
      let remaining = hosts.length;
      hosts.forEach(h => {
        streamScriptOnHost(h, script, (ev) => {
          if (ev.type === 'hostStart') ee.emit('hostStart', ev);
          else if (ev.type === 'log') ee.emit('log', ev);
          else if (ev.type === 'hostEnd') {
            ee.emit('hostEnd', ev);
            remaining -= 1;
            if (remaining === 0) ee.emit('done', {});
          }
        });
      });
    });

    res.json({ ok: true, jobId });
  } catch (e) {
    console.error('runCustomStream error:', e);
    res.status(500).json({ error: e.message || 'runCustomStream failed' });
  }
});

app.get('/api/stream/runCustom', requireAuth, (req, res) => {
  const jobId = String(req.query.job || '');
  const ee = jobs.get(jobId);
  if (!ee) return res.status(404).end();

  sseInit(res);

  const onStart = (d) => sseSend(res, 'hostStart', d);
  const onLog = (d) => sseSend(res, 'log', d);
  const onEnd = (d) => sseSend(res, 'hostEnd', d);
  const onDone = (d) => { sseSend(res, 'done', d || {}); cleanup(); res.end(); };

  ee.on('hostStart', onStart);
  ee.on('log', onLog);
  ee.on('hostEnd', onEnd);
  ee.on('done', onDone);

  function cleanup() {
    ee.off('hostStart', onStart);
    ee.off('log', onLog);
    ee.off('hostEnd', onEnd);
    ee.off('done', onDone);
  }
  req.on('close', cleanup);
});

// ─────────────────────────────────────────────────────────────────────────────
// Static (fallback)
// ─────────────────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────────────────────
(async function start() {
  await mongoose.connect(MONGO_URL, { ignoreUndefined: true });
  console.log('Connected to Mongo:', MONGO_URL);
  app.listen(PORT, () => console.log(`ssh-updater listening on http://0.0.0.0:${PORT}`));
})().catch(err => { console.error('Fatal:', err); process.exit(1); });

