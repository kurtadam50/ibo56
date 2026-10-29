'use strict';

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const Database = require('better-sqlite3');
const { randomBytes, randomUUID, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');
const fs = require('node:fs/promises');
const path = require('node:path');

const scryptAsync = promisify(scrypt);
const sessionTtlMs = 8 * 60 * 60 * 1000;
const allowedTypes = new Set(['Gelir', 'Gider', 'Borç Verdim', 'Borç Tahsilatı', 'Personel Harcaması']);
const allowedCategories = new Set(['Genel', 'Satış', 'Gıda / Malzeme', 'Fatura', 'Kira', 'Ulaşım', 'Personel', 'Diğer']);

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Eksik ortam değişkeni: ${name}`);
  return value;
}

function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

function text(value, maxLength) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function normalizeState(input) {
  if (!input || !Array.isArray(input.transactions) || !input.closings ||
      typeof input.closings !== 'object' || Array.isArray(input.closings)) {
    const error = new Error('Yedek biçimi geçersiz.');
    error.status = 400;
    throw error;
  }
  if (input.transactions.length > 50000 || Object.keys(input.closings).length > 10000) {
    const error = new Error('Yedek izin verilen kayıt sınırını aşıyor.');
    error.status = 400;
    throw error;
  }

  const transactions = input.transactions.map(item => {
    if (!item || typeof item !== 'object' || !validDate(item.date) ||
        !allowedTypes.has(item.type) || !Number.isFinite(Number(item.amount)) ||
        Number(item.amount) <= 0 || Number(item.amount) > 1e12) {
      const error = new Error('Yedekte geçersiz işlem kaydı var.');
      error.status = 400;
      throw error;
    }
    const id = typeof item.id === 'string' && /^[\w.-]{1,100}$/.test(item.id) ? item.id : randomUUID();
    return {
      id,
      date: item.date,
      type: item.type,
      amount: Number(item.amount),
      description: text(item.description, 180),
      person: text(item.person, 100),
      category: allowedCategories.has(item.category) ? item.category : 'Genel',
      staffName: text(item.staffName, 100),
      created: Number.isFinite(Number(item.created)) ? Number(item.created) : Date.now()
    };
  });

  const closings = {};
  for (const [date, closing] of Object.entries(input.closings)) {
    if (!validDate(date) || !closing || typeof closing !== 'object' ||
        !Number.isFinite(Number(closing.amount)) || Number(closing.amount) < 0 ||
        Number(closing.amount) > 1e12) {
      const error = new Error('Yedekte geçersiz gün sonu kaydı var.');
      error.status = 400;
      throw error;
    }
    closings[date] = { amount: Number(closing.amount), note: text(closing.note, 160) };
  }
  return { transactions, closings };
}

class SqliteSessionStore extends session.Store {
  constructor(db) {
    super();
    this.db = db;
    this.getStatement = db.prepare('SELECT sess, expires FROM sessions WHERE sid = ?');
    this.setStatement = db.prepare('INSERT INTO sessions (sid, sess, expires) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires = excluded.expires');
    this.destroyStatement = db.prepare('DELETE FROM sessions WHERE sid = ?');
    this.pruneStatement = db.prepare('DELETE FROM sessions WHERE expires <= ?');
  }

  get(sid, callback) {
    try {
      const row = this.getStatement.get(sid);
      if (!row || row.expires <= Date.now()) {
        if (row) this.destroyStatement.run(sid);
        return callback(null, null);
      }
      return callback(null, JSON.parse(row.sess));
    } catch (error) {
      return callback(error);
    }
  }

  set(sid, value, callback = () => {}) {
    try {
      const expires = value.cookie?.expires ? new Date(value.cookie.expires).getTime() : Date.now() + sessionTtlMs;
      this.setStatement.run(sid, JSON.stringify(value), expires);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  touch(sid, value, callback = () => {}) {
    this.set(sid, value, callback);
  }

  destroy(sid, callback = () => {}) {
    try {
      this.destroyStatement.run(sid);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  prune() {
    this.pruneStatement.run(Date.now());
  }
}

async function main() {
  const adminUsername = (process.env.ADMIN_USERNAME || 'İBO AĞA').normalize('NFKC').trim();
  const adminPassword = process.env.ADMIN_PASSWORD || 'İBRAHİM5600';
  const sessionSecret = requiredEnv('SESSION_SECRET');
  const isProduction = process.env.NODE_ENV === 'production';
  if (adminUsername.length < 2 || adminPassword.length < 10) {
    throw new Error('Yönetici adı en az 2, yönetici şifresi en az 10 karakter olmalıdır.');
  }
  if (sessionSecret.length < 32) {
    throw new Error('SESSION_SECRET en az 32 karakterlik rastgele bir değer olmalıdır.');
  }

  const adminSalt = randomBytes(16);
  const adminHash = await scryptAsync(adminPassword, adminSalt, 64);
  const dbPath = path.resolve(process.env.DB_PATH || path.join(__dirname, 'data', 'haci-usta.sqlite'));
  await fs.mkdir(path.dirname(dbPath), { recursive: true });

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expires INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires);
    CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  db.prepare('INSERT OR IGNORE INTO app_state (id, payload, updated_at) VALUES (1, ?, ?)')
    .run(JSON.stringify({ transactions: [], closings: {} }), new Date().toISOString());

  const sessionStore = new SqliteSessionStore(db);
  sessionStore.prune();
  const pruneTimer = setInterval(() => sessionStore.prune(), 60 * 60 * 1000);
  pruneTimer.unref();

  const app = express();
  if (isProduction) app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.locals.cspNonce = randomBytes(18).toString('base64');
    next();
  });
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`, 'https://cdn.jsdelivr.net'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: isProduction ? [] : null
      }
    },
    referrerPolicy: { policy: 'no-referrer' }
  }));
  app.use(express.json({ limit: '10mb', strict: true }));
  app.use(session({
    name: 'haciusta.sid',
    secret: sessionSecret,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: sessionTtlMs,
      path: '/'
    }
  }));

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 8,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'Çok fazla giriş denemesi. Bir süre sonra tekrar deneyin.' }
  });

  function requireSameOrigin(req, res, next) {
    const origin = req.get('origin');
    const expected = `${req.protocol}://${req.get('host')}`;
    if (!origin || origin !== expected) return res.status(403).json({ error: 'İstek kaynağı doğrulanamadı.' });
    next();
  }

  function requireAdmin(req, res, next) {
    if (req.session?.isAdmin !== true) return res.status(401).json({ error: 'Yönetici girişi gerekli.' });
    next();
  }

  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  app.get('/api/session', (req, res) => {
    res.json({
      authenticated: req.session?.isAdmin === true,
      username: req.session?.isAdmin === true ? req.session.username : null
    });
  });

  app.post('/api/login', requireSameOrigin, loginLimiter, async (req, res, next) => {
    try {
      const username = typeof req.body?.username === 'string' ? req.body.username.normalize('NFKC').trim() : '';
      const password = typeof req.body?.password === 'string' ? req.body.password : '';
      if (username.length > 100 || password.length > 256) {
        return res.status(401).json({ error: 'Yönetici adı veya şifre hatalı.' });
      }
      const candidate = await scryptAsync(password, adminSalt, 64);
      const usernameMatches = username.toLocaleLowerCase('tr-TR') === adminUsername.toLocaleLowerCase('tr-TR');
      const passwordMatches = timingSafeEqual(adminHash, candidate);
      if (!usernameMatches || !passwordMatches) return res.status(401).json({ error: 'Yönetici adı veya şifre hatalı.' });

      req.session.regenerate(error => {
        if (error) return next(error);
        req.session.isAdmin = true;
        req.session.username = adminUsername;
        req.session.save(saveError => {
          if (saveError) return next(saveError);
          res.json({ authenticated: true, username: adminUsername });
        });
      });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/logout', requireSameOrigin, requireAdmin, (req, res, next) => {
    req.session.destroy(error => {
      if (error) return next(error);
      res.clearCookie('haciusta.sid', { httpOnly: true, secure: isProduction, sameSite: 'strict', path: '/' });
      res.json({ ok: true });
    });
  });

  app.get('/api/data', requireAdmin, (req, res) => {
    const row = db.prepare('SELECT payload, updated_at FROM app_state WHERE id = 1').get();
    res.json({ ...JSON.parse(row.payload), savedAt: row.updated_at });
  });

  app.put('/api/data', requireSameOrigin, requireAdmin, (req, res) => {
    const state = normalizeState(req.body);
    const savedAt = new Date().toISOString();
    db.prepare('UPDATE app_state SET payload = ?, updated_at = ? WHERE id = 1')
      .run(JSON.stringify(state), savedAt);
    res.json({ ok: true, savedAt });
  });

  app.get(['/', '/index.html'], async (req, res, next) => {
    try {
      const html = await fs.readFile(path.join(__dirname, 'index.html'), 'utf8');
      res.set('Cache-Control', 'no-store');
      res.type('html').send(html.replace('<script>', `<script nonce="${res.locals.cspNonce}">`));
    } catch (error) {
      next(error);
    }
  });

  app.use((req, res) => res.status(404).json({ error: 'Sayfa bulunamadı.' }));
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    console.error('İstek işlenemedi:', error.message);
    const status = error.status >= 400 && error.status < 500 ? error.status : 500;
    res.status(status).json({ error: status === 500 ? 'Sunucuda beklenmeyen bir hata oluştu.' : 'İstek işlenemedi.' });
  });

  const port = Number(process.env.PORT) || 3000;
  const server = app.listen(port, '0.0.0.0', () => {
    console.log(`Hacı Usta paneli ${port} portunda çalışıyor.`);
  });
  const shutdown = () => {
    clearInterval(pruneTimer);
    server.close(() => {
      db.close();
      process.exit(0);
    });
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
