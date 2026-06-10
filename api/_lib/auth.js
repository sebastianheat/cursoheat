// Shared backend helpers for the HEAT Academy portal.
// Real authentication: Neon Postgres + scrypt password hashing + signed JWT.

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { neon } = require('@neondatabase/serverless');

const DB_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
const sql = DB_URL ? neon(DB_URL) : null;

const AUTH_SECRET = process.env.AUTH_SECRET || '';
const ROLES = ['alumna', 'setter', 'closer', 'lider', 'admin'];
const TOKEN_TTL = '30d';

// ---------- passwords ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(pw, stored) {
  if (!stored) return false;
  const [scheme, salt, hash] = stored.split('$');
  if (scheme !== 'scrypt' || !salt || !hash) return false;
  const calc = crypto.scryptSync(pw, salt, 64);
  const ref = Buffer.from(hash, 'hex');
  return calc.length === ref.length && crypto.timingSafeEqual(calc, ref);
}

// ---------- tokens ----------
function signToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role, name: user.name },
    AUTH_SECRET,
    { expiresIn: TOKEN_TTL }
  );
}

function verifyToken(token) {
  return jwt.verify(token, AUTH_SECRET);
}

// ---------- schema + seed (idempotent, runs once per warm instance) ----------
let initialized = false;
async function ensureInit() {
  if (initialized) return;
  if (!sql) throw new Error('DATABASE_URL no está configurada');
  await sql`
    CREATE TABLE IF NOT EXISTS portal_users (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email         text UNIQUE NOT NULL,
      name          text NOT NULL,
      role          text NOT NULL DEFAULT 'alumna',
      status        text NOT NULL DEFAULT 'active',
      password_hash text NOT NULL,
      created_at    timestamptz NOT NULL DEFAULT now()
    )`;

  // Seed the first administrator from env vars if the table has no admin yet.
  const adminEmail = (process.env.SEED_ADMIN_EMAIL || 'admin@heat.cl').toLowerCase();
  const adminPass = process.env.SEED_ADMIN_PASSWORD;
  if (adminPass) {
    const existing = await sql`SELECT 1 FROM portal_users WHERE email = ${adminEmail} LIMIT 1`;
    if (existing.length === 0) {
      await sql`
        INSERT INTO portal_users (email, name, role, password_hash)
        VALUES (${adminEmail}, 'Administrador HEAT', 'admin', ${hashPassword(adminPass)})
        ON CONFLICT (email) DO NOTHING`;
    }
  }
  initialized = true;
}

// ---------- request helpers ----------
function getBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return req.body;
}

function bearer(req) {
  const h = req.headers.authorization || req.headers.Authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}

// Returns the decoded JWT payload, or sends 401 and returns null.
function requireAuth(req, res) {
  const token = bearer(req);
  if (!token) { res.status(401).json({ error: 'No autenticado' }); return null; }
  try {
    return verifyToken(token);
  } catch {
    res.status(401).json({ error: 'Sesión inválida o expirada' });
    return null;
  }
}

// Returns the decoded payload only if the caller is an admin, else sends an error.
function requireAdmin(req, res) {
  const payload = requireAuth(req, res);
  if (!payload) return null;
  if (payload.role !== 'admin') {
    res.status(403).json({ error: 'Solo un administrador puede hacer esto' });
    return null;
  }
  return payload;
}

function publicUser(row) {
  return { id: row.id, email: row.email, name: row.name, role: row.role, status: row.status };
}

module.exports = {
  sql, ROLES,
  hashPassword, verifyPassword,
  signToken, verifyToken,
  ensureInit, getBody, requireAuth, requireAdmin, publicUser,
};
