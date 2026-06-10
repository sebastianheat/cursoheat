// GET /api/me  (Bearer) -> { user }  · restores the session on page load
const { sql, ensureInit, requireAuth, publicUser } = require('./_lib/auth');

module.exports = async (req, res) => {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Método no permitido' });
  try {
    await ensureInit();
    const payload = requireAuth(req, res);
    if (!payload) return;
    const rows = await sql`SELECT * FROM portal_users WHERE id = ${payload.sub} LIMIT 1`;
    const user = rows[0];
    if (!user || user.status !== 'active') return res.status(401).json({ error: 'Sesión inválida' });
    return res.status(200).json({ user: publicUser(user) });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Error del servidor' });
  }
};
