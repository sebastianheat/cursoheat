// POST /api/login  { email, password } -> { token, user }
const { sql, ensureInit, getBody, verifyPassword, signToken, publicUser } = require('./_lib/auth');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });
  try {
    await ensureInit();
    const { email, password } = getBody(req);
    const mail = (email || '').trim().toLowerCase();
    if (!mail || !password) return res.status(400).json({ error: 'Email y contraseña son obligatorios' });

    const rows = await sql`SELECT * FROM portal_users WHERE email = ${mail} LIMIT 1`;
    const user = rows[0];
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'Correo o clave incorrectos.' });
    }
    if (user.status !== 'active') {
      return res.status(403).json({ error: 'Tu cuenta está inactiva. Contacta al administrador.' });
    }
    return res.status(200).json({ token: signToken(user), user: publicUser(user) });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Error del servidor' });
  }
};
