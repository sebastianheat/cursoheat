// /api/users  · admin-only user management
//   GET    -> { users: [...] }            list all users
//   POST   { name, email, password, role } create a user
//   PATCH  { id, role?, status? }          update a user's role or status
//   DELETE { id }                          remove a user
const {
  sql, ROLES, ensureInit, getBody, requireAdmin, hashPassword, publicUser,
} = require('./_lib/auth');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = async (req, res) => {
  try {
    await ensureInit();
    const admin = requireAdmin(req, res);
    if (!admin) return;

    // ---- list ----
    if (req.method === 'GET') {
      const rows = await sql`SELECT * FROM portal_users ORDER BY created_at ASC`;
      return res.status(200).json({ users: rows.map(publicUser) });
    }

    // ---- create ----
    if (req.method === 'POST') {
      const { name, email, password, role } = getBody(req);
      const mail = (email || '').trim().toLowerCase();
      const nm = (name || '').trim();
      const rl = (role || 'alumna').trim();
      if (!nm || !EMAIL_RE.test(mail) || !password || password.length < 6) {
        return res.status(400).json({ error: 'Completa nombre, email válido y contraseña de 6+ caracteres.' });
      }
      if (!ROLES.includes(rl)) return res.status(400).json({ error: 'Rol no válido' });

      const dup = await sql`SELECT 1 FROM portal_users WHERE email = ${mail} LIMIT 1`;
      if (dup.length) return res.status(409).json({ error: 'Ya existe un usuario con ese email.' });

      const rows = await sql`
        INSERT INTO portal_users (email, name, role, password_hash)
        VALUES (${mail}, ${nm}, ${rl}, ${hashPassword(password)})
        RETURNING *`;
      return res.status(201).json({ user: publicUser(rows[0]) });
    }

    // ---- update role / status ----
    if (req.method === 'PATCH') {
      const { id, role, status } = getBody(req);
      if (!id) return res.status(400).json({ error: 'Falta el id del usuario' });
      if (role !== undefined && !ROLES.includes(role)) return res.status(400).json({ error: 'Rol no válido' });
      if (status !== undefined && !['active', 'inactive'].includes(status)) {
        return res.status(400).json({ error: 'Estado no válido' });
      }
      if (id === admin.sub && (role && role !== 'admin')) {
        return res.status(400).json({ error: 'No puedes quitarte a ti mismo el rol de administrador.' });
      }
      const rows = await sql`
        UPDATE portal_users
        SET role   = COALESCE(${role ?? null}, role),
            status = COALESCE(${status ?? null}, status)
        WHERE id = ${id}
        RETURNING *`;
      if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
      return res.status(200).json({ user: publicUser(rows[0]) });
    }

    // ---- delete ----
    if (req.method === 'DELETE') {
      const { id } = getBody(req);
      if (!id) return res.status(400).json({ error: 'Falta el id del usuario' });
      if (id === admin.sub) return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta.' });
      const rows = await sql`DELETE FROM portal_users WHERE id = ${id} RETURNING id`;
      if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'Método no permitido' });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Error del servidor' });
  }
};
