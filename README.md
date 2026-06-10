# HEAT Academy · Portal del curso

Portal de formación y certificación en venta consultiva con IA para el equipo HEAT.

- **Producción:** https://academy.heatchile.com
- **Stack:** sitio estático (HTML/CSS/JS) + funciones serverless en Vercel.
- **Autenticación:** real, con Neon (Postgres) + JWT firmado. Las contraseñas se guardan hasheadas (scrypt); no hay credenciales en el código.

## Estructura

```
index.html            Portal del alumno (landing + login + panel)
primercurso/          Primer curso (slides de inducción)
api/                  Funciones serverless
  login.js            POST  /api/login   inicia sesión, devuelve JWT
  me.js               GET   /api/me      valida la sesión actual
  users.js            CRUD  /api/users   gestión de usuarios (solo admin)
  _lib/auth.js        Helpers: hashing, JWT, esquema y seed
vercel.json           Configuración de Vercel (cleanUrls)
```

## Variables de entorno (Vercel)

| Variable | Descripción |
|----------|-------------|
| `DATABASE_URL` | Conexión a Neon Postgres (la inyecta la integración). |
| `AUTH_SECRET` | Llave secreta para firmar los JWT. |
| `SEED_ADMIN_EMAIL` | Email del administrador inicial. |
| `SEED_ADMIN_PASSWORD` | Contraseña del administrador inicial (siembra). |

## Despliegue

Cada push a la rama `main` despliega automáticamente a producción vía la integración de Git de Vercel.
