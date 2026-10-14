import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { createHmac, timingSafeEqual } from 'node:crypto';

function sameSecret(left, right) {
  const a = createHmac('sha256', 'baxtersec-login-check').update(left).digest();
  const b = createHmac('sha256', 'baxtersec-login-check').update(right).digest();
  return timingSafeEqual(a, b);
}

function authDemo(env) {
  const cookieName = 'baxtersec_session';
  const secret = env.SESSION_SECRET || '';
  const sign = (value) => createHmac('sha256', secret).update(value).digest('base64url');
  const makeSession = (email, remember) => {
    const maxAge = remember ? 30 * 24 * 60 * 60 : 8 * 60 * 60;
    const payload = Buffer.from(JSON.stringify({ email, exp: Date.now() + maxAge * 1000 })).toString('base64url');
    return `${payload}.${sign(payload)}`;
  };
  const readSession = (request) => {
    const cookie = request.headers.cookie?.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${cookieName}=`));
    if (!cookie || !secret) return null;
    const [payload, signature] = cookie.slice(cookieName.length + 1).split('.');
    if (!payload || !signature) return null;
    const expected = sign(payload);
    const actualBytes = Buffer.from(signature);
    const expectedBytes = Buffer.from(expected);
    if (actualBytes.length !== expectedBytes.length || !timingSafeEqual(actualBytes, expectedBytes)) return null;
    try {
      const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
      return data.exp > Date.now() ? data.email : null;
    } catch {
      return null;
    }
  };

  return {
    name: 'baxtersec-local-auth',
    configureServer(server) {
      server.middlewares.use('/api/auth', (request, response, next) => {
        const path = request.url?.split('?')[0];
        response.setHeader('Content-Type', 'application/json; charset=utf-8');
        if (path === '/login' && request.method === 'POST') {
          let body = '';
          request.on('data', (chunk) => { body += chunk; if (body.length > 16_384) request.destroy(); });
          request.on('end', () => {
            try {
              const credentials = JSON.parse(body);
              const email = String(credentials.email || '').trim();
              const password = String(credentials.password || '');
              const remember = Boolean(credentials.remember);
              const validEmail = sameSecret(email.toLowerCase(), String(env.LOGIN_EMAIL || '').toLowerCase());
              const validPassword = sameSecret(password, String(env.LOGIN_PASSWORD || ''));
              if (!env.LOGIN_EMAIL || !env.LOGIN_PASSWORD || !secret) {
                response.statusCode = 503;
                response.end(JSON.stringify({ authenticated: false }));
                return;
              }
              if (!validEmail || !validPassword) {
                response.statusCode = 401;
                response.end(JSON.stringify({ authenticated: false }));
                return;
              }
              const maxAge = remember ? 30 * 24 * 60 * 60 : 8 * 60 * 60;
              response.setHeader('Set-Cookie', `${cookieName}=${makeSession(email, remember)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`);
              response.end(JSON.stringify({ authenticated: true, email }));
            } catch {
              response.statusCode = 400;
              response.end(JSON.stringify({ authenticated: false }));
            }
          });
          return;
        }
        if (path === '/session' && request.method === 'GET') {
          const email = readSession(request);
          response.statusCode = email ? 200 : 401;
          response.end(JSON.stringify(email ? { authenticated: true, email } : { authenticated: false }));
          return;
        }
        if (path === '/logout' && request.method === 'POST') {
          response.setHeader('Set-Cookie', `${cookieName}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
          response.end(JSON.stringify({ authenticated: false }));
          return;
        }
        next();
      });
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return { plugins: [react(), authDemo(env)] };
});
