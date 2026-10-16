
import { pbkdf2 as nodePbkdf2 } from 'node:crypto';

interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
}

type User = {
  id: string;
  nome: string;
  email: string;
  perfil: 'ADMIN' | 'USUARIO';
  ativo: number;
};

const json = (value: unknown, status = 200) =>
  Response.json(value, {
    status,
    headers: {
      'Cache-Control': 'no-store'
    }
  });

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, b =>
    b.toString(16).padStart(2, '0')
  ).join('');

const random = (): string =>
  hex(crypto.getRandomValues(new Uint8Array(32)));

const sha256 = async (value: string): Promise<string> =>
  hex(
    new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(value)
      )
    )
  );

// PBKDF2-SHA256 com 210.000 iterações.
// Usa a API assíncrona Node.js compatível
// com Workers quando nodejs_compat está ativo.
const pbkdf2 = async (
  password: string,
  salt: string
): Promise<string> => {
  if (!/^[a-f0-9]{64}$/i.test(salt)) {
    throw new Error('Salt inválido');
  }

  const saltBytes = Uint8Array.from(
    salt.match(/.{2}/g)!,
    x => parseInt(x, 16)
  );

  return new Promise<string>((resolve, reject) => {
    nodePbkdf2(
      password,
      saltBytes,
      210000,
      32,
      'sha256',
      (error, derivedKey) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(derivedKey.toString('hex'));
      }
    );
  });
};

const safeEqual = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return difference === 0;
};

const cookie = (token: string, maxAge: number) =>
  `agenda_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;

async function currentUser(
  request: Request,
  env: Env
): Promise<{ user: User; hash: string } | null> {
  const token = request.headers
    .get('Cookie')
    ?.match(
      /(?:^|;\s*)agenda_session=([a-f0-9]{64})(?:;|$)/
    )?.[1];

  if (!token) return null;

  const hash = await sha256(token);

  const user = await env.DB.prepare(`
    SELECT
      u.id,
      u.nome,
      u.email,
      u.perfil,
      u.ativo
    FROM sessoes s
    JOIN usuarios u ON u.id = s.usuario_id
    WHERE s.token_hash = ?
      AND s.expira_em > ?
      AND u.ativo = 1
  `)
    .bind(hash, new Date().toISOString())
    .first<User>();

  return user ? { user, hash } : null;
}

const allowedOrigin = (request: Request): boolean => {
  const origin = request.headers.get('Origin');

  return (
    !origin ||
    origin === new URL(request.url).origin
  );
};

const emailOK = (email: string): boolean =>
  email.length <= 254 &&
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

async function body(
  request: Request
): Promise<Record<string, unknown>> {
  if (
    Number(request.headers.get('content-length') || 0) >
    8192
  ) {
    throw new Error('Requisição muito grande');
  }

  const data: unknown = await request.json();

  if (
    !data ||
    typeof data !== 'object' ||
    Array.isArray(data)
  ) {
    throw new Error('JSON inválido');
  }

  return data as Record<string, unknown>;
}

export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    const url = new URL(request.url);

    // Arquivos estáticos do React
    if (!url.pathname.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }

    if (!allowedOrigin(request)) {
      return json(
        { erro: 'Origem não permitida' },
        403
      );
    }

    try {
      // TESTE DE CONEXÃO
      if (
        url.pathname === '/api/health' &&
        request.method === 'GET'
      ) {
        const result = await env.DB
          .prepare('SELECT 1 AS conectado')
          .first<{ conectado: number }>();

        return json({
          status: 'online',
          banco:
            result?.conectado === 1
              ? 'conectado'
              : 'erro'
        });
      }

      // LOGIN
      if (
        url.pathname === '/api/login' &&
        request.method === 'POST'
      ) {
        const data = await body(request);

        const email = String(
          data.email || ''
        ).trim().toLowerCase();

        const password = String(data.senha || '');

        if (
          !emailOK(email) ||
          password.length > 1024
        ) {
          return json(
            { erro: 'Credenciais inválidas' },
            401
          );
        }

        const row = await env.DB.prepare(`
          SELECT
            id,
            nome,
            email,
            perfil,
            ativo,
            senha_hash
          FROM usuarios
          WHERE email = ?
        `)
          .bind(email)
          .first<User & { senha_hash: string }>();

        let valid = false;

        if (row?.senha_hash) {
          const parts = row.senha_hash.split('$');

          if (
            parts.length === 3 &&
            parts[0] === 'pbkdf2_sha256'
          ) {
            const calculated = await pbkdf2(
              password,
              parts[1]
            );

            valid = safeEqual(
              calculated,
              parts[2]
            );
          }
        }

        if (!row || !row.ativo || !valid) {
          return json(
            { erro: 'E-mail ou senha inválidos' },
            401
          );
        }

        const token = random();
        const hash = await sha256(token);

        const expires = new Date(
          Date.now() + 7 * 86400000
        ).toISOString();

        await env.DB.prepare(`
          INSERT INTO sessoes (
            token_hash,
            usuario_id,
            expira_em
          )
          VALUES (?, ?, ?)
        `)
          .bind(hash, row.id, expires)
          .run();

        const response = json({
          usuario: {
            id: row.id,
            nome: row.nome,
            email: row.email,
            perfil: row.perfil,
            ativo: row.ativo
          }
        });

        response.headers.set(
          'Set-Cookie',
          cookie(token, 7 * 86400)
        );

        return response;
      }

      // IDENTIFICAR USUÁRIO AUTENTICADO
      const auth = await currentUser(request, env);

      if (
        url.pathname === '/api/me' &&
        request.method === 'GET'
      ) {
        return auth
          ? json({ usuario: auth.user })
          : json(
              { erro: 'Não autenticado' },
              401
            );
      }

      if (!auth) {
        return json(
          { erro: 'Não autenticado' },
          401
        );
      }

      // LOGOUT
      if (
        url.pathname === '/api/logout' &&
        request.method === 'POST'
      ) {
        await env.DB.prepare(`
          DELETE FROM sessoes
          WHERE token_hash = ?
        `)
          .bind(auth.hash)
          .run();

        const response = json({ ok: true });

        response.headers.set(
          'Set-Cookie',
          cookie('', 0)
        );

        return response;
      }

      // SOMENTE ADMINISTRADORES
      if (
        url.pathname === '/api/usuarios' &&
        auth.user.perfil !== 'ADMIN'
      ) {
        return json(
          {
            erro: 'Acesso restrito ao administrador'
          },
          403
        );
      }

      // LISTAR USUÁRIOS
      if (
        url.pathname === '/api/usuarios' &&
        request.method === 'GET'
      ) {
        const users = await env.DB.prepare(`
          SELECT
            id,
            nome,
            email,
            perfil,
            ativo,
            criado_em
          FROM usuarios
          ORDER BY nome
          LIMIT 200
        `).all();

        return json({
          usuarios: users.results
        });
      }

      // CADASTRAR USUÁRIOS
      if (
        url.pathname === '/api/usuarios' &&
        request.method === 'POST'
      ) {
        const data = await body(request);

        const nome = String(
          data.nome || ''
        ).trim();

        const email = String(
          data.email || ''
        ).trim().toLowerCase();

        const senha = String(data.senha || '');

        const perfil =
          data.perfil === 'ADMIN'
            ? 'ADMIN'
            : 'USUARIO';

        if (
          nome.length < 2 ||
          nome.length > 120 ||
          !emailOK(email) ||
          senha.length < 12 ||
          senha.length > 1024
        ) {
          return json(
            {
              erro:
                'Informe nome, e-mail válido e senha de no mínimo 12 caracteres'
            },
            400
          );
        }

        const salt = random();

        const hash = await pbkdf2(
          senha,
          salt
        );

        const id = crypto.randomUUID();

        try {
          await env.DB.prepare(`
            INSERT INTO usuarios (
              id,
              nome,
              email,
              senha_hash,
              perfil
            )
            VALUES (?, ?, ?, ?, ?)
          `)
            .bind(
              id,
              nome,
              email,
              `pbkdf2_sha256$${salt}$${hash}`,
              perfil
            )
            .run();
        } catch {
          return json(
            {
              erro:
                'Não foi possível cadastrar. Verifique se o e-mail já existe.'
            },
            409
          );
        }

        return json(
          {
            usuario: {
              id,
              nome,
              email,
              perfil,
              ativo: 1
            }
          },
          201
        );
      }

      return json(
        { erro: 'Rota não encontrada' },
        404
      );
    } catch (error) {
      console.error(
        'Erro na API',
        error instanceof Error
          ? error.message
          : 'desconhecido'
      );

      return json(
        {
          erro: 'Falha ao processar solicitação'
        },
        500
      );
    }
  }
};
