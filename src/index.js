import {
  authenticateEmailPasswordWithStytch,
  authenticateSessionWithStytch,
  buildCorsHeaders,
  jsonResponse,
  normalizeAuthDomain,
  renderLoginPage,
  resolveLoginContext,
} from './lib.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return jsonResponse({ ok: true, service: 'flowz-auth-gateway' });
    }

    if (request.method === 'GET' && url.pathname === '/login') {
      return handleLoginPage(request, env);
    }

    if (request.method === 'POST' && url.pathname === '/auth/email_password') {
      return handleEmailPasswordAuthenticate(request, env);
    }

    if (url.pathname === '/auth/stytch/session/authenticate' && request.method === 'OPTIONS') {
      return handleAuthPreflight(request, env);
    }

    if (url.pathname === '/auth/stytch/session/authenticate' && request.method === 'POST') {
      return handleAuthenticate(request, env);
    }

    return jsonResponse({ error: 'not_found' }, 404);
  },
};

async function handleLoginPage(request, env) {
  const context = resolveLoginContext(request.url, env);
  if (!context.ok) {
    return jsonResponse({ error: context.code, message: context.message }, context.status);
  }

  const authDomain = normalizeAuthDomain(env.STYTCH_AUTH_DOMAIN || '');
  const publicToken = (env.STYTCH_PUBLIC_TOKEN || '').trim();
  if (!authDomain || !publicToken) {
    return jsonResponse(
      {
        error: 'misconfigured_worker',
        message: 'STYTCH_AUTH_DOMAIN and STYTCH_PUBLIC_TOKEN are required for /login.',
      },
      500,
    );
  }

  const html = renderLoginPage({
    returnTo: context.returnTo,
    appOrigin: context.appOrigin,
    authDomain,
    publicToken,
  });

  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

async function handleEmailPasswordAuthenticate(request, env) {
  const context = resolveLoginContext(request.url, env);
  if (!context.ok) {
    return jsonResponse({ error: context.code, message: context.message }, context.status);
  }
  if (!env.STYTCH_PROJECT_ID || !env.STYTCH_SECRET) {
    return new Response(JSON.stringify({ error: 'misconfigured_worker' }), {
      status: 500,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
  }

  let formData;
  try {
    formData = await request.formData();
  } catch {
    return jsonResponse(
      {
        error: 'invalid_form',
        message: 'Request body must be application/x-www-form-urlencoded.',
      },
      400,
    );
  }

  const email = typeof formData.get('email') === 'string' ? formData.get('email').trim() : '';
  const password = typeof formData.get('password') === 'string' ? formData.get('password') : '';
  if (!email || !password) {
    return jsonResponse(
      {
        error: 'missing_email_or_password',
        message: 'Both email and password are required.',
      },
      400,
    );
  }

  try {
    const payload = await authenticateEmailPasswordWithStytch(email, password, env);
    const sessionToken =
      payload.session_token ||
      payload.session?.session_token ||
      payload.session_jwt ||
      payload.session?.session_jwt ||
      '';

    if (!sessionToken) {
      return jsonResponse(
        {
          error: 'stytch_missing_session_token',
          message: 'Stytch response did not include a session token.',
        },
        502,
      );
    }

    const redirectUrl = new URL(context.returnTo);
    redirectUrl.searchParams.set('stytch_token_type', 'password');
    redirectUrl.searchParams.set('token', sessionToken);

    return new Response(null, {
      status: 302,
      headers: {
        location: redirectUrl.toString(),
        'cache-control': 'no-store',
      },
    });
  } catch (error) {
    const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : 502;
    return jsonResponse(
      {
        error: 'stytch_password_authenticate_failed',
        message: error.message || 'Unable to authenticate email/password with Stytch.',
      },
      statusCode,
    );
  }
}

function handleAuthPreflight(request, env) {
  const origin = request.headers.get('origin');
  const cors = buildCorsHeaders(origin, env);
  if (!cors) {
    return jsonResponse({ error: 'origin_not_allowed' }, 403);
  }
  return new Response(null, { status: 204, headers: cors });
}

async function handleAuthenticate(request, env) {
  const origin = request.headers.get('origin');
  const cors = origin ? buildCorsHeaders(origin, env) : null;
  if (origin && !cors) {
    return jsonResponse({ error: 'origin_not_allowed' }, 403);
  }
  if (!env.STYTCH_PROJECT_ID || !env.STYTCH_SECRET) {
    return new Response(JSON.stringify({ error: 'misconfigured_worker' }), {
      status: 500,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        ...(cors || {}),
      },
    });
  }

  const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';
  const rateLimit = await enforceRateLimit(clientIp, env);
  if (!rateLimit.ok) {
    return jsonResponse(
      {
        error: 'rate_limited',
        message: 'Too many authentication attempts. Try again later.',
      },
      429,
      {
        ...(cors || {}),
        'retry-after': rateLimit.retryAfter,
      },
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'invalid_json' }, 400, cors || {});
  }

  const sessionToken = typeof body.session_token === 'string' ? body.session_token.trim() : '';
  if (!sessionToken) {
    return jsonResponse({ error: 'missing_session_token' }, 400, cors || {});
  }

  try {
    const payload = await authenticateSessionWithStytch(sessionToken, env);
    return jsonResponse(payload, 200, cors || {});
  } catch (error) {
    const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : 502;
    return jsonResponse(
      {
        error: 'stytch_authenticate_failed',
        message: error.message || 'Unable to authenticate session token.',
      },
      statusCode,
      cors || {},
    );
  }
}

async function enforceRateLimit(ip, env) {
  if (!env.RATE_LIMITER) {
    return { ok: true };
  }

  const id = env.RATE_LIMITER.idFromName(ip);
  const stub = env.RATE_LIMITER.get(id);
  const response = await stub.fetch('https://rate-limiter/internal/check', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ limit: 10, window_ms: 60000 }),
  });

  if (response.status === 429) {
    return {
      ok: false,
      retryAfter: response.headers.get('retry-after') || '60',
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      retryAfter: '60',
    };
  }

  return { ok: true };
}

export class RateLimiter {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'method_not_allowed' }, 405);
    }

    let input;
    try {
      input = await request.json();
    } catch {
      input = {};
    }

    const limit = Number.isFinite(input.limit) ? Number(input.limit) : 10;
    const windowMs = Number.isFinite(input.window_ms) ? Number(input.window_ms) : 60000;

    const now = Date.now();
    const existing = (await this.state.storage.get('bucket')) || null;
    let bucket = existing;
    if (!bucket || now >= bucket.resetAt) {
      bucket = {
        count: 0,
        resetAt: now + windowMs,
      };
    }

    bucket.count += 1;
    await this.state.storage.put('bucket', bucket);

    if (bucket.count > limit) {
      const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      return jsonResponse(
        { ok: false, error: 'rate_limited', retry_after: retryAfter },
        429,
        { 'retry-after': String(retryAfter) },
      );
    }

    return jsonResponse({
      ok: true,
      remaining: Math.max(0, limit - bucket.count),
      reset_at: new Date(bucket.resetAt).toISOString(),
    });
  }
}
