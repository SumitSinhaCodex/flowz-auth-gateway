const DEFAULT_STYTCH_API_BASE = 'https://test.stytch.com';

export function jsonResponse(payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...headers,
    },
  });
}

export function parseAllowedOrigins(rawAllowedOrigins) {
  const set = new Set();
  if (!rawAllowedOrigins) {
    return set;
  }
  for (const value of rawAllowedOrigins.split(',')) {
    const trimmed = value.trim();
    if (!trimmed) {
      continue;
    }
    try {
      set.add(new URL(trimmed).origin);
    } catch {
      // Ignore malformed origins in env.
    }
  }
  return set;
}

export function getOriginFromAbsoluteUrl(value) {
  if (!value || !value.trim()) {
    return null;
  }
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

export function resolveLoginContext(requestUrl, env) {
  const request = new URL(requestUrl);
  const rawReturnTo = request.searchParams.get('return_to') || env.DEFAULT_RETURN_TO;
  if (!rawReturnTo) {
    return {
      ok: false,
      status: 400,
      code: 'missing_return_to',
      message: 'Missing return_to query parameter and DEFAULT_RETURN_TO is not configured.',
    };
  }

  let returnToUrl;
  try {
    returnToUrl = new URL(rawReturnTo);
  } catch {
    return {
      ok: false,
      status: 400,
      code: 'invalid_return_to',
      message: 'return_to must be an absolute URL.',
    };
  }

  const allowedOrigins = parseAllowedOrigins(env.ALLOWED_ORIGINS || '');
  const defaultOrigin = getOriginFromAbsoluteUrl(env.DEFAULT_RETURN_TO || '');
  const returnToOrigin = returnToUrl.origin;
  const allowedByList = allowedOrigins.has(returnToOrigin);
  const allowedByDefaultOrigin = defaultOrigin !== null && defaultOrigin === returnToOrigin;
  if (!allowedByList && !allowedByDefaultOrigin) {
    return {
      ok: false,
      status: 400,
      code: 'origin_not_allowed',
      message: `return_to origin is not allowed: ${returnToOrigin}`,
    };
  }

  const rawAppOrigin = request.searchParams.get('app_origin');
  let appOrigin = returnToOrigin;
  if (rawAppOrigin && rawAppOrigin.trim()) {
    try {
      appOrigin = new URL(rawAppOrigin).origin;
    } catch {
      return {
        ok: false,
        status: 400,
        code: 'invalid_app_origin',
        message: 'app_origin must be an absolute URL when provided.',
      };
    }
  }

  return {
    ok: true,
    returnTo: returnToUrl.toString(),
    returnToOrigin,
    appOrigin,
  };
}

export function isOriginAllowed(origin, env) {
  if (!origin) {
    return false;
  }
  const allowedOrigins = parseAllowedOrigins(env.ALLOWED_ORIGINS || '');
  return allowedOrigins.has(origin);
}

export function buildCorsHeaders(origin, env) {
  if (!isOriginAllowed(origin, env)) {
    return null;
  }
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'POST,OPTIONS',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '600',
    vary: 'Origin',
  };
}

export function buildStytchAuthenticateRequest(sessionToken, env) {
  const projectId = (env.STYTCH_PROJECT_ID || '').trim();
  const secret = (env.STYTCH_SECRET || '').trim();
  if (!projectId || !secret) {
    throw new Error('STYTCH_PROJECT_ID and STYTCH_SECRET must be configured.');
  }

  const apiBase = (env.STYTCH_API_BASE || DEFAULT_STYTCH_API_BASE).replace(/\/$/, '');
  const credentials = `${projectId}:${secret}`;
  const encodedCredentials = toBase64(credentials);

  return {
    url: `${apiBase}/v1/sessions/authenticate`,
    init: {
      method: 'POST',
      headers: {
        authorization: `Basic ${encodedCredentials}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ session_token: sessionToken }),
    },
  };
}

export async function authenticateSessionWithStytch(sessionToken, env, fetchImpl = fetch) {
  const { url, init } = buildStytchAuthenticateRequest(sessionToken, env);
  const response = await fetchImpl(url, init);
  const rawText = await response.text();

  let payload = {};
  if (rawText.trim()) {
    try {
      payload = JSON.parse(rawText);
    } catch {
      payload = {};
    }
  }

  if (!response.ok) {
    const errorMessage =
      payload.error_message ||
      payload.error ||
      payload.message ||
      `Stytch authenticate failed with status ${response.status}.`;
    const error = new Error(errorMessage);
    error.statusCode = response.status;
    error.responseBody = rawText;
    throw error;
  }

  return {
    user_id: payload.user_id || payload.user?.user_id || payload.user?.id || payload.session?.user_id || null,
    session_jwt: payload.session_jwt || payload.session?.session_jwt || null,
    session_token: payload.session_token || payload.session?.session_token || sessionToken,
    expires_at: payload.expires_at || payload.session?.expires_at || null,
  };
}

export function renderLoginPage({ returnTo, appOrigin, authDomain, publicToken, projectId }) {
  const safe = {
    returnTo: escapeHtml(returnTo),
    appOrigin: escapeHtml(appOrigin),
    authDomain: escapeHtml(normalizeAuthDomain(authDomain)),
    publicToken: escapeHtml(publicToken),
    projectId: escapeHtml(projectId || ''),
  };

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Flowz Login</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f6f8fc;
        --card: #ffffff;
        --text: #172033;
        --muted: #586482;
        --primary: #2663ff;
        --border: #d9e0ef;
        --danger: #c62828;
      }
      body {
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: linear-gradient(180deg, #f8fbff 0%, #eef3ff 100%);
        color: var(--text);
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 16px;
      }
      .card {
        width: 100%;
        max-width: 420px;
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 16px;
        box-shadow: 0 10px 30px rgba(17, 40, 84, 0.08);
        padding: 24px;
      }
      h1 {
        margin: 0 0 8px;
        font-size: 28px;
      }
      p {
        margin: 0 0 20px;
        color: var(--muted);
      }
      button,
      input {
        width: 100%;
        border-radius: 10px;
        border: 1px solid var(--border);
        font-size: 16px;
        padding: 12px;
        box-sizing: border-box;
      }
      button {
        border: none;
        background: var(--primary);
        color: #fff;
        font-weight: 600;
        cursor: pointer;
      }
      button.secondary {
        background: #fff;
        color: var(--text);
        border: 1px solid var(--border);
      }
      .row { margin-top: 12px; }
      .sep {
        display: flex;
        align-items: center;
        color: var(--muted);
        font-size: 13px;
        margin: 18px 0;
      }
      .sep::before,
      .sep::after {
        content: "";
        flex: 1;
        border-bottom: 1px solid var(--border);
      }
      .sep::before { margin-right: 8px; }
      .sep::after { margin-left: 8px; }
      .error {
        color: var(--danger);
        font-size: 14px;
        min-height: 20px;
        margin-top: 10px;
      }
      .meta {
        margin-top: 14px;
        color: var(--muted);
        font-size: 12px;
        word-break: break-all;
      }
    </style>
  </head>
  <body>
    <main class="card">
      <h1>Flowz Login</h1>
      <p>Sign in to continue learning.</p>

      <button id="google-btn" type="button">Continue with Google</button>

      <div class="sep">or</div>

      <form id="email-form">
        <input id="email" name="email" type="email" autocomplete="email" placeholder="Email" required />
        <div class="row"></div>
        <input id="password" name="password" type="password" autocomplete="current-password" placeholder="Password" required />
        <div class="row"></div>
        <button type="submit" class="secondary">Sign in</button>
      </form>

      <div class="error" id="error"></div>

      <div class="meta">return_to: ${safe.returnTo}</div>
      <div class="meta">app_origin: ${safe.appOrigin}</div>
    </main>

    <script>
      const config = {
        returnTo: ${JSON.stringify(returnTo)},
        appOrigin: ${JSON.stringify(appOrigin)},
        authDomain: ${JSON.stringify(normalizeAuthDomain(authDomain))},
        publicToken: ${JSON.stringify(publicToken)},
        projectId: ${JSON.stringify(projectId || '')},
      };

      const errorNode = document.getElementById('error');
      const googleBtn = document.getElementById('google-btn');
      const emailForm = document.getElementById('email-form');

      function setError(message) {
        errorNode.textContent = message || '';
      }

      function buildStytchBase() {
        return 'https://' + config.authDomain.replace(/^https?:\/\//, '').replace(/\/$/, '');
      }

      function redirectToCallbackWithToken(tokenType, token) {
        const callback = new URL(config.returnTo);
        callback.searchParams.set('stytch_token_type', tokenType);
        callback.searchParams.set('token', token);
        window.location.assign(callback.toString());
      }

      googleBtn.addEventListener('click', () => {
        setError('');
        const base = buildStytchBase();
        const start = new URL(base + '/v1/public/oauth/google/start');
        start.searchParams.set('public_token', config.publicToken);
        start.searchParams.set('login_redirect_url', config.returnTo);
        start.searchParams.set('signup_redirect_url', config.returnTo);
        if (config.projectId) {
          start.searchParams.set('project_id', config.projectId);
        }
        window.location.assign(start.toString());
      });

      emailForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        setError('');
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        if (!email || !password) {
          setError('Email and password are required.');
          return;
        }

        const base = buildStytchBase();
        const endpoint = base + '/v1/public/passwords/authenticate';
        const body = {
          public_token: config.publicToken,
          email,
          password,
          session_duration_minutes: 60,
        };
        if (config.projectId) {
          body.project_id = config.projectId;
        }

        try {
          const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok) {
            throw new Error(payload.error_message || payload.error || ('Sign-in failed (' + response.status + ').'));
          }
          const token =
            payload.session_token ||
            payload.session_jwt ||
            payload.session?.session_token ||
            payload.session?.session_jwt;
          if (!token) {
            throw new Error('Stytch response did not include a session token.');
          }
          redirectToCallbackWithToken('session', token);
        } catch (error) {
          setError(error?.message || 'Could not sign in.');
        }
      });
    </script>
  </body>
</html>`;
}

export function normalizeAuthDomain(value) {
  const trimmed = (value || '').trim();
  if (!trimmed) {
    return '';
  }
  return trimmed.replace(/^https?:\/\//, '').replace(/\/$/, '');
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function toBase64(value) {
  if (typeof btoa === 'function') {
    return btoa(value);
  }
  return Buffer.from(value, 'utf8').toString('base64');
}
