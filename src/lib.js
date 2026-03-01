const DEFAULT_STYTCH_API_BASE = 'https://test.stytch.com';
export const STYTCH_CREDENTIALS_INVALID_MESSAGE =
  'STYTCH_PROJECT_ID/SECRET invalid. Ensure you set Stytch Project credentials, not M2M/Connected App.';

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
  return buildStytchRequest('/v1/sessions/authenticate', { session_token: sessionToken }, env);
}

export function buildStytchPasswordAuthenticateRequest(email, password, env) {
  return buildStytchRequest(
    '/v1/passwords/authenticate',
    {
      email,
      password,
      session_duration_minutes: 60,
    },
    env,
  );
}

export async function authenticateSessionWithStytch(sessionToken, env, fetchImpl = fetch) {
  const { url, init, diagnostics } = buildStytchAuthenticateRequest(sessionToken, env);
  const response = await fetchImpl(url, init);
  const rawText = await response.text();
  logStytchCallDiagnostics({ ...diagnostics, stytchStatus: response.status });

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

export async function authenticateEmailPasswordWithStytch(email, password, env, fetchImpl = fetch) {
  const { url, init, diagnostics } = buildStytchPasswordAuthenticateRequest(email, password, env);
  const response = await fetchImpl(url, init);
  const rawText = await response.text();
  logStytchCallDiagnostics({ ...diagnostics, stytchStatus: response.status });

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
      `Stytch password authenticate failed with status ${response.status}.`;
    const error = new Error(errorMessage);
    error.statusCode = response.status;
    error.responseBody = rawText;
    throw error;
  }

  return payload;
}

export function buildStytchOauthAuthenticateRequest(oauthToken, sessionDurationMinutes, env) {
  return buildStytchRequest(
    '/v1/oauth/authenticate',
    {
      token: oauthToken,
      session_duration_minutes: sessionDurationMinutes,
    },
    env,
  );
}

export async function authenticateOauthWithStytch(
  oauthToken,
  sessionDurationMinutes = 43200,
  env,
  fetchImpl = fetch,
) {
  const { url, init, diagnostics } = buildStytchOauthAuthenticateRequest(oauthToken, sessionDurationMinutes, env);
  const response = await fetchImpl(url, init);
  const rawText = await response.text();
  logStytchCallDiagnostics({ ...diagnostics, stytchStatus: response.status });

  let payload = {};
  if (rawText.trim()) {
    try {
      payload = JSON.parse(rawText);
    } catch {
      payload = {};
    }
  }

  const normalized = {
    user_id: payload.user_id || payload.user?.user_id || payload.user?.id || payload.session?.user_id || null,
    session_jwt: payload.session_jwt || payload.session?.session_jwt || null,
    session_token: payload.session_token || payload.session?.session_token || null,
    expires_at: payload.expires_at || payload.session?.expires_at || null,
  };

  if (!response.ok) {
    const errorMessage =
      payload.error_message ||
      payload.error ||
      payload.message ||
      `Stytch oauth authenticate failed with status ${response.status}.`;
    const error = new Error(errorMessage);
    error.statusCode = response.status;
    error.responseBody = rawText;
    throw error;
  }

  return normalized;
}

export function renderLoginPage({ returnTo, appOrigin, authDomain, publicToken }) {
  const normalizedAuthDomain = normalizeAuthDomain(authDomain);
  const googleStartUrl = buildGoogleStartUrl({
    returnTo,
    authDomain: normalizedAuthDomain,
    publicToken,
  });
  const emailPasswordAction = buildEmailPasswordAction({
    returnTo,
    appOrigin,
  });

  const safe = {
    returnTo: escapeHtml(returnTo),
    appOrigin: escapeHtml(appOrigin),
    googleStartUrl: escapeHtml(googleStartUrl),
    emailPasswordAction: escapeHtml(emailPasswordAction),
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
      .btn,
      button,
      input {
        width: 100%;
        border-radius: 10px;
        border: 1px solid var(--border);
        font-size: 16px;
        padding: 12px;
        box-sizing: border-box;
      }
      .btn,
      button {
        display: inline-block;
        text-decoration: none;
        text-align: center;
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

      <a class="btn" href="${safe.googleStartUrl}">Continue with Google</a>

      <div class="sep">or</div>

      <form method="POST" action="${safe.emailPasswordAction}">
        <input name="email" type="email" autocomplete="email" placeholder="Email" required />
        <div class="row"></div>
        <input name="password" type="password" autocomplete="current-password" placeholder="Password" required />
        <div class="row"></div>
        <button type="submit" class="secondary">Sign in</button>
      </form>

      <div class="meta">return_to: ${safe.returnTo}</div>
      <div class="meta">app_origin: ${safe.appOrigin}</div>
    </main>
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

export function validateStytchCredentials(env) {
  const projectId = (env.STYTCH_PROJECT_ID || '').trim();
  const secret = (env.STYTCH_SECRET || '').trim();
  const isValid = Boolean(projectId) && Boolean(secret) && projectId.startsWith('project-');
  return {
    projectId,
    secret,
    isValid,
  };
}

function buildStytchAuthorizationHeader(env) {
  const credentialState = validateStytchCredentials(env);
  if (!credentialState.isValid) {
    throw new Error(STYTCH_CREDENTIALS_INVALID_MESSAGE);
  }

  const { projectId, secret } = credentialState;
  const credentialPair = `${projectId}:${secret}`;
  return `Basic ${toBase64(credentialPair)}`;
}

function buildStytchRequest(stytchPath, body, env) {
  const apiBase = (env.STYTCH_API_BASE || DEFAULT_STYTCH_API_BASE).replace(/\/$/, '');
  const authorization = buildStytchAuthorizationHeader(env);
  const { projectId, secret } = validateStytchCredentials(env);

  return {
    url: `${apiBase}${stytchPath}`,
    init: {
      method: 'POST',
      headers: {
        Authorization: authorization,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    },
    diagnostics: {
      authorization,
      projectId,
      secretPresent: secret.length > 10,
      stytchApiBase: apiBase,
      stytchPath,
    },
  };
}

function logStytchCallDiagnostics({
  authorization,
  projectId,
  secretPresent,
  stytchApiBase,
  stytchPath,
  stytchStatus,
}) {
  console.log(
    JSON.stringify({
      auth_header_prefix: authorization.split(' ')[0] || '',
      project_id_prefix: projectId.slice(0, 12),
      project_id_has_expected_prefix:
        projectId.startsWith('project-test-') || projectId.startsWith('project-live-'),
      secret_present: secretPresent,
      stytch_api_base: stytchApiBase,
      stytch_path: stytchPath,
      stytch_status: stytchStatus,
    }),
  );
}

function buildGoogleStartUrl({ returnTo, authDomain, publicToken }) {
  const url = new URL(`https://${normalizeAuthDomain(authDomain)}/v1/public/oauth/google/start`);
  url.searchParams.set('public_token', publicToken);
  url.searchParams.set('login_redirect_url', returnTo);
  url.searchParams.set('signup_redirect_url', returnTo);
  return url.toString();
}

function buildEmailPasswordAction({ returnTo, appOrigin }) {
  const params = new URLSearchParams();
  params.set('return_to', returnTo);
  params.set('app_origin', appOrigin);
  return `/auth/email_password?${params.toString()}`;
}
