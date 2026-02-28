# flowz-auth-gateway

Cloudflare Worker for hosted Learner App auth.

## Endpoints

- `GET /health`
  - Returns `200` JSON: `{ "ok": true, "service": "flowz-auth-gateway" }`
- `GET /login?return_to=...&app_origin=...`
  - Returns hosted login HTML (Google + email/password).
  - Validates `return_to` origin against `ALLOWED_ORIGINS` or `DEFAULT_RETURN_TO` origin.
- `POST /auth/stytch/session/authenticate`
  - Accepts `{ "session_token": "..." }`.
  - Calls Stytch server API `POST /v1/sessions/authenticate` with Basic auth.
  - Returns minimal JSON:
    - `user_id`
    - `session_jwt`
    - `session_token`
    - `expires_at`

Rate limit:
- `/auth/stytch/session/authenticate` is limited to `10 requests / minute / IP` via Durable Object.

## Required Variables and Secrets

Set these in Cloudflare Worker settings or via Wrangler:

Variables:
- `ALLOWED_ORIGINS` (comma-separated absolute origins)
- `DEFAULT_RETURN_TO` (absolute callback URL)
- `STYTCH_AUTH_DOMAIN` (e.g. `flowzlogin-test.sinhasumit.com`)
- `STYTCH_PUBLIC_TOKEN` (public token for hosted login page)
- `STYTCH_API_BASE` (default `https://test.stytch.com`)

Secrets:
- `STYTCH_PROJECT_ID`
- `STYTCH_SECRET`

## Local Dev

```bash
npm install
npm run lint
npm test
```

Run worker locally:

```bash
npx wrangler dev
```

## Deploy with Wrangler

1. Authenticate Wrangler:
```bash
npx wrangler login
```
2. Set secrets:
```bash
npx wrangler secret put STYTCH_PROJECT_ID
npx wrangler secret put STYTCH_SECRET
```
3. Deploy:
```bash
npx wrangler deploy
```

## Dashboard Deploy (No CLI)

1. Cloudflare Dashboard -> Workers & Pages -> Create application -> Workers -> Create Worker.
2. Copy code from `src/index.js` into editor and save.
3. Settings -> Variables:
   - Add vars above.
   - Add secrets `STYTCH_PROJECT_ID` and `STYTCH_SECRET`.
4. Settings -> Durable Objects:
   - Bind class `RateLimiter` with binding name `RATE_LIMITER`.
5. Deploy.
