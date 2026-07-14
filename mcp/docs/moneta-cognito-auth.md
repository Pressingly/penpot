# Moneta fork — Cognito OAuth gate

This document covers the Pressingly/Moneta fork additions that put the Penpot
MCP server behind AWS Cognito / mPass SSO, mirroring `surfsense-mcp-server`
and `plane-mcp-server`. Everything lives in
`packages/server/src/moneta/`; upstream files carry three one-line hooks
(`index.ts`, `PenpotMcpServer.ts`, `PluginBridge.ts`).

## How the two legs pair

```
MCP client (Claude/Cursor)                Penpot user's browser
        │                                          │
        ▼ Bearer (Cognito access token)            ▼ _oauth2_proxy cookie
https://design-mcp.<domain>/mcp           wss://design.<domain>/mcp/ws
        │ Traefik: strip-auth-headers only         │ Traefik: mpass-auth ForwardAuth
        ▼                                          ▼ + X-Auth-Request-Email injected
   Cognito gate (this fork)               penpot-frontend nginx → :4402
        │ identity = id_token email                │ identity = header email
        └────────────► pair by equality ◄──────────┘
                  (PluginBridge clientsByToken)
```

- **MCP leg.** `/mcp` is *not* behind mPass. The server is its own OAuth 2.0
  authorization server (RFC 8414/9728 discovery, RFC 7591 DCR shim,
  `/authorize` + `/token` proxied to Cognito with a two-hop redirect through
  `{MCP_BASE_URL}/auth/callback`), so MCP clients auto-OAuth — no manual
  token paste. Inbound Bearers are Cognito **access tokens**, JWKS-verified
  per request.
- **Pairing identity.** A Cognito access token has no `email` and an opaque
  UUID `username` for federated users, so identity comes from the **id_token**
  captured at code/refresh exchange (userInfo endpoint as self-healing
  fallback), precedence `email → cognito:username → access-token username` —
  the same order oauth2-proxy uses for `X-Auth-Request-Email` /
  `X-Auth-Request-User`. No identity → fail closed (401).
- **Plugin leg.** Unchanged for the user: the Penpot plugin connects to
  `wss://design.<domain>/mcp/ws` (the URL penpot's `cfg/mcp-ws-uri` already
  produces), which traverses mPass. The bridge prefers the injected
  `X-Auth-Request-Email` header over the upstream `?userToken=` JWE.
- The resolved identity is exposed to the untouched upstream handlers as
  `req.query.userToken`, so session bookkeeping and `PluginBridge` pairing
  work exactly as upstream wrote them. Each `mcp-session-id` is additionally
  pinned to the identity that created it.

In Cognito mode multi-user mode is forced on (`index.ts` hook), so the
single-user "any connected plugin" fallback can never cross users. The
upstream `/mcp/stream?userToken=<JWE>` path effectively retires in this mode
(requests without a Bearer get 401); MCP clients use
`https://design-mcp.<domain>/mcp` instead of the URL shown in Penpot's UI.

## Environment

| Variable | Purpose |
|---|---|
| `COGNITO_USER_POOL_ID` | Enables Cognito mode (its presence is the switch). |
| `COGNITO_AWS_REGION` / `AWS_REGION` | Cognito region. |
| `OIDC_CLIENT_ID` | Pre-registered Cognito app client (shared with the other MCPs). |
| `OIDC_CLIENT_SECRET` | Optional — omit for public/PKCE clients. |
| `MCP_BASE_URL` | Public URL of this server, e.g. `https://design-mcp.<domain>`. |
| `MCP_ALLOWED_ORIGINS` | CSV CORS allow-list, or `*` (dev/Inspector). |
| `MCP_ALLOWED_CLIENT_REDIRECT_URIS` | CSV allow-list for DCR redirect URIs; unset = allow all. |
| `MCP_OAUTH_STORAGE_URL` | `redis://valkey:6379/13` — encrypted OAuth state (AES-256-GCM, key HKDF-derived from `OIDC_CLIENT_SECRET` or `MCP_JWT_SIGNING_KEY`). Unset = in-memory. |
| `MCP_JWT_SIGNING_KEY` | Storage-encryption key material when there is no client secret. |
| `MCP_ENV` | `production` logs a warning when storage is in-memory. |

Valkey DB allocation: 11 = surfsense-mcp, 12 = plane-mcp, **13 = penpot-mcp**.

## One-time IdP step

Add `https://design-mcp.<domain>/auth/callback` to the Cognito app client's
allowed callback URLs (same app client as the sibling MCPs — no new client).

## Devstack

Service `penpot-mcp` in `foss-server-bundle/docker-compose.dev.yml` (profiles
`penpot-mcp` / `mcp`): Traefik router `design-mcp.<domain>` →
`penpot-mcp:4401` with `strip-auth-headers` only, healthcheck on `/healthz`.
Rebuild with `make dev.build.penpot.mcp`. Remember `PENPOT_MCP_URI` /
`PENPOT_MCP_URI_WS` in `.env` so penpot-frontend's nginx proxies `/mcp/ws` to
this server (the plugin leg).

Local smoke test without Cognito reachability: start with a fake pool id and
probe `GET /healthz`, `GET /.well-known/oauth-authorization-server`,
`POST /register`, and confirm `/mcp` answers 401 with a `WWW-Authenticate`
challenge.
