/**
 * Moneta fork — installs the Cognito OAuth gate onto the server's Express app.
 *
 * Called from PenpotMcpServer.start() (one guarded line) BEFORE the upstream
 * /mcp /sse /messages routes are registered, so everything here is plain
 * middleware ordering — no upstream handler is modified:
 *
 *   1. /healthz                — unauthenticated, for the compose healthcheck.
 *   2. CORS                    — MCP_ALLOWED_ORIGINS; answers preflight before auth.
 *   3. mcpAuthRouter           — /.well-known discovery, /register (DCR shim),
 *                                /authorize, /token, /revoke (SDK-provided).
 *   4. /auth/callback          — the upstream Cognito redirect target.
 *   5. Bearer guard            — JWKS-validates the Cognito access token on
 *                                /mcp, /sse and /messages.
 *   6. Session binding         — pins each mcp-session-id to the identity that
 *                                created it (defense-in-depth against session-id reuse
 *                                across users; the ids are unguessable UUIDs).
 *   7. userToken rewrite       — exposes the resolved identity as
 *                                req.query.userToken, which is exactly what the
 *                                untouched upstream handlers consume for plugin pairing.
 */

import type { Logger } from "pino";
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { CognitoClient } from "./cognito";
import { loadMonetaAuthConfig, UPSTREAM_SCOPE } from "./config";
import { CognitoProxyProvider } from "./provider";
import { buildOAuthStorage } from "./storage";

/** Express types are kept loose ("any") to match the host class's `app: any`. */
type ExpressApp = any;

const PROTECTED_PATHS = ["/mcp", "/sse", "/messages"];
const SESSION_BINDING_TTL_MS = 24 * 3600 * 1000;

function corsMiddleware(allowedOrigins: string[]) {
    const allowAll = allowedOrigins.includes("*");
    return (req: any, res: any, next: any) => {
        const origin = req.headers.origin as string | undefined;
        if (origin && (allowAll || allowedOrigins.includes(origin))) {
            res.setHeader("Access-Control-Allow-Origin", allowAll ? "*" : origin);
            res.setHeader("Vary", "Origin");
            // Mcp-Session-Id must be readable by browser-based clients (MCP Inspector).
            res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate");
        }
        if (req.method === "OPTIONS") {
            res.setHeader(
                "Access-Control-Allow-Methods",
                (req.headers["access-control-request-method"] as string | undefined) ?? "GET, POST, DELETE, OPTIONS"
            );
            res.setHeader(
                "Access-Control-Allow-Headers",
                (req.headers["access-control-request-headers"] as string | undefined) ??
                    "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-Id"
            );
            res.setHeader("Access-Control-Max-Age", "86400");
            res.status(204).end();
            return;
        }
        next();
    };
}

/**
 * Pins each MCP session id to the identity that first used it. The upstream
 * streamable handler keys plugin pairing on the session's stored userToken, so
 * without this a caller presenting a *different* user's valid Cognito token
 * could attach to an existing session id and execute in the original user's
 * Penpot plugin.
 */
function sessionBindingMiddleware(logger: Logger) {
    const bindings = new Map<string, { identity: string; expiresAt: number }>();
    const sweep = setInterval(() => {
        const now = Date.now();
        for (const [key, value] of bindings) {
            if (value.expiresAt <= now) {
                bindings.delete(key);
            }
        }
    }, 60_000);
    sweep.unref();

    return (req: any, res: any, next: any) => {
        const sessionId =
            (req.headers["mcp-session-id"] as string | undefined) ??
            (typeof req.query.sessionId === "string" ? (req.query.sessionId as string) : undefined);
        const identity = req.auth?.extra?.identity as string | undefined;
        if (!sessionId || !identity) {
            next();
            return;
        }
        const existing = bindings.get(sessionId);
        if (existing && existing.expiresAt > Date.now() && existing.identity !== identity) {
            logger.warn("Rejected session reuse across identities (session=%s)", sessionId.slice(0, 8));
            res.status(403).json({ error: "forbidden", error_description: "Session belongs to a different user" });
            return;
        }
        bindings.set(sessionId, { identity, expiresAt: Date.now() + SESSION_BINDING_TTL_MS });
        next();
    };
}

/**
 * Replaces req.query.userToken with the Cognito-derived identity. The upstream
 * /mcp and /sse handlers read exactly that key when creating a session, and the
 * plugin bridge pairs connections by the same string — so this one property is
 * the entire integration surface with upstream. Express 5 exposes req.query as
 * a getter, hence defineProperty instead of assignment.
 */
function identityAsUserTokenMiddleware() {
    return (req: any, _res: any, next: any) => {
        const identity = req.auth?.extra?.identity as string | undefined;
        if (identity) {
            Object.defineProperty(req, "query", {
                value: { ...req.query, userToken: identity },
                writable: true,
                configurable: true,
            });
        }
        next();
    };
}

/**
 * Installs the Cognito OAuth gate. Must be called before the upstream routes
 * are registered (middleware order is the only sequencing Express honours).
 */
export async function installMonetaAuth(app: ExpressApp, logger: Logger): Promise<void> {
    const config = loadMonetaAuthConfig();
    if (config.allowedClientRedirectUris === null && config.isProduction) {
        // Matches the FastMCP siblings' default, but in production an open
        // allow-list lets any DCR client register any callback — the Cognito
        // login + PKCE still gate token issuance, yet a phished user could be
        // walked through authorizing a malicious client. Warn, don't fail.
        logger.warn(
            "MCP_ALLOWED_CLIENT_REDIRECT_URIS is unset — dynamic client registration accepts any " +
                "redirect_uri. Set an allow-list for production deployments."
        );
    }
    const storage = await buildOAuthStorage(config, logger);
    const cognito = new CognitoClient(config, logger);
    const provider = new CognitoProxyProvider(config, cognito, storage, logger);

    app.get("/healthz", (_req: any, res: any) => res.status(200).send("ok"));

    app.use(corsMiddleware(config.allowedOrigins));

    const baseUrl = new URL(config.baseUrl);
    const resourceServerUrl = new URL(`${config.baseUrl}/mcp`);
    // Quiet express-rate-limit's trust-proxy validation: behind Traefik every
    // request shares the proxy's source IP, which the library flags. Limits stay on.
    const rateLimit = { validate: false } as const;
    app.use(
        mcpAuthRouter({
            provider,
            issuerUrl: baseUrl,
            baseUrl,
            resourceServerUrl,
            resourceName: "Penpot MCP",
            scopesSupported: UPSTREAM_SCOPE.split(" "),
            authorizationOptions: { rateLimit },
            tokenOptions: { rateLimit },
            clientRegistrationOptions: { rateLimit },
        })
    );

    app.get("/auth/callback", (req: any, res: any) => {
        provider.handleCallback(req, res).catch((error: unknown) => {
            logger.error(error, "Unhandled error in /auth/callback");
            if (!res.headersSent) {
                res.status(500).send("Authorization callback failed");
            }
        });
    });

    const guard = requireBearerAuth({
        verifier: provider,
        resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceServerUrl),
    });
    app.use(PROTECTED_PATHS, guard, sessionBindingMiddleware(logger), identityAsUserTokenMiddleware());

    logger.info("Cognito OAuth gate installed (issuer=%s, callback=%s)", config.issuer, config.callbackUrl);
}
