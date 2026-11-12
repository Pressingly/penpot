/**
 * Moneta fork — plugin-side identity for the WebSocket bridge.
 *
 * In the devstack the plugin connects from the user's browser to
 * wss://design.<domain>/mcp/ws, which traverses Traefik's mpass-auth
 * ForwardAuth: oauth2-proxy validates the shared SSO cookie and Traefik
 * injects X-Auth-Request-Email / X-Auth-Request-User into the upgrade request
 * before nginx proxies it to this server. Reading those headers gives the
 * plugin connection the same identity string that the Cognito gate derives
 * for MCP sessions, so the two sides pair by simple equality.
 *
 * Precedence mirrors cognito.pickPairingIdentity exactly: a *usable* email
 * first (see cognito.usablePairingEmail — in the Moneta pool this header
 * carries the bare askii user id, the join key with the MCP leg's native
 * twin identity), then X-Auth-Request-User, which oauth2-proxy fills from
 * the `cognito:username` claim (OAUTH2_PROXY_USER_ID_CLAIM).
 *
 * Trust: the docker backend network is not a boundary — any container on it
 * can reach this port directly and set X-Auth-Request-* itself. Traefik's
 * SSO router therefore also sets X-Mpass-Edge-Secret to PENPOT_MPASS_EDGE_SECRET,
 * and the identity headers are trusted only when that header matches. An
 * unusable secret trusts nothing.
 *
 * In Cognito mode the ?userToken= query parameter is never consulted: it is
 * caller-controlled, so accepting it would let a direct caller claim any
 * user's pairing identity. Without a trusted identity the connection gets no
 * token and the multi-user check in PluginBridge rejects it.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import type * as http from "node:http";
import { createLogger } from "../logger";
import { usablePairingEmail } from "./cognito";
import { monetaAuthEnabled } from "./config";

const logger = createLogger("moneta.bridge");

export const EDGE_SECRET_ENV = "PENPOT_MPASS_EDGE_SECRET";
export const EDGE_SECRET_HEADER = "x-mpass-edge-secret";
export const MIN_EDGE_SECRET_LENGTH = 32;
const PLACEHOLDER_PREFIX = "CHANGE_ME_";

export interface EdgeGate {
    /** Why the configured secret is unusable, or null when it is usable. */
    readonly problem: string | null;
    isFromEdge(request: http.IncomingMessage): boolean;
}

function headerValue(request: http.IncomingMessage, name: string): string | null {
    const raw = request.headers[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    const trimmed = value?.trim();
    return trimmed ? trimmed : null;
}

function sha256(value: string): Buffer {
    return createHash("sha256").update(value, "utf8").digest();
}

export function edgeSecretProblem(rawSecret: string | undefined): string | null {
    const secret = rawSecret?.trim() ?? "";
    if (!secret) {
        return `${EDGE_SECRET_ENV} is unset`;
    }
    if (secret.startsWith(PLACEHOLDER_PREFIX)) {
        return `${EDGE_SECRET_ENV} is still the ${PLACEHOLDER_PREFIX} placeholder`;
    }
    if (secret.length < MIN_EDGE_SECRET_LENGTH) {
        return `${EDGE_SECRET_ENV} is shorter than ${MIN_EDGE_SECRET_LENGTH} characters`;
    }
    return null;
}

export function createEdgeGate(rawSecret: string | undefined): EdgeGate {
    const problem = edgeSecretProblem(rawSecret);
    if (problem) {
        return { problem, isFromEdge: () => false };
    }
    const expectedDigest = sha256(rawSecret!.trim());
    return {
        problem: null,
        isFromEdge: (request) =>
            timingSafeEqual(expectedDigest, sha256(headerValue(request, EDGE_SECRET_HEADER) ?? "")),
    };
}

let processEdgeGate: EdgeGate | undefined;

/**
 * The process-wide gate, read from the environment once. The first call logs
 * an unusable secret at error level, naming the problem but never the value;
 * installMonetaAuth makes that first call at startup.
 */
export function edgeGate(): EdgeGate {
    if (!processEdgeGate) {
        processEdgeGate = createEdgeGate(process.env[EDGE_SECRET_ENV]);
        if (processEdgeGate.problem) {
            logger.error(
                "%s; plugin bridge identity headers will not be trusted and every plugin connection will be refused",
                processEdgeGate.problem
            );
        }
    }
    return processEdgeGate;
}

/** Short non-reversible marker for log correlation — never the full identifier. */
function fingerprint(value: string | null): string {
    return value ? `${value.slice(0, 8)}…` : "<unset>";
}

/** mPass ids are safe to log; anything shaped like an email is not. */
function loggableIdentity(value: string | null): string {
    if (!value) {
        return "<none>";
    }
    return value.includes("@") ? "<redacted email>" : value;
}

function requestPath(request: http.IncomingMessage): string {
    return (request.url ?? "").split("?")[0] || "<unknown>";
}

function warnUntrusted(request: http.IncomingMessage, claimedIdentity: string | null, gate: EdgeGate): void {
    logger.warn(
        "Ignoring identity headers without a valid %s (%s): claimed=%s path=%s remote=%s",
        EDGE_SECRET_HEADER,
        gate.problem ?? "secret mismatch",
        loggableIdentity(claimedIdentity),
        requestPath(request),
        request.socket?.remoteAddress ?? "<unknown>"
    );
}

export function monetaIdentityFromUpgrade(request: http.IncomingMessage, gate: EdgeGate = edgeGate()): string | null {
    if (!monetaAuthEnabled()) {
        return null;
    }
    const emailHeader = headerValue(request, "x-auth-request-email");
    const userHeader = headerValue(request, "x-auth-request-user");
    const claimedIdentity = usablePairingEmail(emailHeader) ?? userHeader;
    if (!gate.isFromEdge(request)) {
        if (emailHeader || userHeader) {
            warnUntrusted(request, claimedIdentity, gate);
        }
        return null;
    }
    // Fingerprints only at info — full identifiers would leak PII into
    // production logs. Raw header values are available at debug for pairing
    // diagnosis (the dev overlay runs with PENPOT_MCP_LOG_LEVEL=debug).
    logger.info(
        "Plugin connection identity: %s (email header=%s, user header=%s)",
        claimedIdentity ? fingerprint(claimedIdentity) : "<none — connection will be refused>",
        fingerprint(emailHeader),
        fingerprint(userHeader)
    );
    logger.debug(
        "Plugin connection identity (full): %s (email header=%s, user header=%s)",
        claimedIdentity ?? "<none>",
        emailHeader ?? "<unset>",
        userHeader ?? "<unset>"
    );
    return claimedIdentity;
}

/**
 * The pairing token for a plugin connection. Upstream behaviour (the
 * ?userToken= query parameter) when Cognito mode is off; only the edge-trusted
 * identity headers when it is on.
 */
export function pluginUserToken(
    request: http.IncomingMessage,
    queryUserToken: string | null,
    gate?: EdgeGate
): string | null {
    return monetaAuthEnabled() ? monetaIdentityFromUpgrade(request, gate) : queryUserToken;
}
