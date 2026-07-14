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
 * Trust: external requests can never carry forged headers — Traefik's
 * strip-auth-headers middleware removes inbound X-Auth-Request-* on every
 * router before mpass-auth re-adds them. Inside the docker network the
 * boundary is the network itself, the same model the sibling MCP servers use
 * for their identity-header paths.
 *
 * Returns null when Cognito mode is off or no header is present, in which
 * case the caller falls back to the upstream ?userToken= pairing untouched.
 */

import type * as http from "node:http";
import { createLogger } from "../logger";
import { usablePairingEmail } from "./cognito";
import { monetaAuthEnabled } from "./config";

const logger = createLogger("moneta.bridge");

function headerValue(request: http.IncomingMessage, name: string): string | null {
    const raw = request.headers[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    const trimmed = value?.trim();
    return trimmed ? trimmed : null;
}

/** Short non-reversible marker for log correlation — never the full identifier. */
function fingerprint(value: string | null): string {
    return value ? `${value.slice(0, 8)}…` : "<unset>";
}

export function monetaIdentityFromUpgrade(request: http.IncomingMessage): string | null {
    if (!monetaAuthEnabled()) {
        return null;
    }
    const emailHeader = headerValue(request, "x-auth-request-email");
    const userHeader = headerValue(request, "x-auth-request-user");
    const identity = usablePairingEmail(emailHeader) ?? userHeader;
    // Fingerprints only at info — full identifiers would leak PII into
    // production logs. Raw header values are available at debug for pairing
    // diagnosis (the dev overlay runs with PENPOT_MCP_LOG_LEVEL=debug).
    logger.info(
        "Plugin connection identity: %s (email header=%s, user header=%s)",
        identity ? fingerprint(identity) : "<none — falling back to ?userToken>",
        fingerprint(emailHeader),
        fingerprint(userHeader)
    );
    logger.debug(
        "Plugin connection identity (full): %s (email header=%s, user header=%s)",
        identity ?? "<none>",
        emailHeader ?? "<unset>",
        userHeader ?? "<unset>"
    );
    return identity;
}
