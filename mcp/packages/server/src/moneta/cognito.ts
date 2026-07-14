/**
 * Moneta fork — AWS Cognito client: OIDC discovery, JWKS validation of access
 * tokens, code/refresh exchanges, and identity extraction.
 *
 * Identity precedence (why the id_token matters)
 * ----------------------------------------------
 * A Cognito *access* token carries no `email` claim and, for users federated
 * from an external IdP, a `username` that is an opaque Cognito UUID. The
 * mPass browser flow (oauth2-proxy) keys on the id_token's `email` /
 * `cognito:username` claims, so to pair an MCP session with the same human as
 * the Penpot web login we must derive identity from the **id_token** captured
 * at token-exchange time (or from the userInfo endpoint, which serves the
 * same attributes). This mirrors surfsense-mcp's SurfSenseCognitoProvider and
 * plane-mcp's PlaneCognitoProvider.
 *
 * The id_token is decoded WITHOUT signature verification, which is safe here:
 * it arrives directly from Cognito's token endpoint over this server's own
 * TLS call — never from the MCP client — and is only used to label sessions,
 * while the inbound access token is independently JWKS-verified per request.
 */

import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTPayload } from "jose";
import type { Logger } from "pino";
import type { MonetaAuthConfig } from "./config";
import { UPSTREAM_SCOPE } from "./config";

export interface CognitoTokenResponse {
    access_token: string;
    token_type?: string;
    expires_in?: number;
    refresh_token?: string;
    id_token?: string;
    scope?: string;
}

export interface CognitoIdentity {
    email?: string;
    /** The id_token's cognito:username — the human handle mPass keys on. */
    username?: string;
}

interface DiscoveryDocument {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
    userinfo_endpoint?: string;
    revocation_endpoint?: string;
}

const EMAIL_CLAIM = "email";
const COGNITO_USERNAME_CLAIM = "cognito:username";

/** Extracts pairing identity claims from a Cognito id_token (unverified — see module docstring). */
export function identityFromIdToken(idToken: string, logger?: Logger): CognitoIdentity {
    try {
        const claims = decodeJwt(idToken);
        const identity: CognitoIdentity = {};
        if (typeof claims[EMAIL_CLAIM] === "string" && claims[EMAIL_CLAIM]) {
            identity.email = claims[EMAIL_CLAIM] as string;
        }
        if (typeof claims[COGNITO_USERNAME_CLAIM] === "string" && claims[COGNITO_USERNAME_CLAIM]) {
            identity.username = claims[COGNITO_USERNAME_CLAIM] as string;
        }
        return identity;
    } catch (error) {
        logger?.warn(error, "Failed to decode Cognito id_token");
        return {};
    }
}

/**
 * Email-claim values usable as a pairing key. Two Moneta-pool realities shape
 * this rule:
 *
 * - Humans exist twice in the pool: a *federated* identity (used by the mPass
 *   browser login via Moneta's own login bridge; `cognito:username` is an
 *   opaque UUID, email attribute carries the bare askii user id, e.g.
 *   "1020010000020127") and a *native* twin (the only login the Cognito
 *   hosted UI offers — no IdPs are enabled on it; `cognito:username` IS the
 *   askii id, email is a mapping placeholder). The bare askii id in the email
 *   claim/header is therefore the join key between the browser (plugin) leg
 *   and the MCP leg — it must be accepted even though it has no "@".
 * - Native accounts carry the literal placeholder "cognito:default_val" in
 *   the email claim — identical for every user, so pairing on it would funnel
 *   all users onto one key and cross their plugin sessions. Anything in the
 *   "cognito:"-namespace is mapping junk, never a real identifier.
 *
 * The same rule runs on the plugin-bridge side for X-Auth-Request-Email.
 */
export function usablePairingEmail(value: string | undefined | null): string | null {
    if (!value || value.startsWith("cognito:")) {
        return null;
    }
    return value;
}

/**
 * Resolves the single pairing string for a user, in the same precedence order
 * the plugin-bridge side uses for mPass identity headers (X-Auth-Request-Email
 * first, then X-Auth-Request-User): usable email → cognito:username →
 * access-token username. With the Moneta pool's twin identities this makes
 * both legs converge on the askii user id: the bridge's federated session
 * resolves it from the email header, the MCP leg's native login resolves it
 * from `cognito:username`. Returns null when nothing usable is present —
 * callers fail closed rather than pair against an opaque UUID `sub`.
 */
export function pickPairingIdentity(identity: CognitoIdentity, accessTokenUsername?: string): string | null {
    const email = usablePairingEmail(identity.email);
    if (email) {
        return email;
    }
    if (identity.username) {
        return identity.username;
    }
    if (accessTokenUsername) {
        return accessTokenUsername;
    }
    return null;
}

export class CognitoClient {
    private discoveryPromise: Promise<DiscoveryDocument> | undefined;
    private jwks: ReturnType<typeof createRemoteJWKSet> | undefined;

    constructor(
        private readonly config: MonetaAuthConfig,
        private readonly logger: Logger
    ) {}

    /** Fetches and caches the pool's OIDC discovery document; a failed fetch is retried on the next call. */
    discovery(): Promise<DiscoveryDocument> {
        if (!this.discoveryPromise) {
            this.discoveryPromise = this.fetchDiscovery().catch((error) => {
                this.discoveryPromise = undefined;
                throw error;
            });
        }
        return this.discoveryPromise;
    }

    private async fetchDiscovery(): Promise<DiscoveryDocument> {
        const url = `${this.config.issuer}/.well-known/openid-configuration`;
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Cognito discovery failed: ${response.status} ${response.statusText} (${url})`);
        }
        const doc = (await response.json()) as DiscoveryDocument;
        this.logger.info("Cognito discovery loaded (issuer=%s)", doc.issuer);
        return doc;
    }

    /**
     * Validates an inbound Bearer as a Cognito **access** token: JWKS
     * signature, issuer, token_use, and that it was issued to our app client.
     * Throws on any failure; callers translate into an OAuth 401.
     */
    async verifyAccessToken(token: string): Promise<JWTPayload> {
        const discovery = await this.discovery();
        if (!this.jwks) {
            this.jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
        }
        const { payload } = await jwtVerify(token, this.jwks, { issuer: this.config.issuer });
        if (payload.token_use !== "access") {
            throw new Error(`Expected a Cognito access token, got token_use=${String(payload.token_use)}`);
        }
        if (payload.client_id !== this.config.clientId) {
            throw new Error("Access token was issued to a different client");
        }
        return payload;
    }

    private async tokenRequest(params: Record<string, string>): Promise<CognitoTokenResponse> {
        const discovery = await this.discovery();
        const body = new URLSearchParams({ ...params, client_id: this.config.clientId });
        const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
        if (this.config.clientSecret) {
            const basic = Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString("base64");
            headers["Authorization"] = `Basic ${basic}`;
        }
        const response = await fetch(discovery.token_endpoint, { method: "POST", headers, body });
        if (!response.ok) {
            const detail = await response.text().catch(() => "");
            throw new Error(`Cognito token endpoint returned ${response.status}: ${detail.slice(0, 300)}`);
        }
        return (await response.json()) as CognitoTokenResponse;
    }

    /** Exchanges the upstream authorization code received on /auth/callback. */
    exchangeCode(code: string, codeVerifier: string): Promise<CognitoTokenResponse> {
        return this.tokenRequest({
            grant_type: "authorization_code",
            code,
            redirect_uri: this.config.callbackUrl,
            code_verifier: codeVerifier,
        });
    }

    /** Proxies a refresh_token grant. Cognito returns a fresh access + id token (no new refresh token). */
    refresh(refreshToken: string): Promise<CognitoTokenResponse> {
        return this.tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
    }

    /**
     * Fetches identity attributes for a live access token. Fallback used when
     * the identity map has no entry for a (still valid) token — e.g. after a
     * restart with in-memory storage — so sessions self-heal without a forced
     * re-auth. Returns null on any failure.
     */
    async userInfo(accessToken: string): Promise<CognitoIdentity | null> {
        const discovery = await this.discovery();
        if (!discovery.userinfo_endpoint) {
            return null;
        }
        try {
            const response = await fetch(discovery.userinfo_endpoint, {
                headers: { Authorization: `Bearer ${accessToken}` },
            });
            if (!response.ok) {
                this.logger.warn("Cognito userInfo returned %d", response.status);
                return null;
            }
            const attributes = (await response.json()) as Record<string, unknown>;
            const identity: CognitoIdentity = {};
            if (typeof attributes[EMAIL_CLAIM] === "string" && attributes[EMAIL_CLAIM]) {
                identity.email = attributes[EMAIL_CLAIM] as string;
            }
            // userInfo exposes cognito:username as plain `username`.
            if (typeof attributes["username"] === "string" && attributes["username"]) {
                identity.username = attributes["username"] as string;
            }
            return identity;
        } catch (error) {
            this.logger.warn(error, "Cognito userInfo request failed");
            return null;
        }
    }

    /** Best-effort revocation of a refresh token at Cognito; failures are logged, never thrown. */
    async revoke(token: string): Promise<void> {
        try {
            const discovery = await this.discovery();
            if (!discovery.revocation_endpoint) {
                return;
            }
            const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
            if (this.config.clientSecret) {
                const basic = Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString("base64");
                headers["Authorization"] = `Basic ${basic}`;
            }
            await fetch(discovery.revocation_endpoint, {
                method: "POST",
                headers,
                body: new URLSearchParams({ token, client_id: this.config.clientId }),
            });
        } catch (error) {
            this.logger.warn(error, "Cognito token revocation failed (ignored)");
        }
    }

    /** Builds the upstream authorize redirect with our own callback, state and PKCE pair. */
    async authorizeUrl(state: string, codeChallenge: string): Promise<string> {
        const discovery = await this.discovery();
        const url = new URL(discovery.authorization_endpoint);
        url.searchParams.set("response_type", "code");
        url.searchParams.set("client_id", this.config.clientId);
        url.searchParams.set("redirect_uri", this.config.callbackUrl);
        url.searchParams.set("scope", UPSTREAM_SCOPE);
        url.searchParams.set("state", state);
        url.searchParams.set("code_challenge", codeChallenge);
        url.searchParams.set("code_challenge_method", "S256");
        return url.href;
    }
}
