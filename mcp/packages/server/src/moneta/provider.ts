/**
 * Moneta fork — OAuth 2.0 authorization-server facade over AWS Cognito.
 *
 * Implements the MCP TypeScript SDK's `OAuthServerProvider` so that
 * `mcpAuthRouter` can publish RFC 8414 / 9728 discovery metadata, a DCR
 * `/register` shim, and `/authorize` + `/token` endpoints — making this
 * server self-describing for MCP clients (Claude, Cursor, MCP Inspector),
 * which then run the whole OAuth dance automatically. This is the TypeScript
 * counterpart of FastMCP's `AWSCognitoProvider` used by surfsense-mcp and
 * plane-mcp.
 *
 * Why a two-hop redirect (not a passthrough proxy)
 * ------------------------------------------------
 * Cognito has no dynamic client registration and only accepts pre-registered
 * redirect URIs, while MCP clients register arbitrary callback URLs via DCR.
 * So /authorize stores the client's request as a transaction and redirects to
 * Cognito with OUR fixed callback ({MCP_BASE_URL}/auth/callback — the one URL
 * registered on the Cognito app client); /auth/callback exchanges Cognito's
 * code server-side, captures the id_token identity, mints OUR single-use
 * authorization code, and redirects to the MCP client's own callback. The
 * client then redeems our code at /token and receives the Cognito tokens.
 *
 * The inbound Bearer on /mcp is the Cognito access token, JWKS-verified on
 * every request. Pairing identity (email) comes from the identity map written
 * at exchange/refresh time, with Cognito's userInfo endpoint as a self-healing
 * fallback; if no identity can be resolved the request fails closed with a 401
 * rather than letting an opaque-UUID identity through (it would pair with the
 * wrong — or no — Penpot plugin session).
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Request, Response } from "express";
import type { Logger } from "pino";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import {
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { CognitoClient, identityFromIdToken, pickPairingIdentity, type CognitoIdentity } from "./cognito";
import type { MonetaAuthConfig } from "./config";
import type { KeyValueStore } from "./storage";

const COLLECTION_CLIENTS = "clients";
const COLLECTION_TXNS = "txns";
const COLLECTION_CODES = "codes";
const COLLECTION_IDENTITY = "identity";

const CLIENT_TTL_SECONDS = 90 * 24 * 3600;
const TXN_TTL_SECONDS = 600;
const CODE_TTL_SECONDS = 120;
/** Used when Cognito's token response carries no expires_in (it always should). */
const DEFAULT_TOKEN_TTL_SECONDS = 3600;

/** In-flight /authorize transaction, persisted between the redirect to Cognito and our callback. */
interface AuthorizationTxn {
    clientId: string;
    redirectUri: string;
    /** The MCP client's PKCE challenge, validated by the SDK at /token. */
    codeChallenge: string;
    state?: string;
    /** Our own PKCE verifier for the upstream Cognito leg. */
    upstreamVerifier: string;
}

/** Payload behind one of our single-use authorization codes. */
interface CodeRecord {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    tokens: OAuthTokens;
}

function sha256(value: string): string {
    return createHash("sha256").update(value).digest("hex");
}

function base64url(buffer: Buffer): string {
    return buffer.toString("base64url");
}

/**
 * Matches an allow-list entry: exact, or prefix when the entry ends with '*'.
 * Wildcard matching is URL-aware: the candidate must share the entry's exact
 * origin (scheme + host + port) before the prefix test, so a too-broad entry
 * like "https://example.com*" can never match a host-extension such as
 * "https://example.com.evil/cb". Unparseable values never match.
 */
function redirectUriAllowed(uri: string, allowList: string[] | null): boolean {
    if (allowList === null) {
        return true;
    }
    return allowList.some((entry) => {
        if (!entry.endsWith("*")) {
            return uri === entry;
        }
        const prefix = entry.slice(0, -1);
        let entryOrigin: string;
        let uriOrigin: string;
        try {
            entryOrigin = new URL(prefix).origin;
            uriOrigin = new URL(uri).origin;
        } catch {
            return false;
        }
        return uriOrigin === entryOrigin && uri.startsWith(prefix);
    });
}

/**
 * DCR client store. The SDK's /register handler generates client_id/secret;
 * we only validate redirect URIs against MCP_ALLOWED_CLIENT_REDIRECT_URIS
 * (unset = allow all, matching the FastMCP servers' default — the real gate
 * is the Cognito login plus PKCE, not the registration).
 */
export class MonetaClientsStore implements OAuthRegisteredClientsStore {
    constructor(
        private readonly storage: KeyValueStore,
        private readonly allowedRedirectUris: string[] | null,
        private readonly logger: Logger
    ) {}

    async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
        const stored = await this.storage.get(COLLECTION_CLIENTS, clientId);
        return stored ? (JSON.parse(stored) as OAuthClientInformationFull) : undefined;
    }

    async registerClient(
        client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at"> &
            Partial<Pick<OAuthClientInformationFull, "client_id" | "client_id_issued_at">>
    ): Promise<OAuthClientInformationFull> {
        for (const uri of client.redirect_uris ?? []) {
            if (!redirectUriAllowed(uri, this.allowedRedirectUris)) {
                throw new InvalidRequestError(`redirect_uri is not allowed by this server: ${uri}`);
            }
        }
        const full = client as OAuthClientInformationFull;
        await this.storage.set(COLLECTION_CLIENTS, full.client_id, JSON.stringify(full), CLIENT_TTL_SECONDS);
        this.logger.info(
            "Registered MCP client %s (%s)",
            full.client_id,
            full.client_name ?? (full.redirect_uris ?? []).join(",")
        );
        return full;
    }
}

export class CognitoProxyProvider implements OAuthServerProvider {
    public readonly clientsStore: MonetaClientsStore;
    /** We validate the MCP client's PKCE locally; the upstream leg has its own verifier. */
    public readonly skipLocalPkceValidation = false;

    constructor(
        private readonly config: MonetaAuthConfig,
        private readonly cognito: CognitoClient,
        private readonly storage: KeyValueStore,
        private readonly logger: Logger
    ) {
        this.clientsStore = new MonetaClientsStore(storage, config.allowedClientRedirectUris, logger);
    }

    /**
     * First hop: park the client's authorize request as a transaction and
     * redirect the browser to Cognito with our fixed callback. The RFC 8707
     * `resource` parameter is intentionally dropped — Cognito does not support
     * it, same as the FastMCP-based siblings.
     */
    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        const txnId = randomUUID();
        const upstreamVerifier = base64url(randomBytes(48));
        const upstreamChallenge = base64url(createHash("sha256").update(upstreamVerifier).digest());
        const txn: AuthorizationTxn = {
            clientId: client.client_id,
            redirectUri: params.redirectUri,
            codeChallenge: params.codeChallenge,
            state: params.state,
            upstreamVerifier,
        };
        await this.storage.set(COLLECTION_TXNS, txnId, JSON.stringify(txn), TXN_TTL_SECONDS);
        const url = await this.cognito.authorizeUrl(txnId, upstreamChallenge);
        this.logger.info("authorize: client=%s txn=%s -> Cognito", client.client_id, txnId.slice(0, 8));
        res.redirect(url);
    }

    /**
     * Second hop: Cognito redirected back to {MCP_BASE_URL}/auth/callback.
     * Exchange the upstream code, capture the id_token identity, mint our own
     * single-use code and send the browser on to the MCP client's callback.
     */
    async handleCallback(req: Request, res: Response): Promise<void> {
        const state = typeof req.query.state === "string" ? req.query.state : undefined;
        const code = typeof req.query.code === "string" ? req.query.code : undefined;
        const upstreamError = typeof req.query.error === "string" ? req.query.error : undefined;
        const upstreamErrorDescription =
            typeof req.query.error_description === "string" ? req.query.error_description : undefined;

        const storedTxn = state ? await this.storage.get(COLLECTION_TXNS, state) : null;
        if (!storedTxn) {
            this.logger.warn("auth callback with unknown or expired state");
            res.status(400).send("Invalid or expired authorization request. Please retry from your MCP client.");
            return;
        }
        await this.storage.delete(COLLECTION_TXNS, state as string);
        const txn = JSON.parse(storedTxn) as AuthorizationTxn;

        const redirectError = (error: string, description: string): void => {
            const target = new URL(txn.redirectUri);
            target.searchParams.set("error", error);
            target.searchParams.set("error_description", description);
            if (txn.state !== undefined) {
                target.searchParams.set("state", txn.state);
            }
            res.redirect(target.href);
        };

        if (upstreamError || !code) {
            // Cognito puts the useful detail (e.g. "invalid_scope") in
            // error_description — preserve it for the log and the MCP client.
            this.logger.warn(
                "Cognito returned an authorize error: %s (%s)",
                upstreamError ?? "missing code",
                upstreamErrorDescription ?? "no error_description"
            );
            redirectError(upstreamError ?? "access_denied", upstreamErrorDescription ?? "Cognito authorization failed");
            return;
        }

        let tokens;
        try {
            tokens = await this.cognito.exchangeCode(code, txn.upstreamVerifier);
        } catch (error) {
            this.logger.error(error, "Cognito code exchange failed");
            redirectError("server_error", "Token exchange with Cognito failed");
            return;
        }

        await this.rememberIdentity(tokens.access_token, tokens.id_token, tokens.expires_in);

        const ourCode = base64url(randomBytes(32));
        const record: CodeRecord = {
            clientId: txn.clientId,
            redirectUri: txn.redirectUri,
            codeChallenge: txn.codeChallenge,
            tokens: {
                access_token: tokens.access_token,
                token_type: tokens.token_type ?? "Bearer",
                expires_in: tokens.expires_in,
                refresh_token: tokens.refresh_token,
                id_token: tokens.id_token,
                scope: tokens.scope,
            },
        };
        await this.storage.set(COLLECTION_CODES, ourCode, JSON.stringify(record), CODE_TTL_SECONDS);

        const target = new URL(txn.redirectUri);
        target.searchParams.set("code", ourCode);
        if (txn.state !== undefined) {
            target.searchParams.set("state", txn.state);
        }
        this.logger.info("auth callback: minted code for client=%s", txn.clientId);
        res.redirect(target.href);
    }

    async challengeForAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string
    ): Promise<string> {
        const stored = await this.storage.get(COLLECTION_CODES, authorizationCode);
        if (!stored) {
            throw new InvalidGrantError("Unknown or expired authorization code");
        }
        const record = JSON.parse(stored) as CodeRecord;
        if (record.clientId !== client.client_id) {
            throw new InvalidClientError("Authorization code was issued to a different client");
        }
        return record.codeChallenge;
    }

    async exchangeAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string,
        _codeVerifier?: string,
        redirectUri?: string
    ): Promise<OAuthTokens> {
        const stored = await this.storage.get(COLLECTION_CODES, authorizationCode);
        if (!stored) {
            throw new InvalidGrantError("Unknown or expired authorization code");
        }
        // Single use: drop before returning tokens so a replayed code always fails.
        await this.storage.delete(COLLECTION_CODES, authorizationCode);
        const record = JSON.parse(stored) as CodeRecord;
        if (record.clientId !== client.client_id) {
            throw new InvalidClientError("Authorization code was issued to a different client");
        }
        if (redirectUri && redirectUri !== record.redirectUri) {
            throw new InvalidGrantError("redirect_uri does not match the authorization request");
        }
        this.logger.info("token: code exchanged for client=%s", client.client_id);
        return record.tokens;
    }

    async exchangeRefreshToken(
        client: OAuthClientInformationFull,
        refreshToken: string,
        _scopes?: string[]
    ): Promise<OAuthTokens> {
        let response;
        try {
            response = await this.cognito.refresh(refreshToken);
        } catch (error) {
            this.logger.warn(error, "Cognito refresh grant failed");
            throw new InvalidGrantError("Refresh token was rejected by Cognito");
        }
        // A refresh response carries a fresh id_token — re-capture identity so
        // the pairing map stays warm across access-token rotations and restarts.
        await this.rememberIdentity(response.access_token, response.id_token, response.expires_in);
        this.logger.info("token: refresh grant served for client=%s", client.client_id);
        return {
            access_token: response.access_token,
            token_type: response.token_type ?? "Bearer",
            expires_in: response.expires_in,
            // Cognito does not rotate refresh tokens; hand the original back.
            refresh_token: response.refresh_token ?? refreshToken,
            id_token: response.id_token,
            scope: response.scope,
        };
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        let payload;
        try {
            payload = await this.cognito.verifyAccessToken(token);
        } catch (error) {
            // Wrap into the SDK's error type so requireBearerAuth answers 401
            // (anything else becomes an opaque 500).
            throw new InvalidTokenError(error instanceof Error ? error.message : "Token verification failed");
        }

        const identity = await this.resolveIdentity(token, payload.exp);
        const username = typeof payload.username === "string" ? payload.username : undefined;
        const pairingIdentity = pickPairingIdentity(identity ?? {}, username);
        if (!pairingIdentity) {
            // Fail closed: without email/cognito:username we could only pair by
            // the opaque UUID sub, which matches no mPass identity header.
            throw new InvalidTokenError(
                "Could not resolve a user identity (email/username) for this token — re-authorize"
            );
        }

        return {
            token,
            clientId: typeof payload.client_id === "string" ? payload.client_id : this.config.clientId,
            scopes: typeof payload.scope === "string" ? payload.scope.split(" ") : [],
            expiresAt: typeof payload.exp === "number" ? payload.exp : undefined,
            extra: {
                identity: pairingIdentity,
                email: identity?.email,
                username: identity?.username ?? username,
            },
        };
    }

    /** Best-effort passthrough to Cognito's revocation endpoint (refresh tokens only — access tokens just expire). */
    async revokeToken(_client: OAuthClientInformationFull, request: { token: string }): Promise<void> {
        await this.cognito.revoke(request.token);
    }

    private async rememberIdentity(
        accessToken: string,
        idToken: string | undefined,
        expiresIn: number | undefined
    ): Promise<void> {
        if (!idToken) {
            this.logger.warn("Cognito token response has no id_token — identity will rely on the userInfo fallback");
            return;
        }
        const identity = identityFromIdToken(idToken, this.logger);
        if (!identity.email && !identity.username) {
            this.logger.warn("Cognito id_token carries neither email nor cognito:username");
            return;
        }
        await this.storage.set(
            COLLECTION_IDENTITY,
            sha256(accessToken),
            JSON.stringify(identity),
            expiresIn ?? DEFAULT_TOKEN_TTL_SECONDS
        );
    }

    private async resolveIdentity(token: string, exp: number | undefined): Promise<CognitoIdentity | null> {
        const stored = await this.storage.get(COLLECTION_IDENTITY, sha256(token));
        if (stored) {
            return JSON.parse(stored) as CognitoIdentity;
        }
        const fetched = await this.cognito.userInfo(token);
        if (fetched && (fetched.email || fetched.username)) {
            const ttl = exp ? Math.max(exp - Math.floor(Date.now() / 1000), 60) : DEFAULT_TOKEN_TTL_SECONDS;
            await this.storage.set(COLLECTION_IDENTITY, sha256(token), JSON.stringify(fetched), ttl);
            return fetched;
        }
        return null;
    }
}
