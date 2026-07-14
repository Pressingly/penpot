/**
 * Moneta fork — environment configuration for the Cognito OAuth gate.
 *
 * The presence of COGNITO_USER_POOL_ID switches the server into Cognito mode
 * (mirroring plane-mcp's `moneta.http.enabled()` convention). All other
 * variables follow the names used by surfsense-mcp / plane-mcp so the
 * foss-server-bundle compose blocks stay uniform across the three MCP servers:
 *
 *   COGNITO_USER_POOL_ID             ap-southeast-1_XXXXX — enables Cognito mode
 *   COGNITO_AWS_REGION / AWS_REGION  Cognito region
 *   OIDC_CLIENT_ID                   pre-registered Cognito app client
 *   OIDC_CLIENT_SECRET               optional — public/PKCE clients have none
 *   MCP_BASE_URL                     public URL of this server (https://design-mcp.<domain>)
 *   MCP_ALLOWED_ORIGINS              CSV CORS allow-list, or '*'
 *   MCP_ALLOWED_CLIENT_REDIRECT_URIS CSV allow-list for DCR redirect URIs (unset = allow all)
 *   MCP_OAUTH_STORAGE_URL            redis://valkey:6379/13 — persistent OAuth state (unset = in-memory)
 *   MCP_JWT_SIGNING_KEY              storage-encryption key fallback when no client secret
 *   MCP_ENV                          'production' warns when storage is left in-memory
 */

export const CALLBACK_PATH = "/auth/callback";

/**
 * Scopes requested from Cognito on the upstream authorize redirect. Fixed
 * rather than forwarded from the MCP client: Cognito hard-rejects any scope
 * not enabled on the app client (error=invalid_request/invalid_scope before
 * the login page), and the Moneta app client allows exactly `openid` +
 * `email` — which is also all the identity relay needs (the id_token carries
 * `cognito:username` with `openid` alone and `email` with the email scope).
 */
export const UPSTREAM_SCOPE = "openid email";

export interface MonetaAuthConfig {
    userPoolId: string;
    region: string;
    clientId: string;
    clientSecret: string | undefined;
    /** Cognito issuer URL: https://cognito-idp.<region>.amazonaws.com/<poolId> */
    issuer: string;
    /** Public base URL of this MCP server, no trailing slash. */
    baseUrl: string;
    /** Absolute URL of the upstream OAuth callback ({baseUrl}/auth/callback). */
    callbackUrl: string;
    /** CORS allow-list; ["*"] means any origin. */
    allowedOrigins: string[];
    /** DCR redirect-URI allow-list; null means allow all. */
    allowedClientRedirectUris: string[] | null;
    storageUrl: string | undefined;
    /** Key material for at-rest encryption of OAuth state in Valkey. */
    encryptionSecret: string | undefined;
    /** Override Cognito's authorization_endpoint with a custom auth proxy URL (e.g. mpass-auth-proxy). */
    upstreamAuthUrl: string | undefined;
    isProduction: boolean;
}

/**
 * Whether the Cognito OAuth gate is enabled. Keyed on COGNITO_USER_POOL_ID
 * alone so upstream behaviour is completely untouched when it is unset.
 */
export function monetaAuthEnabled(): boolean {
    return Boolean(process.env.COGNITO_USER_POOL_ID);
}

function csv(value: string | undefined): string[] {
    return (value ?? "")
        .split(",")
        .map((part) => part.trim())
        .filter((part) => part.length > 0);
}

/**
 * Reads and validates the Cognito configuration from the environment.
 * Throws with a list of all missing variables so a misconfigured container
 * fails fast at startup rather than on the first OAuth request.
 */
export function loadMonetaAuthConfig(): MonetaAuthConfig {
    const userPoolId = process.env.COGNITO_USER_POOL_ID ?? "";
    const region = process.env.COGNITO_AWS_REGION ?? process.env.AWS_REGION ?? "";
    const clientId = process.env.OIDC_CLIENT_ID ?? "";
    const clientSecret = process.env.OIDC_CLIENT_SECRET || undefined;
    const baseUrl = (process.env.MCP_BASE_URL ?? "").replace(/\/+$/, "");

    const missing: string[] = [];
    if (!userPoolId) missing.push("COGNITO_USER_POOL_ID");
    if (!region) missing.push("COGNITO_AWS_REGION (or AWS_REGION)");
    if (!clientId) missing.push("OIDC_CLIENT_ID");
    if (!baseUrl) missing.push("MCP_BASE_URL");
    if (missing.length > 0) {
        throw new Error(`Cognito auth is enabled but configuration is incomplete; missing: ${missing.join(", ")}`);
    }

    const storageUrl = process.env.MCP_OAUTH_STORAGE_URL || undefined;
    const encryptionSecret = clientSecret ?? (process.env.MCP_JWT_SIGNING_KEY || undefined);
    if (storageUrl && !encryptionSecret) {
        throw new Error(
            "MCP_OAUTH_STORAGE_URL is set but neither OIDC_CLIENT_SECRET nor MCP_JWT_SIGNING_KEY is available " +
                "to derive the storage encryption key."
        );
    }

    const upstreamAuthUrl = (process.env.COGNITO_UPSTREAM_AUTH_URL ?? "").trim() || undefined;

    const origins = csv(process.env.MCP_ALLOWED_ORIGINS);
    const redirectUris = csv(process.env.MCP_ALLOWED_CLIENT_REDIRECT_URIS);

    return {
        userPoolId,
        region,
        clientId,
        clientSecret,
        issuer: `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`,
        baseUrl,
        callbackUrl: `${baseUrl}${CALLBACK_PATH}`,
        allowedOrigins: origins.length > 0 ? origins : [baseUrl],
        allowedClientRedirectUris: redirectUris.length > 0 ? redirectUris : null,
        storageUrl,
        encryptionSecret,
        upstreamAuthUrl,
        isProduction: (process.env.MCP_ENV ?? "production") === "production",
    };
}
