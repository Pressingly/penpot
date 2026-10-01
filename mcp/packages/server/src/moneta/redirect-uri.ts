/**
 * Moneta fork — DCR redirect-URI allow-list matching.
 *
 * Mirrors FastMCP's `redirect_validation.matches_allowed_pattern`, so the one
 * MCP_ALLOWED_CLIENT_REDIRECT_URIS value shared across the stack means the same
 * thing here as it does for outline-mcp and plane-mcp:
 *
 *   http://localhost:*               any localhost port, any path
 *   http://localhost                 loopback without a port: any port (RFC 8252 §7.3)
 *   https://claude.ai/api/cb         exact host, default port, exact path
 *   https://*.example.com            any true subdomain (not the apex), any path
 *   claude://claude.ai/sdk           custom schemes compare the same way
 *
 * Components are compared one at a time: scheme exactly, host exactly or by a
 * leading `*.` subdomain wildcard, port exactly or by `*`, path as an fnmatch
 * glob (`*`, `[...]`; a `?` starts the pattern's query, as with urlparse). A
 * bare `*` host is literal, as in FastMCP. URIs carrying userinfo never match,
 * so http://localhost@evil.com cannot satisfy a localhost pattern. Unparseable
 * URIs and patterns never match and never throw. The URI path is compared
 * after WHATWG normalisation, so dot segments cannot walk out of a path
 * prefix (FastMCP compares the raw path, which is looser).
 */

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

interface PatternParts {
    scheme: string;
    host: string;
    port: string | null;
    path: string;
}

function escapeRegExp(value: string): string {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function translateBracket(pattern: string, open: number): { source: string; next: number } | null {
    let i = open + 1;
    if (pattern[i] === "!") {
        i++;
    }
    if (pattern[i] === "]") {
        i++;
    }
    const close = pattern.indexOf("]", i);
    if (close === -1) {
        return null;
    }
    const body = pattern.slice(open + 1, close).replace(/\\/g, "\\\\");
    const negated = body.startsWith("!");
    const members = (negated ? body.slice(1) : body).replace(/^\^/, "\\^");
    return { source: `[${negated ? "^" : ""}${members}]`, next: close + 1 };
}

/** fnmatch.translate equivalent: `*` any run, `?` one char, `[...]` / `[!...]` a class. */
export function globToRegExp(pattern: string): RegExp {
    let source = "";
    let i = 0;
    while (i < pattern.length) {
        const char = pattern[i];
        if (char === "*") {
            source += ".*";
            i++;
        } else if (char === "?") {
            source += ".";
            i++;
        } else if (char === "[") {
            const bracket = translateBracket(pattern, i);
            source += bracket ? bracket.source : "\\[";
            i = bracket ? bracket.next : i + 1;
        } else {
            source += escapeRegExp(char);
            i++;
        }
    }
    return new RegExp(`^${source}$`, "s");
}

function splitHostPort(netloc: string): { host: string; port: string | null } | null {
    if (netloc.startsWith("[")) {
        const end = netloc.indexOf("]");
        if (end === -1) {
            return null;
        }
        const after = netloc.slice(end + 1);
        return { host: netloc.slice(1, end), port: after.startsWith(":") ? after.slice(1) : null };
    }
    const colon = netloc.lastIndexOf(":");
    if (colon === -1) {
        return { host: netloc, port: null };
    }
    return { host: netloc.slice(0, colon), port: netloc.slice(colon + 1) };
}

/** WHATWG URL refuses a `*` port, so patterns are split by hand. */
export function parsePattern(pattern: string): PatternParts | null {
    const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(pattern.trim());
    if (!schemeMatch) {
        return null;
    }
    const rest = pattern.trim().slice(schemeMatch[0].length);
    const pathStart = rest.search(/[/?#]/);
    const netloc = pathStart === -1 ? rest : rest.slice(0, pathStart);
    const path = pathStart === -1 ? "" : rest.slice(pathStart).replace(/[?#].*$/s, "");
    if (!netloc || netloc.includes("@")) {
        return null;
    }
    const hostPort = splitHostPort(netloc);
    if (!hostPort || !hostPort.host) {
        return null;
    }
    return {
        scheme: schemeMatch[1].toLowerCase(),
        host: hostPort.host.toLowerCase(),
        port: hostPort.port || null,
        path,
    };
}

function matchHost(uriHost: string, patternHost: string): boolean {
    if (patternHost.startsWith("*.")) {
        const suffix = patternHost.slice(1);
        return uriHost.endsWith(suffix) && uriHost !== patternHost.slice(2);
    }
    return uriHost === patternHost;
}

function defaultPort(scheme: string): string {
    return scheme === "https" ? "443" : "80";
}

function matchPort(uriPort: string, pattern: PatternParts, scheme: string): boolean {
    const loopbackAnyPort = LOOPBACK_HOSTS.has(pattern.host) && pattern.port === null;
    if (loopbackAnyPort || pattern.port === "*") {
        return true;
    }
    return (uriPort || defaultPort(scheme)) === (pattern.port ?? defaultPort(scheme));
}

function matchPath(uriPath: string, patternPath: string): boolean {
    const pattern = patternPath || "/";
    if (pattern === "/") {
        return true;
    }
    return globToRegExp(pattern).test(uriPath || "/");
}

function parseUri(uri: string): URL | null {
    try {
        return new URL(uri);
    } catch {
        return null;
    }
}

export function matchesAllowedPattern(uri: string, pattern: string): boolean {
    const parsedUri = parseUri(uri);
    const parts = parsePattern(pattern);
    if (!parsedUri || !parts || parsedUri.username || parsedUri.password) {
        return false;
    }
    const scheme = parsedUri.protocol.replace(/:$/, "").toLowerCase();
    const host = parsedUri.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    return (
        scheme === parts.scheme &&
        matchHost(host, parts.host) &&
        matchPort(parsedUri.port, parts, scheme) &&
        matchPath(parsedUri.pathname, parts.path)
    );
}

/** `null` allow-list means the variable is unset: everything is allowed, as in FastMCP. */
export function redirectUriAllowed(uri: string, allowList: readonly string[] | null): boolean {
    if (allowList === null) {
        return true;
    }
    return allowList.some((entry) => matchesAllowedPattern(uri, entry));
}

/**
 * Narrows a stored client's redirect URIs to those the current allow-list
 * accepts. Returns `undefined` when none survive, so a client registered while
 * the list was empty (or wider) stops working instead of keeping a disallowed
 * callback for the rest of its storage TTL.
 */
export function restrictToAllowedRedirectUris<T extends { redirect_uris?: readonly string[] }>(
    client: T,
    allowList: readonly string[] | null
): T | undefined {
    if (allowList === null) {
        return client;
    }
    const allowed = (client.redirect_uris ?? []).filter((uri) => redirectUriAllowed(uri, allowList));
    if (allowed.length === 0) {
        return undefined;
    }
    return { ...client, redirect_uris: allowed };
}
