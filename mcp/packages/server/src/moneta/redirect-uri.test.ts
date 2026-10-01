import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
    globMatch,
    matchesAllowedPattern,
    parsePattern,
    redirectUriAllowed,
    restrictToAllowedRedirectUris,
} from "./redirect-uri.ts";

const BUNDLE_DEFAULT = [
    "https://claude.ai/api/mcp/auth_callback",
    "claude://claude.ai/mcp-auth-callback/sdk",
    "http://localhost:*/*",
    "http://127.0.0.1:*/*",
    "http://[::1]:*/*",
];

function expectMatch(uri: string, pattern: string, expected: boolean): void {
    assert.equal(matchesAllowedPattern(uri, pattern), expected, `${uri} vs ${pattern}`);
}

describe("matchesAllowedPattern", () => {
    it("matches any loopback port with a :* port wildcard", () => {
        expectMatch("http://localhost:3000/callback", "http://localhost:*/*", true);
        expectMatch("http://localhost:6274/oauth/callback/debug", "http://localhost:*/*", true);
        expectMatch("http://127.0.0.1:51659/callback/JTYSJllr9Kjt", "http://127.0.0.1:*/*", true);
        expectMatch("http://[::1]:8080/callback", "http://[::1]:*/*", true);
    });

    it("lets a loopback pattern without a port match any port (RFC 8252 §7.3)", () => {
        expectMatch("http://localhost:3000/callback", "http://localhost", true);
        expectMatch("http://127.0.0.1:9999/cb", "http://127.0.0.1", true);
        expectMatch("http://localhost:3000/callback", "http://localhost/", true);
    });

    it("requires the default port when a non-loopback pattern has none", () => {
        expectMatch("https://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback", true);
        expectMatch("https://claude.ai:443/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback", true);
        expectMatch("https://claude.ai:8443/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback", false);
        expectMatch("https://example.com:8443/cb", "https://example.com:8443/cb", true);
    });

    it("treats an empty pattern port as the default port", () => {
        expectMatch("http://example.com/cb", "http://example.com:/cb", true);
        expectMatch("http://example.com:81/cb", "http://example.com:/cb", false);
        expectMatch("http://localhost/cb", "http://localhost:/cb", true);
        expectMatch("http://localhost:3000/cb", "http://localhost:/cb", false);
        expectMatch("http://[::1]:3000/cb", "http://[::1]:/cb", false);
    });

    it("matches custom schemes component-wise", () => {
        expectMatch("claude://claude.ai/mcp-auth-callback/sdk", "claude://claude.ai/mcp-auth-callback/sdk", true);
        expectMatch("claude://claude.ai/other", "claude://claude.ai/mcp-auth-callback/sdk", false);
        expectMatch("cursor://anysphere.cursor-retrieval/oauth/cb", "cursor://anysphere.cursor-retrieval/*", true);
    });

    it("never treats a bare * host as a wildcard", () => {
        expectMatch("cursor://anysphere.cursor-retrieval/oauth/cb", "cursor://*", false);
        expectMatch("https://evil.com/cb", "https://*/*", false);
    });

    it("compares the scheme exactly", () => {
        expectMatch("https://localhost:3000/cb", "http://localhost:*/*", false);
        expectMatch("http://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback", false);
        expectMatch("HTTP://LOCALHOST:3000/cb", "http://localhost:*/*", true);
    });

    it("matches only true subdomains for *.suffix hosts", () => {
        expectMatch("https://app.example.com/cb", "https://*.example.com/*", true);
        expectMatch("https://a.b.example.com/cb", "https://*.example.com/*", true);
        expectMatch("https://example.com/cb", "https://*.example.com/*", false);
        expectMatch("https://evilexample.com/cb", "https://*.example.com/*", false);
        expectMatch("https://example.com.evil.com/cb", "https://*.example.com/*", false);
    });

    it("rejects host spoofing", () => {
        expectMatch("http://localhost.evil.com:3000/cb", "http://localhost:*/*", false);
        expectMatch(
            "https://claude.ai.evil.com/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/auth_callback",
            false
        );
    });

    it("rejects userinfo in the URI", () => {
        expectMatch("http://localhost@evil.com/cb", "http://localhost:*/*", false);
        expectMatch("http://user:pass@localhost:3000/cb", "http://localhost:*/*", false);
        expectMatch("http://localhost:3000@evil.com/cb", "http://localhost:*/*", false);
    });

    it("rejects userinfo in the pattern", () => {
        expectMatch("http://evil.com/cb", "http://localhost@evil.com/*", false);
    });

    it("globs the path like fnmatch", () => {
        expectMatch("https://app.example.com/auth/callback", "https://app.example.com/auth/*", true);
        expectMatch("https://app.example.com/auth/a/b", "https://app.example.com/auth/*", true);
        expectMatch("https://app.example.com/other", "https://app.example.com/auth/*", false);
        expectMatch("https://app.example.com/v2/cb", "https://app.example.com/v[0-9]/cb", true);
        expectMatch("https://app.example.com/vx/cb", "https://app.example.com/v[!0-9]/cb", true);
        expectMatch("https://app.example.com/v2/cb", "https://app.example.com/v[!0-9]/cb", false);
    });

    it("reads ? in a pattern as the start of a query, as urlparse does", () => {
        expectMatch("https://app.example.com/cb", "https://app.example.com/cb?", true);
        expectMatch("https://app.example.com/cb1", "https://app.example.com/cb?", false);
    });

    it("matches any path for an empty or root pattern path", () => {
        expectMatch("https://app.example.com/anything/here", "https://app.example.com", true);
        expectMatch("https://app.example.com/anything/here", "https://app.example.com/", true);
    });

    it("compares the normalised path, so dot segments cannot escape a prefix", () => {
        expectMatch("https://app.example.com/auth/../admin", "https://app.example.com/auth/*", false);
    });

    it("ignores the query string", () => {
        expectMatch("https://app.example.com/auth/cb?x=1", "https://app.example.com/auth/cb", true);
    });

    it("returns false instead of throwing on unparseable input", () => {
        expectMatch("not a url", "http://localhost:*/*", false);
        expectMatch("http://localhost:3000/cb", "not a pattern", false);
        expectMatch("http://localhost:3000/cb", "http://[::1:*/*", false);
        expectMatch("http://localhost:3000/cb", "", false);
    });
});

describe("parsePattern", () => {
    it("splits a wildcard port that WHATWG URL refuses", () => {
        assert.deepEqual(parsePattern("http://localhost:*/*"), {
            scheme: "http",
            host: "localhost",
            port: "*",
            path: "/*",
        });
    });

    it("unwraps bracketed IPv6 hosts", () => {
        assert.deepEqual(parsePattern("http://[::1]:*/*"), { scheme: "http", host: "::1", port: "*", path: "/*" });
        assert.deepEqual(parsePattern("http://[::1]/cb"), { scheme: "http", host: "::1", port: null, path: "/cb" });
    });

    it("drops a query or fragment from the pattern path", () => {
        assert.equal(parsePattern("https://a.example.com/cb?x=1")?.path, "/cb");
        assert.equal(parsePattern("https://a.example.com?x=1")?.path, "");
    });
});

describe("globMatch", () => {
    it("treats an unterminated bracket as a literal", () => {
        assert.equal(globMatch("/a[b", "/a[b"), true);
    });

    it("treats regex metacharacters as literals", () => {
        assert.equal(globMatch("/axb", "/a.b"), false);
        assert.equal(globMatch("/a+b", "/a+b"), true);
        assert.equal(globMatch("/a(b", "/a(b"), true);
    });

    it("drops a reversed range instead of throwing", () => {
        assert.equal(globMatch("/v1/cb", "/v[z-a]/cb"), false);
        assert.equal(globMatch("/v1/cb", "/v[!z-a]/cb"), true);
        assert.equal(matchesAllowedPattern("https://a.example.com/v1/cb", "https://a.example.com/v[z-a]/cb"), false);
    });

    it("reads a leading ] as a class member", () => {
        assert.equal(globMatch("/v]/cb", "/v[]x]/cb"), true);
        assert.equal(globMatch("/vy/cb", "/v[!]x]/cb"), true);
        assert.equal(globMatch("/v]/cb", "/v[!]x]/cb"), false);
        assert.equal(globMatch("/vxx]/cb", "/v[!]x]/cb"), false);
    });

    it("lets * span path separators and match the empty string", () => {
        assert.equal(globMatch("/a/b/c", "/a*"), true);
        assert.equal(globMatch("/a", "/a*"), true);
        assert.equal(globMatch("/a/end", "/*/*/end"), false);
        assert.equal(globMatch("/a/b/end", "/*/*/end"), true);
    });

    it("stays fast on a long hostile path against a multi-star pattern", () => {
        const started = Date.now();
        const path = `/cb/${"x/".repeat(50_000)}`;
        assert.equal(globMatch(path, "/cb/*/*/*/end"), false);
        assert.ok(Date.now() - started < 1000, `took ${Date.now() - started}ms`);
    });
});

describe("redirectUriAllowed", () => {
    it("allows everything when the list is unset", () => {
        assert.equal(redirectUriAllowed("https://evil.com/cb", null), true);
    });

    it("allows nothing when the list is empty", () => {
        assert.equal(redirectUriAllowed("http://localhost:3000/cb", []), false);
    });

    it("accepts every client shape observed on production with the bundle default", () => {
        const observed = [
            "https://claude.ai/api/mcp/auth_callback",
            "claude://claude.ai/mcp-auth-callback/sdk",
            "http://localhost:6274/oauth/callback",
            "http://localhost:6274/oauth/callback/debug",
            "http://localhost:3118/callback",
            "http://127.0.0.1:51659/callback/JTYSJllr9Kjt",
            "http://127.0.0.1:19876/mcp/oauth/callback",
        ];
        for (const uri of observed) {
            assert.equal(redirectUriAllowed(uri, BUNDLE_DEFAULT), true, uri);
        }
    });

    it("rejects an attacker callback with the bundle default", () => {
        assert.equal(redirectUriAllowed("https://attacker.example/cb", BUNDLE_DEFAULT), false);
        assert.equal(redirectUriAllowed("https://claude.ai/evil", BUNDLE_DEFAULT), false);
    });
});

describe("restrictToAllowedRedirectUris", () => {
    const client = { client_id: "c1", redirect_uris: ["https://attacker.example/cb", "http://localhost:3000/cb"] };

    it("returns the client unchanged when the list is unset", () => {
        assert.equal(restrictToAllowedRedirectUris(client, null), client);
    });

    it("keeps only allowed redirect URIs without mutating the stored client", () => {
        const restricted = restrictToAllowedRedirectUris(client, BUNDLE_DEFAULT);
        assert.deepEqual(restricted?.redirect_uris, ["http://localhost:3000/cb"]);
        assert.deepEqual(client.redirect_uris, ["https://attacker.example/cb", "http://localhost:3000/cb"]);
    });

    it("drops a client when none of its redirect URIs are allowed", () => {
        const hostile = { client_id: "c2", redirect_uris: ["https://attacker.example/cb"] };
        assert.equal(restrictToAllowedRedirectUris(hostile, BUNDLE_DEFAULT), undefined);
    });

    it("drops a client with no redirect URIs once a list is set", () => {
        assert.equal(restrictToAllowedRedirectUris({ client_id: "c3" }, BUNDLE_DEFAULT), undefined);
    });
});
