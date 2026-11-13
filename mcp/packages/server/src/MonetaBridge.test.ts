import assert from "node:assert/strict";
import type * as http from "node:http";
import test, { afterEach, beforeEach } from "node:test";
import {
    createEdgeGate,
    EDGE_SECRET_ENV,
    EDGE_SECRET_HEADER,
    edgeSecretProblem,
    monetaIdentityFromUpgrade,
    pluginUserToken,
} from "./moneta/bridge";

const SECRET = "s3cr3t-edge-value-that-is-long-enough-0123";
const MPASS_ID = "askii-user-1234";

function upgradeRequest(headers: Record<string, string | string[]>): http.IncomingMessage {
    return {
        headers,
        url: "/mcp/ws?userToken=someone-else",
        socket: { remoteAddress: "172.18.0.9" },
    } as unknown as http.IncomingMessage;
}

function edgeRequest(extra: Record<string, string | string[]> = {}): http.IncomingMessage {
    return upgradeRequest({ [EDGE_SECRET_HEADER]: SECRET, "x-auth-request-email": MPASS_ID, ...extra });
}

let savedPoolId: string | undefined;

beforeEach(() => {
    savedPoolId = process.env.COGNITO_USER_POOL_ID;
    process.env.COGNITO_USER_POOL_ID = "ap-southeast-1_test";
});

afterEach(() => {
    if (savedPoolId === undefined) {
        delete process.env.COGNITO_USER_POOL_ID;
    } else {
        process.env.COGNITO_USER_POOL_ID = savedPoolId;
    }
});

test("an unset secret is unusable", () => {
    assert.match(edgeSecretProblem(undefined) ?? "", /is unset/);
    assert.match(edgeSecretProblem("   ") ?? "", /is unset/);
});

test("a CHANGE_ME_ placeholder is unusable", () => {
    assert.match(edgeSecretProblem("CHANGE_ME_penpot_edge_secret_0123456789abcdef") ?? "", /placeholder/);
});

test("a secret shorter than 32 characters after trimming is unusable", () => {
    assert.match(edgeSecretProblem(`  ${"a".repeat(31)}  `) ?? "", /shorter than 32/);
    assert.equal(edgeSecretProblem("a".repeat(32)), null);
});

test("problem messages never contain the secret value", () => {
    const shortSecret = "short-but-sensitive";
    assert.ok(!(edgeSecretProblem(shortSecret) ?? "").includes(shortSecret));
});

test("trusts identity headers when the edge secret matches", () => {
    assert.equal(monetaIdentityFromUpgrade(edgeRequest(), createEdgeGate(SECRET)), MPASS_ID);
});

test("tolerates surrounding whitespace on the configured secret and the header", () => {
    const request = edgeRequest({ [EDGE_SECRET_HEADER]: `  ${SECRET} ` });
    assert.equal(monetaIdentityFromUpgrade(request, createEdgeGate(`\n${SECRET}\n`)), MPASS_ID);
});

test("falls back to X-Auth-Request-User when the email header is not a usable pairing email", () => {
    const request = edgeRequest({ "x-auth-request-email": "cognito:abc", "x-auth-request-user": "user-42" });
    assert.equal(monetaIdentityFromUpgrade(request, createEdgeGate(SECRET)), "user-42");
});

test("ignores identity headers when the edge secret header is missing", () => {
    const request = upgradeRequest({ "x-auth-request-email": MPASS_ID });
    assert.equal(monetaIdentityFromUpgrade(request, createEdgeGate(SECRET)), null);
});

test("ignores identity headers when the edge secret header is wrong", () => {
    const request = edgeRequest({ [EDGE_SECRET_HEADER]: `${SECRET}x` });
    assert.equal(monetaIdentityFromUpgrade(request, createEdgeGate(SECRET)), null);
});

test("ignores identity headers when the edge secret header is duplicated", () => {
    const request = edgeRequest({ [EDGE_SECRET_HEADER]: `${SECRET}, ${SECRET}` });
    assert.equal(monetaIdentityFromUpgrade(request, createEdgeGate(SECRET)), null);
});

test("reads the same edge secret variable as the Penpot backend", () => {
    assert.equal(EDGE_SECRET_ENV, "PENPOT_MPASS_EDGE_SECRET");
    assert.match(edgeSecretProblem(undefined) ?? "", /^PENPOT_MPASS_EDGE_SECRET is unset/);
});

test("an unusable configured secret trusts nothing, even a matching header", () => {
    const placeholder = "CHANGE_ME_penpot_edge_secret_0123456789abcdef";
    const request = edgeRequest({ [EDGE_SECRET_HEADER]: placeholder });
    assert.equal(monetaIdentityFromUpgrade(request, createEdgeGate(placeholder)), null);
    assert.equal(monetaIdentityFromUpgrade(edgeRequest({ [EDGE_SECRET_HEADER]: "" }), createEdgeGate("")), null);
});

test("in Cognito mode the ?userToken query parameter is never used", () => {
    const request = upgradeRequest({});
    assert.equal(pluginUserToken(request, "victim-mpass-id", createEdgeGate(SECRET)), null);
});

test("in Cognito mode untrusted headers do not fall back to ?userToken", () => {
    const request = upgradeRequest({ "x-auth-request-email": MPASS_ID });
    assert.equal(pluginUserToken(request, "victim-mpass-id", createEdgeGate(SECRET)), null);
});

test("in Cognito mode a trusted identity wins over ?userToken", () => {
    assert.equal(pluginUserToken(edgeRequest(), "victim-mpass-id", createEdgeGate(SECRET)), MPASS_ID);
});

test("outside Cognito mode the upstream ?userToken pairing is untouched", () => {
    delete process.env.COGNITO_USER_POOL_ID;
    assert.equal(pluginUserToken(edgeRequest(), "query-token", createEdgeGate(SECRET)), "query-token");
    assert.equal(pluginUserToken(upgradeRequest({}), null, createEdgeGate(undefined)), null);
});
