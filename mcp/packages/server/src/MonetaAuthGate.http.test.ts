import assert from "node:assert/strict";
import { afterEach, beforeEach, mock, test } from "node:test";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { PenpotMcpServer } from "./PenpotMcpServer";
import { CognitoProxyProvider } from "./moneta/provider";

const IDENTITY_BY_BEARER: Record<string, string> = { "alice-token": "alice-mpass-id" };

let server: PenpotMcpServer;
let baseUrl: string;
let previousEnv: NodeJS.ProcessEnv;
let nextPort = 16_700;
let executedFor: (string | null)[];

beforeEach(async () => {
    previousEnv = { ...process.env };
    process.env.PENPOT_MCP_SERVER_HOST = "127.0.0.1";
    process.env.PENPOT_MCP_SERVER_PORT = String(nextPort++);
    process.env.PENPOT_MCP_WEBSOCKET_PORT = "0";
    process.env.PENPOT_MCP_DEVENV = "false";
    process.env.PENPOT_MCP_REPL_ENABLE = "false";
    delete process.env.PENPOT_MCP_REDIS_URI;
    delete process.env.MCP_OAUTH_STORAGE_URL;
    process.env.COGNITO_USER_POOL_ID = "ap-southeast-1_test";
    process.env.COGNITO_AWS_REGION = "ap-southeast-1";
    process.env.OIDC_CLIENT_ID = "test-client";
    process.env.MCP_BASE_URL = `http://127.0.0.1:${process.env.PENPOT_MCP_SERVER_PORT}`;

    mock.method(CognitoProxyProvider.prototype, "verifyAccessToken", async (token: string): Promise<AuthInfo> => {
        const identity = IDENTITY_BY_BEARER[token];
        if (!identity) {
            throw new InvalidTokenError("unknown token");
        }
        const expiresAt = Math.floor(Date.now() / 1000) + 3600;
        return { token, clientId: "test-client", scopes: [], expiresAt, extra: { identity } };
    });

    server = new PenpotMcpServer(true);
    baseUrl = `http://127.0.0.1:${server.port}`;
    executedFor = [];
    mock.method(server.pluginBridge, "executePluginTask", async () => {
        const userToken = server.getSessionContext()?.userToken ?? null;
        executedFor.push(userToken);
        return { data: userToken };
    });
    await server.start();
});

afterEach(async () => {
    await server?.stop();
    mock.restoreAll();
    process.env = previousEnv;
});

function callExecuteCode(options: { bearer?: string; query?: string; extraHeaders?: Record<string, string> }) {
    const params = {
        name: "execute_code",
        arguments: { code: "return 1;", userToken: "victim-mpass-id" },
        userToken: "victim-mpass-id",
        _meta: {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": { name: "moneta-gate-test", version: "1" },
            "io.modelcontextprotocol/clientCapabilities": {},
        },
    };
    return fetch(`${baseUrl}/mcp${options.query ?? ""}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "execute_code",
            ...(options.bearer ? { Authorization: `Bearer ${options.bearer}` } : {}),
            ...options.extraHeaders,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params }),
    });
}

test("a spoofed userToken in the query, body or headers resolves to the bearer's own identity", async () => {
    const response = await callExecuteCode({
        bearer: "alice-token",
        query: "?userToken=victim-mpass-id",
        extraHeaders: { "X-User-Token": "victim-mpass-id", userToken: "victim-mpass-id" },
    });
    const body = (await response.json()) as { result: { content: { type: string; text: string }[] } };

    assert.equal(response.status, 200, JSON.stringify(body));
    assert.equal(JSON.parse(body.result.content[0].text), "alice-mpass-id");
    assert.deepEqual(executedFor, ["alice-mpass-id"]);
});

test("a request without a bearer never reaches a tool", async () => {
    const response = await callExecuteCode({ query: "?userToken=victim-mpass-id" });

    assert.equal(response.status, 401);
    assert.match(response.headers.get("www-authenticate") ?? "", /Bearer/);
    assert.deepEqual(executedFor, []);
});

test("a request with an invalid bearer never reaches a tool", async () => {
    const response = await callExecuteCode({ bearer: "forged-token", query: "?userToken=victim-mpass-id" });

    assert.equal(response.status, 401);
    assert.deepEqual(executedFor, []);
});

test("path variants of /mcp stay behind the gate", async () => {
    for (const path of ["/MCP", "/mcp/", "/Mcp?userToken=victim-mpass-id"]) {
        const response = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
            body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
        });
        assert.notEqual(response.status, 200, path);
    }
    assert.deepEqual(executedFor, []);
});

test("healthz stays reachable without a bearer", async () => {
    const response = await fetch(`${baseUrl}/healthz`);

    assert.equal(response.status, 200);
});
