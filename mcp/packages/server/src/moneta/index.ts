/**
 * Moneta fork additions for the Penpot MCP server.
 *
 * All Pressingly/Moneta-specific code lives in this package so the upstream
 * modules stay as close to the Penpot original as possible. Hooks into
 * upstream (kept intentionally tiny):
 *
 * - `index.ts`            — forces multi-user mode when Cognito auth is enabled.
 * - `PenpotMcpServer.ts`  — `start()` calls `installMonetaAuth(app, logger)`
 *                           before registering the /mcp /sse /messages routes.
 * - `PluginBridge.ts`     — `pluginUserToken(request, queryToken)` pairs
 *                           plugin connections; in Cognito mode it uses only
 *                           edge-trusted identity headers, never ?userToken=.
 *
 * The flow itself mirrors surfsense-mcp / plane-mcp: the /mcp endpoint is NOT
 * behind mPass (Traefik keeps strip-auth-headers only) and this server is its
 * own OAuth 2.0 authorization server proxying AWS Cognito, so MCP clients
 * discover and complete the OAuth dance automatically.
 */

export { monetaAuthEnabled } from "./config";
export { installMonetaAuth } from "./install";
export { monetaIdentityFromUpgrade, pluginUserToken } from "./bridge";
