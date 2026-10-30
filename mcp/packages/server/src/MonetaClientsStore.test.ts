import assert from "node:assert/strict";
import test, { mock } from "node:test";
import type { Logger } from "pino";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { MonetaClientsStore } from "./moneta/provider";
import { MemoryStore, ValkeyStore, ValueEncryption, type KeyValueStore } from "./moneta/storage";

const NINETY_DAYS_SECONDS = 90 * 24 * 3600;

const CLIENT: OAuthClientInformationFull = {
    client_id: "client-123",
    client_id_issued_at: 1_700_000_000,
    redirect_uris: ["https://askiimall.example/callback"],
};

interface ExpireCall {
    collection: string;
    key: string;
    ttlSeconds: number;
}

function recordingStore(
    entries: Record<string, string>,
    expire: (call: ExpireCall) => Promise<void> = async () => {}
): { store: KeyValueStore; expireCalls: ExpireCall[] } {
    const expireCalls: ExpireCall[] = [];
    const store: KeyValueStore = {
        get: async (_collection, key) => entries[key] ?? null,
        set: async () => {},
        delete: async () => {},
        expire: async (collection, key, ttlSeconds) => {
            const call = { collection, key, ttlSeconds };
            expireCalls.push(call);
            await expire(call);
        },
    };
    return { store, expireCalls };
}

function recordingLogger(): { logger: Logger; warnings: unknown[][] } {
    const warnings: unknown[][] = [];
    const logger = {
        info: () => {},
        warn: (...args: unknown[]) => warnings.push(args),
    } as unknown as Logger;
    return { logger, warnings };
}

test("getClient refreshes the registration TTL of a known client", async () => {
    const { store, expireCalls } = recordingStore({ [CLIENT.client_id]: JSON.stringify(CLIENT) });
    const clients = new MonetaClientsStore(store, null, recordingLogger().logger);

    assert.deepEqual(await clients.getClient(CLIENT.client_id), CLIENT);
    assert.deepEqual(expireCalls, [{ collection: "clients", key: CLIENT.client_id, ttlSeconds: NINETY_DAYS_SECONDS }]);
});

test("getClient returns undefined for an unknown client without refreshing", async () => {
    const { store, expireCalls } = recordingStore({});
    const clients = new MonetaClientsStore(store, null, recordingLogger().logger);

    assert.equal(await clients.getClient("unknown"), undefined);
    assert.deepEqual(expireCalls, []);
});

test("getClient still returns the client and logs when the TTL refresh fails", async () => {
    const { store } = recordingStore({ [CLIENT.client_id]: JSON.stringify(CLIENT) }, async () => {
        throw new Error("valkey unavailable");
    });
    const { logger, warnings } = recordingLogger();
    const clients = new MonetaClientsStore(store, null, logger);

    assert.deepEqual(await clients.getClient(CLIENT.client_id), CLIENT);
    assert.equal(warnings.length, 1);
    assert.match(String(warnings[0][1]), /registration TTL/);
});

test("getClient propagates storage read errors", async () => {
    const store: KeyValueStore = {
        ...recordingStore({}).store,
        get: async () => {
            throw new Error("valkey unavailable");
        },
    };
    const clients = new MonetaClientsStore(store, null, recordingLogger().logger);

    await assert.rejects(clients.getClient(CLIENT.client_id), /valkey unavailable/);
});

test("MemoryStore.expire slides the expiry of a live entry", async (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: 0 });
    const store = new MemoryStore();

    await store.set("clients", "a", "value", 10);
    t.mock.timers.tick(5_000);
    await store.expire("clients", "a", 10);
    t.mock.timers.tick(7_000);

    assert.equal(await store.get("clients", "a"), "value");
    t.mock.timers.tick(4_000);
    assert.equal(await store.get("clients", "a"), null);
});

test("MemoryStore.expire does not revive a missing or expired entry", async (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: 0 });
    const store = new MemoryStore();

    await store.set("clients", "a", "value", 1);
    t.mock.timers.tick(2_000);
    await store.expire("clients", "a", 10);
    await store.expire("clients", "missing", 10);

    assert.equal(await store.get("clients", "a"), null);
    assert.equal(await store.get("clients", "missing"), null);
});

test("ValkeyStore.expire issues EXPIRE on the namespaced key", async () => {
    const expire = mock.fn(async (_key: string, _seconds: number) => 1);
    const redis = {
        get: async () => null,
        set: async () => "OK",
        expire,
        del: async () => 1,
    };
    const store = new ValkeyStore(redis, new ValueEncryption("secret"));

    await store.expire("clients", "a", 12.5);

    assert.deepEqual(
        expire.mock.calls.map((call) => call.arguments),
        [["penpot-mcp-oauth::clients::a", 13]]
    );
});
