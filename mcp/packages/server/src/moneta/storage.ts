/**
 * Moneta fork — key-value storage for OAuth state.
 *
 * The Cognito gate keeps four collections of state: DCR client registrations,
 * in-flight authorize transactions, our own authorization codes, and the
 * access-token → identity map. Two backends:
 *
 * - In-memory (default). Restarts drop everything, which is survivable:
 *   identity is re-derived from Cognito's userInfo endpoint, short-lived
 *   txns/codes just force the user back through /authorize, and MCP clients
 *   re-register on an invalid_client error. Single-replica only.
 * - Valkey/Redis via MCP_OAUTH_STORAGE_URL (redis://valkey:6379/13 in the
 *   devstack), mirroring surfsense-mcp (DB 11) and plane-mcp (DB 12). Values
 *   are AES-256-GCM encrypted with a key HKDF-derived from the client secret
 *   (or MCP_JWT_SIGNING_KEY for public clients) so the RDB/AOF on disk never
 *   carries plaintext tokens — the same property FastMCP's Fernet wrapper
 *   gives the Python MCP servers.
 *
 * Keys are namespaced `penpot-mcp-oauth::<collection>::<key>`; '::' matches
 * the compound-separator convention of the sibling MCP servers' storage.
 */

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import type { Logger } from "pino";

export interface KeyValueStore {
    get(collection: string, key: string): Promise<string | null>;
    set(collection: string, key: string, value: string, ttlSeconds: number): Promise<void>;
    delete(collection: string, key: string): Promise<void>;
}

const KEY_PREFIX = "penpot-mcp-oauth";

function compoundKey(collection: string, key: string): string {
    return `${KEY_PREFIX}::${collection}::${key}`;
}

/**
 * Process-local store with TTL expiry. A periodic sweep (unref'd so it never
 * keeps the process alive) bounds memory; expiry is also checked on read.
 */
export class MemoryStore implements KeyValueStore {
    private readonly entries = new Map<string, { value: string; expiresAt: number }>();
    private readonly sweeper: NodeJS.Timeout;

    constructor(sweepIntervalMs: number = 60_000) {
        this.sweeper = setInterval(() => this.sweep(), sweepIntervalMs);
        this.sweeper.unref();
    }

    private sweep(): void {
        const now = Date.now();
        for (const [key, entry] of this.entries) {
            if (entry.expiresAt <= now) {
                this.entries.delete(key);
            }
        }
    }

    async get(collection: string, key: string): Promise<string | null> {
        const entry = this.entries.get(compoundKey(collection, key));
        if (!entry) {
            return null;
        }
        if (entry.expiresAt <= Date.now()) {
            this.entries.delete(compoundKey(collection, key));
            return null;
        }
        return entry.value;
    }

    async set(collection: string, key: string, value: string, ttlSeconds: number): Promise<void> {
        this.entries.set(compoundKey(collection, key), { value, expiresAt: Date.now() + ttlSeconds * 1000 });
    }

    async delete(collection: string, key: string): Promise<void> {
        this.entries.delete(compoundKey(collection, key));
    }
}

/**
 * AES-256-GCM with a per-value random salt and IV. Layout (base64):
 * salt(16) | iv(12) | authTag(16) | ciphertext. The key is HKDF-derived per
 * value from the configured secret, so rotating the secret invalidates stored
 * state cleanly (decrypt failures read as cache misses).
 */
export class ValueEncryption {
    constructor(private readonly secret: string) {}

    encrypt(plaintext: string): string {
        const salt = randomBytes(16);
        const iv = randomBytes(12);
        const key = Buffer.from(hkdfSync("sha256", this.secret, salt, "penpot-mcp-oauth-storage", 32));
        const cipher = createCipheriv("aes-256-gcm", key, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
        return Buffer.concat([salt, iv, cipher.getAuthTag(), ciphertext]).toString("base64");
    }

    decrypt(encoded: string): string | null {
        try {
            const raw = Buffer.from(encoded, "base64");
            const salt = raw.subarray(0, 16);
            const iv = raw.subarray(16, 28);
            const tag = raw.subarray(28, 44);
            const ciphertext = raw.subarray(44);
            const key = Buffer.from(hkdfSync("sha256", this.secret, salt, "penpot-mcp-oauth-storage", 32));
            const decipher = createDecipheriv("aes-256-gcm", key, iv);
            decipher.setAuthTag(tag);
            return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
        } catch {
            return null;
        }
    }
}

/** Valkey/Redis-backed store; values encrypted at rest (see ValueEncryption). */
export class ValkeyStore implements KeyValueStore {
    // Type kept loose so ioredis stays a constructor-injected dependency
    // (no module-level import side effects when Cognito mode is off).
    constructor(
        private readonly redis: {
            get(key: string): Promise<string | null>;
            set(key: string, value: string, mode: "EX", ttl: number): Promise<unknown>;
            del(key: string): Promise<unknown>;
        },
        private readonly encryption: ValueEncryption
    ) {}

    async get(collection: string, key: string): Promise<string | null> {
        const stored = await this.redis.get(compoundKey(collection, key));
        if (stored === null) {
            return null;
        }
        return this.encryption.decrypt(stored);
    }

    async set(collection: string, key: string, value: string, ttlSeconds: number): Promise<void> {
        await this.redis.set(compoundKey(collection, key), this.encryption.encrypt(value), "EX", Math.ceil(ttlSeconds));
    }

    async delete(collection: string, key: string): Promise<void> {
        await this.redis.del(compoundKey(collection, key));
    }
}

/**
 * Builds the configured store: Valkey when MCP_OAUTH_STORAGE_URL is set,
 * otherwise in-memory (with a warning in production, mirroring surfsense-mcp's
 * warn_if_storage_missing_in_production — not a hard failure, so evaluation
 * runs of the image still come up).
 */
export async function buildOAuthStorage(
    config: { storageUrl?: string; encryptionSecret?: string; isProduction: boolean },
    logger: Logger
): Promise<KeyValueStore> {
    if (!config.storageUrl) {
        if (config.isProduction) {
            logger.warn(
                "MCP_OAUTH_STORAGE_URL is not set — OAuth state is in-memory and every restart will force " +
                    "MCP clients to re-authorize. Set it to a Valkey/Redis URL for production."
            );
        }
        return new MemoryStore();
    }
    if (!config.encryptionSecret) {
        // loadMonetaAuthConfig enforces this; repeated here so the store is safe standalone.
        throw new Error("OAuth storage requires an encryption secret (OIDC_CLIENT_SECRET or MCP_JWT_SIGNING_KEY).");
    }
    const { default: Redis } = await import("ioredis");
    const redis = new Redis(config.storageUrl, { maxRetriesPerRequest: 2 });
    redis.on("error", (error: Error) => logger.error(error, "OAuth storage (Valkey) connection error"));
    logger.info("OAuth state storage: Valkey (%s)", config.storageUrl.replace(/\/\/[^@]*@/, "//***@"));
    return new ValkeyStore(redis, new ValueEncryption(config.encryptionSecret));
}
