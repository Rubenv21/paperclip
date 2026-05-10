import { randomUUID } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  createDb,
  authUsers,
  oauthAuthorizationStates,
  oauthConnections,
  companies,
  companySecretBindings,
  companySecretVersions,
  companySecrets,
  companySecretProviderConfigs,
} from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "../helpers/embedded-postgres.js";
import { secretService } from "../../services/secrets.js";
import type { ProviderRegistry } from "../../oauth/registry.js";
import { refreshConnection } from "../../oauth/refresh.js";

export type Db = ReturnType<typeof createDb>;

export interface OAuthTestEnv {
  db: Db;
  /** Connection string suitable for creating ephemeral postgres-js handles. */
  connectionString: string;
  cleanup: () => Promise<void>;
  /** Reset all OAuth-touched tables; safe to call between tests. */
  reset: () => Promise<void>;
  secretsTmpDir: string;
  previousKeyFile: string | undefined;
}

/**
 * Boots an embedded Postgres database with all schema migrations applied and
 * configures the secrets master-key file the way `secrets-service.test.ts`
 * does. Returns an object with the live Drizzle handle and a cleanup hook
 * (call from `afterAll`). Returns `null` if embedded-postgres is unsupported
 * on this host (callers should `describe.skip`).
 */
export async function setupOAuthTestEnv(label: string): Promise<OAuthTestEnv> {
  const previousKeyFile = process.env.PAPERCLIP_SECRETS_MASTER_KEY_FILE;
  const secretsTmpDir = path.join(
    os.tmpdir(),
    `paperclip-oauth-${label}-${randomUUID()}`,
  );
  mkdirSync(secretsTmpDir, { recursive: true });
  process.env.PAPERCLIP_SECRETS_MASTER_KEY_FILE = path.join(
    secretsTmpDir,
    "master.key",
  );

  const started = await startEmbeddedPostgresTestDatabase(label);
  const db = createDb(started.connectionString);

  return {
    db,
    connectionString: started.connectionString,
    secretsTmpDir,
    previousKeyFile,
    reset: async () => {
      // Order matters: child rows first to satisfy FK constraints.
      await db.delete(oauthConnections);
      await db.delete(oauthAuthorizationStates);
      await db.delete(companySecretBindings);
      await db.delete(companySecretVersions);
      await db.delete(companySecrets);
      await db.delete(companySecretProviderConfigs);
      await db.delete(companies);
      await db.delete(authUsers);
    },
    cleanup: async () => {
      await started.cleanup();
      if (previousKeyFile === undefined) {
        delete process.env.PAPERCLIP_SECRETS_MASTER_KEY_FILE;
      } else {
        process.env.PAPERCLIP_SECRETS_MASTER_KEY_FILE = previousKeyFile;
      }
      rmSync(secretsTmpDir, { recursive: true, force: true });
    },
  };
}

/** Cheap probe that mirrors `secrets-service.test.ts` so the suite can `describe.skip` cleanly. */
export const oauthEmbeddedPostgresSupport =
  await getEmbeddedPostgresTestSupport();

export async function seedTestCompany(
  db: Db,
  opts: { id?: string; name?: string } = {},
): Promise<string> {
  const companyId = opts.id ?? randomUUID();
  const name = opts.name ?? "TestCo";
  await db.insert(companies).values({
    id: companyId,
    name,
    issuePrefix: `T${companyId.slice(0, 7)}`.toUpperCase(),
    status: "active",
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  return companyId;
}

/**
 * Seed an auth_users row so the OAuth state-row insert can satisfy its FK
 * (`initiated_by_user_id` references `user.id`). Idempotent across tests.
 */
export async function seedTestUser(
  db: Db,
  opts: { id?: string; email?: string; name?: string } = {},
): Promise<string> {
  const userId = opts.id ?? `user-${randomUUID()}`;
  await db
    .insert(authUsers)
    .values({
      id: userId,
      email: opts.email ?? `${userId}@example.test`,
      name: opts.name ?? "Test User",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    })
    .onConflictDoNothing();
  return userId;
}

/**
 * Construct a real secretService bound to the test DB and the supplied
 * registry. Mirrors how production wires it (refreshFn injected to break the
 * circular import). The integration tests need this for OAuth-token resolution
 * to exercise the lazy-refresh path.
 */
export function createTestSecretService(db: Db, registry: ProviderRegistry) {
  return secretService(db, {
    registry,
    refreshFn: refreshConnection,
  });
}

/**
 * Wraps a Drizzle handle so the OAuth refresh-worker's advisory-lock pings
 * never reach Postgres: `pg_try_advisory_lock` always reports success and
 * `pg_advisory_unlock` is a no-op. This is necessary in tests because
 * postgres-js maintains a multi-connection pool and the worker's session-
 * scoped lock + unlock can land on different connections, leaking a held
 * lock across scenarios. Stripping the lock dance also exercises a worker
 * `lockResult.rows?.[0]?.result` shape that matches the production
 * `node-postgres` Result-of-rows expectation. The combined shim is
 * documented as a follow-up in the Phase-7 report; production code is
 * deliberately left untouched.
 */
export function withSyntheticAdvisoryLock<
  T extends { execute: (...args: any[]) => any },
>(db: T): T {
  const originalExecute = db.execute.bind(db);
  return new Proxy(db, {
    get(target, prop, receiver) {
      if (prop === "execute") {
        return async (query: any, ...rest: any[]) => {
          const sqlText = serializeSqlForMatch(query);
          if (sqlText.includes("pg_try_advisory_lock")) {
            return Object.assign([{ result: true }], {
              rows: [{ result: true }],
            });
          }
          if (sqlText.includes("pg_advisory_unlock")) {
            return Object.assign([{ result: true }], {
              rows: [{ result: true }],
            });
          }
          return await originalExecute(query, ...rest);
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  }) as T;
}

function serializeSqlForMatch(query: unknown): string {
  if (!query || typeof query !== "object") return "";
  // Drizzle SQL objects expose `.queryChunks` — `StringChunk` chunks have a
  // `.value: string[]` field, parameter chunks are bigint/number/string.
  // We just need a coarse text view to spot the advisory-lock query, so we
  // walk both shapes and join. Avoids `JSON.stringify` which throws on
  // BigInt parameters like the worker's lock-key constant.
  const chunks = (query as { queryChunks?: unknown[] }).queryChunks;
  if (!Array.isArray(chunks)) return "";
  const out: string[] = [];
  for (const chunk of chunks) {
    if (typeof chunk === "string") {
      out.push(chunk);
      continue;
    }
    if (chunk && typeof chunk === "object" && "value" in chunk) {
      const v = (chunk as { value: unknown }).value;
      if (typeof v === "string") out.push(v);
      else if (Array.isArray(v)) {
        for (const part of v) {
          if (typeof part === "string") out.push(part);
        }
      }
    }
  }
  return out.join(" ");
}

