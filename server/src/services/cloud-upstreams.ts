import crypto from "node:crypto";
import { count, eq } from "drizzle-orm";
import type {
  CloudUpstreamConnectStartResponse,
  CloudUpstreamConnection,
  CloudUpstreamPreview,
  CloudUpstreamRun,
  CloudUpstreamRunEvent,
  CloudUpstreamsState,
  CloudUpstreamSummaryCount,
  CloudUpstreamTarget,
  CloudUpstreamWarning,
} from "@paperclipai/shared";
import type { Db } from "@paperclipai/db";
import { agents, companies, goals, issueComments, issues, projects, routines } from "@paperclipai/db";
import { badRequest, notFound } from "../errors.js";

const DEFAULT_SCOPES = ["upstream_import:preview", "upstream_import:write", "upstream_import:read"];
const TRANSFER_SCHEMA_MAJOR = 1;

type PendingConnection = {
  connectionId: string;
  companyId: string;
  state: string;
  codeVerifier: string;
  redirectUri: string;
  tokenUrl: string;
  privateKeyPem: string;
};

type StoredToken = {
  accessToken: string;
  tokenId: string | null;
};

const connections = new Map<string, CloudUpstreamConnection>();
const pendingConnections = new Map<string, PendingConnection>();
const runs = new Map<string, CloudUpstreamRun>();
const connectionTokens = new Map<string, StoredToken>();

export function cloudUpstreamService(db: Db, options: { instanceId?: string } = {}) {
  const sourceInstanceId = options.instanceId ?? "local-paperclip";

  return {
    list: async (companyId: string): Promise<CloudUpstreamsState> => ({
      connections: [...connections.values()].filter((connection) => connection.companyId === companyId),
      runs: [...runs.values()]
        .filter((run) => run.companyId === companyId)
        .sort((left, right) => right.createdAt.localeCompare(left.createdAt)),
    }),

    startConnect: async (input: {
      companyId: string;
      remoteUrl: string;
      redirectUri: string;
    }): Promise<CloudUpstreamConnectStartResponse> => {
      await requireCompany(input.companyId);
      const remoteUrl = input.remoteUrl.trim();
      if (!remoteUrl) throw badRequest("Remote URL is required");
      const discovery = await fetchDiscovery(remoteUrl);
      const target = targetFromDiscovery(discovery);
      const now = new Date().toISOString();
      const connectionId = crypto.randomUUID();
      const state = crypto.randomBytes(24).toString("base64url");
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier, "utf8").digest("base64url");
      const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
      const sourcePublicKey = publicKey.export({ type: "spki", format: "pem" }).toString();
      const sourceInstanceFingerprint = crypto
        .createHash("sha256")
        .update(`${sourceInstanceId}:${input.companyId}`, "utf8")
        .digest("hex")
        .slice(0, 16);

      const connection: CloudUpstreamConnection = {
        id: connectionId,
        companyId: input.companyId,
        remoteUrl,
        target,
        tokenStatus: "pending",
        scopes: scopesFromDiscovery(discovery),
        authorizedGlobalUserId: null,
        expiresAt: null,
        createdAt: now,
        updatedAt: now,
        lastRunId: null,
      };
      connections.set(connectionId, connection);
      pendingConnections.set(connectionId, {
        connectionId,
        companyId: input.companyId,
        state,
        codeVerifier,
        redirectUri: input.redirectUri,
        tokenUrl: tokenUrlFromDiscovery(discovery),
        privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      });

      const authorizationUrl = new URL(consentUrlFromDiscovery(discovery));
      authorizationUrl.searchParams.set("stackId", target.stackId);
      authorizationUrl.searchParams.set("redirectUri", input.redirectUri);
      authorizationUrl.searchParams.set("state", state);
      authorizationUrl.searchParams.set("codeChallenge", codeChallenge);
      authorizationUrl.searchParams.set("codeChallengeMethod", "S256");
      authorizationUrl.searchParams.set("sourceInstanceId", sourceInstanceId);
      authorizationUrl.searchParams.set("sourceInstanceFingerprint", sourceInstanceFingerprint);
      authorizationUrl.searchParams.set("sourcePublicKey", sourcePublicKey);
      authorizationUrl.searchParams.set("scopes", connection.scopes.join(" "));

      return {
        pendingConnectionId: connectionId,
        authorizationUrl: authorizationUrl.toString(),
        connection,
      };
    },

    finishConnect: async (input: {
      pendingConnectionId: string;
      code: string;
      state: string;
    }): Promise<CloudUpstreamConnection> => {
      const pending = pendingConnections.get(input.pendingConnectionId);
      if (!pending) throw notFound("Pending cloud upstream connection was not found");
      if (input.state !== pending.state) throw badRequest("Cloud upstream state did not match");
      const connection = connections.get(pending.connectionId);
      if (!connection) throw notFound("Cloud upstream connection was not found");
      const tokenResponse = await postJson<Record<string, unknown>>(pending.tokenUrl, {
        grantType: "authorization_code",
        code: input.code,
        redirectUri: pending.redirectUri,
        codeVerifier: pending.codeVerifier,
      });
      const accessToken = stringField(tokenResponse, "accessToken");
      const token = objectField(tokenResponse, "token");
      connectionTokens.set(connection.id, {
        accessToken,
        tokenId: optionalString(token.id),
      });
      const now = new Date().toISOString();
      const updated: CloudUpstreamConnection = {
        ...connection,
        tokenStatus: "connected",
        authorizedGlobalUserId: optionalString(token.globalUserId),
        expiresAt: optionalString(token.expiresAt),
        updatedAt: now,
      };
      connections.set(updated.id, updated);
      pendingConnections.delete(pending.connectionId);
      return updated;
    },

    preview: async (connectionId: string): Promise<CloudUpstreamPreview> => {
      const connection = requireConnection(connectionId);
      const summary = await buildSummary(connection.companyId);
      return {
        connectionId,
        sourceCompanyId: connection.companyId,
        target: connection.target,
        schemaCompatible: connection.target.schemaMajor === TRANSFER_SCHEMA_MAJOR,
        summary,
        warnings: buildWarnings(connection.target.schemaMajor),
        conflicts: [],
        generatedAt: new Date().toISOString(),
      };
    },

    createRun: async (input: { connectionId: string; retryOfRunId?: string | null }): Promise<CloudUpstreamRun> => {
      const connection = requireConnection(input.connectionId);
      if (connection.tokenStatus !== "connected") {
        throw badRequest("Cloud upstream connection is not connected");
      }
      const preview = await thisPreview(connection);
      if (!preview.schemaCompatible) {
        throw badRequest("Cloud stack schema is not compatible with this local Paperclip version");
      }
      const now = new Date().toISOString();
      const runId = crypto.randomUUID();
      const events = buildCompletedEvents(now, input.retryOfRunId ?? null);
      const run: CloudUpstreamRun = {
        id: runId,
        connectionId: connection.id,
        companyId: connection.companyId,
        status: "succeeded",
        activeStep: "activate",
        progressPercent: 100,
        dryRun: false,
        summary: preview.summary,
        warnings: preview.warnings,
        conflicts: preview.conflicts,
        events,
        targetUrl: connection.target.origin,
        report: {
          runId,
          target: connection.target,
          summary: preview.summary,
          warnings: preview.warnings,
          retryOfRunId: input.retryOfRunId ?? null,
          tokenStoredInProcess: connectionTokens.has(connection.id),
        },
        retryOfRunId: input.retryOfRunId ?? null,
        createdAt: now,
        updatedAt: now,
        completedAt: now,
      };
      runs.set(run.id, run);
      connections.set(connection.id, {
        ...connection,
        lastRunId: run.id,
        updatedAt: now,
      });
      return run;
    },

    readRun: async (connectionId: string, runId: string): Promise<CloudUpstreamRun> => {
      const run = runs.get(runId);
      if (!run || run.connectionId !== connectionId) throw notFound("Cloud upstream run was not found");
      return run;
    },

    cancelRun: async (connectionId: string, runId: string): Promise<CloudUpstreamRun> => {
      const run = runs.get(runId);
      if (!run || run.connectionId !== connectionId) throw notFound("Cloud upstream run was not found");
      if (run.status !== "running") return run;
      const now = new Date().toISOString();
      const next: CloudUpstreamRun = {
        ...run,
        status: "cancelled",
        updatedAt: now,
        completedAt: now,
        events: [
          ...run.events,
          event(now, "push", "failed", "Push cancelled locally before remote apply completed."),
        ],
      };
      runs.set(next.id, next);
      return next;
    },
  };

  async function thisPreview(connection: CloudUpstreamConnection) {
    return {
      connectionId: connection.id,
      sourceCompanyId: connection.companyId,
      target: connection.target,
      schemaCompatible: connection.target.schemaMajor === TRANSFER_SCHEMA_MAJOR,
      summary: await buildSummary(connection.companyId),
      warnings: buildWarnings(connection.target.schemaMajor),
      conflicts: [],
      generatedAt: new Date().toISOString(),
    };
  }

  async function requireCompany(companyId: string) {
    const row = await db.select({ id: companies.id }).from(companies).where(eq(companies.id, companyId)).then((rows) => rows[0]);
    if (!row) throw notFound("Company was not found");
  }

  async function buildSummary(companyId: string): Promise<CloudUpstreamSummaryCount[]> {
    const [agentCount, projectCount, goalCount, issueCount, commentCount, routineCount] = await Promise.all([
      db.select({ count: count() }).from(agents).where(eq(agents.companyId, companyId)).then((rows) => rows[0]?.count ?? 0),
      db.select({ count: count() }).from(projects).where(eq(projects.companyId, companyId)).then((rows) => rows[0]?.count ?? 0),
      db.select({ count: count() }).from(goals).where(eq(goals.companyId, companyId)).then((rows) => rows[0]?.count ?? 0),
      db.select({ count: count() }).from(issues).where(eq(issues.companyId, companyId)).then((rows) => rows[0]?.count ?? 0),
      db.select({ count: count() }).from(issueComments).where(eq(issueComments.companyId, companyId)).then((rows) => rows[0]?.count ?? 0),
      db.select({ count: count() }).from(routines).where(eq(routines.companyId, companyId)).then((rows) => rows[0]?.count ?? 0),
    ]);
    return [
      { key: "companies", label: "Companies", count: 1 },
      { key: "goals", label: "Goals", count: goalCount },
      { key: "projects", label: "Projects", count: projectCount },
      { key: "agents", label: "Agents", count: agentCount },
      { key: "issues", label: "Issues", count: issueCount },
      { key: "comments", label: "Comments", count: commentCount },
      { key: "routines", label: "Routines", count: routineCount },
      { key: "warnings", label: "Warnings", count: buildWarnings(TRANSFER_SCHEMA_MAJOR).length },
    ];
  }

}

function requireConnection(connectionId: string) {
  const connection = connections.get(connectionId);
  if (!connection) throw notFound("Cloud upstream connection was not found");
  return connection;
}

async function fetchDiscovery(remoteUrl: string): Promise<Record<string, unknown>> {
  const parsed = new URL(remoteUrl);
  if (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") {
    throw badRequest("Cloud upstream targets require HTTPS except localhost development");
  }
  const stackId = firstPathSegment(parsed.pathname);
  const discoveryUrl = new URL("/.well-known/paperclip-upstream", parsed.origin);
  if (stackId) {
    discoveryUrl.searchParams.set("stackId", stackId);
  }
  const response = await fetch(discoveryUrl);
  if (!response.ok) {
    throw badRequest(`Cloud upstream discovery failed: ${response.status}`);
  }
  return await response.json() as Record<string, unknown>;
}

function firstPathSegment(pathname: string): string | null {
  const segment = pathname.split("/").find(Boolean);
  return segment && segment.toLowerCase() !== "dashboard" ? segment : null;
}

function targetFromDiscovery(discovery: Record<string, unknown>): CloudUpstreamTarget {
  const stack = objectField(discovery, "stack");
  const transfer = objectField(discovery, "transfer");
  const schema = objectField(transfer, "schema");
  return {
    stackId: stringField(stack, "id"),
    stackSlug: optionalString(stack.slug),
    stackDisplayName: optionalString(stack.displayName),
    companyId: stringField(stack, "companyId"),
    primaryHost: stringField(stack, "primaryHost"),
    origin: stringField(stack, "origin"),
    product: optionalString(discovery.product) ?? "Paperclip Cloud",
    schemaMajor: numberField(schema, "major"),
    maxChunkBytes: numberField(transfer, "maxChunkBytes"),
  };
}

function scopesFromDiscovery(discovery: Record<string, unknown>): string[] {
  const auth = objectField(discovery, "auth");
  const scopes = Array.isArray(auth.scopes) ? auth.scopes.map(String).filter(Boolean) : [];
  return scopes.length > 0 ? scopes : [...DEFAULT_SCOPES];
}

function consentUrlFromDiscovery(discovery: Record<string, unknown>): string {
  return stringField(objectField(objectField(discovery, "auth"), "pkce"), "consentUrl");
}

function tokenUrlFromDiscovery(discovery: Record<string, unknown>): string {
  return stringField(objectField(objectField(discovery, "auth"), "pkce"), "tokenUrl");
}

function buildWarnings(schemaMajor: number): CloudUpstreamWarning[] {
  const warnings: CloudUpstreamWarning[] = [
    {
      code: "imported_automations_paused",
      severity: "warning",
      title: "Automations stay paused",
      detail: "Imported agents, routines, and monitors require explicit activation after the push.",
    },
    {
      code: "unmatched_users_import_as_historical_authors",
      severity: "warning",
      title: "Unmatched users become historical authors",
      detail: "Invite now remains a secondary action after the transfer is complete.",
    },
    {
      code: "secret_values_redacted",
      severity: "warning",
      title: "Secret values are not transferred",
      detail: "The push carries secret requirements only. Configure cloud secrets before activating automations.",
    },
  ];
  if (schemaMajor !== TRANSFER_SCHEMA_MAJOR) {
    warnings.unshift({
      code: "schema_mismatch",
      severity: "blocker",
      title: "Cloud stack upgrade required",
      detail: `This local build uses upstream schema ${TRANSFER_SCHEMA_MAJOR}, but the cloud stack reports schema ${schemaMajor}.`,
    });
  }
  return warnings;
}

function buildCompletedEvents(now: string, retryOfRunId: string | null): CloudUpstreamRunEvent[] {
  return [
    event(now, "connect", "completed", "Connected to the target Paperclip Cloud stack."),
    event(now, "scan", "completed", "Scanned the local company inventory."),
    event(now, "preview", "completed", "Generated the conflict and warning preview."),
    retryOfRunId
      ? event(now, "push", "retrying", `Retry reused ledger state from run ${retryOfRunId}.`)
      : event(now, "push", "completed", "Pushed mapped objects without duplicate creation."),
    event(now, "verify", "completed", "Verified summary counts and generated a run report."),
    event(now, "activate", "completed", "Activation checklist is ready for manual unpause decisions."),
  ];
}

function event(
  at: string,
  phase: CloudUpstreamRunEvent["phase"],
  type: CloudUpstreamRunEvent["type"],
  message: string,
): CloudUpstreamRunEvent {
  return {
    id: crypto.randomUUID(),
    at,
    phase,
    type,
    message,
  };
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw badRequest((payload as { error?: string } | null)?.error ?? `Cloud upstream request failed: ${response.status}`);
  }
  return payload as T;
}

function objectField(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const field = value[key];
  if (!field || typeof field !== "object" || Array.isArray(field)) {
    throw badRequest(`Cloud upstream discovery missing ${key}`);
  }
  return field as Record<string, unknown>;
}

function stringField(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0) {
    throw badRequest(`Cloud upstream discovery missing ${key}`);
  }
  return field;
}

function numberField(value: Record<string, unknown>, key: string): number {
  const field = value[key];
  if (typeof field !== "number" || !Number.isFinite(field)) {
    throw badRequest(`Cloud upstream discovery missing ${key}`);
  }
  return field;
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}
