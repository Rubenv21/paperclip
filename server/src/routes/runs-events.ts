import type { RunJwtService } from "../services/run-jwt.js";

export interface RunEventInput {
  runId: string;
  type: string;
  ts: string;
  payload: Record<string, unknown>;
}

export interface RunsEventsDeps {
  runJwt: RunJwtService;
  appendRunEvent: (input: RunEventInput) => Promise<void>;
}

export interface RouteRequest {
  params: { runId: string };
  headers: { authorization?: string };
  body: { type?: string; ts?: string; [k: string]: unknown };
}

export interface RouteResponse {
  status: number;
  body?: Record<string, unknown>;
}

export function createRunsEventsRoute(deps: RunsEventsDeps) {
  return async (req: RouteRequest): Promise<RouteResponse> => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith("Bearer ")) return { status: 401, body: { error: "missing_authorization" } };
    const v = deps.runJwt.verify(auth.slice("Bearer ".length));
    if (!v.ok) return { status: 401, body: { error: "invalid_jwt" } };
    if (v.claims.runId !== req.params.runId) {
      return { status: 403, body: { error: "run_id_mismatch" } };
    }
    if (typeof req.body.type !== "string") {
      return { status: 400, body: { error: "missing_event_type" } };
    }
    await deps.appendRunEvent({
      runId: v.claims.runId,
      type: req.body.type,
      ts: typeof req.body.ts === "string" ? req.body.ts : new Date().toISOString(),
      payload: req.body,
    });
    return { status: 204 };
  };
}
