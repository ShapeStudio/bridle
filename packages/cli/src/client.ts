import { readConfig } from "./home.js";
import { requestJson } from "./http.js";
import type { Envelope } from "bridle-core";

async function call<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const { coord, token } = readConfig();
  if (!coord) throw new Error("not joined to a bridlenet — run `bridle join --coord <url> --invite <code>`");
  const { status, body: res } = await requestJson(new URL(path, coord).toString(), {
    method,
    body,
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
  if (status >= 400) throw new Error((res as { error?: string }).error ?? `HTTP ${status}`);
  return res as T;
}

/**
 * The hosted coordination server.
 *
 * Baked in so `bridle up` works with no flags and no environment — that is the
 * whole point of a cloud default. Self-hosters override it with BRIDLE_COORD or
 * `--coord`, and once a node has joined, the coord it joined is remembered in
 * config.json and used from then on regardless of this value.
 */
export const DEFAULT_COORD = process.env.BRIDLE_COORD ?? "https://api.bridle.network";

export interface DeviceCode {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  interval: number;
  expiresIn: number;
}

/** Device-flow calls happen before we have a token, so they take the URL directly. */
export const device = {
  start: async (coord: string, body: { name: string; key: string; sealKey: string }): Promise<DeviceCode> => {
    const { status, body: res } = await requestJson(new URL("/v1/device/code", coord).toString(), {
      method: "POST", body,
    });
    if (status >= 400) throw new Error((res as { error?: string }).error ?? `HTTP ${status}`);
    return res as DeviceCode;
  },
  poll: async (
    coord: string,
    deviceCode: string
  ): Promise<{ status: "pending" } | { status: "approved"; orgId: string; name: string; token: string }> => {
    const { status, body: res } = await requestJson(new URL("/v1/device/token", coord).toString(), {
      method: "POST", body: { deviceCode },
    });
    if (status === 200) return res as never;
    const err = (res as { error?: string }).error ?? `HTTP ${status}`;
    if (err === "expired_token") throw new Error("that code expired — run `bridle up` again");
    if (err === "access_denied") throw new Error("the request was denied in the dashboard");
    throw new Error(err);
  },
};

export const api = {
  register: async (coord: string, body: unknown) => {
    const { status, body: res } = await requestJson(new URL("/v1/register", coord).toString(), {
      method: "POST",
      body,
    });
    if (status >= 400) throw new Error((res as { error?: string }).error ?? `HTTP ${status}`);
    return res as { name: string; token: string };
  },
  invite: () => call<{ code: string }>("/v1/invite", "POST"),
  peers: () => call<{ peers: { name: string; key: string; sealKey: string }[] }>("/v1/peers"),
  send: (envelope: Envelope) => call<{ id: string }>("/v1/envelope", "POST", { envelope }),
  inbox: () => call<{ envelopes: Envelope[] }>("/v1/inbox"),
  /** `heldMs` rides along when an operator settled it — how long approval took. Metadata; older servers ignore it. */
  ack: (id: string, verdict: string, reason?: string, heldMs?: number) =>
    call<{ ok: true }>("/v1/ack", "POST", { id, verdict, reason, heldMs }),
  audit: () => call<{ events: Record<string, unknown>[] }>("/v1/audit"),
};
