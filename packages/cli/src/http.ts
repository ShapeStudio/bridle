import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

/**
 * A tiny request helper on node:http rather than fetch.
 *
 * fetch's connection pool keeps the event loop alive after a one-shot CLI
 * command has printed its output, so `bridle send` would sit there for seconds
 * doing nothing. Explicit sockets with keep-alive off exit the moment we are done.
 */
export interface HttpResult {
  status: number;
  body: unknown;
}

export function requestJson(
  url: string,
  opts: { method?: string; headers?: Record<string, string>; body?: unknown; timeoutMs?: number } = {}
): Promise<HttpResult> {
  const u = new URL(url);
  const send = u.protocol === "https:" ? httpsRequest : httpRequest;
  const payload = opts.body === undefined ? undefined : Buffer.from(JSON.stringify(opts.body), "utf8");

  return new Promise((resolve, reject) => {
    const req = send(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method: opts.method ?? "GET",
        agent: false,
        headers: {
          "content-type": "application/json",
          connection: "close",
          ...(payload ? { "content-length": String(payload.length) } : {}),
          ...(opts.headers ?? {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let body: unknown = {};
          if (text) {
            try {
              body = JSON.parse(text);
            } catch {
              return reject(new Error(`bad response from ${u.host}: ${text.slice(0, 120)}`));
            }
          }
          resolve({ status: res.statusCode ?? 0, body });
        });
      }
    );
    req.setTimeout(opts.timeoutMs ?? 10_000, () => req.destroy(new Error(`timed out talking to ${u.host}`)));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}
