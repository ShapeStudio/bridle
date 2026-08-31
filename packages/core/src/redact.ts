/**
 * Redaction runs on outbound payloads *and* on state.read responses. It is a
 * safety net, not a guarantee: policy still refuses whole fields by name.
 */
/**
 * Order matters: the most specific pattern for a given prefix has to come first,
 * or a broader one claims the match and mislabels it.
 */
const PATTERNS: { name: string; re: RegExp }[] = [
  { name: "private-key", re: /-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----/g },
  { name: "aws-access-key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g },
  { name: "slack-token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "stripe-key", re: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  // Must precede the generic sk- rule, which would otherwise swallow and mislabel it.
  { name: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: "openai-key", re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: "bearer", re: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/gi },
  // Catches FOO_SECRET=, AWS_SECRET_ACCESS_KEY=, DB_PASSWORD: and friends, while
  // leaving innocent identifiers that merely end in "KEY" (MONKEY=1) alone.
  { name: "env-assignment", re: /\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|API_?KEY|ACCESS_KEY|PRIVATE_KEY|_KEY)\b\s*[=:]\s*\S+/g },
];

export interface RedactionResult<T> {
  value: T;
  found: string[];
}

export function redactString(input: string): RedactionResult<string> {
  let out = input;
  const found: string[] = [];
  for (const { name, re } of PATTERNS) {
    if (re.test(out)) {
      found.push(name);
      out = out.replace(new RegExp(re.source, re.flags), `[redacted:${name}]`);
    }
    re.lastIndex = 0;
  }
  return { value: out, found };
}

/** Walks any JSON value, redacting every string it contains. */
export function redactDeep<T>(input: T): RedactionResult<T> {
  const found = new Set<string>();
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") {
      const r = redactString(v);
      r.found.forEach((f) => found.add(f));
      return r.value;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x)]));
    }
    return v;
  };
  return { value: walk(input) as T, found: [...found] };
}
