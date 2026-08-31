import {
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  createPublicKey,
  createPrivateKey,
  type KeyObject,
} from "node:crypto";
import { signingBytes, type Envelope } from "./envelope.js";
import { generateSealingKeys } from "./seal.js";

export interface Identity {
  /** Node name inside the bridlenet, e.g. "marko.dev". */
  name: string;
  /** Ed25519 — proves who sent an envelope. */
  publicKey: string; // base64 (SPKI DER)
  privateKey: string; // base64 (PKCS8 DER) — never leaves the machine
  /** X25519 — decides who can read one. */
  sealPublicKey: string;
  sealPrivateKey: string;
}

export function generateIdentity(name: string): Identity {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const sealing = generateSealingKeys();
  return {
    name,
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
    sealPublicKey: sealing.publicKey,
    sealPrivateKey: sealing.privateKey,
  };
}

function toPublic(b64: string): KeyObject {
  return createPublicKey({ key: Buffer.from(b64, "base64"), format: "der", type: "spki" });
}
function toPrivate(b64: string): KeyObject {
  return createPrivateKey({ key: Buffer.from(b64, "base64"), format: "der", type: "pkcs8" });
}

/** Short, human-comparable fingerprint — the thing two people read aloud when pairing. */
export function fingerprint(publicKeyB64: string): string {
  const raw = Buffer.from(publicKeyB64, "base64").subarray(-32);
  const hex = raw.toString("hex").slice(0, 16).toUpperCase();
  return (hex.match(/.{4}/g) ?? []).join("-");
}

export function signEnvelope(env: Envelope, identity: Identity): Envelope {
  if (env.fromKey !== identity.publicKey) {
    throw new Error("refusing to sign: envelope.fromKey does not match this identity");
  }
  const sig = nodeSign(null, signingBytes(env), toPrivate(identity.privateKey));
  return { ...env, sig: sig.toString("base64") };
}

/**
 * Verifies the signature against the key carried *in the envelope*. The caller
 * must separately confirm that key is the one they granted a scope to —
 * see `verifyFrom`.
 */
export function verifyEnvelope(env: Envelope): boolean {
  if (!env.sig) return false;
  try {
    return nodeVerify(null, signingBytes(env), toPublic(env.fromKey), Buffer.from(env.sig, "base64"));
  } catch {
    return false;
  }
}

/**
 * The check that actually matters: the signature is valid AND the key belongs to
 * the peer we think we are talking to. Verifying the signature alone would let
 * anyone claim to be anyone by bringing their own key.
 */
export function verifyFrom(env: Envelope, expectedKeyB64: string | undefined): { ok: boolean; reason?: string } {
  if (!env.sig) return { ok: false, reason: "envelope is unsigned" };
  if (!expectedKeyB64) return { ok: false, reason: `no known key for peer "${env.from}"` };
  if (env.fromKey !== expectedKeyB64) return { ok: false, reason: `key mismatch for peer "${env.from}"` };
  return verifyEnvelope(env) ? { ok: true } : { ok: false, reason: "bad signature" };
}
