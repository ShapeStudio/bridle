import { canonical, validateEnvelope, validatePayload, type Envelope, type Payload } from "./envelope.js";
import { seal, open as openBox, type SealingKeys } from "./seal.js";

/**
 * Moves the payload into a sealed box addressed to the recipient. Do this
 * *before* signing, so the signature covers the ciphertext that actually travels.
 */
export function sealEnvelope(env: Envelope, recipientSealPublicKey: string): Envelope {
  if (env.sealed) throw new Error("envelope is already sealed");
  if (!env.payload) throw new Error("nothing to seal");
  if (env.sig) throw new Error("seal before signing, not after");
  const box = seal(Buffer.from(canonical(env.payload), "utf8"), recipientSealPublicKey, env.id);
  const { payload: _drop, ...rest } = env;
  return { ...rest, sealed: box };
}

/**
 * Opens a sealed envelope on the receiving machine and re-validates the payload.
 * A payload is never trusted just because it decrypted — it still has to be a
 * well-formed payload for the verb it claims.
 */
export function openEnvelope(env: Envelope, keys: SealingKeys): Envelope {
  if (!env.sealed) throw new Error("envelope is not sealed");
  const plain = openBox(env.sealed, keys, env.id);
  const payload = JSON.parse(plain.toString("utf8")) as Payload;
  validatePayload(env.verb, payload as unknown as Record<string, unknown>);
  const { sealed: _drop, ...rest } = env;
  const opened = { ...rest, payload } as Envelope;
  validateEnvelope(opened);
  return opened;
}
