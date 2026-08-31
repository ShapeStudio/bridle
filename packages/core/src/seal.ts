import {
  generateKeyPairSync,
  diffieHellman,
  createPublicKey,
  createPrivateKey,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

/**
 * Payload sealing.
 *
 * Signing keys prove who sent an envelope; these keys decide who can read one.
 * The relay handles sealed boxes only — it can verify a signature and route by
 * name, and it cannot open the payload. That is what makes "self-host the
 * coordination server, or don't, the relay still can't read your work" true
 * rather than a promise.
 *
 * X25519 ECDH with an ephemeral sender key -> HKDF-SHA256 -> AES-256-GCM.
 * The envelope id is bound in as additional data, so a sealed box cannot be
 * lifted out of one envelope and replayed inside another.
 */
export interface SealedBox {
  /** Ephemeral sender public key, base64 SPKI DER. */
  epk: string;
  iv: string;
  ct: string;
  tag: string;
}

export interface SealingKeys {
  publicKey: string;
  privateKey: string;
}

export function generateSealingKeys(): SealingKeys {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

const pub = (b64: string) =>
  createPublicKey({ key: Buffer.from(b64, "base64"), format: "der", type: "spki" });
const priv = (b64: string) =>
  createPrivateKey({ key: Buffer.from(b64, "base64"), format: "der", type: "pkcs8" });

function deriveKey(shared: Buffer, epkB64: string, recipientB64: string, aad: string): Buffer {
  const salt = Buffer.from(epkB64 + "|" + recipientB64, "utf8");
  return Buffer.from(hkdfSync("sha256", shared, salt, Buffer.from("bridle/seal/v1|" + aad, "utf8"), 32));
}

export function seal(plaintext: Buffer, recipientPublicKeyB64: string, aad: string): SealedBox {
  const eph = generateKeyPairSync("x25519");
  const epk = eph.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: pub(recipientPublicKeyB64) });
  const key = deriveKey(shared, epk, recipientPublicKeyB64, aad);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    epk,
    iv: iv.toString("base64"),
    ct: ct.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

export class SealError extends Error {}

export function open(box: SealedBox, recipient: SealingKeys, aad: string): Buffer {
  let shared: Buffer;
  try {
    shared = diffieHellman({ privateKey: priv(recipient.privateKey), publicKey: pub(box.epk) });
  } catch {
    throw new SealError("malformed ephemeral key");
  }
  const key = deriveKey(shared, box.epk, recipient.publicKey, aad);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(box.iv, "base64"));
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(Buffer.from(box.tag, "base64"));
  try {
    return Buffer.concat([decipher.update(Buffer.from(box.ct, "base64")), decipher.final()]);
  } catch {
    throw new SealError("could not open sealed payload: wrong recipient, or it was tampered with");
  }
}

/** Constant-time compare, for anywhere we check a token or a code. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
