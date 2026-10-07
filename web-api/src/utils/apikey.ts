import crypto from "node:crypto";

const PREFIX = "crk_";
const KEY_BYTES = 32;

export function generateApiKey(): { plaintext: string; hash: string; prefix: string } {
  const raw = crypto.randomBytes(KEY_BYTES).toString("base64url");
  const plaintext = `${PREFIX}${raw}`;
  const hash = crypto.createHash("sha256").update(plaintext).digest("hex");
  const prefix = plaintext.slice(0, 12);
  return { plaintext, hash, prefix };
}

export function hashApiKey(plaintext: string): string {
  return crypto.createHash("sha256").update(plaintext).digest("hex");
}
