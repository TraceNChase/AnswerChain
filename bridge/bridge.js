"use strict";
/**
 * AnswerChain cryptographic bridge (Node.js <-> Python), NDJSON over stdio.
 * Requires noble single-file bundles placed NEXT TO this file:
 *   - noble-hashes.js  (exports { sha3_256, hmac, hkdf, sha256, argon2id })
 *   - noble-ciphers.js (exports { gcm, chacha20poly1305, xchacha20poly1305 })
 */
const fs = require("node:fs");
const vm = require("node:vm");
const crypto = require("node:crypto");
const path = require("node:path");

function loadBundle(p, globalNameCandidates) {
  const code = fs.readFileSync(p, "utf8");
  const ctx = { console: undefined, module: {}, exports: {} };
  vm.createContext(ctx);
  vm.runInContext(code, ctx, { filename: p, displayErrors: true });

  // Try UMD/CommonJS exports first
  if (ctx.module && ctx.module.exports && Object.keys(ctx.module.exports).length) return ctx.module.exports;
  if (ctx.exports && Object.keys(ctx.exports).length) return ctx.exports;

  // Otherwise, fall back to known global names
  for (const name of globalNameCandidates) {
    if (name in ctx) return ctx[name];
  }
  throw new Error(`Bundle ${p} did not expose expected exports or globals`);
}

const DIR = __dirname;
const hashesPath = path.join(DIR, "noble-hashes.js");
const ciphersPath = path.join(DIR, "noble-ciphers.js");

if (!fs.existsSync(hashesPath)) throw new Error(`Missing ${hashesPath}`);
if (!fs.existsSync(ciphersPath)) throw new Error(`Missing ${ciphersPath}`);

const nobleHashes = loadBundle(hashesPath, ["nobleHashes"]);
const nobleCiphers = loadBundle(ciphersPath, ["nobleCiphers"]);

const { sha3_256, hmac, hkdf, sha256, argon2id } = nobleHashes;
const { gcm, chacha20poly1305, xchacha20poly1305 } = nobleCiphers;

function b64(buf) { return Buffer.from(buf).toString("base64"); }
function b64d(s) {
  if (typeof s !== "string") throw new Error("expected base64 string");
  return Buffer.from(s, "base64");
}
function toU8(b) {
  if (Buffer.isBuffer(b)) return new Uint8Array(b);
  if (b instanceof Uint8Array) return b;
  return new Uint8Array(Buffer.from(b));
}
function assertLen(name, bytes, len) {
  if (bytes.length !== len) throw new Error(`${name} must be exactly ${len} bytes`);
}
function assertMinLen(name, bytes, min) {
  if (bytes.length < min) throw new Error(`${name} must be at least ${min} bytes`);
}
function optBytes(s) { return s == null ? undefined : toU8(b64d(s)); }

function ok(id, result) { process.stdout.write(JSON.stringify({ id, ok: true, result }) + "\n"); }
function fail(id, error) { process.stdout.write(JSON.stringify({ id, ok: false, error: String(error) }) + "\n"); }
function safe(id, fn) { try { fn(); } catch (e) { fail(id, e && e.stack || e); } }

const OPS = {
  ping: () => ({ pong: 1 }),

  sha3_256: ({ data }) => {
    const out = sha3_256(toU8(b64d(data)));
    return { digest: b64(Buffer.from(out)) };
  },

  hmac_sha256: ({ key, data }) => {
    const out = hmac.create(sha256, toU8(b64d(key))).update(toU8(b64d(data))).digest();
    return { digest: b64(Buffer.from(out)) };
  },

  hkdf_sha256: ({ ikm, salt = "", info = "", length }) => {
    const L = Number(length);
    if (!Number.isInteger(L) || L <= 0 || L > 255 * 32) throw new Error("length must be in (0, 8160]");
    const out = hkdf(sha256, toU8(b64d(ikm)), toU8(b64d(salt)), toU8(b64d(info)), L);
    return { okm: b64(Buffer.from(out)) };
  },

  argon2id: ({ password, salt, t = 2, m = 65536, p = 1, dkLen = 32, version = 19 }) => {
    const pwd = toU8(b64d(password));
    const slt = toU8(b64d(salt));
    assertMinLen("salt", slt, 16);
    const opts = { t: Number(t), m: Number(m), p: Number(p), dkLen: Number(dkLen), version: Number(version) };
    if (!(opts.t >= 1 && opts.m >= 8 && opts.p >= 1 && opts.dkLen >= 16 && opts.dkLen <= 1024)) {
      throw new Error("invalid argon2id parameters");
    }
    const out = argon2id(pwd, slt, opts);
    return { okm: b64(Buffer.from(out)) };
  },

  aes_gcm_encrypt: ({ key, nonce, aad, plaintext }) => {
    const K = toU8(b64d(key));  assertLen("key", K, 32);
    const N = toU8(b64d(nonce));assertLen("nonce", N, 12);
    const A = aad == null ? undefined : toU8(b64d(aad));
    const P = toU8(b64d(plaintext));
    const C = gcm(K, N, A).encrypt(P);
    return { ciphertext: b64(Buffer.from(C)) };
  },

  aes_gcm_decrypt: ({ key, nonce, aad, ciphertext }) => {
    const K = toU8(b64d(key));  assertLen("key", K, 32);
    const N = toU8(b64d(nonce));assertLen("nonce", N, 12);
    const A = aad == null ? undefined : toU8(b64d(aad));
    const C = toU8(b64d(ciphertext));
    const P = gcm(K, N, A).decrypt(C);
    return { plaintext: b64(Buffer.from(P)) };
  },

  chacha20poly1305_encrypt: ({ key, nonce, aad, plaintext }) => {
    const K = toU8(b64d(key));  assertLen("key", K, 32);
    const N = toU8(b64d(nonce));assertLen("nonce", N, 12);
    const A = aad == null ? undefined : toU8(b64d(aad));
    const P = toU8(b64d(plaintext));
    const C = chacha20poly1305(K, N, A).encrypt(P);
    return { ciphertext: b64(Buffer.from(C)) };
  },

  chacha20poly1305_decrypt: ({ key, nonce, aad, ciphertext }) => {
    const K = toU8(b64d(key));  assertLen("key", K, 32);
    const N = toU8(b64d(nonce));assertLen("nonce", N, 12);
    const A = aad == null ? undefined : toU8(b64d(aad));
    const C = toU8(b64d(ciphertext));
    const P = chacha20poly1305(K, N, A).decrypt(C);
    return { plaintext: b64(Buffer.from(P)) };
  },

  xchacha20poly1305_encrypt: ({ key, nonce, aad, plaintext }) => {
    const K = toU8(b64d(key));  assertLen("key", K, 32);
    const N = toU8(b64d(nonce));assertLen("nonce", N, 24);
    const A = aad == null ? undefined : toU8(b64d(aad));
    const P = toU8(b64d(plaintext));
    const C = xchacha20poly1305(K, N, A).encrypt(P);
    return { ciphertext: b64(Buffer.from(C)) };
  },

  xchacha20poly1305_decrypt: ({ key, nonce, aad, ciphertext }) => {
    const K = toU8(b64d(key));  assertLen("key", K, 32);
    const N = toU8(b64d(nonce));assertLen("nonce", N, 24);
    const A = aad == null ? undefined : toU8(b64d(aad));
    const C = toU8(b64d(ciphertext));
    const P = xchacha20poly1305(K, N, A).decrypt(C);
    return { plaintext: b64(Buffer.from(P)) };
  },

  ct_equal: ({ a, b }) => {
    const A = b64d(a), B = b64d(b);
    if (A.length !== B.length) return { equal: false };
    return { equal: crypto.timingSafeEqual(A, B) };
  }
};

function handle(line) {
  let msg;
  try { msg = JSON.parse(line); } catch { return fail(null, "invalid json"); }
  const { id, op, args } = msg || {};
  if (typeof op !== "string" || !(op in OPS)) return fail(id, "unknown op");
  safe(id, () => ok(id, OPS[op](args || {})));
}

function main() {
  delete process.env.NODE_OPTIONS; // avoid user overrides
  process.stdin.setEncoding("utf8");
  let buf = "";
  process.stdin.on("data", (chunk) => {
    buf += chunk;
    while (true) {
      const idx = buf.indexOf("\n");
      if (idx === -1) break;
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (line.length) handle(line);
    }
  });
  process.stdin.on("end", () => process.exit(0));
}
if (require.main === module) main();
