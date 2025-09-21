// bridge/crypto-bridge.js
import { stdin as i, stdout as o } from 'node:process';
import { timingSafeEqual } from 'node:crypto';
import { decode as b64d, encode as b64e } from './utils/base64url.js';
import { sha3_256 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { argon2id } from '@noble/hashes/argon2';
import { randomBytes as randHash } from '@noble/hashes/utils';
import { gcm } from '@noble/ciphers/aes';
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes as randCipher } from '@noble/ciphers/webcrypto';

function randomBytes(n) { try { return randCipher(n); } catch { return randHash(n); } }
function toU8(b64) { return new Uint8Array(b64d(b64)); }
function toB64(u8) { return b64e(u8); }

async function main() {
  const raw = await new Promise((res) => {
    let buf = ''; i.setEncoding('utf8'); i.on('data', (d) => (buf += d)); i.on('end', () => res(buf));
  });
  const req = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  const { op } = req;
  const out = {};
  try {
    switch (op) {
      case 'argon2id': {
        const { password_b64, salt_b64, mCost, t, p, dkLen } = req;
        const key = await argon2id(toU8(password_b64), toU8(salt_b64), { m: mCost, t, p, dkLen });
        out.ok = true; out.key_b64 = toB64(key); break;
      }
      case 'argon2id_batch': {
        const { items, mCost, t, p, dkLen } = req;
        if (!Array.isArray(items)) throw new Error('items must be an array');
        const results = [];
        for (const it of items) {
          const key = await argon2id(toU8(it.password_b64), toU8(it.salt_b64), { m: mCost, t, p, dkLen });
          results.push(toB64(key));
        }
        out.ok = true; out.keys_b64 = results; break;
      } case 'hkdf_sha256': {
        const { ikm_b64, salt_b64, info_b64, dkLen } = req;
        out.ok = true; out.key_b64 = toB64(hkdf(sha256, toU8(ikm_b64), toU8(salt_b64), toU8(info_b64), dkLen)); break;
      } case 'hmac_sha256': {
        out.ok = true; out.tag_b64 = toB64(hmac(sha256, toU8(req.key_b64), toU8(req.data_b64))); break;
      } case 'sha3_256': {
        out.ok = true; out.hash_b64 = toB64(sha3_256(toU8(req.data_b64))); break;
      } case 'aes_gcm_encrypt': {
        const { key_b64, nonce_b64, pt_b64, aad_b64 } = req;
        const aes = gcm(toU8(key_b64), toU8(nonce_b64), aad_b64 ? toU8(aad_b64) : undefined);
        out.ok = true; out.ct_b64 = toB64(aes.encrypt(toU8(pt_b64))); break;
      } case 'aes_gcm_decrypt': {
        const { key_b64, nonce_b64, ct_b64, aad_b64 } = req;
        const aes = gcm(toU8(key_b64), toU8(nonce_b64), aad_b64 ? toU8(aad_b64) : undefined);
        out.ok = true; out.pt_b64 = toB64(aes.decrypt(toU8(ct_b64))); break;
      } case 'chacha20poly1305_encrypt': {
        const { key_b64, nonce_b64, pt_b64, aad_b64 } = req;
        const ch = chacha20poly1305(toU8(key_b64), toU8(nonce_b64), aad_b64 ? toU8(aad_b64) : undefined);
        out.ok = true; out.ct_b64 = toB64(ch.encrypt(toU8(pt_b64))); break;
      } case 'chacha20poly1305_decrypt': {
        const { key_b64, nonce_b64, ct_b64, aad_b64 } = req;
        const ch = chacha20poly1305(toU8(key_b64), toU8(nonce_b64), aad_b64 ? toU8(aad_b64) : undefined);
        out.ok = true; out.pt_b64 = toB64(ch.decrypt(toU8(ct_b64))); break;
      } case 'xchacha20poly1305_encrypt': {
        const { key_b64, nonce_b64, pt_b64, aad_b64 } = req;
        const ch = xchacha20poly1305(toU8(key_b64), toU8(nonce_b64), aad_b64 ? toU8(aad_b64) : undefined);
        out.ok = true; out.ct_b64 = toB64(ch.encrypt(toU8(pt_b64))); break;
      } case 'xchacha20poly1305_decrypt': {
        const { key_b64, nonce_b64, ct_b64, aad_b64 } = req;
        const ch = xchacha20poly1305(toU8(key_b64), toU8(nonce_b64), aad_b64 ? toU8(aad_b64) : undefined);
        out.ok = true; out.pt_b64 = toB64(ch.decrypt(toU8(ct_b64))); break;
      } case 'random_bytes': {
        out.ok = true; out.bytes_b64 = toB64(randomBytes(req.n)); break;
      } case 'consttime_equal': {
        const bufA = Buffer.from(toU8(req.a_b64)), bufB = Buffer.from(toU8(req.b_b64));
        out.ok = true; out.equal = bufA.length === bufB.length && timingSafeEqual(bufA, bufB); break;
      } default: throw new Error(`Unknown op: ${op}`);
    }
  } catch (e) { out.ok = false; out.error = String(e?.message || e); }
  o.write(Buffer.from(JSON.stringify(out), 'utf8').toString('base64url'));
}
await main();
