#!/usr/bin/env node
// sss-bridge.cjs — JSON-over-stdin CLI around the audited library

const fs = require("fs");
const path = require("path");

// FIX: Prefer the vendored package but fall back to a globally installed one.
// This makes the script more resilient to different environment setups.
const vendorPath = path.join(__dirname, "vendor", "shamir-secret-sharing-0.0.3");
let split, combine;
try {
  ({ split, combine } = require(vendorPath));
} catch (e1) {
  try {
    ({ split, combine } = require("shamir-secret-sharing"));
  } catch (e2) {
    // If both fail, send a clean JSON error back to Python instead of crashing.
    process.stdout.write(JSON.stringify({ ok: false, error: "Cannot load shamir-secret-sharing (from vendor or node_modules)." }) + "\n");
    process.exit(0);
  }
}

const readStdin = () => fs.readFileSync(0, "utf8");
const ok = (obj) => process.stdout.write(JSON.stringify({ ok: true, ...obj }) + "\n");
const fail = (err) =>
  process.stdout.write(JSON.stringify({ ok: false, error: String(err && err.message ? err.message : err) }) + "\n");

(async () => {
  try {
    const req = JSON.parse(readStdin());

    if (req.cmd === "split") {
      if (typeof req.secret_b64 !== "string") throw new Error("secret_b64 missing");
      if (typeof req.shares !== "number" || typeof req.threshold !== "number") throw new Error("shares/threshold missing");
      const secret = new Uint8Array(Buffer.from(req.secret_b64, "base64"));
      const shares = await split(secret, req.shares, req.threshold);
      const shares_b64 = shares.map((u8) => Buffer.from(u8).toString("base64"));
      ok({ shares_b64 });
      return;
    }

    if (req.cmd === "combine") {
      if (!Array.isArray(req.shares_b64)) throw new Error("shares_b64 missing");
      const shares = req.shares_b64.map((b64) => new Uint8Array(Buffer.from(b64, "base64")));
      const secret = await combine(shares);
      ok({ secret_b64: Buffer.from(secret).toString("base64") });
      return;
    }

    throw new Error("unknown cmd");
  } catch (e) {
    fail(e);
  }
})();