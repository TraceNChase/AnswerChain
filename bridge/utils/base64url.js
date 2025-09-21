// bridge/utils/base64url.js
export function encode(u8) {
  return Buffer.from(u8).toString('base64url');
}
export function decode(b64url) {
  return new Uint8Array(Buffer.from(b64url, 'base64url'));
}