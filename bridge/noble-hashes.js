var nobleHashes = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // input.js
  var input_exports = {};
  __export(input_exports, {
    argon2id: () => argon2id,
    blake224: () => blake224,
    blake256: () => blake256,
    blake2b: () => blake2b,
    blake2s: () => blake2s,
    blake3: () => blake3,
    blake384: () => blake384,
    blake512: () => blake512,
    cshake128: () => cshake128,
    cshake256: () => cshake256,
    eskdf: () => eskdf,
    hkdf: () => hkdf,
    hmac: () => hmac,
    keccak_224: () => keccak_224,
    keccak_256: () => keccak_256,
    keccak_384: () => keccak_384,
    keccak_512: () => keccak_512,
    keccakprg: () => keccakprg,
    kmac128: () => kmac128,
    kmac256: () => kmac256,
    kt128: () => kt128,
    kt256: () => kt256,
    md5: () => md5,
    pbkdf2: () => pbkdf2,
    pbkdf2Async: () => pbkdf2Async,
    ripemd160: () => ripemd160,
    scrypt: () => scrypt,
    scryptAsync: () => scryptAsync,
    sha1: () => sha1,
    sha224: () => sha224,
    sha256: () => sha256,
    sha384: () => sha384,
    sha3_224: () => sha3_224,
    sha3_256: () => sha3_256,
    sha3_384: () => sha3_384,
    sha3_512: () => sha3_512,
    sha512: () => sha512,
    sha512_224: () => sha512_224,
    sha512_256: () => sha512_256,
    shake128: () => shake128,
    shake256: () => shake256,
    turboshake128: () => turboshake128,
    turboshake256: () => turboshake256,
    utils: () => utils,
    webcrypto: () => webcrypto_exports
  });

  // ../../utils.js
  function isBytes(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
  }
  function anumber(n, title = "") {
    if (!Number.isSafeInteger(n) || n < 0) {
      const prefix = title && `"${title}" `;
      throw new Error(`${prefix}expected integer >0, got ${n}`);
    }
  }
  function abytes(value, length, title = "") {
    const bytes = isBytes(value);
    const len = value?.length;
    const needsLen = length !== void 0;
    if (!bytes || needsLen && len !== length) {
      const prefix = title && `"${title}" `;
      const ofLen = needsLen ? ` of length ${length}` : "";
      const got = bytes ? `length=${len}` : `type=${typeof value}`;
      throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
    }
    return value;
  }
  function ahash(h) {
    if (typeof h !== "function" || typeof h.create !== "function")
      throw new Error("Hash must wrapped by utils.createHasher");
    anumber(h.outputLen);
    anumber(h.blockLen);
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished)
      throw new Error("Hash#digest() has already been called");
  }
  function aoutput(out, instance) {
    abytes(out, void 0, "digestInto() output");
    const min = instance.outputLen;
    if (out.length < min) {
      throw new Error('"digestInto() output" expected to be of length >=' + min);
    }
  }
  function u8(arr) {
    return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function rotr(word, shift) {
    return word << 32 - shift | word >>> shift;
  }
  function rotl(word, shift) {
    return word << shift | word >>> 32 - shift >>> 0;
  }
  var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
  function byteSwap(word) {
    return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
  }
  var swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n);
  function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = byteSwap(arr[i]);
    }
    return arr;
  }
  var swap32IfBE = isLE ? (u) => u : byteSwap32;
  var hasHexBuiltin = /* @__PURE__ */ (() => (
    // @ts-ignore
    typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
  ))();
  var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
  function bytesToHex(bytes) {
    abytes(bytes);
    if (hasHexBuiltin)
      return bytes.toHex();
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += hexes[bytes[i]];
    }
    return hex;
  }
  var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
  function asciiToBase16(ch) {
    if (ch >= asciis._0 && ch <= asciis._9)
      return ch - asciis._0;
    if (ch >= asciis.A && ch <= asciis.F)
      return ch - (asciis.A - 10);
    if (ch >= asciis.a && ch <= asciis.f)
      return ch - (asciis.a - 10);
    return;
  }
  function hexToBytes(hex) {
    if (typeof hex !== "string")
      throw new Error("hex string expected, got " + typeof hex);
    if (hasHexBuiltin)
      return Uint8Array.fromHex(hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
      throw new Error("hex string expected, got unpadded hex of length " + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
      const n1 = asciiToBase16(hex.charCodeAt(hi));
      const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
      if (n1 === void 0 || n2 === void 0) {
        const char = hex[hi] + hex[hi + 1];
        throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
      }
      array[ai] = n1 * 16 + n2;
    }
    return array;
  }
  var nextTick = async () => {
  };
  async function asyncLoop(iters, tick, cb) {
    let ts = Date.now();
    for (let i = 0; i < iters; i++) {
      cb(i);
      const diff = Date.now() - ts;
      if (diff >= 0 && diff < tick)
        continue;
      await nextTick();
      ts += diff;
    }
  }
  function utf8ToBytes(str) {
    if (typeof str !== "string")
      throw new Error("string expected");
    return new Uint8Array(new TextEncoder().encode(str));
  }
  function kdfInputToBytes(data, errorTitle = "") {
    if (typeof data === "string")
      return utf8ToBytes(data);
    return abytes(data, void 0, errorTitle);
  }
  function concatBytes(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
      const a = arrays[i];
      abytes(a);
      sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
      const a = arrays[i];
      res.set(a, pad);
      pad += a.length;
    }
    return res;
  }
  function checkOpts(defaults, opts) {
    if (opts !== void 0 && {}.toString.call(opts) !== "[object Object]")
      throw new Error("options must be object or undefined");
    const merged = Object.assign(defaults, opts);
    return merged;
  }
  function createHasher(hashCons, info = {}) {
    const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
    const tmp = hashCons(void 0);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
  }
  function randomBytes(bytesLength = 32) {
    const cr = typeof globalThis === "object" ? globalThis.crypto : null;
    if (typeof cr?.getRandomValues !== "function")
      throw new Error("crypto.getRandomValues must be defined");
    return cr.getRandomValues(new Uint8Array(bytesLength));
  }
  var oidNist = (suffix) => ({
    oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
  });

  // ../../_u64.js
  var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
  var _32n = /* @__PURE__ */ BigInt(32);
  function fromBig(n, le = false) {
    if (le)
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
  }
  function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
      const { h, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
  }
  var shrSH = (h, _l, s) => h >>> s;
  var shrSL = (h, l, s) => h << 32 - s | l >>> s;
  var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
  var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
  var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
  var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
  var rotr32H = (_h, l) => l;
  var rotr32L = (h, _l) => h;
  var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
  var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
  var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
  var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
  function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
  }
  var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
  var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
  var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
  var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
  var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
  var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;

  // ../../_blake.js
  var BSIGMA = /* @__PURE__ */ Uint8Array.from([
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3,
    11,
    8,
    12,
    0,
    5,
    2,
    15,
    13,
    10,
    14,
    3,
    6,
    7,
    1,
    9,
    4,
    7,
    9,
    3,
    1,
    13,
    12,
    11,
    14,
    2,
    6,
    5,
    10,
    4,
    0,
    15,
    8,
    9,
    0,
    5,
    7,
    2,
    4,
    10,
    15,
    14,
    1,
    11,
    12,
    6,
    8,
    3,
    13,
    2,
    12,
    6,
    10,
    0,
    11,
    8,
    3,
    4,
    13,
    7,
    5,
    15,
    14,
    1,
    9,
    12,
    5,
    1,
    15,
    14,
    13,
    4,
    10,
    0,
    7,
    6,
    3,
    9,
    2,
    8,
    11,
    13,
    11,
    7,
    14,
    12,
    1,
    3,
    9,
    5,
    0,
    15,
    4,
    8,
    6,
    2,
    10,
    6,
    15,
    14,
    9,
    11,
    3,
    0,
    8,
    12,
    2,
    13,
    7,
    1,
    4,
    10,
    5,
    10,
    2,
    8,
    4,
    7,
    6,
    1,
    5,
    15,
    11,
    9,
    14,
    3,
    12,
    13,
    0,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3,
    // Blake1, unused in others
    11,
    8,
    12,
    0,
    5,
    2,
    15,
    13,
    10,
    14,
    3,
    6,
    7,
    1,
    9,
    4,
    7,
    9,
    3,
    1,
    13,
    12,
    11,
    14,
    2,
    6,
    5,
    10,
    4,
    0,
    15,
    8,
    9,
    0,
    5,
    7,
    2,
    4,
    10,
    15,
    14,
    1,
    11,
    12,
    6,
    8,
    3,
    13,
    2,
    12,
    6,
    10,
    0,
    11,
    8,
    3,
    4,
    13,
    7,
    5,
    15,
    14,
    1,
    9
  ]);
  function G1s(a, b, c, d, x) {
    a = a + b + x | 0;
    d = rotr(d ^ a, 16);
    c = c + d | 0;
    b = rotr(b ^ c, 12);
    return { a, b, c, d };
  }
  function G2s(a, b, c, d, x) {
    a = a + b + x | 0;
    d = rotr(d ^ a, 8);
    c = c + d | 0;
    b = rotr(b ^ c, 7);
    return { a, b, c, d };
  }

  // ../../_md.js
  function Chi(a, b, c) {
    return a & b ^ ~a & c;
  }
  function Maj(a, b, c) {
    return a & b ^ a & c ^ b & c;
  }
  var HashMD = class {
    blockLen;
    outputLen;
    padOffset;
    isLE;
    // For partial updates less than block size
    buffer;
    view;
    finished = false;
    length = 0;
    pos = 0;
    destroyed = false;
    constructor(blockLen, outputLen, padOffset, isLE2) {
      this.blockLen = blockLen;
      this.outputLen = outputLen;
      this.padOffset = padOffset;
      this.isLE = isLE2;
      this.buffer = new Uint8Array(blockLen);
      this.view = createView(this.buffer);
    }
    update(data) {
      aexists(this);
      abytes(data);
      const { view, buffer, blockLen } = this;
      const len = data.length;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          const dataView = createView(data);
          for (; blockLen <= len - pos; pos += blockLen)
            this.process(dataView, pos);
          continue;
        }
        buffer.set(data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.process(view, 0);
          this.pos = 0;
        }
      }
      this.length += data.length;
      this.roundClean();
      return this;
    }
    digestInto(out) {
      aexists(this);
      aoutput(out, this);
      this.finished = true;
      const { buffer, view, blockLen, isLE: isLE2 } = this;
      let { pos } = this;
      buffer[pos++] = 128;
      clean(this.buffer.subarray(pos));
      if (this.padOffset > blockLen - pos) {
        this.process(view, 0);
        pos = 0;
      }
      for (let i = pos; i < blockLen; i++)
        buffer[i] = 0;
      view.setBigUint64(blockLen - 8, BigInt(this.length * 8), isLE2);
      this.process(view, 0);
      const oview = createView(out);
      const len = this.outputLen;
      if (len % 4)
        throw new Error("_sha2: outputLen must be aligned to 32bit");
      const outLen = len / 4;
      const state = this.get();
      if (outLen > state.length)
        throw new Error("_sha2: outputLen bigger than state");
      for (let i = 0; i < outLen; i++)
        oview.setUint32(4 * i, state[i], isLE2);
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
    _cloneInto(to) {
      to ||= new this.constructor();
      to.set(...this.get());
      const { blockLen, buffer, length, finished, destroyed, pos } = this;
      to.destroyed = destroyed;
      to.finished = finished;
      to.length = length;
      to.pos = pos;
      if (length % blockLen)
        to.buffer.set(buffer);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
    1779033703,
    3144134277,
    1013904242,
    2773480762,
    1359893119,
    2600822924,
    528734635,
    1541459225
  ]);
  var SHA224_IV = /* @__PURE__ */ Uint32Array.from([
    3238371032,
    914150663,
    812702999,
    4144912697,
    4290775857,
    1750603025,
    1694076839,
    3204075428
  ]);
  var SHA384_IV = /* @__PURE__ */ Uint32Array.from([
    3418070365,
    3238371032,
    1654270250,
    914150663,
    2438529370,
    812702999,
    355462360,
    4144912697,
    1731405415,
    4290775857,
    2394180231,
    1750603025,
    3675008525,
    1694076839,
    1203062813,
    3204075428
  ]);
  var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
    1779033703,
    4089235720,
    3144134277,
    2227873595,
    1013904242,
    4271175723,
    2773480762,
    1595750129,
    1359893119,
    2917565137,
    2600822924,
    725511199,
    528734635,
    4215389547,
    1541459225,
    327033209
  ]);

  // ../../blake2.js
  var B2B_IV = /* @__PURE__ */ Uint32Array.from([
    4089235720,
    1779033703,
    2227873595,
    3144134277,
    4271175723,
    1013904242,
    1595750129,
    2773480762,
    2917565137,
    1359893119,
    725511199,
    2600822924,
    4215389547,
    528734635,
    327033209,
    1541459225
  ]);
  var BBUF = /* @__PURE__ */ new Uint32Array(32);
  function G1b(a, b, c, d, msg, x) {
    const Xl = msg[x], Xh = msg[x + 1];
    let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1];
    let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1];
    let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1];
    let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1];
    let ll = add3L(Al, Bl, Xl);
    Ah = add3H(ll, Ah, Bh, Xh);
    Al = ll | 0;
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: rotr32H(Dh, Dl), Dl: rotr32L(Dh, Dl) });
    ({ h: Ch, l: Cl } = add(Ch, Cl, Dh, Dl));
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: rotrSH(Bh, Bl, 24), Bl: rotrSL(Bh, Bl, 24) });
    BBUF[2 * a] = Al, BBUF[2 * a + 1] = Ah;
    BBUF[2 * b] = Bl, BBUF[2 * b + 1] = Bh;
    BBUF[2 * c] = Cl, BBUF[2 * c + 1] = Ch;
    BBUF[2 * d] = Dl, BBUF[2 * d + 1] = Dh;
  }
  function G2b(a, b, c, d, msg, x) {
    const Xl = msg[x], Xh = msg[x + 1];
    let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1];
    let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1];
    let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1];
    let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1];
    let ll = add3L(Al, Bl, Xl);
    Ah = add3H(ll, Ah, Bh, Xh);
    Al = ll | 0;
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: rotrSH(Dh, Dl, 16), Dl: rotrSL(Dh, Dl, 16) });
    ({ h: Ch, l: Cl } = add(Ch, Cl, Dh, Dl));
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: rotrBH(Bh, Bl, 63), Bl: rotrBL(Bh, Bl, 63) });
    BBUF[2 * a] = Al, BBUF[2 * a + 1] = Ah;
    BBUF[2 * b] = Bl, BBUF[2 * b + 1] = Bh;
    BBUF[2 * c] = Cl, BBUF[2 * c + 1] = Ch;
    BBUF[2 * d] = Dl, BBUF[2 * d + 1] = Dh;
  }
  function checkBlake2Opts(outputLen, opts = {}, keyLen, saltLen, persLen) {
    anumber(keyLen);
    if (outputLen < 0 || outputLen > keyLen)
      throw new Error("outputLen bigger than keyLen");
    const { key, salt, personalization } = opts;
    if (key !== void 0 && (key.length < 1 || key.length > keyLen))
      throw new Error('"key" expected to be undefined or of length=1..' + keyLen);
    if (salt !== void 0)
      abytes(salt, saltLen, "salt");
    if (personalization !== void 0)
      abytes(personalization, persLen, "personalization");
  }
  var _BLAKE2 = class {
    buffer;
    buffer32;
    finished = false;
    destroyed = false;
    length = 0;
    pos = 0;
    blockLen;
    outputLen;
    constructor(blockLen, outputLen) {
      anumber(blockLen);
      anumber(outputLen);
      this.blockLen = blockLen;
      this.outputLen = outputLen;
      this.buffer = new Uint8Array(blockLen);
      this.buffer32 = u32(this.buffer);
    }
    update(data) {
      aexists(this);
      abytes(data);
      const { blockLen, buffer, buffer32 } = this;
      const len = data.length;
      const offset = data.byteOffset;
      const buf = data.buffer;
      for (let pos = 0; pos < len; ) {
        if (this.pos === blockLen) {
          swap32IfBE(buffer32);
          this.compress(buffer32, 0, false);
          swap32IfBE(buffer32);
          this.pos = 0;
        }
        const take = Math.min(blockLen - this.pos, len - pos);
        const dataOffset = offset + pos;
        if (take === blockLen && !(dataOffset % 4) && pos + take < len) {
          const data32 = new Uint32Array(buf, dataOffset, Math.floor((len - pos) / 4));
          swap32IfBE(data32);
          for (let pos32 = 0; pos + blockLen < len; pos32 += buffer32.length, pos += blockLen) {
            this.length += blockLen;
            this.compress(data32, pos32, false);
          }
          swap32IfBE(data32);
          continue;
        }
        buffer.set(data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        this.length += take;
        pos += take;
      }
      return this;
    }
    digestInto(out) {
      aexists(this);
      aoutput(out, this);
      const { pos, buffer32 } = this;
      this.finished = true;
      clean(this.buffer.subarray(pos));
      swap32IfBE(buffer32);
      this.compress(buffer32, 0, true);
      swap32IfBE(buffer32);
      const out32 = u32(out);
      this.get().forEach((v, i) => out32[i] = swap8IfBE(v));
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
    _cloneInto(to) {
      const { buffer, length, finished, destroyed, outputLen, pos } = this;
      to ||= new this.constructor({ dkLen: outputLen });
      to.set(...this.get());
      to.buffer.set(buffer);
      to.destroyed = destroyed;
      to.finished = finished;
      to.length = length;
      to.pos = pos;
      to.outputLen = outputLen;
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  var _BLAKE2b = class extends _BLAKE2 {
    // Same as SHA-512, but LE
    v0l = B2B_IV[0] | 0;
    v0h = B2B_IV[1] | 0;
    v1l = B2B_IV[2] | 0;
    v1h = B2B_IV[3] | 0;
    v2l = B2B_IV[4] | 0;
    v2h = B2B_IV[5] | 0;
    v3l = B2B_IV[6] | 0;
    v3h = B2B_IV[7] | 0;
    v4l = B2B_IV[8] | 0;
    v4h = B2B_IV[9] | 0;
    v5l = B2B_IV[10] | 0;
    v5h = B2B_IV[11] | 0;
    v6l = B2B_IV[12] | 0;
    v6h = B2B_IV[13] | 0;
    v7l = B2B_IV[14] | 0;
    v7h = B2B_IV[15] | 0;
    constructor(opts = {}) {
      const olen = opts.dkLen === void 0 ? 64 : opts.dkLen;
      super(128, olen);
      checkBlake2Opts(olen, opts, 64, 16, 16);
      let { key, personalization, salt } = opts;
      let keyLength = 0;
      if (key !== void 0) {
        abytes(key, void 0, "key");
        keyLength = key.length;
      }
      this.v0l ^= this.outputLen | keyLength << 8 | 1 << 16 | 1 << 24;
      if (salt !== void 0) {
        abytes(salt, void 0, "salt");
        const slt = u32(salt);
        this.v4l ^= swap8IfBE(slt[0]);
        this.v4h ^= swap8IfBE(slt[1]);
        this.v5l ^= swap8IfBE(slt[2]);
        this.v5h ^= swap8IfBE(slt[3]);
      }
      if (personalization !== void 0) {
        abytes(personalization, void 0, "personalization");
        const pers = u32(personalization);
        this.v6l ^= swap8IfBE(pers[0]);
        this.v6h ^= swap8IfBE(pers[1]);
        this.v7l ^= swap8IfBE(pers[2]);
        this.v7h ^= swap8IfBE(pers[3]);
      }
      if (key !== void 0) {
        const tmp = new Uint8Array(this.blockLen);
        tmp.set(key);
        this.update(tmp);
      }
    }
    // prettier-ignore
    get() {
      let { v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h } = this;
      return [v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h];
    }
    // prettier-ignore
    set(v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h) {
      this.v0l = v0l | 0;
      this.v0h = v0h | 0;
      this.v1l = v1l | 0;
      this.v1h = v1h | 0;
      this.v2l = v2l | 0;
      this.v2h = v2h | 0;
      this.v3l = v3l | 0;
      this.v3h = v3h | 0;
      this.v4l = v4l | 0;
      this.v4h = v4h | 0;
      this.v5l = v5l | 0;
      this.v5h = v5h | 0;
      this.v6l = v6l | 0;
      this.v6h = v6h | 0;
      this.v7l = v7l | 0;
      this.v7h = v7h | 0;
    }
    compress(msg, offset, isLast) {
      this.get().forEach((v, i) => BBUF[i] = v);
      BBUF.set(B2B_IV, 16);
      let { h, l } = fromBig(BigInt(this.length));
      BBUF[24] = B2B_IV[8] ^ l;
      BBUF[25] = B2B_IV[9] ^ h;
      if (isLast) {
        BBUF[28] = ~BBUF[28];
        BBUF[29] = ~BBUF[29];
      }
      let j = 0;
      const s = BSIGMA;
      for (let i = 0; i < 12; i++) {
        G1b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
        G2b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
        G1b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
        G2b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
        G1b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
        G2b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
        G1b(3, 7, 11, 15, msg, offset + 2 * s[j++]);
        G2b(3, 7, 11, 15, msg, offset + 2 * s[j++]);
        G1b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
        G2b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
        G1b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
        G2b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
        G1b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
        G2b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
        G1b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
        G2b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
      }
      this.v0l ^= BBUF[0] ^ BBUF[16];
      this.v0h ^= BBUF[1] ^ BBUF[17];
      this.v1l ^= BBUF[2] ^ BBUF[18];
      this.v1h ^= BBUF[3] ^ BBUF[19];
      this.v2l ^= BBUF[4] ^ BBUF[20];
      this.v2h ^= BBUF[5] ^ BBUF[21];
      this.v3l ^= BBUF[6] ^ BBUF[22];
      this.v3h ^= BBUF[7] ^ BBUF[23];
      this.v4l ^= BBUF[8] ^ BBUF[24];
      this.v4h ^= BBUF[9] ^ BBUF[25];
      this.v5l ^= BBUF[10] ^ BBUF[26];
      this.v5h ^= BBUF[11] ^ BBUF[27];
      this.v6l ^= BBUF[12] ^ BBUF[28];
      this.v6h ^= BBUF[13] ^ BBUF[29];
      this.v7l ^= BBUF[14] ^ BBUF[30];
      this.v7h ^= BBUF[15] ^ BBUF[31];
      clean(BBUF);
    }
    destroy() {
      this.destroyed = true;
      clean(this.buffer32);
      this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
  };
  var blake2b = /* @__PURE__ */ createHasher((opts) => new _BLAKE2b(opts));
  function compress(s, offset, msg, rounds, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) {
    let j = 0;
    for (let i = 0; i < rounds; i++) {
      ({ a: v0, b: v4, c: v8, d: v12 } = G1s(v0, v4, v8, v12, msg[offset + s[j++]]));
      ({ a: v0, b: v4, c: v8, d: v12 } = G2s(v0, v4, v8, v12, msg[offset + s[j++]]));
      ({ a: v1, b: v5, c: v9, d: v13 } = G1s(v1, v5, v9, v13, msg[offset + s[j++]]));
      ({ a: v1, b: v5, c: v9, d: v13 } = G2s(v1, v5, v9, v13, msg[offset + s[j++]]));
      ({ a: v2, b: v6, c: v10, d: v14 } = G1s(v2, v6, v10, v14, msg[offset + s[j++]]));
      ({ a: v2, b: v6, c: v10, d: v14 } = G2s(v2, v6, v10, v14, msg[offset + s[j++]]));
      ({ a: v3, b: v7, c: v11, d: v15 } = G1s(v3, v7, v11, v15, msg[offset + s[j++]]));
      ({ a: v3, b: v7, c: v11, d: v15 } = G2s(v3, v7, v11, v15, msg[offset + s[j++]]));
      ({ a: v0, b: v5, c: v10, d: v15 } = G1s(v0, v5, v10, v15, msg[offset + s[j++]]));
      ({ a: v0, b: v5, c: v10, d: v15 } = G2s(v0, v5, v10, v15, msg[offset + s[j++]]));
      ({ a: v1, b: v6, c: v11, d: v12 } = G1s(v1, v6, v11, v12, msg[offset + s[j++]]));
      ({ a: v1, b: v6, c: v11, d: v12 } = G2s(v1, v6, v11, v12, msg[offset + s[j++]]));
      ({ a: v2, b: v7, c: v8, d: v13 } = G1s(v2, v7, v8, v13, msg[offset + s[j++]]));
      ({ a: v2, b: v7, c: v8, d: v13 } = G2s(v2, v7, v8, v13, msg[offset + s[j++]]));
      ({ a: v3, b: v4, c: v9, d: v14 } = G1s(v3, v4, v9, v14, msg[offset + s[j++]]));
      ({ a: v3, b: v4, c: v9, d: v14 } = G2s(v3, v4, v9, v14, msg[offset + s[j++]]));
    }
    return { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 };
  }
  var B2S_IV = /* @__PURE__ */ SHA256_IV.slice();
  var _BLAKE2s = class extends _BLAKE2 {
    // Internal state, same as SHA-256
    v0 = B2S_IV[0] | 0;
    v1 = B2S_IV[1] | 0;
    v2 = B2S_IV[2] | 0;
    v3 = B2S_IV[3] | 0;
    v4 = B2S_IV[4] | 0;
    v5 = B2S_IV[5] | 0;
    v6 = B2S_IV[6] | 0;
    v7 = B2S_IV[7] | 0;
    constructor(opts = {}) {
      const olen = opts.dkLen === void 0 ? 32 : opts.dkLen;
      super(64, olen);
      checkBlake2Opts(olen, opts, 32, 8, 8);
      let { key, personalization, salt } = opts;
      let keyLength = 0;
      if (key !== void 0) {
        abytes(key, void 0, "key");
        keyLength = key.length;
      }
      this.v0 ^= this.outputLen | keyLength << 8 | 1 << 16 | 1 << 24;
      if (salt !== void 0) {
        abytes(salt, void 0, "salt");
        const slt = u32(salt);
        this.v4 ^= swap8IfBE(slt[0]);
        this.v5 ^= swap8IfBE(slt[1]);
      }
      if (personalization !== void 0) {
        abytes(personalization, void 0, "personalization");
        const pers = u32(personalization);
        this.v6 ^= swap8IfBE(pers[0]);
        this.v7 ^= swap8IfBE(pers[1]);
      }
      if (key !== void 0) {
        const tmp = new Uint8Array(this.blockLen);
        tmp.set(key);
        this.update(tmp);
      }
    }
    get() {
      const { v0, v1, v2, v3, v4, v5, v6, v7 } = this;
      return [v0, v1, v2, v3, v4, v5, v6, v7];
    }
    // prettier-ignore
    set(v0, v1, v2, v3, v4, v5, v6, v7) {
      this.v0 = v0 | 0;
      this.v1 = v1 | 0;
      this.v2 = v2 | 0;
      this.v3 = v3 | 0;
      this.v4 = v4 | 0;
      this.v5 = v5 | 0;
      this.v6 = v6 | 0;
      this.v7 = v7 | 0;
    }
    compress(msg, offset, isLast) {
      const { h, l } = fromBig(BigInt(this.length));
      const { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 } = compress(BSIGMA, offset, msg, 10, this.v0, this.v1, this.v2, this.v3, this.v4, this.v5, this.v6, this.v7, B2S_IV[0], B2S_IV[1], B2S_IV[2], B2S_IV[3], l ^ B2S_IV[4], h ^ B2S_IV[5], isLast ? ~B2S_IV[6] : B2S_IV[6], B2S_IV[7]);
      this.v0 ^= v0 ^ v8;
      this.v1 ^= v1 ^ v9;
      this.v2 ^= v2 ^ v10;
      this.v3 ^= v3 ^ v11;
      this.v4 ^= v4 ^ v12;
      this.v5 ^= v5 ^ v13;
      this.v6 ^= v6 ^ v14;
      this.v7 ^= v7 ^ v15;
    }
    destroy() {
      this.destroyed = true;
      clean(this.buffer32);
      this.set(0, 0, 0, 0, 0, 0, 0, 0);
    }
  };
  var blake2s = /* @__PURE__ */ createHasher((opts) => new _BLAKE2s(opts));

  // ../../argon2.js
  var AT = { Argond2d: 0, Argon2i: 1, Argon2id: 2 };
  var ARGON2_SYNC_POINTS = 4;
  var abytesOrZero = (buf, errorTitle = "") => {
    if (buf === void 0)
      return Uint8Array.of();
    return kdfInputToBytes(buf, errorTitle);
  };
  function mul(a, b) {
    const aL = a & 65535;
    const aH = a >>> 16;
    const bL = b & 65535;
    const bH = b >>> 16;
    const ll = Math.imul(aL, bL);
    const hl = Math.imul(aH, bL);
    const lh = Math.imul(aL, bH);
    const hh = Math.imul(aH, bH);
    const carry = (ll >>> 16) + (hl & 65535) + lh;
    const high = hh + (hl >>> 16) + (carry >>> 16) | 0;
    const low = carry << 16 | ll & 65535;
    return { h: high, l: low };
  }
  function mul2(a, b) {
    const { h, l } = mul(a, b);
    return { h: (h << 1 | l >>> 31) & 4294967295, l: l << 1 & 4294967295 };
  }
  function blamka(Ah, Al, Bh, Bl) {
    const { h: Ch, l: Cl } = mul2(Al, Bl);
    const Rll = add3L(Al, Bl, Cl);
    return { h: add3H(Rll, Ah, Bh, Ch), l: Rll | 0 };
  }
  var A2_BUF = new Uint32Array(256);
  function G(a, b, c, d) {
    let Al = A2_BUF[2 * a], Ah = A2_BUF[2 * a + 1];
    let Bl = A2_BUF[2 * b], Bh = A2_BUF[2 * b + 1];
    let Cl = A2_BUF[2 * c], Ch = A2_BUF[2 * c + 1];
    let Dl = A2_BUF[2 * d], Dh = A2_BUF[2 * d + 1];
    ({ h: Ah, l: Al } = blamka(Ah, Al, Bh, Bl));
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: rotr32H(Dh, Dl), Dl: rotr32L(Dh, Dl) });
    ({ h: Ch, l: Cl } = blamka(Ch, Cl, Dh, Dl));
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: rotrSH(Bh, Bl, 24), Bl: rotrSL(Bh, Bl, 24) });
    ({ h: Ah, l: Al } = blamka(Ah, Al, Bh, Bl));
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: rotrSH(Dh, Dl, 16), Dl: rotrSL(Dh, Dl, 16) });
    ({ h: Ch, l: Cl } = blamka(Ch, Cl, Dh, Dl));
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: rotrBH(Bh, Bl, 63), Bl: rotrBL(Bh, Bl, 63) });
    A2_BUF[2 * a] = Al, A2_BUF[2 * a + 1] = Ah;
    A2_BUF[2 * b] = Bl, A2_BUF[2 * b + 1] = Bh;
    A2_BUF[2 * c] = Cl, A2_BUF[2 * c + 1] = Ch;
    A2_BUF[2 * d] = Dl, A2_BUF[2 * d + 1] = Dh;
  }
  function P(v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11, v12, v13, v14, v15) {
    G(v00, v04, v08, v12);
    G(v01, v05, v09, v13);
    G(v02, v06, v10, v14);
    G(v03, v07, v11, v15);
    G(v00, v05, v10, v15);
    G(v01, v06, v11, v12);
    G(v02, v07, v08, v13);
    G(v03, v04, v09, v14);
  }
  function block(x, xPos, yPos, outPos, needXor) {
    for (let i = 0; i < 256; i++)
      A2_BUF[i] = x[xPos + i] ^ x[yPos + i];
    for (let i = 0; i < 128; i += 16) {
      P(i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7, i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15);
    }
    for (let i = 0; i < 16; i += 2) {
      P(i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49, i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113);
    }
    if (needXor)
      for (let i = 0; i < 256; i++)
        x[outPos + i] ^= A2_BUF[i] ^ x[xPos + i] ^ x[yPos + i];
    else
      for (let i = 0; i < 256; i++)
        x[outPos + i] = A2_BUF[i] ^ x[xPos + i] ^ x[yPos + i];
    clean(A2_BUF);
  }
  function Hp(A, dkLen) {
    const A8 = u8(A);
    const T = new Uint32Array(1);
    const T8 = u8(T);
    T[0] = dkLen;
    if (dkLen <= 64)
      return blake2b.create({ dkLen }).update(T8).update(A8).digest();
    const out = new Uint8Array(dkLen);
    let V = blake2b.create({}).update(T8).update(A8).digest();
    let pos = 0;
    out.set(V.subarray(0, 32));
    pos += 32;
    for (; dkLen - pos > 64; pos += 32) {
      const Vh = blake2b.create({}).update(V);
      Vh.digestInto(V);
      Vh.destroy();
      out.set(V.subarray(0, 32), pos);
    }
    out.set(blake2b(V, { dkLen: dkLen - pos }), pos);
    clean(V, T);
    return u32(out);
  }
  function indexAlpha(r, s, laneLen, segmentLen, index, randL, sameLane = false) {
    let area;
    if (r === 0) {
      if (s === 0)
        area = index - 1;
      else if (sameLane)
        area = s * segmentLen + index - 1;
      else
        area = s * segmentLen + (index == 0 ? -1 : 0);
    } else if (sameLane)
      area = laneLen - segmentLen + index - 1;
    else
      area = laneLen - segmentLen + (index == 0 ? -1 : 0);
    const startPos = r !== 0 && s !== ARGON2_SYNC_POINTS - 1 ? (s + 1) * segmentLen : 0;
    const rel = area - 1 - mul(area, mul(randL, randL).h).h;
    return (startPos + rel) % laneLen;
  }
  var maxUint32 = Math.pow(2, 32);
  function isU32(num) {
    return Number.isSafeInteger(num) && num >= 0 && num < maxUint32;
  }
  function argon2Opts(opts) {
    const merged = {
      version: 19,
      dkLen: 32,
      maxmem: maxUint32 - 1,
      asyncTick: 10
    };
    for (let [k, v] of Object.entries(opts))
      if (v !== void 0)
        merged[k] = v;
    const { dkLen, p, m, t, version, onProgress, asyncTick } = merged;
    if (!isU32(dkLen) || dkLen < 4)
      throw new Error('"dkLen" must be 4..');
    if (!isU32(p) || p < 1 || p >= Math.pow(2, 24))
      throw new Error('"p" must be 1..2^24');
    if (!isU32(m))
      throw new Error('"m" must be 0..2^32');
    if (!isU32(t) || t < 1)
      throw new Error('"t" (iterations) must be 1..2^32');
    if (onProgress !== void 0 && typeof onProgress !== "function")
      throw new Error('"progressCb" must be a function');
    anumber(asyncTick, "asyncTick");
    if (!isU32(m) || m < 8 * p)
      throw new Error('"m" (memory) must be at least 8*p bytes');
    if (version !== 16 && version !== 19)
      throw new Error('"version" must be 0x10 or 0x13, got ' + version);
    return merged;
  }
  function argon2Init(password, salt, type, opts) {
    password = kdfInputToBytes(password, "password");
    salt = kdfInputToBytes(salt, "salt");
    if (!isU32(password.length))
      throw new Error('"password" must be less of length 1..4Gb');
    if (!isU32(salt.length) || salt.length < 8)
      throw new Error('"salt" must be of length 8..4Gb');
    if (!Object.values(AT).includes(type))
      throw new Error('"type" was invalid');
    let { p, dkLen, m, t, version, key, personalization, maxmem, onProgress, asyncTick } = argon2Opts(opts);
    key = abytesOrZero(key, "key");
    personalization = abytesOrZero(personalization, "personalization");
    const h = blake2b.create();
    const BUF = new Uint32Array(1);
    const BUF8 = u8(BUF);
    for (let item of [p, dkLen, m, t, version, type]) {
      BUF[0] = item;
      h.update(BUF8);
    }
    for (let i of [password, salt, key, personalization]) {
      BUF[0] = i.length;
      h.update(BUF8).update(i);
    }
    const H0 = new Uint32Array(18);
    const H0_8 = u8(H0);
    h.digestInto(H0_8);
    const lanes = p;
    const mP = 4 * p * Math.floor(m / (ARGON2_SYNC_POINTS * p));
    const laneLen = Math.floor(mP / p);
    const segmentLen = Math.floor(laneLen / ARGON2_SYNC_POINTS);
    const memUsed = mP * 256;
    if (!isU32(maxmem) || memUsed > maxmem)
      throw new Error('"maxmem" expected <2**32, got: maxmem=' + maxmem + ", memused=" + memUsed);
    const B = new Uint32Array(memUsed);
    for (let l = 0; l < p; l++) {
      const i = 256 * laneLen * l;
      H0[17] = l;
      H0[16] = 0;
      B.set(Hp(H0, 1024), i);
      H0[16] = 1;
      B.set(Hp(H0, 1024), i + 256);
    }
    let perBlock = () => {
    };
    if (onProgress) {
      const totalBlock = t * ARGON2_SYNC_POINTS * p * segmentLen;
      const callbackPer = Math.max(Math.floor(totalBlock / 1e4), 1);
      let blockCnt = 0;
      perBlock = () => {
        blockCnt++;
        if (onProgress && (!(blockCnt % callbackPer) || blockCnt === totalBlock))
          onProgress(blockCnt / totalBlock);
      };
    }
    clean(BUF, H0);
    return { type, mP, p, t, version, B, laneLen, lanes, segmentLen, dkLen, perBlock, asyncTick };
  }
  function argon2Output(B, p, laneLen, dkLen) {
    const B_final = new Uint32Array(256);
    for (let l = 0; l < p; l++)
      for (let j = 0; j < 256; j++)
        B_final[j] ^= B[256 * (laneLen * l + laneLen - 1) + j];
    const res = u8(Hp(B_final, dkLen));
    clean(B_final);
    return res;
  }
  function processBlock(B, address, l, r, s, index, laneLen, segmentLen, lanes, offset, prev, dataIndependent, needXor) {
    if (offset % laneLen)
      prev = offset - 1;
    let randL, randH;
    if (dataIndependent) {
      let i128 = index % 128;
      if (i128 === 0) {
        address[256 + 12]++;
        block(address, 256, 2 * 256, 0, false);
        block(address, 0, 2 * 256, 0, false);
      }
      randL = address[2 * i128];
      randH = address[2 * i128 + 1];
    } else {
      const T = 256 * prev;
      randL = B[T];
      randH = B[T + 1];
    }
    const refLane = r === 0 && s === 0 ? l : randH % lanes;
    const refPos = indexAlpha(r, s, laneLen, segmentLen, index, randL, refLane == l);
    const refBlock = laneLen * refLane + refPos;
    block(B, 256 * prev, 256 * refBlock, offset * 256, needXor);
  }
  function argon2(type, password, salt, opts) {
    const { mP, p, t, version, B, laneLen, lanes, segmentLen, dkLen, perBlock } = argon2Init(password, salt, type, opts);
    const address = new Uint32Array(3 * 256);
    address[256 + 6] = mP;
    address[256 + 8] = t;
    address[256 + 10] = type;
    for (let r = 0; r < t; r++) {
      const needXor = r !== 0 && version === 19;
      address[256 + 0] = r;
      for (let s = 0; s < ARGON2_SYNC_POINTS; s++) {
        address[256 + 4] = s;
        const dataIndependent = type == AT.Argon2i || type == AT.Argon2id && r === 0 && s < 2;
        for (let l = 0; l < p; l++) {
          address[256 + 2] = l;
          address[256 + 12] = 0;
          let startPos = 0;
          if (r === 0 && s === 0) {
            startPos = 2;
            if (dataIndependent) {
              address[256 + 12]++;
              block(address, 256, 2 * 256, 0, false);
              block(address, 0, 2 * 256, 0, false);
            }
          }
          let offset = l * laneLen + s * segmentLen + startPos;
          let prev = offset % laneLen ? offset - 1 : offset + laneLen - 1;
          for (let index = startPos; index < segmentLen; index++, offset++, prev++) {
            perBlock();
            processBlock(B, address, l, r, s, index, laneLen, segmentLen, lanes, offset, prev, dataIndependent, needXor);
          }
        }
      }
    }
    clean(address);
    return argon2Output(B, p, laneLen, dkLen);
  }
  var argon2id = (password, salt, opts) => argon2(AT.Argon2id, password, salt, opts);

  // ../../blake1.js
  var EMPTY_SALT = /* @__PURE__ */ new Uint32Array(8);
  var BLAKE1 = class {
    finished = false;
    length = 0;
    pos = 0;
    destroyed = false;
    // For partial updates less than block size
    buffer;
    view;
    salt;
    blockLen;
    outputLen;
    lengthFlag;
    counterLen;
    constants;
    constructor(blockLen, outputLen, lengthFlag, counterLen, saltLen, constants, opts = {}) {
      const { salt } = opts;
      this.blockLen = blockLen;
      this.outputLen = outputLen;
      this.lengthFlag = lengthFlag;
      this.counterLen = counterLen;
      this.buffer = new Uint8Array(blockLen);
      this.view = createView(this.buffer);
      if (salt !== void 0) {
        let slt = salt;
        abytes(slt, 4 * saltLen, "salt");
        const salt32 = this.salt = new Uint32Array(saltLen);
        const sv = createView(slt);
        this.constants = constants.slice();
        for (let i = 0, offset = 0; i < salt32.length; i++, offset += 4) {
          salt32[i] = sv.getUint32(offset, false);
          this.constants[i] ^= salt32[i];
        }
      } else {
        this.salt = EMPTY_SALT;
        this.constants = constants;
      }
    }
    update(data) {
      aexists(this);
      abytes(data);
      const { view, buffer, blockLen } = this;
      const len = data.length;
      let dataView;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          if (!dataView)
            dataView = createView(data);
          for (; blockLen <= len - pos; pos += blockLen) {
            this.length += blockLen;
            this.compress(dataView, pos);
          }
          continue;
        }
        buffer.set(data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.length += blockLen;
          this.compress(view, 0, true);
          this.pos = 0;
        }
      }
      return this;
    }
    destroy() {
      this.destroyed = true;
      if (this.salt !== EMPTY_SALT) {
        clean(this.salt, this.constants);
      }
    }
    _cloneInto(to) {
      to ||= new this.constructor();
      to.set(...this.get());
      const { buffer, length, finished, destroyed, constants, salt, pos } = this;
      to.buffer.set(buffer);
      to.constants = constants.slice();
      to.destroyed = destroyed;
      to.finished = finished;
      to.length = length;
      to.pos = pos;
      to.salt = salt.slice();
      return to;
    }
    clone() {
      return this._cloneInto();
    }
    digestInto(out) {
      aexists(this);
      aoutput(out, this);
      this.finished = true;
      const { buffer, blockLen, counterLen, lengthFlag, view } = this;
      clean(buffer.subarray(this.pos));
      const counter = BigInt((this.length + this.pos) * 8);
      const counterPos = blockLen - counterLen - 1;
      buffer[this.pos] |= 128;
      this.length += this.pos;
      if (this.pos > counterPos) {
        this.compress(view, 0);
        clean(buffer);
        this.pos = 0;
      }
      buffer[counterPos] |= lengthFlag;
      view.setBigUint64(blockLen - 8, counter, false);
      this.compress(view, 0, this.pos !== 0);
      clean(buffer);
      const v = createView(out);
      const state = this.get();
      for (let i = 0; i < this.outputLen / 4; ++i)
        v.setUint32(i * 4, state[i]);
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
  };
  var B64C = /* @__PURE__ */ Uint32Array.from([
    608135816,
    2242054355,
    320440878,
    57701188,
    2752067618,
    698298832,
    137296536,
    3964562569,
    1160258022,
    953160567,
    3193202383,
    887688300,
    3232508343,
    3380367581,
    1065670069,
    3041331479,
    2450970073,
    2306472731,
    3509652390,
    2564797868,
    805139163,
    3491422135,
    3101798381,
    1780907670,
    3128725573,
    4046225305,
    614570311,
    3012652279,
    134345442,
    2240740374,
    1667834072,
    1901547113
  ]);
  var B32C = B64C.slice(0, 16);
  var B256_IV = /* @__PURE__ */ SHA256_IV.slice();
  var B224_IV = /* @__PURE__ */ SHA224_IV.slice();
  var B384_IV = /* @__PURE__ */ SHA384_IV.slice();
  var B512_IV = /* @__PURE__ */ SHA512_IV.slice();
  function generateTBL256() {
    const TBL = [];
    for (let i = 0, j = 0; i < 14; i++, j += 16) {
      for (let offset = 1; offset < 16; offset += 2) {
        TBL.push(B32C[BSIGMA[j + offset]]);
        TBL.push(B32C[BSIGMA[j + offset - 1]]);
      }
    }
    return new Uint32Array(TBL);
  }
  var TBL256 = /* @__PURE__ */ generateTBL256();
  var BLAKE256_W = /* @__PURE__ */ new Uint32Array(16);
  var BLAKE1_32B = class extends BLAKE1 {
    v0;
    v1;
    v2;
    v3;
    v4;
    v5;
    v6;
    v7;
    constructor(outputLen, IV, lengthFlag, opts = {}) {
      super(64, outputLen, lengthFlag, 8, 4, B32C, opts);
      this.v0 = IV[0] | 0;
      this.v1 = IV[1] | 0;
      this.v2 = IV[2] | 0;
      this.v3 = IV[3] | 0;
      this.v4 = IV[4] | 0;
      this.v5 = IV[5] | 0;
      this.v6 = IV[6] | 0;
      this.v7 = IV[7] | 0;
    }
    get() {
      const { v0, v1, v2, v3, v4, v5, v6, v7 } = this;
      return [v0, v1, v2, v3, v4, v5, v6, v7];
    }
    // prettier-ignore
    set(v0, v1, v2, v3, v4, v5, v6, v7) {
      this.v0 = v0 | 0;
      this.v1 = v1 | 0;
      this.v2 = v2 | 0;
      this.v3 = v3 | 0;
      this.v4 = v4 | 0;
      this.v5 = v5 | 0;
      this.v6 = v6 | 0;
      this.v7 = v7 | 0;
    }
    destroy() {
      super.destroy();
      this.set(0, 0, 0, 0, 0, 0, 0, 0);
    }
    compress(view, offset, withLength = true) {
      for (let i = 0; i < 16; i++, offset += 4)
        BLAKE256_W[i] = view.getUint32(offset, false);
      let v00 = this.v0 | 0;
      let v01 = this.v1 | 0;
      let v02 = this.v2 | 0;
      let v03 = this.v3 | 0;
      let v04 = this.v4 | 0;
      let v05 = this.v5 | 0;
      let v06 = this.v6 | 0;
      let v07 = this.v7 | 0;
      let v08 = this.constants[0] | 0;
      let v09 = this.constants[1] | 0;
      let v10 = this.constants[2] | 0;
      let v11 = this.constants[3] | 0;
      const { h, l } = fromBig(BigInt(withLength ? this.length * 8 : 0));
      let v12 = (this.constants[4] ^ l) >>> 0;
      let v13 = (this.constants[5] ^ l) >>> 0;
      let v14 = (this.constants[6] ^ h) >>> 0;
      let v15 = (this.constants[7] ^ h) >>> 0;
      for (let i = 0, k = 0, j = 0; i < 14; i++) {
        ({ a: v00, b: v04, c: v08, d: v12 } = G1s(v00, v04, v08, v12, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v00, b: v04, c: v08, d: v12 } = G2s(v00, v04, v08, v12, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v01, b: v05, c: v09, d: v13 } = G1s(v01, v05, v09, v13, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v01, b: v05, c: v09, d: v13 } = G2s(v01, v05, v09, v13, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v02, b: v06, c: v10, d: v14 } = G1s(v02, v06, v10, v14, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v02, b: v06, c: v10, d: v14 } = G2s(v02, v06, v10, v14, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v03, b: v07, c: v11, d: v15 } = G1s(v03, v07, v11, v15, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v03, b: v07, c: v11, d: v15 } = G2s(v03, v07, v11, v15, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v00, b: v05, c: v10, d: v15 } = G1s(v00, v05, v10, v15, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v00, b: v05, c: v10, d: v15 } = G2s(v00, v05, v10, v15, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v01, b: v06, c: v11, d: v12 } = G1s(v01, v06, v11, v12, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v01, b: v06, c: v11, d: v12 } = G2s(v01, v06, v11, v12, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v02, b: v07, c: v08, d: v13 } = G1s(v02, v07, v08, v13, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v02, b: v07, c: v08, d: v13 } = G2s(v02, v07, v08, v13, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v03, b: v04, c: v09, d: v14 } = G1s(v03, v04, v09, v14, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
        ({ a: v03, b: v04, c: v09, d: v14 } = G2s(v03, v04, v09, v14, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      }
      this.v0 = (this.v0 ^ v00 ^ v08 ^ this.salt[0]) >>> 0;
      this.v1 = (this.v1 ^ v01 ^ v09 ^ this.salt[1]) >>> 0;
      this.v2 = (this.v2 ^ v02 ^ v10 ^ this.salt[2]) >>> 0;
      this.v3 = (this.v3 ^ v03 ^ v11 ^ this.salt[3]) >>> 0;
      this.v4 = (this.v4 ^ v04 ^ v12 ^ this.salt[0]) >>> 0;
      this.v5 = (this.v5 ^ v05 ^ v13 ^ this.salt[1]) >>> 0;
      this.v6 = (this.v6 ^ v06 ^ v14 ^ this.salt[2]) >>> 0;
      this.v7 = (this.v7 ^ v07 ^ v15 ^ this.salt[3]) >>> 0;
      clean(BLAKE256_W);
    }
  };
  var BBUF2 = /* @__PURE__ */ new Uint32Array(32);
  var BLAKE512_W = /* @__PURE__ */ new Uint32Array(32);
  function generateTBL512() {
    const TBL = [];
    for (let r = 0, k = 0; r < 16; r++, k += 16) {
      for (let offset = 1; offset < 16; offset += 2) {
        TBL.push(B64C[BSIGMA[k + offset] * 2 + 0]);
        TBL.push(B64C[BSIGMA[k + offset] * 2 + 1]);
        TBL.push(B64C[BSIGMA[k + offset - 1] * 2 + 0]);
        TBL.push(B64C[BSIGMA[k + offset - 1] * 2 + 1]);
      }
    }
    return new Uint32Array(TBL);
  }
  var TBL512 = /* @__PURE__ */ generateTBL512();
  function G1b2(a, b, c, d, msg, k) {
    const Xpos = 2 * BSIGMA[k];
    const Xl = msg[Xpos + 1] ^ TBL512[k * 2 + 1], Xh = msg[Xpos] ^ TBL512[k * 2];
    let Al = BBUF2[2 * a + 1], Ah = BBUF2[2 * a];
    let Bl = BBUF2[2 * b + 1], Bh = BBUF2[2 * b];
    let Cl = BBUF2[2 * c + 1], Ch = BBUF2[2 * c];
    let Dl = BBUF2[2 * d + 1], Dh = BBUF2[2 * d];
    let ll = add3L(Al, Bl, Xl);
    Ah = add3H(ll, Ah, Bh, Xh) >>> 0;
    Al = (ll | 0) >>> 0;
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: rotr32H(Dh, Dl), Dl: rotr32L(Dh, Dl) });
    ({ h: Ch, l: Cl } = add(Ch, Cl, Dh, Dl));
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: rotrSH(Bh, Bl, 25), Bl: rotrSL(Bh, Bl, 25) });
    BBUF2[2 * a + 1] = Al, BBUF2[2 * a] = Ah;
    BBUF2[2 * b + 1] = Bl, BBUF2[2 * b] = Bh;
    BBUF2[2 * c + 1] = Cl, BBUF2[2 * c] = Ch;
    BBUF2[2 * d + 1] = Dl, BBUF2[2 * d] = Dh;
  }
  function G2b2(a, b, c, d, msg, k) {
    const Xpos = 2 * BSIGMA[k];
    const Xl = msg[Xpos + 1] ^ TBL512[k * 2 + 1], Xh = msg[Xpos] ^ TBL512[k * 2];
    let Al = BBUF2[2 * a + 1], Ah = BBUF2[2 * a];
    let Bl = BBUF2[2 * b + 1], Bh = BBUF2[2 * b];
    let Cl = BBUF2[2 * c + 1], Ch = BBUF2[2 * c];
    let Dl = BBUF2[2 * d + 1], Dh = BBUF2[2 * d];
    let ll = add3L(Al, Bl, Xl);
    Ah = add3H(ll, Ah, Bh, Xh);
    Al = ll | 0;
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: rotrSH(Dh, Dl, 16), Dl: rotrSL(Dh, Dl, 16) });
    ({ h: Ch, l: Cl } = add(Ch, Cl, Dh, Dl));
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: rotrSH(Bh, Bl, 11), Bl: rotrSL(Bh, Bl, 11) });
    BBUF2[2 * a + 1] = Al, BBUF2[2 * a] = Ah;
    BBUF2[2 * b + 1] = Bl, BBUF2[2 * b] = Bh;
    BBUF2[2 * c + 1] = Cl, BBUF2[2 * c] = Ch;
    BBUF2[2 * d + 1] = Dl, BBUF2[2 * d] = Dh;
  }
  var BLAKE1_64B = class extends BLAKE1 {
    v0l;
    v0h;
    v1l;
    v1h;
    v2l;
    v2h;
    v3l;
    v3h;
    v4l;
    v4h;
    v5l;
    v5h;
    v6l;
    v6h;
    v7l;
    v7h;
    constructor(outputLen, IV, lengthFlag, opts = {}) {
      super(128, outputLen, lengthFlag, 16, 8, B64C, opts);
      this.v0l = IV[0] | 0;
      this.v0h = IV[1] | 0;
      this.v1l = IV[2] | 0;
      this.v1h = IV[3] | 0;
      this.v2l = IV[4] | 0;
      this.v2h = IV[5] | 0;
      this.v3l = IV[6] | 0;
      this.v3h = IV[7] | 0;
      this.v4l = IV[8] | 0;
      this.v4h = IV[9] | 0;
      this.v5l = IV[10] | 0;
      this.v5h = IV[11] | 0;
      this.v6l = IV[12] | 0;
      this.v6h = IV[13] | 0;
      this.v7l = IV[14] | 0;
      this.v7h = IV[15] | 0;
    }
    // prettier-ignore
    get() {
      let { v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h } = this;
      return [v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h];
    }
    // prettier-ignore
    set(v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h) {
      this.v0l = v0l | 0;
      this.v0h = v0h | 0;
      this.v1l = v1l | 0;
      this.v1h = v1h | 0;
      this.v2l = v2l | 0;
      this.v2h = v2h | 0;
      this.v3l = v3l | 0;
      this.v3h = v3h | 0;
      this.v4l = v4l | 0;
      this.v4h = v4h | 0;
      this.v5l = v5l | 0;
      this.v5h = v5h | 0;
      this.v6l = v6l | 0;
      this.v6h = v6h | 0;
      this.v7l = v7l | 0;
      this.v7h = v7h | 0;
    }
    destroy() {
      super.destroy();
      this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
    compress(view, offset, withLength = true) {
      for (let i = 0; i < 32; i++, offset += 4)
        BLAKE512_W[i] = view.getUint32(offset, false);
      this.get().forEach((v, i) => BBUF2[i] = v);
      BBUF2.set(this.constants.subarray(0, 16), 16);
      if (withLength) {
        const { h, l } = fromBig(BigInt(this.length * 8));
        BBUF2[24] = (BBUF2[24] ^ h) >>> 0;
        BBUF2[25] = (BBUF2[25] ^ l) >>> 0;
        BBUF2[26] = (BBUF2[26] ^ h) >>> 0;
        BBUF2[27] = (BBUF2[27] ^ l) >>> 0;
      }
      for (let i = 0, k = 0; i < 16; i++) {
        G1b2(0, 4, 8, 12, BLAKE512_W, k++);
        G2b2(0, 4, 8, 12, BLAKE512_W, k++);
        G1b2(1, 5, 9, 13, BLAKE512_W, k++);
        G2b2(1, 5, 9, 13, BLAKE512_W, k++);
        G1b2(2, 6, 10, 14, BLAKE512_W, k++);
        G2b2(2, 6, 10, 14, BLAKE512_W, k++);
        G1b2(3, 7, 11, 15, BLAKE512_W, k++);
        G2b2(3, 7, 11, 15, BLAKE512_W, k++);
        G1b2(0, 5, 10, 15, BLAKE512_W, k++);
        G2b2(0, 5, 10, 15, BLAKE512_W, k++);
        G1b2(1, 6, 11, 12, BLAKE512_W, k++);
        G2b2(1, 6, 11, 12, BLAKE512_W, k++);
        G1b2(2, 7, 8, 13, BLAKE512_W, k++);
        G2b2(2, 7, 8, 13, BLAKE512_W, k++);
        G1b2(3, 4, 9, 14, BLAKE512_W, k++);
        G2b2(3, 4, 9, 14, BLAKE512_W, k++);
      }
      this.v0l ^= BBUF2[0] ^ BBUF2[16] ^ this.salt[0];
      this.v0h ^= BBUF2[1] ^ BBUF2[17] ^ this.salt[1];
      this.v1l ^= BBUF2[2] ^ BBUF2[18] ^ this.salt[2];
      this.v1h ^= BBUF2[3] ^ BBUF2[19] ^ this.salt[3];
      this.v2l ^= BBUF2[4] ^ BBUF2[20] ^ this.salt[4];
      this.v2h ^= BBUF2[5] ^ BBUF2[21] ^ this.salt[5];
      this.v3l ^= BBUF2[6] ^ BBUF2[22] ^ this.salt[6];
      this.v3h ^= BBUF2[7] ^ BBUF2[23] ^ this.salt[7];
      this.v4l ^= BBUF2[8] ^ BBUF2[24] ^ this.salt[0];
      this.v4h ^= BBUF2[9] ^ BBUF2[25] ^ this.salt[1];
      this.v5l ^= BBUF2[10] ^ BBUF2[26] ^ this.salt[2];
      this.v5h ^= BBUF2[11] ^ BBUF2[27] ^ this.salt[3];
      this.v6l ^= BBUF2[12] ^ BBUF2[28] ^ this.salt[4];
      this.v6h ^= BBUF2[13] ^ BBUF2[29] ^ this.salt[5];
      this.v7l ^= BBUF2[14] ^ BBUF2[30] ^ this.salt[6];
      this.v7h ^= BBUF2[15] ^ BBUF2[31] ^ this.salt[7];
      clean(BBUF2, BLAKE512_W);
    }
  };
  var _BLAKE224 = class extends BLAKE1_32B {
    constructor(opts = {}) {
      super(28, B224_IV, 0, opts);
    }
  };
  var _BLAKE256 = class extends BLAKE1_32B {
    constructor(opts = {}) {
      super(32, B256_IV, 1, opts);
    }
  };
  var _BLAKE384 = class extends BLAKE1_64B {
    constructor(opts = {}) {
      super(48, B384_IV, 0, opts);
    }
  };
  var _BLAKE512 = class extends BLAKE1_64B {
    constructor(opts = {}) {
      super(64, B512_IV, 1, opts);
    }
  };
  var blake224 = /* @__PURE__ */ createHasher((opts) => new _BLAKE224(opts));
  var blake256 = /* @__PURE__ */ createHasher((opts) => new _BLAKE256(opts));
  var blake384 = /* @__PURE__ */ createHasher((opts) => new _BLAKE384(opts));
  var blake512 = /* @__PURE__ */ createHasher((opts) => new _BLAKE512(opts));

  // ../../blake3.js
  var B3_Flags = {
    CHUNK_START: 1,
    CHUNK_END: 2,
    PARENT: 4,
    ROOT: 8,
    KEYED_HASH: 16,
    DERIVE_KEY_CONTEXT: 32,
    DERIVE_KEY_MATERIAL: 64
  };
  var B3_IV = /* @__PURE__ */ SHA256_IV.slice();
  var B3_SIGMA = /* @__PURE__ */ (() => {
    const Id = Array.from({ length: 16 }, (_, i) => i);
    const permute = (arr) => [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8].map((i) => arr[i]);
    const res = [];
    for (let i = 0, v = Id; i < 7; i++, v = permute(v))
      res.push(...v);
    return Uint8Array.from(res);
  })();
  var _BLAKE3 = class __BLAKE3 extends _BLAKE2 {
    chunkPos = 0;
    // Position of current block in chunk
    chunksDone = 0;
    // How many chunks we already have
    flags = 0 | 0;
    IV;
    state;
    stack = [];
    // Output
    posOut = 0;
    bufferOut32 = new Uint32Array(16);
    bufferOut;
    chunkOut = 0;
    // index of output chunk
    enableXOF = true;
    constructor(opts = {}, flags = 0) {
      super(64, opts.dkLen === void 0 ? 32 : opts.dkLen);
      const { key, context } = opts;
      const hasContext = context !== void 0;
      if (key !== void 0) {
        if (hasContext)
          throw new Error('Only "key" or "context" can be specified at same time');
        abytes(key, 32, "key");
        const k = key.slice();
        this.IV = u32(k);
        swap32IfBE(this.IV);
        this.flags = flags | B3_Flags.KEYED_HASH;
      } else if (hasContext) {
        abytes(context, void 0, "context");
        const ctx = context;
        const contextKey = new __BLAKE3({ dkLen: 32 }, B3_Flags.DERIVE_KEY_CONTEXT).update(ctx).digest();
        this.IV = u32(contextKey);
        swap32IfBE(this.IV);
        this.flags = flags | B3_Flags.DERIVE_KEY_MATERIAL;
      } else {
        this.IV = B3_IV.slice();
        this.flags = flags;
      }
      this.state = this.IV.slice();
      this.bufferOut = u8(this.bufferOut32);
    }
    // Unused
    get() {
      return [];
    }
    set() {
    }
    b2Compress(counter, flags, buf, bufPos = 0) {
      const { state: s, pos } = this;
      const { h, l } = fromBig(BigInt(counter), true);
      const { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 } = compress(B3_SIGMA, bufPos, buf, 7, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3], h, l, pos, flags);
      s[0] = v0 ^ v8;
      s[1] = v1 ^ v9;
      s[2] = v2 ^ v10;
      s[3] = v3 ^ v11;
      s[4] = v4 ^ v12;
      s[5] = v5 ^ v13;
      s[6] = v6 ^ v14;
      s[7] = v7 ^ v15;
    }
    compress(buf, bufPos = 0, isLast = false) {
      let flags = this.flags;
      if (!this.chunkPos)
        flags |= B3_Flags.CHUNK_START;
      if (this.chunkPos === 15 || isLast)
        flags |= B3_Flags.CHUNK_END;
      if (!isLast)
        this.pos = this.blockLen;
      this.b2Compress(this.chunksDone, flags, buf, bufPos);
      this.chunkPos += 1;
      if (this.chunkPos === 16 || isLast) {
        let chunk = this.state;
        this.state = this.IV.slice();
        for (let last, chunks = this.chunksDone + 1; isLast || !(chunks & 1); chunks >>= 1) {
          if (!(last = this.stack.pop()))
            break;
          this.buffer32.set(last, 0);
          this.buffer32.set(chunk, 8);
          this.pos = this.blockLen;
          this.b2Compress(0, this.flags | B3_Flags.PARENT, this.buffer32, 0);
          chunk = this.state;
          this.state = this.IV.slice();
        }
        this.chunksDone++;
        this.chunkPos = 0;
        this.stack.push(chunk);
      }
      this.pos = 0;
    }
    _cloneInto(to) {
      to = super._cloneInto(to);
      const { IV, flags, state, chunkPos, posOut, chunkOut, stack, chunksDone } = this;
      to.state.set(state.slice());
      to.stack = stack.map((i) => Uint32Array.from(i));
      to.IV.set(IV);
      to.flags = flags;
      to.chunkPos = chunkPos;
      to.chunksDone = chunksDone;
      to.posOut = posOut;
      to.chunkOut = chunkOut;
      to.enableXOF = this.enableXOF;
      to.bufferOut32.set(this.bufferOut32);
      return to;
    }
    destroy() {
      this.destroyed = true;
      clean(this.state, this.buffer32, this.IV, this.bufferOut32);
      clean(...this.stack);
    }
    // Same as b2Compress, but doesn't modify state and returns 16 u32 array (instead of 8)
    b2CompressOut() {
      const { state: s, pos, flags, buffer32, bufferOut32: out32 } = this;
      const { h, l } = fromBig(BigInt(this.chunkOut++));
      swap32IfBE(buffer32);
      const { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 } = compress(B3_SIGMA, 0, buffer32, 7, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3], l, h, pos, flags);
      out32[0] = v0 ^ v8;
      out32[1] = v1 ^ v9;
      out32[2] = v2 ^ v10;
      out32[3] = v3 ^ v11;
      out32[4] = v4 ^ v12;
      out32[5] = v5 ^ v13;
      out32[6] = v6 ^ v14;
      out32[7] = v7 ^ v15;
      out32[8] = s[0] ^ v8;
      out32[9] = s[1] ^ v9;
      out32[10] = s[2] ^ v10;
      out32[11] = s[3] ^ v11;
      out32[12] = s[4] ^ v12;
      out32[13] = s[5] ^ v13;
      out32[14] = s[6] ^ v14;
      out32[15] = s[7] ^ v15;
      swap32IfBE(buffer32);
      swap32IfBE(out32);
      this.posOut = 0;
    }
    finish() {
      if (this.finished)
        return;
      this.finished = true;
      clean(this.buffer.subarray(this.pos));
      let flags = this.flags | B3_Flags.ROOT;
      if (this.stack.length) {
        flags |= B3_Flags.PARENT;
        swap32IfBE(this.buffer32);
        this.compress(this.buffer32, 0, true);
        swap32IfBE(this.buffer32);
        this.chunksDone = 0;
        this.pos = this.blockLen;
      } else {
        flags |= (!this.chunkPos ? B3_Flags.CHUNK_START : 0) | B3_Flags.CHUNK_END;
      }
      this.flags = flags;
      this.b2CompressOut();
    }
    writeInto(out) {
      aexists(this, false);
      abytes(out);
      this.finish();
      const { blockLen, bufferOut } = this;
      for (let pos = 0, len = out.length; pos < len; ) {
        if (this.posOut >= blockLen)
          this.b2CompressOut();
        const take = Math.min(blockLen - this.posOut, len - pos);
        out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
        this.posOut += take;
        pos += take;
      }
      return out;
    }
    xofInto(out) {
      if (!this.enableXOF)
        throw new Error("XOF is not possible after digest call");
      return this.writeInto(out);
    }
    xof(bytes) {
      anumber(bytes);
      return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
      aoutput(out, this);
      if (this.finished)
        throw new Error("digest() was already called");
      this.enableXOF = false;
      this.writeInto(out);
      this.destroy();
      return out;
    }
    digest() {
      return this.digestInto(new Uint8Array(this.outputLen));
    }
  };
  var blake3 = /* @__PURE__ */ createHasher((opts = {}) => new _BLAKE3(opts));

  // ../../hmac.js
  var _HMAC = class {
    oHash;
    iHash;
    blockLen;
    outputLen;
    finished = false;
    destroyed = false;
    constructor(hash, key) {
      ahash(hash);
      abytes(key, void 0, "key");
      this.iHash = hash.create();
      if (typeof this.iHash.update !== "function")
        throw new Error("Expected instance of class which extends utils.Hash");
      this.blockLen = this.iHash.blockLen;
      this.outputLen = this.iHash.outputLen;
      const blockLen = this.blockLen;
      const pad = new Uint8Array(blockLen);
      pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
      for (let i = 0; i < pad.length; i++)
        pad[i] ^= 54;
      this.iHash.update(pad);
      this.oHash = hash.create();
      for (let i = 0; i < pad.length; i++)
        pad[i] ^= 54 ^ 92;
      this.oHash.update(pad);
      clean(pad);
    }
    update(buf) {
      aexists(this);
      this.iHash.update(buf);
      return this;
    }
    digestInto(out) {
      aexists(this);
      abytes(out, this.outputLen, "output");
      this.finished = true;
      this.iHash.digestInto(out);
      this.oHash.update(out);
      this.oHash.digestInto(out);
      this.destroy();
    }
    digest() {
      const out = new Uint8Array(this.oHash.outputLen);
      this.digestInto(out);
      return out;
    }
    _cloneInto(to) {
      to ||= Object.create(Object.getPrototypeOf(this), {});
      const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
      to = to;
      to.finished = finished;
      to.destroyed = destroyed;
      to.blockLen = blockLen;
      to.outputLen = outputLen;
      to.oHash = oHash._cloneInto(to.oHash);
      to.iHash = iHash._cloneInto(to.iHash);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
    destroy() {
      this.destroyed = true;
      this.oHash.destroy();
      this.iHash.destroy();
    }
  };
  var hmac = (hash, key, message) => new _HMAC(hash, key).update(message).digest();
  hmac.create = (hash, key) => new _HMAC(hash, key);

  // ../../hkdf.js
  function extract(hash, ikm, salt) {
    ahash(hash);
    if (salt === void 0)
      salt = new Uint8Array(hash.outputLen);
    return hmac(hash, salt, ikm);
  }
  var HKDF_COUNTER = /* @__PURE__ */ Uint8Array.of(0);
  var EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();
  function expand(hash, prk, info, length = 32) {
    ahash(hash);
    anumber(length, "length");
    const olen = hash.outputLen;
    if (length > 255 * olen)
      throw new Error("Length must be <= 255*HashLen");
    const blocks = Math.ceil(length / olen);
    if (info === void 0)
      info = EMPTY_BUFFER;
    else
      abytes(info, void 0, "info");
    const okm = new Uint8Array(blocks * olen);
    const HMAC = hmac.create(hash, prk);
    const HMACTmp = HMAC._cloneInto();
    const T = new Uint8Array(HMAC.outputLen);
    for (let counter = 0; counter < blocks; counter++) {
      HKDF_COUNTER[0] = counter + 1;
      HMACTmp.update(counter === 0 ? EMPTY_BUFFER : T).update(info).update(HKDF_COUNTER).digestInto(T);
      okm.set(T, olen * counter);
      HMAC._cloneInto(HMACTmp);
    }
    HMAC.destroy();
    HMACTmp.destroy();
    clean(T, HKDF_COUNTER);
    return okm.slice(0, length);
  }
  var hkdf = (hash, ikm, salt, info, length) => expand(hash, extract(hash, ikm, salt), info, length);

  // ../../pbkdf2.js
  function pbkdf2Init(hash, _password, _salt, _opts) {
    ahash(hash);
    const opts = checkOpts({ dkLen: 32, asyncTick: 10 }, _opts);
    const { c, dkLen, asyncTick } = opts;
    anumber(c, "c");
    anumber(dkLen, "dkLen");
    anumber(asyncTick, "asyncTick");
    if (c < 1)
      throw new Error("iterations (c) must be >= 1");
    const password = kdfInputToBytes(_password, "password");
    const salt = kdfInputToBytes(_salt, "salt");
    const DK = new Uint8Array(dkLen);
    const PRF = hmac.create(hash, password);
    const PRFSalt = PRF._cloneInto().update(salt);
    return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
  }
  function pbkdf2Output(PRF, PRFSalt, DK, prfW, u) {
    PRF.destroy();
    PRFSalt.destroy();
    if (prfW)
      prfW.destroy();
    clean(u);
    return DK;
  }
  function pbkdf2(hash, password, salt, opts) {
    const { c, dkLen, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
    let prfW;
    const arr = new Uint8Array(4);
    const view = createView(arr);
    const u = new Uint8Array(PRF.outputLen);
    for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
      const Ti = DK.subarray(pos, pos + PRF.outputLen);
      view.setInt32(0, ti, false);
      (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
      Ti.set(u.subarray(0, Ti.length));
      for (let ui = 1; ui < c; ui++) {
        PRF._cloneInto(prfW).update(u).digestInto(u);
        for (let i = 0; i < Ti.length; i++)
          Ti[i] ^= u[i];
      }
    }
    return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
  }
  async function pbkdf2Async(hash, password, salt, opts) {
    const { c, dkLen, asyncTick, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
    let prfW;
    const arr = new Uint8Array(4);
    const view = createView(arr);
    const u = new Uint8Array(PRF.outputLen);
    for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
      const Ti = DK.subarray(pos, pos + PRF.outputLen);
      view.setInt32(0, ti, false);
      (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
      Ti.set(u.subarray(0, Ti.length));
      await asyncLoop(c - 1, asyncTick, () => {
        PRF._cloneInto(prfW).update(u).digestInto(u);
        for (let i = 0; i < Ti.length; i++)
          Ti[i] ^= u[i];
      });
    }
    return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
  }

  // ../../sha2.js
  var SHA256_K = /* @__PURE__ */ Uint32Array.from([
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ]);
  var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
  var SHA2_32B = class extends HashMD {
    constructor(outputLen) {
      super(64, outputLen, 8, false);
    }
    get() {
      const { A, B, C, D, E, F, G: G2, H } = this;
      return [A, B, C, D, E, F, G2, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G2, H) {
      this.A = A | 0;
      this.B = B | 0;
      this.C = C | 0;
      this.D = D | 0;
      this.E = E | 0;
      this.F = F | 0;
      this.G = G2 | 0;
      this.H = H | 0;
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4)
        SHA256_W[i] = view.getUint32(offset, false);
      for (let i = 16; i < 64; i++) {
        const W15 = SHA256_W[i - 15];
        const W2 = SHA256_W[i - 2];
        const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
        const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
        SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
      }
      let { A, B, C, D, E, F, G: G2, H } = this;
      for (let i = 0; i < 64; i++) {
        const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
        const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
        const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
        const T2 = sigma0 + Maj(A, B, C) | 0;
        H = G2;
        G2 = F;
        F = E;
        E = D + T1 | 0;
        D = C;
        C = B;
        B = A;
        A = T1 + T2 | 0;
      }
      A = A + this.A | 0;
      B = B + this.B | 0;
      C = C + this.C | 0;
      D = D + this.D | 0;
      E = E + this.E | 0;
      F = F + this.F | 0;
      G2 = G2 + this.G | 0;
      H = H + this.H | 0;
      this.set(A, B, C, D, E, F, G2, H);
    }
    roundClean() {
      clean(SHA256_W);
    }
    destroy() {
      this.set(0, 0, 0, 0, 0, 0, 0, 0);
      clean(this.buffer);
    }
  };
  var _SHA256 = class extends SHA2_32B {
    // We cannot use array here since array allows indexing by variable
    // which means optimizer/compiler cannot use registers.
    A = SHA256_IV[0] | 0;
    B = SHA256_IV[1] | 0;
    C = SHA256_IV[2] | 0;
    D = SHA256_IV[3] | 0;
    E = SHA256_IV[4] | 0;
    F = SHA256_IV[5] | 0;
    G = SHA256_IV[6] | 0;
    H = SHA256_IV[7] | 0;
    constructor() {
      super(32);
    }
  };
  var _SHA224 = class extends SHA2_32B {
    A = SHA224_IV[0] | 0;
    B = SHA224_IV[1] | 0;
    C = SHA224_IV[2] | 0;
    D = SHA224_IV[3] | 0;
    E = SHA224_IV[4] | 0;
    F = SHA224_IV[5] | 0;
    G = SHA224_IV[6] | 0;
    H = SHA224_IV[7] | 0;
    constructor() {
      super(28);
    }
  };
  var K512 = /* @__PURE__ */ (() => split([
    "0x428a2f98d728ae22",
    "0x7137449123ef65cd",
    "0xb5c0fbcfec4d3b2f",
    "0xe9b5dba58189dbbc",
    "0x3956c25bf348b538",
    "0x59f111f1b605d019",
    "0x923f82a4af194f9b",
    "0xab1c5ed5da6d8118",
    "0xd807aa98a3030242",
    "0x12835b0145706fbe",
    "0x243185be4ee4b28c",
    "0x550c7dc3d5ffb4e2",
    "0x72be5d74f27b896f",
    "0x80deb1fe3b1696b1",
    "0x9bdc06a725c71235",
    "0xc19bf174cf692694",
    "0xe49b69c19ef14ad2",
    "0xefbe4786384f25e3",
    "0x0fc19dc68b8cd5b5",
    "0x240ca1cc77ac9c65",
    "0x2de92c6f592b0275",
    "0x4a7484aa6ea6e483",
    "0x5cb0a9dcbd41fbd4",
    "0x76f988da831153b5",
    "0x983e5152ee66dfab",
    "0xa831c66d2db43210",
    "0xb00327c898fb213f",
    "0xbf597fc7beef0ee4",
    "0xc6e00bf33da88fc2",
    "0xd5a79147930aa725",
    "0x06ca6351e003826f",
    "0x142929670a0e6e70",
    "0x27b70a8546d22ffc",
    "0x2e1b21385c26c926",
    "0x4d2c6dfc5ac42aed",
    "0x53380d139d95b3df",
    "0x650a73548baf63de",
    "0x766a0abb3c77b2a8",
    "0x81c2c92e47edaee6",
    "0x92722c851482353b",
    "0xa2bfe8a14cf10364",
    "0xa81a664bbc423001",
    "0xc24b8b70d0f89791",
    "0xc76c51a30654be30",
    "0xd192e819d6ef5218",
    "0xd69906245565a910",
    "0xf40e35855771202a",
    "0x106aa07032bbd1b8",
    "0x19a4c116b8d2d0c8",
    "0x1e376c085141ab53",
    "0x2748774cdf8eeb99",
    "0x34b0bcb5e19b48a8",
    "0x391c0cb3c5c95a63",
    "0x4ed8aa4ae3418acb",
    "0x5b9cca4f7763e373",
    "0x682e6ff3d6b2b8a3",
    "0x748f82ee5defb2fc",
    "0x78a5636f43172f60",
    "0x84c87814a1f0ab72",
    "0x8cc702081a6439ec",
    "0x90befffa23631e28",
    "0xa4506cebde82bde9",
    "0xbef9a3f7b2c67915",
    "0xc67178f2e372532b",
    "0xca273eceea26619c",
    "0xd186b8c721c0c207",
    "0xeada7dd6cde0eb1e",
    "0xf57d4f7fee6ed178",
    "0x06f067aa72176fba",
    "0x0a637dc5a2c898a6",
    "0x113f9804bef90dae",
    "0x1b710b35131c471b",
    "0x28db77f523047d84",
    "0x32caab7b40c72493",
    "0x3c9ebe0a15c9bebc",
    "0x431d67c49c100d4c",
    "0x4cc5d4becb3e42b6",
    "0x597f299cfc657e2a",
    "0x5fcb6fab3ad6faec",
    "0x6c44198c4a475817"
  ].map((n) => BigInt(n))))();
  var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
  var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
  var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
  var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
  var SHA2_64B = class extends HashMD {
    constructor(outputLen) {
      super(128, outputLen, 16, false);
    }
    // prettier-ignore
    get() {
      const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
      return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
    }
    // prettier-ignore
    set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
      this.Ah = Ah | 0;
      this.Al = Al | 0;
      this.Bh = Bh | 0;
      this.Bl = Bl | 0;
      this.Ch = Ch | 0;
      this.Cl = Cl | 0;
      this.Dh = Dh | 0;
      this.Dl = Dl | 0;
      this.Eh = Eh | 0;
      this.El = El | 0;
      this.Fh = Fh | 0;
      this.Fl = Fl | 0;
      this.Gh = Gh | 0;
      this.Gl = Gl | 0;
      this.Hh = Hh | 0;
      this.Hl = Hl | 0;
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4) {
        SHA512_W_H[i] = view.getUint32(offset);
        SHA512_W_L[i] = view.getUint32(offset += 4);
      }
      for (let i = 16; i < 80; i++) {
        const W15h = SHA512_W_H[i - 15] | 0;
        const W15l = SHA512_W_L[i - 15] | 0;
        const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
        const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
        const W2h = SHA512_W_H[i - 2] | 0;
        const W2l = SHA512_W_L[i - 2] | 0;
        const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
        const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
        const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
        const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
        SHA512_W_H[i] = SUMh | 0;
        SHA512_W_L[i] = SUMl | 0;
      }
      let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
      for (let i = 0; i < 80; i++) {
        const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
        const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
        const CHIh = Eh & Fh ^ ~Eh & Gh;
        const CHIl = El & Fl ^ ~El & Gl;
        const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
        const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
        const T1l = T1ll | 0;
        const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
        const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
        const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
        const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
        Hh = Gh | 0;
        Hl = Gl | 0;
        Gh = Fh | 0;
        Gl = Fl | 0;
        Fh = Eh | 0;
        Fl = El | 0;
        ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
        Dh = Ch | 0;
        Dl = Cl | 0;
        Ch = Bh | 0;
        Cl = Bl | 0;
        Bh = Ah | 0;
        Bl = Al | 0;
        const All = add3L(T1l, sigma0l, MAJl);
        Ah = add3H(All, T1h, sigma0h, MAJh);
        Al = All | 0;
      }
      ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
      ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
      ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
      ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
      ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
      ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
      ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
      ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
      this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
    }
    roundClean() {
      clean(SHA512_W_H, SHA512_W_L);
    }
    destroy() {
      clean(this.buffer);
      this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
  };
  var _SHA512 = class extends SHA2_64B {
    Ah = SHA512_IV[0] | 0;
    Al = SHA512_IV[1] | 0;
    Bh = SHA512_IV[2] | 0;
    Bl = SHA512_IV[3] | 0;
    Ch = SHA512_IV[4] | 0;
    Cl = SHA512_IV[5] | 0;
    Dh = SHA512_IV[6] | 0;
    Dl = SHA512_IV[7] | 0;
    Eh = SHA512_IV[8] | 0;
    El = SHA512_IV[9] | 0;
    Fh = SHA512_IV[10] | 0;
    Fl = SHA512_IV[11] | 0;
    Gh = SHA512_IV[12] | 0;
    Gl = SHA512_IV[13] | 0;
    Hh = SHA512_IV[14] | 0;
    Hl = SHA512_IV[15] | 0;
    constructor() {
      super(64);
    }
  };
  var _SHA384 = class extends SHA2_64B {
    Ah = SHA384_IV[0] | 0;
    Al = SHA384_IV[1] | 0;
    Bh = SHA384_IV[2] | 0;
    Bl = SHA384_IV[3] | 0;
    Ch = SHA384_IV[4] | 0;
    Cl = SHA384_IV[5] | 0;
    Dh = SHA384_IV[6] | 0;
    Dl = SHA384_IV[7] | 0;
    Eh = SHA384_IV[8] | 0;
    El = SHA384_IV[9] | 0;
    Fh = SHA384_IV[10] | 0;
    Fl = SHA384_IV[11] | 0;
    Gh = SHA384_IV[12] | 0;
    Gl = SHA384_IV[13] | 0;
    Hh = SHA384_IV[14] | 0;
    Hl = SHA384_IV[15] | 0;
    constructor() {
      super(48);
    }
  };
  var T224_IV = /* @__PURE__ */ Uint32Array.from([
    2352822216,
    424955298,
    1944164710,
    2312950998,
    502970286,
    855612546,
    1738396948,
    1479516111,
    258812777,
    2077511080,
    2011393907,
    79989058,
    1067287976,
    1780299464,
    286451373,
    2446758561
  ]);
  var T256_IV = /* @__PURE__ */ Uint32Array.from([
    573645204,
    4230739756,
    2673172387,
    3360449730,
    596883563,
    1867755857,
    2520282905,
    1497426621,
    2519219938,
    2827943907,
    3193839141,
    1401305490,
    721525244,
    746961066,
    246885852,
    2177182882
  ]);
  var _SHA512_224 = class extends SHA2_64B {
    Ah = T224_IV[0] | 0;
    Al = T224_IV[1] | 0;
    Bh = T224_IV[2] | 0;
    Bl = T224_IV[3] | 0;
    Ch = T224_IV[4] | 0;
    Cl = T224_IV[5] | 0;
    Dh = T224_IV[6] | 0;
    Dl = T224_IV[7] | 0;
    Eh = T224_IV[8] | 0;
    El = T224_IV[9] | 0;
    Fh = T224_IV[10] | 0;
    Fl = T224_IV[11] | 0;
    Gh = T224_IV[12] | 0;
    Gl = T224_IV[13] | 0;
    Hh = T224_IV[14] | 0;
    Hl = T224_IV[15] | 0;
    constructor() {
      super(28);
    }
  };
  var _SHA512_256 = class extends SHA2_64B {
    Ah = T256_IV[0] | 0;
    Al = T256_IV[1] | 0;
    Bh = T256_IV[2] | 0;
    Bl = T256_IV[3] | 0;
    Ch = T256_IV[4] | 0;
    Cl = T256_IV[5] | 0;
    Dh = T256_IV[6] | 0;
    Dl = T256_IV[7] | 0;
    Eh = T256_IV[8] | 0;
    El = T256_IV[9] | 0;
    Fh = T256_IV[10] | 0;
    Fl = T256_IV[11] | 0;
    Gh = T256_IV[12] | 0;
    Gl = T256_IV[13] | 0;
    Hh = T256_IV[14] | 0;
    Hl = T256_IV[15] | 0;
    constructor() {
      super(32);
    }
  };
  var sha256 = /* @__PURE__ */ createHasher(
    () => new _SHA256(),
    /* @__PURE__ */ oidNist(1)
  );
  var sha224 = /* @__PURE__ */ createHasher(
    () => new _SHA224(),
    /* @__PURE__ */ oidNist(4)
  );
  var sha512 = /* @__PURE__ */ createHasher(
    () => new _SHA512(),
    /* @__PURE__ */ oidNist(3)
  );
  var sha384 = /* @__PURE__ */ createHasher(
    () => new _SHA384(),
    /* @__PURE__ */ oidNist(2)
  );
  var sha512_256 = /* @__PURE__ */ createHasher(
    () => new _SHA512_256(),
    /* @__PURE__ */ oidNist(6)
  );
  var sha512_224 = /* @__PURE__ */ createHasher(
    () => new _SHA512_224(),
    /* @__PURE__ */ oidNist(5)
  );

  // ../../scrypt.js
  function XorAndSalsa(prev, pi, input, ii, out, oi) {
    let y00 = prev[pi++] ^ input[ii++], y01 = prev[pi++] ^ input[ii++];
    let y02 = prev[pi++] ^ input[ii++], y03 = prev[pi++] ^ input[ii++];
    let y04 = prev[pi++] ^ input[ii++], y05 = prev[pi++] ^ input[ii++];
    let y06 = prev[pi++] ^ input[ii++], y07 = prev[pi++] ^ input[ii++];
    let y08 = prev[pi++] ^ input[ii++], y09 = prev[pi++] ^ input[ii++];
    let y10 = prev[pi++] ^ input[ii++], y11 = prev[pi++] ^ input[ii++];
    let y12 = prev[pi++] ^ input[ii++], y13 = prev[pi++] ^ input[ii++];
    let y14 = prev[pi++] ^ input[ii++], y15 = prev[pi++] ^ input[ii++];
    let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
    for (let i = 0; i < 8; i += 2) {
      x04 ^= rotl(x00 + x12 | 0, 7);
      x08 ^= rotl(x04 + x00 | 0, 9);
      x12 ^= rotl(x08 + x04 | 0, 13);
      x00 ^= rotl(x12 + x08 | 0, 18);
      x09 ^= rotl(x05 + x01 | 0, 7);
      x13 ^= rotl(x09 + x05 | 0, 9);
      x01 ^= rotl(x13 + x09 | 0, 13);
      x05 ^= rotl(x01 + x13 | 0, 18);
      x14 ^= rotl(x10 + x06 | 0, 7);
      x02 ^= rotl(x14 + x10 | 0, 9);
      x06 ^= rotl(x02 + x14 | 0, 13);
      x10 ^= rotl(x06 + x02 | 0, 18);
      x03 ^= rotl(x15 + x11 | 0, 7);
      x07 ^= rotl(x03 + x15 | 0, 9);
      x11 ^= rotl(x07 + x03 | 0, 13);
      x15 ^= rotl(x11 + x07 | 0, 18);
      x01 ^= rotl(x00 + x03 | 0, 7);
      x02 ^= rotl(x01 + x00 | 0, 9);
      x03 ^= rotl(x02 + x01 | 0, 13);
      x00 ^= rotl(x03 + x02 | 0, 18);
      x06 ^= rotl(x05 + x04 | 0, 7);
      x07 ^= rotl(x06 + x05 | 0, 9);
      x04 ^= rotl(x07 + x06 | 0, 13);
      x05 ^= rotl(x04 + x07 | 0, 18);
      x11 ^= rotl(x10 + x09 | 0, 7);
      x08 ^= rotl(x11 + x10 | 0, 9);
      x09 ^= rotl(x08 + x11 | 0, 13);
      x10 ^= rotl(x09 + x08 | 0, 18);
      x12 ^= rotl(x15 + x14 | 0, 7);
      x13 ^= rotl(x12 + x15 | 0, 9);
      x14 ^= rotl(x13 + x12 | 0, 13);
      x15 ^= rotl(x14 + x13 | 0, 18);
    }
    out[oi++] = y00 + x00 | 0;
    out[oi++] = y01 + x01 | 0;
    out[oi++] = y02 + x02 | 0;
    out[oi++] = y03 + x03 | 0;
    out[oi++] = y04 + x04 | 0;
    out[oi++] = y05 + x05 | 0;
    out[oi++] = y06 + x06 | 0;
    out[oi++] = y07 + x07 | 0;
    out[oi++] = y08 + x08 | 0;
    out[oi++] = y09 + x09 | 0;
    out[oi++] = y10 + x10 | 0;
    out[oi++] = y11 + x11 | 0;
    out[oi++] = y12 + x12 | 0;
    out[oi++] = y13 + x13 | 0;
    out[oi++] = y14 + x14 | 0;
    out[oi++] = y15 + x15 | 0;
  }
  function BlockMix(input, ii, out, oi, r) {
    let head = oi + 0;
    let tail = oi + 16 * r;
    for (let i = 0; i < 16; i++)
      out[tail + i] = input[ii + (2 * r - 1) * 16 + i];
    for (let i = 0; i < r; i++, head += 16, ii += 16) {
      XorAndSalsa(out, tail, input, ii, out, head);
      if (i > 0)
        tail += 16;
      XorAndSalsa(out, head, input, ii += 16, out, tail);
    }
  }
  function scryptInit(password, salt, _opts) {
    const opts = checkOpts({
      dkLen: 32,
      asyncTick: 10,
      maxmem: 1024 ** 3 + 1024
    }, _opts);
    const { N, r, p, dkLen, asyncTick, maxmem, onProgress } = opts;
    anumber(N, "N");
    anumber(r, "r");
    anumber(p, "p");
    anumber(dkLen, "dkLen");
    anumber(asyncTick, "asyncTick");
    anumber(maxmem, "maxmem");
    if (onProgress !== void 0 && typeof onProgress !== "function")
      throw new Error("progressCb must be a function");
    const blockSize = 128 * r;
    const blockSize32 = blockSize / 4;
    const pow32 = Math.pow(2, 32);
    if (N <= 1 || (N & N - 1) !== 0 || N > pow32)
      throw new Error('"N" expected a power of 2, and 2^1 <= N <= 2^32');
    if (p < 1 || p > (pow32 - 1) * 32 / blockSize)
      throw new Error('"p" expected integer 1..((2^32 - 1) * 32) / (128 * r)');
    if (dkLen < 1 || dkLen > (pow32 - 1) * 32)
      throw new Error('"dkLen" expected integer 1..(2^32 - 1) * 32');
    const memUsed = blockSize * (N + p);
    if (memUsed > maxmem)
      throw new Error('"maxmem" limit was hit, expected 128*r*(N+p) > "maxmem"=' + maxmem);
    const B = pbkdf2(sha256, password, salt, { c: 1, dkLen: blockSize * p });
    const B32 = u32(B);
    const V = u32(new Uint8Array(blockSize * N));
    const tmp = u32(new Uint8Array(blockSize));
    let blockMixCb = () => {
    };
    if (onProgress) {
      const totalBlockMix = 2 * N * p;
      const callbackPer = Math.max(Math.floor(totalBlockMix / 1e4), 1);
      let blockMixCnt = 0;
      blockMixCb = () => {
        blockMixCnt++;
        if (onProgress && (!(blockMixCnt % callbackPer) || blockMixCnt === totalBlockMix))
          onProgress(blockMixCnt / totalBlockMix);
      };
    }
    return { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb, asyncTick };
  }
  function scryptOutput(password, dkLen, B, V, tmp) {
    const res = pbkdf2(sha256, password, B, { c: 1, dkLen });
    clean(B, V, tmp);
    return res;
  }
  function scrypt(password, salt, opts) {
    const { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb } = scryptInit(password, salt, opts);
    swap32IfBE(B32);
    for (let pi = 0; pi < p; pi++) {
      const Pi = blockSize32 * pi;
      for (let i = 0; i < blockSize32; i++)
        V[i] = B32[Pi + i];
      for (let i = 0, pos = 0; i < N - 1; i++) {
        BlockMix(V, pos, V, pos += blockSize32, r);
        blockMixCb();
      }
      BlockMix(V, (N - 1) * blockSize32, B32, Pi, r);
      blockMixCb();
      for (let i = 0; i < N; i++) {
        const j = B32[Pi + blockSize32 - 16] % N;
        for (let k = 0; k < blockSize32; k++)
          tmp[k] = B32[Pi + k] ^ V[j * blockSize32 + k];
        BlockMix(tmp, 0, B32, Pi, r);
        blockMixCb();
      }
    }
    swap32IfBE(B32);
    return scryptOutput(password, dkLen, B, V, tmp);
  }
  async function scryptAsync(password, salt, opts) {
    const { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb, asyncTick } = scryptInit(password, salt, opts);
    swap32IfBE(B32);
    for (let pi = 0; pi < p; pi++) {
      const Pi = blockSize32 * pi;
      for (let i = 0; i < blockSize32; i++)
        V[i] = B32[Pi + i];
      let pos = 0;
      await asyncLoop(N - 1, asyncTick, () => {
        BlockMix(V, pos, V, pos += blockSize32, r);
        blockMixCb();
      });
      BlockMix(V, (N - 1) * blockSize32, B32, Pi, r);
      blockMixCb();
      await asyncLoop(N, asyncTick, () => {
        const j = B32[Pi + blockSize32 - 16] % N;
        for (let k = 0; k < blockSize32; k++)
          tmp[k] = B32[Pi + k] ^ V[j * blockSize32 + k];
        BlockMix(tmp, 0, B32, Pi, r);
        blockMixCb();
      });
    }
    swap32IfBE(B32);
    return scryptOutput(password, dkLen, B, V, tmp);
  }

  // ../../eskdf.js
  var SCRYPT_FACTOR = 2 ** 19;
  var PBKDF2_FACTOR = 2 ** 17;
  function scrypt2(password, salt) {
    return scrypt(password, salt, { N: SCRYPT_FACTOR, r: 8, p: 1, dkLen: 32 });
  }
  function pbkdf22(password, salt) {
    return pbkdf2(sha256, password, salt, { c: PBKDF2_FACTOR, dkLen: 32 });
  }
  function xor32(a, b) {
    abytes(a, 32);
    abytes(b, 32);
    const arr = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      arr[i] = a[i] ^ b[i];
    }
    return arr;
  }
  function strHasLength(str, min, max) {
    return typeof str === "string" && str.length >= min && str.length <= max;
  }
  function deriveMainSeed(username, password) {
    if (!strHasLength(username, 8, 255))
      throw new Error("invalid username");
    if (!strHasLength(password, 8, 255))
      throw new Error("invalid password");
    const codes = { _1: 1, _2: 2 };
    const sep = { s: String.fromCharCode(codes._1), p: String.fromCharCode(codes._2) };
    const scr = scrypt2(password + sep.s, username + sep.s);
    const pbk = pbkdf22(password + sep.p, username + sep.p);
    const res = xor32(scr, pbk);
    clean(scr, pbk);
    return res;
  }
  function getSaltInfo(protocol, accountId = 0) {
    if (!(strHasLength(protocol, 3, 15) && /^[a-z0-9]{3,15}$/.test(protocol))) {
      throw new Error("invalid protocol");
    }
    const allowsStr = /^password\d{0,3}|ssh|tor|file$/.test(protocol);
    let salt;
    if (typeof accountId === "string") {
      if (!allowsStr)
        throw new Error("accountId must be a number");
      if (!strHasLength(accountId, 1, 255))
        throw new Error("accountId must be string of length 1..255");
      salt = kdfInputToBytes(accountId);
    } else if (Number.isSafeInteger(accountId)) {
      if (accountId < 0 || accountId > Math.pow(2, 32) - 1)
        throw new Error("invalid accountId");
      salt = new Uint8Array(4);
      createView(salt).setUint32(0, accountId, false);
    } else {
      throw new Error("accountId must be a number" + (allowsStr ? " or string" : ""));
    }
    const info = kdfInputToBytes(protocol);
    return { salt, info };
  }
  function countBytes(num) {
    if (typeof num !== "bigint" || num <= BigInt(128))
      throw new Error("invalid number");
    return Math.ceil(num.toString(2).length / 8);
  }
  function getKeyLength(options) {
    if (!options || typeof options !== "object")
      return 32;
    const hasLen = "keyLength" in options;
    const hasMod = "modulus" in options;
    if (hasLen && hasMod)
      throw new Error("cannot combine keyLength and modulus options");
    if (!hasLen && !hasMod)
      throw new Error("must have either keyLength or modulus option");
    const l = hasMod ? countBytes(options.modulus) + 8 : options.keyLength;
    if (!(typeof l === "number" && l >= 16 && l <= 8192))
      throw new Error("invalid keyLength");
    return l;
  }
  function modReduceKey(key, modulus) {
    const _1 = BigInt(1);
    const num = BigInt("0x" + bytesToHex(key));
    const res = num % (modulus - _1) + _1;
    if (res < _1)
      throw new Error("expected positive number");
    const len = key.length - 8;
    const hex = res.toString(16).padStart(len * 2, "0");
    const bytes = hexToBytes(hex);
    if (bytes.length !== len)
      throw new Error("invalid length of result key");
    return bytes;
  }
  async function eskdf(username, password) {
    let seed = deriveMainSeed(username, password);
    function deriveCK(protocol, accountId = 0, options) {
      abytes(seed, 32);
      const { salt, info } = getSaltInfo(protocol, accountId);
      const keyLength = getKeyLength(options);
      const key = hkdf(sha256, seed, salt, info, keyLength);
      return options && "modulus" in options ? modReduceKey(key, options.modulus) : key;
    }
    function expire() {
      if (seed)
        seed.fill(1);
      seed = void 0;
    }
    const fingerprint = Array.from(deriveCK("fingerprint", 0)).slice(0, 6).map((char) => char.toString(16).padStart(2, "0").toUpperCase()).join(":");
    return Object.freeze({ deriveChildKey: deriveCK, expire, fingerprint });
  }

  // ../../legacy.js
  var SHA1_IV = /* @__PURE__ */ Uint32Array.from([
    1732584193,
    4023233417,
    2562383102,
    271733878,
    3285377520
  ]);
  var SHA1_W = /* @__PURE__ */ new Uint32Array(80);
  var _SHA1 = class extends HashMD {
    A = SHA1_IV[0] | 0;
    B = SHA1_IV[1] | 0;
    C = SHA1_IV[2] | 0;
    D = SHA1_IV[3] | 0;
    E = SHA1_IV[4] | 0;
    constructor() {
      super(64, 20, 8, false);
    }
    get() {
      const { A, B, C, D, E } = this;
      return [A, B, C, D, E];
    }
    set(A, B, C, D, E) {
      this.A = A | 0;
      this.B = B | 0;
      this.C = C | 0;
      this.D = D | 0;
      this.E = E | 0;
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4)
        SHA1_W[i] = view.getUint32(offset, false);
      for (let i = 16; i < 80; i++)
        SHA1_W[i] = rotl(SHA1_W[i - 3] ^ SHA1_W[i - 8] ^ SHA1_W[i - 14] ^ SHA1_W[i - 16], 1);
      let { A, B, C, D, E } = this;
      for (let i = 0; i < 80; i++) {
        let F, K2;
        if (i < 20) {
          F = Chi(B, C, D);
          K2 = 1518500249;
        } else if (i < 40) {
          F = B ^ C ^ D;
          K2 = 1859775393;
        } else if (i < 60) {
          F = Maj(B, C, D);
          K2 = 2400959708;
        } else {
          F = B ^ C ^ D;
          K2 = 3395469782;
        }
        const T = rotl(A, 5) + F + E + K2 + SHA1_W[i] | 0;
        E = D;
        D = C;
        C = rotl(B, 30);
        B = A;
        A = T;
      }
      A = A + this.A | 0;
      B = B + this.B | 0;
      C = C + this.C | 0;
      D = D + this.D | 0;
      E = E + this.E | 0;
      this.set(A, B, C, D, E);
    }
    roundClean() {
      clean(SHA1_W);
    }
    destroy() {
      this.set(0, 0, 0, 0, 0);
      clean(this.buffer);
    }
  };
  var sha1 = /* @__PURE__ */ createHasher(() => new _SHA1());
  var p32 = /* @__PURE__ */ Math.pow(2, 32);
  var K = /* @__PURE__ */ Array.from({ length: 64 }, (_, i) => Math.floor(p32 * Math.abs(Math.sin(i + 1))));
  var MD5_IV = /* @__PURE__ */ SHA1_IV.slice(0, 4);
  var MD5_W = /* @__PURE__ */ new Uint32Array(16);
  var _MD5 = class extends HashMD {
    A = MD5_IV[0] | 0;
    B = MD5_IV[1] | 0;
    C = MD5_IV[2] | 0;
    D = MD5_IV[3] | 0;
    constructor() {
      super(64, 16, 8, true);
    }
    get() {
      const { A, B, C, D } = this;
      return [A, B, C, D];
    }
    set(A, B, C, D) {
      this.A = A | 0;
      this.B = B | 0;
      this.C = C | 0;
      this.D = D | 0;
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4)
        MD5_W[i] = view.getUint32(offset, true);
      let { A, B, C, D } = this;
      for (let i = 0; i < 64; i++) {
        let F, g, s;
        if (i < 16) {
          F = Chi(B, C, D);
          g = i;
          s = [7, 12, 17, 22];
        } else if (i < 32) {
          F = Chi(D, B, C);
          g = (5 * i + 1) % 16;
          s = [5, 9, 14, 20];
        } else if (i < 48) {
          F = B ^ C ^ D;
          g = (3 * i + 5) % 16;
          s = [4, 11, 16, 23];
        } else {
          F = C ^ (B | ~D);
          g = 7 * i % 16;
          s = [6, 10, 15, 21];
        }
        F = F + A + K[i] + MD5_W[g];
        A = D;
        D = C;
        C = B;
        B = B + rotl(F, s[i % 4]);
      }
      A = A + this.A | 0;
      B = B + this.B | 0;
      C = C + this.C | 0;
      D = D + this.D | 0;
      this.set(A, B, C, D);
    }
    roundClean() {
      clean(MD5_W);
    }
    destroy() {
      this.set(0, 0, 0, 0);
      clean(this.buffer);
    }
  };
  var md5 = /* @__PURE__ */ createHasher(() => new _MD5());
  var Rho160 = /* @__PURE__ */ Uint8Array.from([
    7,
    4,
    13,
    1,
    10,
    6,
    15,
    3,
    12,
    0,
    9,
    5,
    2,
    14,
    11,
    8
  ]);
  var Id160 = /* @__PURE__ */ (() => Uint8Array.from(new Array(16).fill(0).map((_, i) => i)))();
  var Pi160 = /* @__PURE__ */ (() => Id160.map((i) => (9 * i + 5) % 16))();
  var idxLR = /* @__PURE__ */ (() => {
    const L = [Id160];
    const R = [Pi160];
    const res = [L, R];
    for (let i = 0; i < 4; i++)
      for (let j of res)
        j.push(j[i].map((k) => Rho160[k]));
    return res;
  })();
  var idxL = /* @__PURE__ */ (() => idxLR[0])();
  var idxR = /* @__PURE__ */ (() => idxLR[1])();
  var shifts160 = /* @__PURE__ */ [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
    [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
    [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
    [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
  ].map((i) => Uint8Array.from(i));
  var shiftsL160 = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts160[i][j]));
  var shiftsR160 = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts160[i][j]));
  var Kl160 = /* @__PURE__ */ Uint32Array.from([
    0,
    1518500249,
    1859775393,
    2400959708,
    2840853838
  ]);
  var Kr160 = /* @__PURE__ */ Uint32Array.from([
    1352829926,
    1548603684,
    1836072691,
    2053994217,
    0
  ]);
  function ripemd_f(group, x, y, z) {
    if (group === 0)
      return x ^ y ^ z;
    if (group === 1)
      return x & y | ~x & z;
    if (group === 2)
      return (x | ~y) ^ z;
    if (group === 3)
      return x & z | y & ~z;
    return x ^ (y | ~z);
  }
  var BUF_160 = /* @__PURE__ */ new Uint32Array(16);
  var _RIPEMD160 = class extends HashMD {
    h0 = 1732584193 | 0;
    h1 = 4023233417 | 0;
    h2 = 2562383102 | 0;
    h3 = 271733878 | 0;
    h4 = 3285377520 | 0;
    constructor() {
      super(64, 20, 8, true);
    }
    get() {
      const { h0, h1, h2, h3, h4 } = this;
      return [h0, h1, h2, h3, h4];
    }
    set(h0, h1, h2, h3, h4) {
      this.h0 = h0 | 0;
      this.h1 = h1 | 0;
      this.h2 = h2 | 0;
      this.h3 = h3 | 0;
      this.h4 = h4 | 0;
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4)
        BUF_160[i] = view.getUint32(offset, true);
      let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
      for (let group = 0; group < 5; group++) {
        const rGroup = 4 - group;
        const hbl = Kl160[group], hbr = Kr160[group];
        const rl = idxL[group], rr = idxR[group];
        const sl = shiftsL160[group], sr = shiftsR160[group];
        for (let i = 0; i < 16; i++) {
          const tl = rotl(al + ripemd_f(group, bl, cl, dl) + BUF_160[rl[i]] + hbl, sl[i]) + el | 0;
          al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl;
        }
        for (let i = 0; i < 16; i++) {
          const tr = rotl(ar + ripemd_f(rGroup, br, cr, dr) + BUF_160[rr[i]] + hbr, sr[i]) + er | 0;
          ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr;
        }
      }
      this.set(this.h1 + cl + dr | 0, this.h2 + dl + er | 0, this.h3 + el + ar | 0, this.h4 + al + br | 0, this.h0 + bl + cr | 0);
    }
    roundClean() {
      clean(BUF_160);
    }
    destroy() {
      this.destroyed = true;
      clean(this.buffer);
      this.set(0, 0, 0, 0, 0);
    }
  };
  var ripemd160 = /* @__PURE__ */ createHasher(() => new _RIPEMD160());

  // ../../sha3.js
  var _0n = BigInt(0);
  var _1n = BigInt(1);
  var _2n = BigInt(2);
  var _7n = BigInt(7);
  var _256n = BigInt(256);
  var _0x71n = BigInt(113);
  var SHA3_PI = [];
  var SHA3_ROTL = [];
  var _SHA3_IOTA = [];
  for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
    let t = _0n;
    for (let j = 0; j < 7; j++) {
      R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
      if (R & _2n)
        t ^= _1n << (_1n << BigInt(j)) - _1n;
    }
    _SHA3_IOTA.push(t);
  }
  var IOTAS = split(_SHA3_IOTA, true);
  var SHA3_IOTA_H = IOTAS[0];
  var SHA3_IOTA_L = IOTAS[1];
  var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
  var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
  function keccakP(s, rounds = 24) {
    const B = new Uint32Array(5 * 2);
    for (let round = 24 - rounds; round < 24; round++) {
      for (let x = 0; x < 10; x++)
        B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
      for (let x = 0; x < 10; x += 2) {
        const idx1 = (x + 8) % 10;
        const idx0 = (x + 2) % 10;
        const B0 = B[idx0];
        const B1 = B[idx0 + 1];
        const Th = rotlH(B0, B1, 1) ^ B[idx1];
        const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
        for (let y = 0; y < 50; y += 10) {
          s[x + y] ^= Th;
          s[x + y + 1] ^= Tl;
        }
      }
      let curH = s[2];
      let curL = s[3];
      for (let t = 0; t < 24; t++) {
        const shift = SHA3_ROTL[t];
        const Th = rotlH(curH, curL, shift);
        const Tl = rotlL(curH, curL, shift);
        const PI = SHA3_PI[t];
        curH = s[PI];
        curL = s[PI + 1];
        s[PI] = Th;
        s[PI + 1] = Tl;
      }
      for (let y = 0; y < 50; y += 10) {
        for (let x = 0; x < 10; x++)
          B[x] = s[y + x];
        for (let x = 0; x < 10; x++)
          s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
      }
      s[0] ^= SHA3_IOTA_H[round];
      s[1] ^= SHA3_IOTA_L[round];
    }
    clean(B);
  }
  var Keccak = class _Keccak {
    state;
    pos = 0;
    posOut = 0;
    finished = false;
    state32;
    destroyed = false;
    blockLen;
    suffix;
    outputLen;
    enableXOF = false;
    rounds;
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
      this.blockLen = blockLen;
      this.suffix = suffix;
      this.outputLen = outputLen;
      this.enableXOF = enableXOF;
      this.rounds = rounds;
      anumber(outputLen, "outputLen");
      if (!(0 < blockLen && blockLen < 200))
        throw new Error("only keccak-f1600 function is supported");
      this.state = new Uint8Array(200);
      this.state32 = u32(this.state);
    }
    clone() {
      return this._cloneInto();
    }
    keccak() {
      swap32IfBE(this.state32);
      keccakP(this.state32, this.rounds);
      swap32IfBE(this.state32);
      this.posOut = 0;
      this.pos = 0;
    }
    update(data) {
      aexists(this);
      abytes(data);
      const { blockLen, state } = this;
      const len = data.length;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        for (let i = 0; i < take; i++)
          state[this.pos++] ^= data[pos++];
        if (this.pos === blockLen)
          this.keccak();
      }
      return this;
    }
    finish() {
      if (this.finished)
        return;
      this.finished = true;
      const { state, suffix, pos, blockLen } = this;
      state[pos] ^= suffix;
      if ((suffix & 128) !== 0 && pos === blockLen - 1)
        this.keccak();
      state[blockLen - 1] ^= 128;
      this.keccak();
    }
    writeInto(out) {
      aexists(this, false);
      abytes(out);
      this.finish();
      const bufferOut = this.state;
      const { blockLen } = this;
      for (let pos = 0, len = out.length; pos < len; ) {
        if (this.posOut >= blockLen)
          this.keccak();
        const take = Math.min(blockLen - this.posOut, len - pos);
        out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
        this.posOut += take;
        pos += take;
      }
      return out;
    }
    xofInto(out) {
      if (!this.enableXOF)
        throw new Error("XOF is not possible for this instance");
      return this.writeInto(out);
    }
    xof(bytes) {
      anumber(bytes);
      return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
      aoutput(out, this);
      if (this.finished)
        throw new Error("digest() was already called");
      this.writeInto(out);
      this.destroy();
      return out;
    }
    digest() {
      return this.digestInto(new Uint8Array(this.outputLen));
    }
    destroy() {
      this.destroyed = true;
      clean(this.state);
    }
    _cloneInto(to) {
      const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
      to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
      to.state32.set(this.state32);
      to.pos = this.pos;
      to.posOut = this.posOut;
      to.finished = this.finished;
      to.rounds = rounds;
      to.suffix = suffix;
      to.outputLen = outputLen;
      to.enableXOF = enableXOF;
      to.destroyed = this.destroyed;
      return to;
    }
  };
  var genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
  var sha3_224 = /* @__PURE__ */ genKeccak(
    6,
    144,
    28,
    /* @__PURE__ */ oidNist(7)
  );
  var sha3_256 = /* @__PURE__ */ genKeccak(
    6,
    136,
    32,
    /* @__PURE__ */ oidNist(8)
  );
  var sha3_384 = /* @__PURE__ */ genKeccak(
    6,
    104,
    48,
    /* @__PURE__ */ oidNist(9)
  );
  var sha3_512 = /* @__PURE__ */ genKeccak(
    6,
    72,
    64,
    /* @__PURE__ */ oidNist(10)
  );
  var keccak_224 = /* @__PURE__ */ genKeccak(1, 144, 28);
  var keccak_256 = /* @__PURE__ */ genKeccak(1, 136, 32);
  var keccak_384 = /* @__PURE__ */ genKeccak(1, 104, 48);
  var keccak_512 = /* @__PURE__ */ genKeccak(1, 72, 64);
  var genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === void 0 ? outputLen : opts.dkLen, true), info);
  var shake128 = /* @__PURE__ */ genShake(31, 168, 16, /* @__PURE__ */ oidNist(11));
  var shake256 = /* @__PURE__ */ genShake(31, 136, 32, /* @__PURE__ */ oidNist(12));

  // ../../sha3-addons.js
  var _8n = /* @__PURE__ */ BigInt(8);
  var _ffn = /* @__PURE__ */ BigInt(255);
  function leftEncode(n) {
    n = BigInt(n);
    const res = [Number(n & _ffn)];
    n >>= _8n;
    for (; n > 0; n >>= _8n)
      res.unshift(Number(n & _ffn));
    res.unshift(res.length);
    return new Uint8Array(res);
  }
  function rightEncode(n) {
    n = BigInt(n);
    const res = [Number(n & _ffn)];
    n >>= _8n;
    for (; n > 0; n >>= _8n)
      res.unshift(Number(n & _ffn));
    res.push(res.length);
    return new Uint8Array(res);
  }
  function chooseLen(opts, outputLen) {
    return opts.dkLen === void 0 ? outputLen : opts.dkLen;
  }
  var abytesOrZero2 = (buf, title = "") => {
    if (buf === void 0)
      return EMPTY_BUFFER2;
    abytes(buf, void 0, title);
    return buf;
  };
  var getPadding = (len, block2) => new Uint8Array((block2 - len % block2) % block2);
  function cshakePers(hash, opts = {}) {
    if (!opts || opts.personalization === void 0 && opts.NISTfn === void 0)
      return hash;
    const blockLenBytes = leftEncode(hash.blockLen);
    const fn = opts.NISTfn === void 0 ? EMPTY_BUFFER2 : kdfInputToBytes(opts.NISTfn);
    const fnLen = leftEncode(_8n * BigInt(fn.length));
    const pers = abytesOrZero2(opts.personalization, "personalization");
    const persLen = leftEncode(_8n * BigInt(pers.length));
    if (!fn.length && !pers.length)
      return hash;
    hash.suffix = 4;
    hash.update(blockLenBytes).update(fnLen).update(fn).update(persLen).update(pers);
    let totalLen = blockLenBytes.length + fnLen.length + fn.length + persLen.length + pers.length;
    hash.update(getPadding(totalLen, hash.blockLen));
    return hash;
  }
  var gencShake = (suffix, blockLen, outputLen) => createHasher((opts = {}) => cshakePers(new Keccak(blockLen, suffix, chooseLen(opts, outputLen), true), opts));
  var cshake128 = /* @__PURE__ */ gencShake(31, 168, 16);
  var cshake256 = /* @__PURE__ */ gencShake(31, 136, 32);
  var _KMAC = class extends Keccak {
    constructor(blockLen, outputLen, enableXOF, key, opts = {}) {
      super(blockLen, 31, outputLen, enableXOF);
      cshakePers(this, { NISTfn: "KMAC", personalization: opts.personalization });
      abytes(key, void 0, "key");
      const blockLenBytes = leftEncode(this.blockLen);
      const keyLen = leftEncode(_8n * BigInt(key.length));
      this.update(blockLenBytes).update(keyLen).update(key);
      const totalLen = blockLenBytes.length + keyLen.length + key.length;
      this.update(getPadding(totalLen, this.blockLen));
    }
    finish() {
      if (!this.finished)
        this.update(rightEncode(this.enableXOF ? 0 : _8n * BigInt(this.outputLen)));
      super.finish();
    }
    _cloneInto(to) {
      if (!to) {
        to = Object.create(Object.getPrototypeOf(this), {});
        to.state = this.state.slice();
        to.blockLen = this.blockLen;
        to.state32 = u32(to.state);
      }
      return super._cloneInto(to);
    }
    clone() {
      return this._cloneInto();
    }
  };
  function genKmac(blockLen, outputLen, xof = false) {
    const kmac = (key, message, opts) => kmac.create(key, opts).update(message).digest();
    kmac.create = (key, opts = {}) => new _KMAC(blockLen, chooseLen(opts, outputLen), xof, key, opts);
    return kmac;
  }
  var kmac128 = /* @__PURE__ */ genKmac(168, 16);
  var kmac256 = /* @__PURE__ */ genKmac(136, 32);
  var genTurbo = (blockLen, outputLen) => createHasher((opts = {}) => {
    const D = opts.D === void 0 ? 31 : opts.D;
    if (!Number.isSafeInteger(D) || D < 1 || D > 127)
      throw new Error('"D" (domain separation byte) must be 0x01..0x7f, got: ' + D);
    return new Keccak(blockLen, D, opts.dkLen === void 0 ? outputLen : opts.dkLen, true, 12);
  });
  var turboshake128 = /* @__PURE__ */ genTurbo(168, 32);
  var turboshake256 = /* @__PURE__ */ genTurbo(136, 64);
  function rightEncodeK12(n) {
    n = BigInt(n);
    const res = [];
    for (; n > 0; n >>= _8n)
      res.unshift(Number(n & _ffn));
    res.push(res.length);
    return Uint8Array.from(res);
  }
  var EMPTY_BUFFER2 = /* @__PURE__ */ Uint8Array.of();
  var _KangarooTwelve = class __KangarooTwelve extends Keccak {
    chunkLen = 8192;
    leafHash;
    leafLen;
    personalization;
    chunkPos = 0;
    // Position of current block in chunk
    chunksDone = 0;
    // How many chunks we already have
    constructor(blockLen, leafLen, outputLen, rounds, opts) {
      super(blockLen, 7, outputLen, true, rounds);
      this.leafLen = leafLen;
      this.personalization = abytesOrZero2(opts.personalization, "personalization");
    }
    update(data) {
      abytes(data);
      const { chunkLen, blockLen, leafLen, rounds } = this;
      for (let pos = 0, len = data.length; pos < len; ) {
        if (this.chunkPos == chunkLen) {
          if (this.leafHash)
            super.update(this.leafHash.digest());
          else {
            this.suffix = 6;
            super.update(Uint8Array.from([3, 0, 0, 0, 0, 0, 0, 0]));
          }
          this.leafHash = new Keccak(blockLen, 11, leafLen, false, rounds);
          this.chunksDone++;
          this.chunkPos = 0;
        }
        const take = Math.min(chunkLen - this.chunkPos, len - pos);
        const chunk = data.subarray(pos, pos + take);
        if (this.leafHash)
          this.leafHash.update(chunk);
        else
          super.update(chunk);
        this.chunkPos += take;
        pos += take;
      }
      return this;
    }
    finish() {
      if (this.finished)
        return;
      const { personalization } = this;
      this.update(personalization).update(rightEncodeK12(personalization.length));
      if (this.leafHash) {
        super.update(this.leafHash.digest());
        super.update(rightEncodeK12(this.chunksDone));
        super.update(Uint8Array.from([255, 255]));
      }
      super.finish.call(this);
    }
    destroy() {
      super.destroy.call(this);
      if (this.leafHash)
        this.leafHash.destroy();
      this.personalization = EMPTY_BUFFER2;
    }
    _cloneInto(to) {
      const { blockLen, leafLen, leafHash, outputLen, rounds } = this;
      to ||= new __KangarooTwelve(blockLen, leafLen, outputLen, rounds, {});
      super._cloneInto(to);
      if (leafHash)
        to.leafHash = leafHash._cloneInto(to.leafHash);
      to.personalization.set(this.personalization);
      to.leafLen = this.leafLen;
      to.chunkPos = this.chunkPos;
      to.chunksDone = this.chunksDone;
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  var kt128 = /* @__PURE__ */ createHasher((opts = {}) => new _KangarooTwelve(168, 32, chooseLen(opts, 32), 12, opts));
  var kt256 = /* @__PURE__ */ createHasher((opts = {}) => new _KangarooTwelve(136, 64, chooseLen(opts, 64), 12, opts));
  var _KeccakPRG = class __KeccakPRG extends Keccak {
    rate;
    constructor(capacity) {
      anumber(capacity);
      const rate = 1600 - capacity;
      const rho = rate - 2;
      if (capacity < 0 || capacity > 1600 - 10 || rho % 8)
        throw new Error("invalid capacity");
      super(rho / 8, 0, 0, true);
      this.rate = rate;
      this.posOut = Math.floor((rate + 7) / 8);
    }
    keccak() {
      this.state[this.pos] ^= 1;
      this.state[this.blockLen] ^= 2;
      super.keccak();
      this.pos = 0;
      this.posOut = 0;
    }
    update(data) {
      super.update(data);
      this.posOut = this.blockLen;
      return this;
    }
    finish() {
    }
    digestInto(_out) {
      throw new Error("digest is not allowed, use .fetch instead");
    }
    addEntropy(seed) {
      this.update(seed);
    }
    randomBytes(length) {
      return this.xof(length);
    }
    clean() {
      if (this.rate < 1600 / 2 + 1)
        throw new Error("rate is too low to use .forget()");
      this.keccak();
      for (let i = 0; i < this.blockLen; i++)
        this.state[i] = 0;
      this.pos = this.blockLen;
      this.keccak();
      this.posOut = this.blockLen;
    }
    _cloneInto(to) {
      const { rate } = this;
      to ||= new __KeccakPRG(1600 - rate);
      super._cloneInto(to);
      to.rate = rate;
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  var keccakprg = (capacity = 254) => new _KeccakPRG(capacity);

  // ../../webcrypto.js
  var webcrypto_exports = {};
  __export(webcrypto_exports, {
    hkdf: () => hkdf2,
    hmac: () => hmac2,
    pbkdf2: () => pbkdf23,
    sha256: () => sha2562,
    sha384: () => sha3842,
    sha512: () => sha5122
  });
  function _subtle() {
    const cr = typeof globalThis === "object" ? globalThis.crypto : null;
    const sb = cr?.subtle;
    if (typeof sb === "object" && sb != null)
      return sb;
    throw new Error("crypto.subtle must be defined");
  }
  function createWebHash(name, blockLen, outputLen) {
    const hashC = async (msg) => {
      abytes(msg);
      const crypto = _subtle();
      return new Uint8Array(await crypto.digest(name, msg));
    };
    hashC.webCryptoName = name;
    hashC.outputLen = outputLen;
    hashC.blockLen = blockLen;
    hashC.create = () => {
      throw new Error("not implemented");
    };
    return hashC;
  }
  function ahashWeb(hash) {
    ahash(hash);
    if (typeof hash.webCryptoName !== "string")
      throw new Error("non-web hash");
  }
  var sha2562 = /* @__PURE__ */ createWebHash("SHA-256", 64, 32);
  var sha3842 = /* @__PURE__ */ createWebHash("SHA-384", 128, 48);
  var sha5122 = /* @__PURE__ */ createWebHash("SHA-512", 128, 64);
  var hmac2 = /* @__PURE__ */ (() => {
    const hmac_ = async (hash, key, message) => {
      const crypto = _subtle();
      abytes(key, void 0, "key");
      abytes(message, void 0, "message");
      ahashWeb(hash);
      const wkey = await crypto.importKey("raw", key, { name: "HMAC", hash: hash.webCryptoName }, false, ["sign"]);
      return new Uint8Array(await crypto.sign("HMAC", wkey, message));
    };
    hmac_.create = (_hash, _key) => {
      throw new Error("not implemented");
    };
    return hmac_;
  })();
  async function hkdf2(hash, ikm, salt, info, length) {
    const crypto = _subtle();
    ahashWeb(hash);
    abytes(ikm, void 0, "ikm");
    anumber(length, "length");
    if (salt !== void 0)
      abytes(salt, void 0, "salt");
    if (info !== void 0)
      abytes(info, void 0, "info");
    const wkey = await crypto.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    const opts = {
      name: "HKDF",
      hash: hash.webCryptoName,
      salt: salt === void 0 ? new Uint8Array(0) : salt,
      info: info === void 0 ? new Uint8Array(0) : info
    };
    return new Uint8Array(await crypto.deriveBits(opts, wkey, 8 * length));
  }
  async function pbkdf23(hash, password, salt, opts) {
    const crypto = _subtle();
    ahashWeb(hash);
    const _opts = checkOpts({ dkLen: 32 }, opts);
    const { c, dkLen } = _opts;
    anumber(c, "c");
    anumber(dkLen, "dkLen");
    const _password = kdfInputToBytes(password, "password");
    const _salt = kdfInputToBytes(salt, "salt");
    const key = await crypto.importKey("raw", _password, "PBKDF2", false, [
      "deriveBits"
    ]);
    const deriveOpts = { name: "PBKDF2", salt: _salt, iterations: c, hash: hash.webCryptoName };
    return new Uint8Array(await crypto.deriveBits(deriveOpts, key, 8 * dkLen));
  }

  // input.js
  var utils = { bytesToHex, hexToBytes, concatBytes, utf8ToBytes, randomBytes };
  return __toCommonJS(input_exports);
})();
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
