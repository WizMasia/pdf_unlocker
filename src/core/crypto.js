/**
 * @file src/core/crypto.js
 * @description Pure JavaScript implementations of MD5, SHA-256, SHA-384, SHA-512, RC4,
 *              AES-128-CBC, and AES-256-CBC with zero external dependencies.
 *              순수 자바스크립트로 구현된 외부 의존성 없는 MD5, SHA-256, SHA-384, SHA-512, RC4,
 *              AES-128/256-CBC 암복호화 엔진.
 */

// ============================================================================
// 1. MD5 Implementation (RFC 1321)
// ============================================================================

function md5Cycle(x, k) {
  let a = x[0], b = x[1], c = x[2], d = x[3];

  a = ff(a, b, c, d, k[0], 7, -680876936);
  d = ff(d, a, b, c, k[1], 12, -389564586);
  c = ff(c, d, a, b, k[2], 17, 606105819);
  b = ff(b, c, d, a, k[3], 22, -1044525330);
  a = ff(a, b, c, d, k[4], 7, -176418897);
  d = ff(d, a, b, c, k[5], 12, 1200080426);
  c = ff(c, d, a, b, k[6], 17, -1473231341);
  b = ff(b, c, d, a, k[7], 22, -45705983);
  a = ff(a, b, c, d, k[8], 7, 1770035416);
  d = ff(d, a, b, c, k[9], 12, -1958414417);
  c = ff(c, d, a, b, k[10], 17, -42063);
  b = ff(b, c, d, a, k[11], 22, -1990404162);
  a = ff(a, b, c, d, k[12], 7, 1804603682);
  d = ff(d, a, b, c, k[13], 12, -40341101);
  c = ff(c, d, a, b, k[14], 17, -1502002290);
  b = ff(b, c, d, a, k[15], 22, 1236535329);

  a = gg(a, b, c, d, k[1], 5, -165796510);
  d = gg(d, a, b, c, k[6], 9, -1069501632);
  c = gg(c, d, a, b, k[11], 14, 643717713);
  b = gg(b, c, d, a, k[0], 20, -373897302);
  a = gg(a, b, c, d, k[5], 5, -701558691);
  d = gg(d, a, b, c, k[10], 9, 38016083);
  c = gg(c, d, a, b, k[15], 14, -660478335);
  b = gg(b, c, d, a, k[4], 20, -405537848);
  a = gg(a, b, c, d, k[9], 5, 568446438);
  d = gg(d, a, b, c, k[14], 9, -1019803690);
  c = gg(c, d, a, b, k[3], 14, -187363961);
  b = gg(b, c, d, a, k[8], 20, 1163531501);
  a = gg(a, b, c, d, k[13], 5, -1444681467);
  d = gg(d, a, b, c, k[2], 9, -51403784);
  c = gg(c, d, a, b, k[7], 14, 1735328473);
  b = gg(b, c, d, a, k[12], 20, -1926607734);

  a = hh(a, b, c, d, k[5], 4, -378558);
  d = hh(d, a, b, c, k[8], 11, -2022574463);
  c = hh(c, d, a, b, k[11], 16, 1839030562);
  b = hh(b, c, d, a, k[14], 23, -35309556);
  a = hh(a, b, c, d, k[1], 4, -1530992060);
  d = hh(d, a, b, c, k[4], 11, 1272893353);
  c = hh(c, d, a, b, k[7], 16, -155497632);
  b = hh(b, c, d, a, k[10], 23, -1094730640);
  a = hh(a, b, c, d, k[13], 4, 681279174);
  d = hh(d, a, b, c, k[0], 11, -358537222);
  c = hh(c, d, a, b, k[3], 16, -722521979);
  b = hh(b, c, d, a, k[6], 23, 76029189);
  a = hh(a, b, c, d, k[9], 4, -640364487);
  d = hh(d, a, b, c, k[12], 11, -421815835);
  c = hh(c, d, a, b, k[15], 16, 530742520);
  b = hh(b, c, d, a, k[2], 23, -995338651);

  a = ii(a, b, c, d, k[0], 6, -198630844);
  d = ii(d, a, b, c, k[7], 10, 1126891415);
  c = ii(c, d, a, b, k[14], 15, -1416354905);
  b = ii(b, c, d, a, k[5], 21, -57434055);
  a = ii(a, b, c, d, k[12], 6, 1700485571);
  d = ii(d, a, b, c, k[3], 10, -1894986606);
  c = ii(c, d, a, b, k[10], 15, -1051523);
  b = ii(b, c, d, a, k[1], 21, -2054922799);
  a = ii(a, b, c, d, k[8], 6, 1873313359);
  d = ii(d, a, b, c, k[15], 10, -30611744);
  c = ii(c, d, a, b, k[6], 15, -1560198380);
  b = ii(b, c, d, a, k[13], 21, 1309151649);
  a = ii(a, b, c, d, k[4], 6, -145523070);
  d = ii(d, a, b, c, k[11], 10, -1120210379);
  c = ii(c, d, a, b, k[2], 15, 718787259);
  b = ii(b, c, d, a, k[9], 21, -343485551);

  x[0] = (a + x[0]) | 0;
  x[1] = (b + x[1]) | 0;
  x[2] = (c + x[2]) | 0;
  x[3] = (d + x[3]) | 0;
}

function cmn(q, a, b, x, s, t) {
  a = (a + q + x + t) | 0;
  return (((a << s) | (a >>> (32 - s))) + b) | 0;
}
function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }

export function md5(data) {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  } else if (!(data instanceof Uint8Array)) {
    data = new Uint8Array(data);
  }

  const n = data.length;
  const state = [1732584193, -271733879, -1732584194, 271733878];
  let i;

  for (i = 64; i <= n; i += 64) {
    const chunk = new Int32Array(16);
    for (let j = 0; j < 16; j++) {
      const idx = (i - 64) + (j * 4);
      chunk[j] = data[idx] | (data[idx + 1] << 8) | (data[idx + 2] << 16) | (data[idx + 3] << 24);
    }
    md5Cycle(state, chunk);
  }

  const tail = new Uint8Array(64);
  const remaining = n - (i - 64);
  for (let j = 0; j < remaining; j++) {
    tail[j] = data[(i - 64) + j];
  }
  tail[remaining] = 0x80;

  if (remaining > 55) {
    const chunk1 = new Int32Array(16);
    for (let j = 0; j < 16; j++) {
      chunk1[j] = tail[j * 4] | (tail[j * 4 + 1] << 8) | (tail[j * 4 + 2] << 16) | (tail[j * 4 + 3] << 24);
    }
    md5Cycle(state, chunk1);
    tail.fill(0);
  }

  const bitLen = n * 8;
  tail[56] = bitLen & 0xff;
  tail[57] = (bitLen >>> 8) & 0xff;
  tail[58] = (bitLen >>> 16) & 0xff;
  tail[59] = (bitLen >>> 24) & 0xff;

  const chunk2 = new Int32Array(16);
  for (let j = 0; j < 16; j++) {
    chunk2[j] = tail[j * 4] | (tail[j * 4 + 1] << 8) | (tail[j * 4 + 2] << 16) | (tail[j * 4 + 3] << 24);
  }
  md5Cycle(state, chunk2);

  const out = new Uint8Array(16);
  for (let j = 0; j < 4; j++) {
    out[j * 4] = state[j] & 0xff;
    out[j * 4 + 1] = (state[j] >>> 8) & 0xff;
    out[j * 4 + 2] = (state[j] >>> 16) & 0xff;
    out[j * 4 + 3] = (state[j] >>> 24) & 0xff;
  }
  return out;
}

// ============================================================================
// 2. SHA-256 Implementation (FIPS 180-4)
// ============================================================================

const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

export function sha256(data) {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  } else if (!(data instanceof Uint8Array)) {
    data = new Uint8Array(data);
  }

  let H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
  let H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;

  const byteLen = data.length;
  const bitLen = byteLen * 8;

  const padLen = (56 - ((byteLen + 1) % 64) + 64) % 64;
  const totalLen = byteLen + 1 + padLen + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(data, 0);
  padded[byteLen] = 0x80;

  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  view.setUint32(totalLen - 4, bitLen >>> 0, false);
  view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);

  const W = new Uint32Array(64);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    let a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ ((~e) & g);
      const temp1 = (h + S1 + ch + K256[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    H0 = (H0 + a) >>> 0;
    H1 = (H1 + b) >>> 0;
    H2 = (H2 + c) >>> 0;
    H3 = (H3 + d) >>> 0;
    H4 = (H4 + e) >>> 0;
    H5 = (H5 + f) >>> 0;
    H6 = (H6 + g) >>> 0;
    H7 = (H7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer, out.byteOffset, out.byteLength);
  outView.setUint32(0, H0, false);
  outView.setUint32(4, H1, false);
  outView.setUint32(8, H2, false);
  outView.setUint32(12, H3, false);
  outView.setUint32(16, H4, false);
  outView.setUint32(20, H5, false);
  outView.setUint32(24, H6, false);
  outView.setUint32(28, H7, false);
  return out;
}

// ============================================================================
// 3. SHA-384 & SHA-512 Implementation (Word64-based for 100% standard compliance)
// ============================================================================

class Word64 {
  constructor(highInteger, lowInteger) {
    this.high = highInteger | 0;
    this.low = lowInteger | 0;
  }

  and(word) {
    this.high &= word.high;
    this.low &= word.low;
  }

  xor(word) {
    this.high ^= word.high;
    this.low ^= word.low;
  }

  shiftRight(places) {
    if (places >= 32) {
      this.low = (this.high >>> (places - 32)) | 0;
      this.high = 0;
    } else {
      this.low = (this.low >>> places) | (this.high << (32 - places));
      this.high = (this.high >>> places) | 0;
    }
  }

  rotateRight(places) {
    let low, high;
    if (places & 32) {
      high = this.low;
      low = this.high;
    } else {
      low = this.low;
      high = this.high;
    }
    places &= 31;
    this.low = (low >>> places) | (high << (32 - places));
    this.high = (high >>> places) | (low << (32 - places));
  }

  not() {
    this.high = ~this.high;
    this.low = ~this.low;
  }

  add(word) {
    const lowAdd = (this.low >>> 0) + (word.low >>> 0);
    let highAdd = (this.high >>> 0) + (word.high >>> 0);
    if (lowAdd > 0xffffffff) {
      highAdd += 1;
    }
    this.low = lowAdd | 0;
    this.high = highAdd | 0;
  }

  copyTo(bytes, offset) {
    bytes[offset] = (this.high >>> 24) & 0xff;
    bytes[offset + 1] = (this.high >> 16) & 0xff;
    bytes[offset + 2] = (this.high >> 8) & 0xff;
    bytes[offset + 3] = this.high & 0xff;
    bytes[offset + 4] = (this.low >>> 24) & 0xff;
    bytes[offset + 5] = (this.low >> 16) & 0xff;
    bytes[offset + 6] = (this.low >> 8) & 0xff;
    bytes[offset + 7] = this.low & 0xff;
  }

  assign(word) {
    this.high = word.high;
    this.low = word.low;
  }
}

const K512_WORDS = [
  new Word64(0x428a2f98, 0xd728ae22), new Word64(0x71374491, 0x23ef65cd),
  new Word64(0xb5c0fbcf, 0xec4d3b2f), new Word64(0xe9b5dba5, 0x8189dbbc),
  new Word64(0x3956c25b, 0xf348b538), new Word64(0x59f111f1, 0xb605d019),
  new Word64(0x923f82a4, 0xaf194f9b), new Word64(0xab1c5ed5, 0xda6d8118),
  new Word64(0xd807aa98, 0xa3030242), new Word64(0x12835b01, 0x45706fbe),
  new Word64(0x243185be, 0x4ee4b28c), new Word64(0x550c7dc3, 0xd5ffb4e2),
  new Word64(0x72be5d74, 0xf27b896f), new Word64(0x80deb1fe, 0x3b1696b1),
  new Word64(0x9bdc06a7, 0x25c71235), new Word64(0xc19bf174, 0xcf692694),
  new Word64(0xe49b69c1, 0x9ef14ad2), new Word64(0xefbe4786, 0x384f25e3),
  new Word64(0x0fc19dc6, 0x8b8cd5b5), new Word64(0x240ca1cc, 0x77ac9c65),
  new Word64(0x2de92c6f, 0x592b0275), new Word64(0x4a7484aa, 0x6ea6e483),
  new Word64(0x5cb0a9dc, 0xbd41fbd4), new Word64(0x76f988da, 0x831153b5),
  new Word64(0x983e5152, 0xee66dfab), new Word64(0xa831c66d, 0x2db43210),
  new Word64(0xb00327c8, 0x98fb213f), new Word64(0xbf597fc7, 0xbeef0ee4),
  new Word64(0xc6e00bf3, 0x3da88fc2), new Word64(0xd5a79147, 0x930aa725),
  new Word64(0x06ca6351, 0xe003826f), new Word64(0x14292967, 0x0a0e6e70),
  new Word64(0x27b70a85, 0x46d22ffc), new Word64(0x2e1b2138, 0x5c26c926),
  new Word64(0x4d2c6dfc, 0x5ac42aed), new Word64(0x53380d13, 0x9d95b3df),
  new Word64(0x650a7354, 0x8baf63de), new Word64(0x766a0abb, 0x3c77b2a8),
  new Word64(0x81c2c92e, 0x47edaee6), new Word64(0x92722c85, 0x1482353b),
  new Word64(0xa2bfe8a1, 0x4cf10364), new Word64(0xa81a664b, 0xbc423001),
  new Word64(0xc24b8b70, 0xd0f89791), new Word64(0xc76c51a3, 0x0654be30),
  new Word64(0xd192e819, 0xd6ef5218), new Word64(0xd6990624, 0x5565a910),
  new Word64(0xf40e3585, 0x5771202a), new Word64(0x106aa070, 0x32bbd1b8),
  new Word64(0x19a4c116, 0xb8d2d0c8), new Word64(0x1e376c08, 0x5141ab53),
  new Word64(0x2748774c, 0xdf8eeb99), new Word64(0x34b0bcb5, 0xe19b48a8),
  new Word64(0x391c0cb3, 0xc5c95a63), new Word64(0x4ed8aa4a, 0xe3418acb),
  new Word64(0x5b9cca4f, 0x7763e373), new Word64(0x682e6ff3, 0xd6b2b8a3),
  new Word64(0x748f82ee, 0x5defb2fc), new Word64(0x78a5636f, 0x43172f60),
  new Word64(0x84c87814, 0xa1f0ab72), new Word64(0x8cc70208, 0x1a6439ec),
  new Word64(0x90befffa, 0x23631e28), new Word64(0xa4506ceb, 0xde82bde9),
  new Word64(0xbef9a3f7, 0xb2c67915), new Word64(0xc67178f2, 0xe372532b),
  new Word64(0xca273ece, 0xea26619c), new Word64(0xd186b8c7, 0x21c0c207),
  new Word64(0xeada7dd6, 0xcde0eb1e), new Word64(0xf57d4f7f, 0xee6ed178),
  new Word64(0x06f067aa, 0x72176fba), new Word64(0x0a637dc5, 0xa2c898a6),
  new Word64(0x113f9804, 0xbef90dae), new Word64(0x1b710b35, 0x131c471b),
  new Word64(0x28db77f5, 0x23047d84), new Word64(0x32caab7b, 0x40c72493),
  new Word64(0x3c9ebe0a, 0x15c9bebc), new Word64(0x431d67c4, 0x9c100d4c),
  new Word64(0x4cc5d4be, 0xcb3e42b6), new Word64(0x597f299c, 0xfc657e2a),
  new Word64(0x5fcb6fab, 0x3ad6faec), new Word64(0x6c44198c, 0x4a475817)
];

function ch512(result, x, y, z, tmp) {
  result.assign(x);
  result.and(y);
  tmp.assign(x);
  tmp.not();
  tmp.and(z);
  result.xor(tmp);
}

function maj512(result, x, y, z, tmp) {
  result.assign(x);
  result.and(y);
  tmp.assign(x);
  tmp.and(z);
  result.xor(tmp);
  tmp.assign(y);
  tmp.and(z);
  result.xor(tmp);
}

function sigma512(result, x, tmp) {
  result.assign(x);
  result.rotateRight(28);
  tmp.assign(x);
  tmp.rotateRight(34);
  result.xor(tmp);
  tmp.assign(x);
  tmp.rotateRight(39);
  result.xor(tmp);
}

function sigmaPrime512(result, x, tmp) {
  result.assign(x);
  result.rotateRight(14);
  tmp.assign(x);
  tmp.rotateRight(18);
  result.xor(tmp);
  tmp.assign(x);
  tmp.rotateRight(41);
  result.xor(tmp);
}

function littleSigma512(result, x, tmp) {
  result.assign(x);
  result.rotateRight(1);
  tmp.assign(x);
  tmp.rotateRight(8);
  result.xor(tmp);
  tmp.assign(x);
  tmp.shiftRight(7);
  result.xor(tmp);
}

function littleSigmaPrime512(result, x, tmp) {
  result.assign(x);
  result.rotateRight(19);
  tmp.assign(x);
  tmp.rotateRight(61);
  result.xor(tmp);
  tmp.assign(x);
  tmp.shiftRight(6);
  result.xor(tmp);
}

function computeSha512Internal(data, mode384 = false) {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  } else if (!(data instanceof Uint8Array)) {
    data = new Uint8Array(data);
  }

  let h0, h1, h2, h3, h4, h5, h6, h7;
  if (!mode384) {
    h0 = new Word64(0x6a09e667, 0xf3bcc908);
    h1 = new Word64(0xbb67ae85, 0x84caa73b);
    h2 = new Word64(0x3c6ef372, 0xfe94f82b);
    h3 = new Word64(0xa54ff53a, 0x5f1d36f1);
    h4 = new Word64(0x510e527f, 0xade682d1);
    h5 = new Word64(0x9b05688c, 0x2b3e6c1f);
    h6 = new Word64(0x1f83d9ab, 0xfb41bd6b);
    h7 = new Word64(0x5be0cd19, 0x137e2179);
  } else {
    h0 = new Word64(0xcbbb9d5d, 0xc1059ed8);
    h1 = new Word64(0x629a292a, 0x367cd507);
    h2 = new Word64(0x9159015a, 0x3070dd17);
    h3 = new Word64(0x152fecd8, 0xf70e5939);
    h4 = new Word64(0x67332667, 0xffc00b31);
    h5 = new Word64(0x8eb44a87, 0x68581511);
    h6 = new Word64(0xdb0c2e0d, 0x64f98fa7);
    h7 = new Word64(0x47b5481d, 0xbefa4fa4);
  }

  const length = data.length;
  const paddedLength = Math.ceil((length + 17) / 128) * 128;
  const padded = new Uint8Array(paddedLength);
  let i, j;
  for (i = 0; i < length; ++i) {
    padded[i] = data[i];
  }
  padded[i++] = 0x80;
  const n = paddedLength - 16;
  if (i < n) {
    i = n;
  }
  i += 11;
  padded[i++] = (length >>> 29) & 0xff;
  padded[i++] = (length >> 21) & 0xff;
  padded[i++] = (length >> 13) & 0xff;
  padded[i++] = (length >> 5) & 0xff;
  padded[i++] = (length << 3) & 0xff;

  const w = new Array(80);
  for (i = 0; i < 80; i++) {
    w[i] = new Word64(0, 0);
  }

  let a = new Word64(0, 0), b = new Word64(0, 0), c = new Word64(0, 0);
  let d = new Word64(0, 0), e = new Word64(0, 0), f = new Word64(0, 0);
  let g = new Word64(0, 0), h = new Word64(0, 0);
  const t1 = new Word64(0, 0), t2 = new Word64(0, 0);
  const tmp1 = new Word64(0, 0), tmp2 = new Word64(0, 0);
  let tmp3;

  for (i = 0; i < paddedLength;) {
    for (j = 0; j < 16; ++j) {
      w[j].high = (padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3];
      w[j].low = (padded[i + 4] << 24) | (padded[i + 5] << 16) | (padded[i + 6] << 8) | padded[i + 7];
      i += 8;
    }
    for (j = 16; j < 80; ++j) {
      tmp3 = w[j];
      littleSigmaPrime512(tmp3, w[j - 2], tmp2);
      tmp3.add(w[j - 7]);
      littleSigma512(tmp1, w[j - 15], tmp2);
      tmp3.add(tmp1);
      tmp3.add(w[j - 16]);
    }

    a.assign(h0); b.assign(h1); c.assign(h2); d.assign(h3);
    e.assign(h4); f.assign(h5); g.assign(h6); h.assign(h7);

    for (j = 0; j < 80; ++j) {
      t1.assign(h);
      sigmaPrime512(tmp1, e, tmp2);
      t1.add(tmp1);
      ch512(tmp1, e, f, g, tmp2);
      t1.add(tmp1);
      t1.add(K512_WORDS[j]);
      t1.add(w[j]);

      sigma512(t2, a, tmp2);
      maj512(tmp1, a, b, c, tmp2);
      t2.add(tmp1);

      tmp3 = h;
      h = g;
      g = f;
      f = e;
      d.add(t1);
      e = d;
      d = c;
      c = b;
      b = a;
      tmp3.assign(t1);
      tmp3.add(t2);
      a = tmp3;
    }
    h0.add(a); h1.add(b); h2.add(c); h3.add(d);
    h4.add(e); h5.add(f); h6.add(g); h7.add(h);
  }

  if (!mode384) {
    const result = new Uint8Array(64);
    h0.copyTo(result, 0); h1.copyTo(result, 8); h2.copyTo(result, 16); h3.copyTo(result, 24);
    h4.copyTo(result, 32); h5.copyTo(result, 40); h6.copyTo(result, 48); h7.copyTo(result, 56);
    return result;
  } else {
    const result = new Uint8Array(48);
    h0.copyTo(result, 0); h1.copyTo(result, 8); h2.copyTo(result, 16); h3.copyTo(result, 24);
    h4.copyTo(result, 32); h5.copyTo(result, 40);
    return result;
  }
}

export function sha384(data) {
  return computeSha512Internal(data, true);
}

export function sha512(data) {
  return computeSha512Internal(data, false);
}

// ============================================================================
// 4. ISO 32000-2 Algorithm 2.B (Revision 6 Hardened Hashing)
// ============================================================================

const HASH_FUNCS_2B = [sha256, sha384, sha512];

export function computeHash2B(input, password, userKey = null) {
  let k = sha256(input);
  let e = null;

  for (let round = 0; round < 64 || (e && (e[e.length - 1] & 0xFF) > round - 32); round++) {
    const hasU = userKey && userKey.length >= 48;
    const blockSize = password.length + k.length + (hasU ? 48 : 0);
    const k1 = new Uint8Array(64 * blockSize);

    let pos = 0;
    for (let i = 0; i < 64; i++) {
      k1.set(password, pos);
      pos += password.length;
      k1.set(k, pos);
      pos += k.length;
      if (hasU) {
        k1.set(userKey.subarray(0, 48), pos);
        pos += 48;
      }
    }

    const kFirst = k.subarray(0, 16);
    const kSecond = k.subarray(16, 32);

    // AES-128-CBC encryption of k1 without padding
    e = aesEncryptCbc(kFirst, kSecond, k1, false);

    // BigInteger remainder mod 3 from first 16 bytes
    let rem = 0;
    for (let i = 0; i < 16; i++) {
      rem = (rem * 256 + e[i]) % 3;
    }

    const nextHashFn = HASH_FUNCS_2B[rem];
    k = nextHashFn(e);
  }

  return k.subarray(0, 32);
}

export function computeHash2A(password, salt, u = null) {
  let userKey = null;
  if (u && u.length >= 48) {
    userKey = u.subarray(0, 48);
  }
  const passTrunc = password.length > 127 ? password.subarray(0, 127) : password;

  let totalLen = passTrunc.length + salt.length + (userKey ? 48 : 0);
  const input = new Uint8Array(totalLen);
  input.set(passTrunc, 0);
  input.set(salt, passTrunc.length);
  if (userKey) {
    input.set(userKey, passTrunc.length + salt.length);
  }

  return computeHash2B(input, passTrunc, userKey);
}

// ============================================================================
// 5. RC4 (ARCFOUR) Stream Cipher
// ============================================================================

export function rc4(key, data) {
  if (typeof key === 'string') key = new TextEncoder().encode(key);
  if (typeof data === 'string') data = new TextEncoder().encode(data);
  if (!(key instanceof Uint8Array)) key = new Uint8Array(key);
  if (!(data instanceof Uint8Array)) data = new Uint8Array(data);

  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;

  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    const tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }

  let i = 0;
  j = 0;
  const out = new Uint8Array(data.length);
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    const tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
    out[k] = data[k] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
}

// ============================================================================
// 6. AES-128 & AES-256 (CBC mode) Implementation
// ============================================================================

const S_BOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]);

const INV_S_BOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  INV_S_BOX[S_BOX[i]] = i;
}

const RCON = new Uint32Array([
  0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
  0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
  0x36000000
]);

function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hiBitSet = a & 0x80;
    a = (a << 1) & 0xff;
    if (hiBitSet) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function expandKey(keyBytes) {
  const Nk = keyBytes.length / 4; // 4 for 128-bit, 8 for 256-bit
  const Nr = Nk + 6;              // 10 for 128-bit, 14 for 256-bit
  const Nb = 4;
  const w = new Uint32Array(Nb * (Nr + 1));

  for (let i = 0; i < Nk; i++) {
    w[i] = (keyBytes[4 * i] << 24) | (keyBytes[4 * i + 1] << 16) | (keyBytes[4 * i + 2] << 8) | (keyBytes[4 * i + 3]);
  }

  for (let i = Nk; i < Nb * (Nr + 1); i++) {
    let temp = w[i - 1];
    if (i % Nk === 0) {
      temp = ((temp << 8) | (temp >>> 24)) >>> 0;
      temp = (S_BOX[(temp >>> 24) & 0xff] << 24) | (S_BOX[(temp >>> 16) & 0xff] << 16) | (S_BOX[(temp >>> 8) & 0xff] << 8) | S_BOX[temp & 0xff];
      temp = (temp ^ RCON[Math.floor(i / Nk)]) >>> 0;
    } else if (Nk > 6 && i % Nk === 4) {
      temp = (S_BOX[(temp >>> 24) & 0xff] << 24) | (S_BOX[(temp >>> 16) & 0xff] << 16) | (S_BOX[(temp >>> 8) & 0xff] << 8) | S_BOX[temp & 0xff];
    }
    w[i] = (w[i - Nk] ^ temp) >>> 0;
  }

  return { w, Nr };
}

function cipherBlock(inputBlock, w, Nr) {
  const state = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    state[i] = inputBlock[i];
  }

  // AddRoundKey 0
  for (let c = 0; c < 4; c++) {
    const word = w[c];
    state[4 * c + 0] ^= (word >>> 24) & 0xff;
    state[4 * c + 1] ^= (word >>> 16) & 0xff;
    state[4 * c + 2] ^= (word >>> 8) & 0xff;
    state[4 * c + 3] ^= word & 0xff;
  }

  for (let round = 1; round < Nr; round++) {
    // SubBytes
    for (let i = 0; i < 16; i++) state[i] = S_BOX[state[i]];

    // ShiftRows
    const t1 = state[1], t2 = state[2], t3 = state[3];
    state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
    state[2] = state[10]; state[10] = t2;
    const t6 = state[6]; state[6] = state[14]; state[14] = t6;
    state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = t3;

    // MixColumns
    for (let c = 0; c < 4; c++) {
      const idx = 4 * c;
      const s0 = state[idx], s1 = state[idx + 1], s2 = state[idx + 2], s3 = state[idx + 3];
      state[idx + 0] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
      state[idx + 1] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
      state[idx + 2] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
      state[idx + 3] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }

    // AddRoundKey
    for (let c = 0; c < 4; c++) {
      const word = w[round * 4 + c];
      state[4 * c + 0] ^= (word >>> 24) & 0xff;
      state[4 * c + 1] ^= (word >>> 16) & 0xff;
      state[4 * c + 2] ^= (word >>> 8) & 0xff;
      state[4 * c + 3] ^= word & 0xff;
    }
  }

  // Final round (no MixColumns)
  for (let i = 0; i < 16; i++) state[i] = S_BOX[state[i]];
  const t1 = state[1], t2 = state[2], t3 = state[3];
  state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
  state[2] = state[10]; state[10] = t2;
  const t6 = state[6]; state[6] = state[14]; state[14] = t6;
  state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = t3;

  for (let c = 0; c < 4; c++) {
    const word = w[Nr * 4 + c];
    state[4 * c + 0] ^= (word >>> 24) & 0xff;
    state[4 * c + 1] ^= (word >>> 16) & 0xff;
    state[4 * c + 2] ^= (word >>> 8) & 0xff;
    state[4 * c + 3] ^= word & 0xff;
  }

  return state;
}

function invCipherBlock(inputBlock, w, Nr) {
  const state = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    state[i] = inputBlock[i];
  }

  // AddRoundKey Nr
  for (let c = 0; c < 4; c++) {
    const word = w[Nr * 4 + c];
    state[4 * c + 0] ^= (word >>> 24) & 0xff;
    state[4 * c + 1] ^= (word >>> 16) & 0xff;
    state[4 * c + 2] ^= (word >>> 8) & 0xff;
    state[4 * c + 3] ^= word & 0xff;
  }

  for (let round = Nr - 1; round >= 1; round--) {
    // InvShiftRows
    const t1 = state[13], t2 = state[10], t3 = state[7];
    state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t1;
    state[10] = state[2]; state[2] = t2;
    const t14 = state[14]; state[14] = state[6]; state[6] = t14;
    state[7] = state[11]; state[11] = state[15]; state[15] = state[3]; state[3] = t3;

    // InvSubBytes
    for (let i = 0; i < 16; i++) state[i] = INV_S_BOX[state[i]];

    // AddRoundKey
    for (let c = 0; c < 4; c++) {
      const word = w[round * 4 + c];
      state[4 * c + 0] ^= (word >>> 24) & 0xff;
      state[4 * c + 1] ^= (word >>> 16) & 0xff;
      state[4 * c + 2] ^= (word >>> 8) & 0xff;
      state[4 * c + 3] ^= word & 0xff;
    }

    // InvMixColumns
    for (let c = 0; c < 4; c++) {
      const idx = 4 * c;
      const s0 = state[idx], s1 = state[idx + 1], s2 = state[idx + 2], s3 = state[idx + 3];
      state[idx + 0] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
      state[idx + 1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
      state[idx + 2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
      state[idx + 3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
    }
  }

  // InvShiftRows
  const t1 = state[13], t2 = state[10], t3 = state[7];
  state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t1;
  state[10] = state[2]; state[2] = t2;
  const t14 = state[14]; state[14] = state[6]; state[6] = t14;
  state[7] = state[11]; state[11] = state[15]; state[15] = state[3]; state[3] = t3;

  // InvSubBytes
  for (let i = 0; i < 16; i++) state[i] = INV_S_BOX[state[i]];

  // AddRoundKey 0
  for (let c = 0; c < 4; c++) {
    const word = w[c];
    state[4 * c + 0] ^= (word >>> 24) & 0xff;
    state[4 * c + 1] ^= (word >>> 16) & 0xff;
    state[4 * c + 2] ^= (word >>> 8) & 0xff;
    state[4 * c + 3] ^= word & 0xff;
  }

  return state;
}

export function aesEncryptCbc(key, iv, data, usePadding = true) {
  if (typeof key === 'string') key = new TextEncoder().encode(key);
  if (typeof data === 'string') data = new TextEncoder().encode(data);
  if (!(key instanceof Uint8Array)) key = new Uint8Array(key);
  if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
  if (!(iv instanceof Uint8Array)) iv = new Uint8Array(iv);

  let input = data;
  if (usePadding) {
    const padLen = 16 - (data.length % 16);
    input = new Uint8Array(data.length + padLen);
    input.set(data, 0);
    input.fill(padLen, data.length);
  }

  const { w, Nr } = expandKey(key);
  const out = new Uint8Array(input.length);
  let currentIv = new Uint8Array(iv.subarray(0, 16));

  for (let i = 0; i < input.length; i += 16) {
    const block = new Uint8Array(16);
    for (let j = 0; j < 16; j++) {
      block[j] = input[i + j] ^ currentIv[j];
    }
    const encrypted = cipherBlock(block, w, Nr);
    out.set(encrypted, i);
    currentIv = encrypted;
  }

  return out;
}

export function aesDecryptCbc(key, iv, data, usePadding = true) {
  if (typeof key === 'string') key = new TextEncoder().encode(key);
  if (typeof data === 'string') data = new TextEncoder().encode(data);
  if (!(key instanceof Uint8Array)) key = new Uint8Array(key);
  if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
  if (!(iv instanceof Uint8Array)) iv = new Uint8Array(iv);

  if (data.length % 16 !== 0) {
    throw new Error('Ciphertext length must be multiple of 16');
  }

  const { w, Nr } = expandKey(key);
  const out = new Uint8Array(data.length);
  let currentIv = new Uint8Array(iv.subarray(0, 16));

  for (let i = 0; i < data.length; i += 16) {
    const block = data.subarray(i, i + 16);
    const decrypted = invCipherBlock(block, w, Nr);
    for (let j = 0; j < 16; j++) {
      out[i + j] = decrypted[j] ^ currentIv[j];
    }
    currentIv = block;
  }

  if (usePadding && out.length > 0) {
    const padLen = out[out.length - 1];
    if (padLen > 0 && padLen <= 16) {
      let valid = true;
      for (let j = out.length - padLen; j < out.length; j++) {
        if (out[j] !== padLen) {
          valid = false;
          break;
        }
      }
      if (valid) {
        return out.subarray(0, out.length - padLen);
      }
    }
  }

  return out;
}
