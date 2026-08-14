/**
 * @file src/core/crypto.js
 * @description Standalone Pure JavaScript Cryptographic Engine for PDF Decryption (MD5, SHA-256, RC4, AES-128/256-CBC).
 *              PDF 복호화를 위한 독립형 순수 JavaScript 암호화 엔진 (MD5, SHA-256, RC4, AES-128/256-CBC).
 */

/* ==========================================================================
 * 1. MD5 Hash Implementation / MD5 해시 구현
 * ========================================================================== */

/**
 * Calculates MD5 digest of binary input.
 * 바이너리 입력의 MD5 해시를 계산합니다.
 * @param {Uint8Array} input - Input data / 입력 데이터
 * @returns {Uint8Array} 16-byte MD5 digest / 16바이트 MD5 다이제스트
 */
export function md5(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const n = bytes.length;

  // Pre-processing / 패딩 처리
  const words = [];
  for (let i = 0; i < n; i++) {
    words[i >> 2] |= (bytes[i] & 0xff) << ((i % 4) * 8);
  }
  words[n >> 2] |= 0x80 << ((n % 4) * 8);
  words[(((n + 8) >> 6) << 4) + 14] = (n * 8) & 0xffffffff;
  words[(((n + 8) >> 6) << 4) + 15] = Math.floor((n * 8) / 0x100000000);

  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

  function safeAdd(x, y) {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  }

  function rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }

  function cmn(q, a, b, x, s, t) {
    return safeAdd(rol(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  }
  function ff(a, b, c, d, x, s, t) {
    return cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function gg(a, b, c, d, x, s, t) {
    return cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function hh(a, b, c, d, x, s, t) {
    return cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function ii(a, b, c, d, x, s, t) {
    return cmn(c ^ (b | ~d), a, b, x, s, t);
  }

  for (let i = 0; i < words.length; i += 16) {
    const olda = a, oldb = b, oldc = c, oldd = d;

    a = ff(a, b, c, d, words[i + 0] || 0, 7, 0xd76aa478);
    d = ff(d, a, b, c, words[i + 1] || 0, 12, 0xe8c7b756);
    c = ff(c, d, a, b, words[i + 2] || 0, 17, 0x242070db);
    b = ff(b, c, d, a, words[i + 3] || 0, 22, 0xc1bdceee);
    a = ff(a, b, c, d, words[i + 4] || 0, 7, 0xf57c0faf);
    d = ff(d, a, b, c, words[i + 5] || 0, 12, 0x4787c62a);
    c = ff(c, d, a, b, words[i + 6] || 0, 17, 0xa8304613);
    b = ff(b, c, d, a, words[i + 7] || 0, 22, 0xfd469501);
    a = ff(a, b, c, d, words[i + 8] || 0, 7, 0x698098d8);
    d = ff(d, a, b, c, words[i + 9] || 0, 12, 0x8b44f7af);
    c = ff(c, d, a, b, words[i + 10] || 0, 17, 0xffff5bb1);
    b = ff(b, c, d, a, words[i + 11] || 0, 22, 0x895cd7be);
    a = ff(a, b, c, d, words[i + 12] || 0, 7, 0x6b901122);
    d = ff(d, a, b, c, words[i + 13] || 0, 12, 0xfd987193);
    c = ff(c, d, a, b, words[i + 14] || 0, 17, 0xa679438e);
    b = ff(b, c, d, a, words[i + 15] || 0, 22, 0x49b40821);

    a = gg(a, b, c, d, words[i + 1] || 0, 5, 0xf61e2562);
    d = gg(d, a, b, c, words[i + 6] || 0, 9, 0xc040b340);
    c = gg(c, d, a, b, words[i + 11] || 0, 14, 0x265e5a51);
    b = gg(b, c, d, a, words[i + 0] || 0, 20, 0xe9b6c7aa);
    a = gg(a, b, c, d, words[i + 5] || 0, 5, 0xd62f105d);
    d = gg(d, a, b, c, words[i + 10] || 0, 9, 0x02441453);
    c = gg(c, d, a, b, words[i + 15] || 0, 14, 0xd8a1e681);
    b = gg(b, c, d, a, words[i + 4] || 0, 20, 0xe7d3fbc8);
    a = gg(a, b, c, d, words[i + 9] || 0, 5, 0x21e1cde6);
    d = gg(d, a, b, c, words[i + 14] || 0, 9, 0xc33707d6);
    c = gg(c, d, a, b, words[i + 3] || 0, 14, 0xf4d50d87);
    b = gg(b, c, d, a, words[i + 8] || 0, 20, 0x455a14ed);
    a = gg(a, b, c, d, words[i + 13] || 0, 5, 0xa9e3e905);
    d = gg(d, a, b, c, words[i + 2] || 0, 9, 0xfcefa3f8);
    c = gg(c, d, a, b, words[i + 7] || 0, 14, 0x676f02d9);
    b = gg(b, c, d, a, words[i + 12] || 0, 20, 0x8d2a4c8a);

    a = hh(a, b, c, d, words[i + 5] || 0, 4, 0xfffa3942);
    d = hh(d, a, b, c, words[i + 8] || 0, 11, 0x8771f681);
    c = hh(c, d, a, b, words[i + 11] || 0, 16, 0x6d9d6122);
    b = hh(b, c, d, a, words[i + 14] || 0, 23, 0xfde5380c);
    a = hh(a, b, c, d, words[i + 1] || 0, 4, 0xa4beea44);
    d = hh(d, a, b, c, words[i + 4] || 0, 11, 0x4bdecfa9);
    c = hh(c, d, a, b, words[i + 7] || 0, 16, 0xf6bb4b60);
    b = hh(b, c, d, a, words[i + 10] || 0, 23, 0xbebfbc70);
    a = hh(a, b, c, d, words[i + 13] || 0, 4, 0x289b7ec6);
    d = hh(d, a, b, c, words[i + 0] || 0, 11, 0xeaa127fa);
    c = hh(c, d, a, b, words[i + 3] || 0, 16, 0xd4ef3085);
    b = hh(b, c, d, a, words[i + 6] || 0, 23, 0x04881d05);
    a = hh(a, b, c, d, words[i + 9] || 0, 4, 0xd9d4d039);
    d = hh(d, a, b, c, words[i + 12] || 0, 11, 0xe6db99e5);
    c = hh(c, d, a, b, words[i + 15] || 0, 16, 0x1fa27cf8);
    b = hh(b, c, d, a, words[i + 2] || 0, 23, 0xc4ac5665);

    a = ii(a, b, c, d, words[i + 0] || 0, 6, 0xf4292244);
    d = ii(d, a, b, c, words[i + 7] || 0, 10, 0x432aff97);
    c = ii(c, d, a, b, words[i + 14] || 0, 15, 0xab9423a7);
    b = ii(b, c, d, a, words[i + 5] || 0, 21, 0xfc93a039);
    a = ii(a, b, c, d, words[i + 12] || 0, 6, 0x655b59c3);
    d = ii(d, a, b, c, words[i + 3] || 0, 10, 0x8f0ccc92);
    c = ii(c, d, a, b, words[i + 10] || 0, 15, 0xffeff47d);
    b = ii(b, c, d, a, words[i + 1] || 0, 21, 0x85845dd1);
    a = ii(a, b, c, d, words[i + 8] || 0, 6, 0x6fa87e4f);
    d = ii(d, a, b, c, words[i + 15] || 0, 10, 0xfe2ce6e0);
    c = ii(c, d, a, b, words[i + 6] || 0, 15, 0xa3014314);
    b = ii(b, c, d, a, words[i + 13] || 0, 21, 0x4e0811a1);
    a = ii(a, b, c, d, words[i + 4] || 0, 6, 0xf7537e82);
    d = ii(d, a, b, c, words[i + 11] || 0, 10, 0xbd3af235);
    c = ii(c, d, a, b, words[i + 2] || 0, 15, 0x2ad7d2bb);
    b = ii(b, c, d, a, words[i + 9] || 0, 21, 0xeb86d391);

    a = safeAdd(a, olda);
    b = safeAdd(b, oldb);
    c = safeAdd(c, oldc);
    d = safeAdd(d, oldd);
  }

  const result = new Uint8Array(16);
  const finalWords = [a, b, c, d];
  for (let i = 0; i < 16; i++) {
    result[i] = (finalWords[i >> 2] >>> ((i % 4) * 8)) & 0xff;
  }
  return result;
}

/* ==========================================================================
 * 2. SHA-256 Hash Implementation / SHA-256 해시 구현
 * ========================================================================== */

/**
 * Calculates SHA-256 digest of binary input.
 * 바이너리 입력의 SHA-256 해시를 계산합니다.
 * @param {Uint8Array} input - Input data / 입력 데이터
 * @returns {Uint8Array} 32-byte SHA-256 digest / 32바이트 SHA-256 다이제스트
 */
export function sha256(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const n = bytes.length;

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const words = [];
  for (let i = 0; i < n; i++) {
    words[i >> 2] |= (bytes[i] & 0xff) << (24 - (i % 4) * 8);
  }
  words[n >> 2] |= 0x80 << (24 - (n % 4) * 8);
  words[(((n + 8) >> 6) << 4) + 15] = (n * 8) & 0xffffffff;

  const W = new Uint32Array(64);

  function ror(x, n) { return (x >>> n) | (x << (32 - n)); }

  for (let i = 0; i < words.length; i += 16) {
    for (let t = 0; t < 16; t++) W[t] = words[i + t] || 0;
    for (let t = 16; t < 64; t++) {
      const s0 = ror(W[t - 15], 7) ^ ror(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = ror(W[t - 2], 17) ^ ror(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    for (let t = 0; t < 64; t++) {
      const S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t] + W[t]) | 0;
      const S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
    h5 = (h5 + f) | 0;
    h6 = (h6 + g) | 0;
    h7 = (h7 + h) | 0;
  }

  const result = new Uint8Array(32);
  const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i = 0; i < 32; i++) {
    result[i] = (hs[i >> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return result;
}

/* ==========================================================================
 * 3. RC4 Stream Cipher / RC4 스트림 암복호화
 * ========================================================================== */

/**
 * RC4 (ARC4) symmetric stream cipher encryption / decryption.
 * RC4 대칭 스트림 암복호화를 수행합니다.
 * @param {Uint8Array} key - Encryption key (1-256 bytes) / 암호화 키
 * @param {Uint8Array} data - Plaintext or ciphertext / 평문 또는 암호문
 * @returns {Uint8Array} Resulting bytes / 결과 바이트 배열
 */
export function rc4(key, data) {
  const k = key instanceof Uint8Array ? key : new Uint8Array(key);
  const d = data instanceof Uint8Array ? data : new Uint8Array(data);
  const s = new Uint8Array(256);

  // KSA (Key-Scheduling Algorithm)
  for (let i = 0; i < 256; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + k[i % k.length]) & 0xff;
    const tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }

  // PRGA (Pseudo-Random Generation Algorithm)
  const out = new Uint8Array(d.length);
  let i = 0;
  j = 0;
  for (let p = 0; p < d.length; p++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    const tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
    const kByte = s[(s[i] + s[j]) & 0xff];
    out[p] = d[p] ^ kByte;
  }
  return out;
}

/* ==========================================================================
 * 4. AES-128 / AES-256 CBC Decryption / AES CBC 복호화
 * ========================================================================== */

// AES S-Box & Inverted S-Box tables / AES S-Box 및 역 S-Box 테이블
const SBOX = new Uint8Array([
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

const RSBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) RSBOX[SBOX[i]] = i;

const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/**
 * Key expansion for AES.
 * AES 키 확장을 수행합니다.
 */
function expandKey(key) {
  const Nk = key.length / 4; // 4 for 128-bit, 8 for 256-bit
  const Nr = Nk + 6;        // 10 for 128-bit, 14 for 256-bit
  const w = new Uint32Array(4 * (Nr + 1));

  for (let i = 0; i < Nk; i++) {
    w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
  }

  function rotWord(word) {
    return ((word << 8) | (word >>> 24)) >>> 0;
  }
  function subWord(word) {
    return ((SBOX[(word >>> 24) & 0xff] << 24) |
            (SBOX[(word >>> 16) & 0xff] << 16) |
            (SBOX[(word >>> 8) & 0xff] << 8) |
            SBOX[word & 0xff]) >>> 0;
  }

  for (let i = Nk; i < 4 * (Nr + 1); i++) {
    let temp = w[i - 1];
    if (i % Nk === 0) {
      temp = (subWord(rotWord(temp)) ^ (RCON[i / Nk] << 24)) >>> 0;
    } else if (Nk > 6 && i % Nk === 4) {
      temp = subWord(temp);
    }
    w[i] = (w[i - Nk] ^ temp) >>> 0;
  }
  return { w, Nr };
}

function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

/**
 * Decrypts a single 16-byte AES block.
 * 단일 16바이트 AES 블록을 복호화합니다.
 */
function decryptBlock(block, w, Nr) {
  const state = new Uint8Array(16);
  for (let i = 0; i < 16; i++) state[i] = block[i];

  function addRoundKey(round) {
    for (let c = 0; c < 4; c++) {
      const kw = w[round * 4 + c];
      state[c * 4 + 0] ^= (kw >>> 24) & 0xff;
      state[c * 4 + 1] ^= (kw >>> 16) & 0xff;
      state[c * 4 + 2] ^= (kw >>> 8) & 0xff;
      state[c * 4 + 3] ^= kw & 0xff;
    }
  }

  function invSubBytes() {
    for (let i = 0; i < 16; i++) state[i] = RSBOX[state[i]];
  }

  function invShiftRows() {
    let tmp = state[1]; state[1] = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;
  }

  function invMixColumns() {
    for (let c = 0; c < 4; c++) {
      const a0 = state[c * 4 + 0], a1 = state[c * 4 + 1], a2 = state[c * 4 + 2], a3 = state[c * 4 + 3];
      state[c * 4 + 0] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
      state[c * 4 + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
      state[c * 4 + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
      state[c * 4 + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
  }

  addRoundKey(Nr);
  for (let round = Nr - 1; round > 0; round--) {
    invShiftRows();
    invSubBytes();
    addRoundKey(round);
    invMixColumns();
  }
  invShiftRows();
  invSubBytes();
  addRoundKey(0);

  return state;
}

/**
 * Decrypts ciphertext using AES-128 or AES-256 in CBC mode.
 * AES-128 또는 AES-256 CBC 모드로 암호문을 복호화합니다.
 * @param {Uint8Array} key - 16-byte (AES-128) or 32-byte (AES-256) key / 키
 * @param {Uint8Array} iv - 16-byte Initialization Vector / 16바이트 IV
 * @param {Uint8Array} ciphertext - Data to decrypt / 복호화할 암호문
 * @param {boolean} [unpad=true] - Strip PKCS#7 padding / PKCS#7 패딩 제거 여부
 * @returns {Uint8Array} Decrypted plaintext / 복호화된 평문
 */
export function aesDecryptCbc(key, iv, ciphertext, unpad = true) {
  const k = key instanceof Uint8Array ? key : new Uint8Array(key);
  const ivBytes = iv instanceof Uint8Array ? iv : new Uint8Array(iv);
  const ct = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext);

  if (ct.length === 0 || ct.length % 16 !== 0) {
    return ct; // Not a valid AES block size / 유효한 블록 크기가 아님
  }

  const { w, Nr } = expandKey(k);
  const pt = new Uint8Array(ct.length);
  let prev = ivBytes;

  for (let i = 0; i < ct.length; i += 16) {
    const block = ct.subarray(i, i + 16);
    const dec = decryptBlock(block, w, Nr);
    for (let b = 0; b < 16; b++) {
      pt[i + b] = dec[b] ^ prev[b];
    }
    prev = block;
  }

  if (unpad && pt.length > 0) {
    const padLen = pt[pt.length - 1];
    if (padLen > 0 && padLen <= 16) {
      let valid = true;
      for (let i = pt.length - padLen; i < pt.length; i++) {
        if (pt[i] !== padLen) { valid = false; break; }
      }
      if (valid) return pt.subarray(0, pt.length - padLen);
    }
  }

  return pt;
}
