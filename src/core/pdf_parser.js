/**
 * @file src/core/pdf_parser.js
 * @description Robust low-level binary PDF Parser & Lexer.
 *              저수준 바이너리 PDF 파서 및 렉서.
 */

/* ==========================================================================
 * PDF AST Data Structures / PDF 구문 트리 자료구조
 * ========================================================================== */

export class PdfRef {
  constructor(num, gen) {
    this.num = Number(num);
    this.gen = Number(gen);
  }
  toString() {
    return `${this.num} ${this.gen} R`;
  }
}

export class PdfString {
  constructor(bytes, isHex = false) {
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.isHex = isHex;
  }
  toString() {
    if (this.isHex) {
      let hex = '';
      for (let i = 0; i < this.bytes.length; i++) {
        hex += this.bytes[i].toString(16).padStart(2, '0');
      }
      return `<${hex}>`;
    }
    // Literal string with escape / 이스케이프 처리된 리터럴 문자열
    let str = '';
    for (let i = 0; i < this.bytes.length; i++) {
      const b = this.bytes[i];
      if (b === 0x28) str += '\\(';
      else if (b === 0x29) str += '\\)';
      else if (b === 0x5c) str += '\\\\';
      else if (b === 0x0a) str += '\\n';
      else if (b === 0x0d) str += '\\r';
      else if (b === 0x09) str += '\\t';
      else if (b >= 32 && b <= 126) str += String.fromCharCode(b);
      else {
        str += '\\' + b.toString(8).padStart(3, '0');
      }
    }
    return `(${str})`;
  }
}

export class PdfDict {
  constructor() {
    this.map = new Map(); // Key: '/KeyName', Value: any
  }
  set(key, val) {
    const k = key.startsWith('/') ? key : '/' + key;
    this.map.set(k, val);
  }
  get(key) {
    const k = key.startsWith('/') ? key : '/' + key;
    return this.map.get(k);
  }
  has(key) {
    const k = key.startsWith('/') ? key : '/' + key;
    return this.map.has(k);
  }
  delete(key) {
    const k = key.startsWith('/') ? key : '/' + key;
    return this.map.delete(k);
  }
  entries() {
    return this.map.entries();
  }
}

export class PdfArray {
  constructor(items = []) {
    this.items = items;
  }
  push(item) {
    this.items.push(item);
  }
  get(index) {
    return this.items[index];
  }
  get length() {
    return this.items.length;
  }
}

export class PdfStream {
  constructor(dict, bytes) {
    this.dict = dict instanceof PdfDict ? dict : new PdfDict();
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  }
}

export class PdfObject {
  constructor(num, gen, data, stream = null) {
    this.num = Number(num);
    this.gen = Number(gen);
    this.data = data; // PdfDict, PdfArray, PdfString, number, boolean, etc.
    this.stream = stream; // PdfStream if object has stream
  }
}

export class PdfDocument {
  constructor(bytes) {
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.headerVersion = '1.7';
    this.trailer = new PdfDict();
    this.encryptRef = null;
    this.objects = new Map(); // Key: `${num}_${gen}`, Value: PdfObject
  }

  getObject(num, gen = 0) {
    return this.objects.get(`${num}_${gen}`);
  }

  setObject(num, gen, data, stream = null) {
    const obj = new PdfObject(num, gen, data, stream);
    this.objects.set(`${num}_${gen}`, obj);
    return obj;
  }
}

/* ==========================================================================
 * Lexer & Parser Implementation / 렉서 및 파서 구현
 * ========================================================================== */

export class PdfLexer {
  constructor(bytes) {
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.pos = 0;
    this.length = this.bytes.length;
  }

  isWhitespace(b) {
    return b === 0x00 || b === 0x09 || b === 0x0a || b === 0x0c || b === 0x0d || b === 0x20;
  }

  isDelimiter(b) {
    return (
      b === 0x28 || b === 0x29 || // ()
      b === 0x3c || b === 0x3e || // <>
      b === 0x5b || b === 0x5d || // []
      b === 0x7b || b === 0x7d || // {}
      b === 0x2f || b === 0x25    // / %
    );
  }

  skipWhitespaceAndComments() {
    while (this.pos < this.length) {
      const b = this.bytes[this.pos];
      if (this.isWhitespace(b)) {
        this.pos++;
      } else if (b === 0x25) { // '%' Comment
        while (this.pos < this.length && this.bytes[this.pos] !== 0x0a && this.bytes[this.pos] !== 0x0d) {
          this.pos++;
        }
      } else {
        break;
      }
    }
  }

  peekByte() {
    this.skipWhitespaceAndComments();
    return this.pos < this.length ? this.bytes[this.pos] : -1;
  }

  nextByte() {
    this.skipWhitespaceAndComments();
    return this.pos < this.length ? this.bytes[this.pos++] : -1;
  }

  readName() {
    this.skipWhitespaceAndComments();
    if (this.bytes[this.pos] !== 0x2f) return null; // '/'
    this.pos++; // skip '/'
    let name = '/';
    while (this.pos < this.length) {
      const b = this.bytes[this.pos];
      if (this.isWhitespace(b) || this.isDelimiter(b)) break;
      if (b === 0x23 && this.pos + 2 < this.length) { // '#HEX' escape
        const hex = String.fromCharCode(this.bytes[this.pos + 1], this.bytes[this.pos + 2]);
        name += String.fromCharCode(parseInt(hex, 16));
        this.pos += 3;
      } else {
        name += String.fromCharCode(b);
        this.pos++;
      }
    }
    return name;
  }

  readHexString() {
    this.skipWhitespaceAndComments();
    if (this.bytes[this.pos] !== 0x3c) return null; // '<'
    this.pos++; // skip '<'
    const hexChars = [];
    while (this.pos < this.length) {
      const b = this.bytes[this.pos++];
      if (b === 0x3e) break; // '>'
      if (this.isWhitespace(b)) continue;
      hexChars.push(String.fromCharCode(b));
    }
    if (hexChars.length % 2 !== 0) hexChars.push('0');
    const bytes = new Uint8Array(hexChars.length / 2);
    for (let i = 0; i < hexChars.length; i += 2) {
      bytes[i / 2] = parseInt(hexChars[i] + hexChars[i + 1], 16);
    }
    return new PdfString(bytes, true);
  }

  readLiteralString() {
    this.skipWhitespaceAndComments();
    if (this.bytes[this.pos] !== 0x28) return null; // '('
    this.pos++; // skip '('
    const out = [];
    let depth = 1;

    while (this.pos < this.length && depth > 0) {
      const b = this.bytes[this.pos++];
      if (b === 0x5c) { // '\' Escape
        if (this.pos >= this.length) break;
        const next = this.bytes[this.pos++];
        if (next === 0x6e) out.push(0x0a); // \n
        else if (next === 0x72) out.push(0x0d); // \r
        else if (next === 0x74) out.push(0x09); // \t
        else if (next === 0x62) out.push(0x08); // \b
        else if (next === 0x66) out.push(0x0c); // \f
        else if (next === 0x28) out.push(0x28); // \(
        else if (next === 0x29) out.push(0x29); // \)
        else if (next === 0x5c) out.push(0x5c); // \\
        else if (next >= 0x30 && next <= 0x37) { // Octal \ddd
          let oct = String.fromCharCode(next);
          if (this.pos < this.length && this.bytes[this.pos] >= 0x30 && this.bytes[this.pos] <= 0x37) {
            oct += String.fromCharCode(this.bytes[this.pos++]);
            if (this.pos < this.length && this.bytes[this.pos] >= 0x30 && this.bytes[this.pos] <= 0x37) {
              oct += String.fromCharCode(this.bytes[this.pos++]);
            }
          }
          out.push(parseInt(oct, 8));
        } else {
          out.push(next);
        }
      } else if (b === 0x28) {
        depth++;
        out.push(b);
      } else if (b === 0x29) {
        depth--;
        if (depth > 0) out.push(b);
      } else {
        out.push(b);
      }
    }
    return new PdfString(new Uint8Array(out), false);
  }

  readToken() {
    this.skipWhitespaceAndComments();
    if (this.pos >= this.length) return null;

    const b = this.bytes[this.pos];
    if (b === 0x2f) return this.readName();
    if (b === 0x3c) {
      if (this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x3c) {
        this.pos += 2;
        return '<<';
      }
      return this.readHexString();
    }
    if (b === 0x3e) {
      if (this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x3e) {
        this.pos += 2;
        return '>>';
      }
      this.pos++;
      return '>';
    }
    if (b === 0x5b) { this.pos++; return '['; }
    if (b === 0x5d) { this.pos++; return ']'; }
    if (b === 0x28) return this.readLiteralString();

    // General token (keyword, number, boolean)
    let tok = '';
    while (this.pos < this.length) {
      const byte = this.bytes[this.pos];
      if (this.isWhitespace(byte) || this.isDelimiter(byte)) break;
      tok += String.fromCharCode(byte);
      this.pos++;
    }

    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (tok === 'null') return null;
    if (/^-?\d+$/.test(tok)) return parseInt(tok, 10);
    if (/^-?\d*\.\d+$/.test(tok)) return parseFloat(tok);
    return tok;
  }

  parseValue() {
    this.skipWhitespaceAndComments();
    const b = this.bytes[this.pos];

    if (b === 0x2f) return this.readName();
    if (b === 0x28) return this.readLiteralString();
    if (b === 0x3c) {
      if (this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x3c) {
        return this.parseDictionary();
      }
      return this.readHexString();
    }
    if (b === 0x5b) return this.parseArray();

    const tok = this.readToken();
    if (typeof tok === 'number') {
      // Check if it's an indirect reference: "N M R"
      const savedPos = this.pos;
      const nextTok = this.readToken();
      if (typeof nextTok === 'number') {
        const rTok = this.readToken();
        if (rTok === 'R') {
          return new PdfRef(tok, nextTok);
        }
      }
      this.pos = savedPos;
      return tok;
    }
    return tok;
  }

  parseDictionary() {
    this.skipWhitespaceAndComments();
    if (this.bytes[this.pos] === 0x3c && this.bytes[this.pos + 1] === 0x3c) {
      this.pos += 2;
    }
    const dict = new PdfDict();
    while (this.pos < this.length) {
      this.skipWhitespaceAndComments();
      if (this.bytes[this.pos] === 0x3e && this.bytes[this.pos + 1] === 0x3e) {
        this.pos += 2;
        break;
      }
      const key = this.readToken();
      if (!key || typeof key !== 'string' || !key.startsWith('/')) break;
      const val = this.parseValue();
      dict.set(key, val);
    }
    return dict;
  }

  parseArray() {
    this.skipWhitespaceAndComments();
    if (this.bytes[this.pos] === 0x5b) this.pos++; // '['
    const arr = new PdfArray();
    while (this.pos < this.length) {
      this.skipWhitespaceAndComments();
      if (this.bytes[this.pos] === 0x5d) { // ']'
        this.pos++;
        break;
      }
      const val = this.parseValue();
      if (val === undefined || val === null && this.bytes[this.pos] === 0x5d) break;
      arr.push(val);
    }
    return arr;
  }

  readStream(length) {
    this.skipWhitespaceAndComments();
    const tok = this.readToken();
    if (tok !== 'stream') return null;

    // Stream keyword is followed by CRLF or LF
    if (this.bytes[this.pos] === 0x0d && this.bytes[this.pos + 1] === 0x0a) {
      this.pos += 2;
    } else if (this.bytes[this.pos] === 0x0a || this.bytes[this.pos] === 0x0d) {
      this.pos += 1;
    }

    let streamBytes;
    if (typeof length === 'number' && length >= 0 && this.pos + length <= this.length) {
      streamBytes = this.bytes.slice(this.pos, this.pos + length);
      this.pos += length;
    } else {
      // Find 'endstream' marker
      const start = this.pos;
      const endstreamMarker = [0x65, 0x6e, 0x64, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d]; // 'endstream'
      let end = -1;
      for (let i = start; i <= this.length - 9; i++) {
        let match = true;
        for (let j = 0; j < 9; j++) {
          if (this.bytes[i + j] !== endstreamMarker[j]) { match = false; break; }
        }
        if (match) { end = i; break; }
      }
      if (end !== -1) {
        // Strip trailing CRLF before endstream if present
        let streamEnd = end;
        if (streamEnd > start && this.bytes[streamEnd - 1] === 0x0a) streamEnd--;
        if (streamEnd > start && this.bytes[streamEnd - 1] === 0x0d) streamEnd--;
        streamBytes = this.bytes.slice(start, streamEnd);
        this.pos = end;
      } else {
        streamBytes = this.bytes.slice(start);
        this.pos = this.length;
      }
    }

    this.skipWhitespaceAndComments();
    const endTok = this.readToken(); // 'endstream'
    return streamBytes;
  }
}

/**
 * Parses binary PDF data into a PdfDocument model.
 * 바이너리 PDF 데이터를 파싱하여 PdfDocument 모델을 구축합니다.
 * @param {Uint8Array} bytes - PDF file bytes / PDF 파일 바이트 배열
 * @returns {PdfDocument}
 */
export function parsePdf(bytes) {
  const doc = new PdfDocument(bytes);
  const text = new TextDecoder('latin1').decode(bytes);

  // 1. Header parsing / 헤더 파싱
  const headerMatch = text.match(/%PDF-(\d+\.\d+)/);
  if (headerMatch) {
    doc.headerVersion = headerMatch[1];
  }

  // 2. Locate startxref / startxref 위치 탐색
  const startxrefMatches = [...text.matchAll(/startxref\s+(\d+)\s+%%EOF/g)];
  if (startxrefMatches.length === 0) {
    // Fallback: Scan objects sequentially if xref is malformed / 손상된 경우 전체 순차 스캔 폴백
    scanObjectsSequentially(doc);
    return doc;
  }

  const lastStartXref = parseInt(startxrefMatches[startxrefMatches.length - 1][1], 10);
  const xrefLexer = new PdfLexer(bytes);
  xrefLexer.pos = lastStartXref;

  const xrefTok = xrefLexer.readToken();
  if (xrefTok === 'xref') {
    // Traditional xref table / 전통적 교차 참조 테이블
    parseTraditionalXref(doc, xrefLexer);
  } else if (typeof xrefTok === 'number') {
    // XRef Stream object (PDF 1.5+) / 압축된 교차 참조 스트림
    scanObjectsSequentially(doc);
  }

  // Ensure all indirect objects in file are fully indexed / 파일 내 모든 간접 객체 인덱싱 보장
  scanObjectsSequentially(doc);

  return doc;
}

function parseTraditionalXref(doc, lexer) {
  while (lexer.pos < lexer.length) {
    lexer.skipWhitespaceAndComments();
    const tok = lexer.readToken();
    if (tok === 'trailer') break;
    if (typeof tok !== 'number') break;

    const startObj = tok;
    const count = lexer.readToken();
    for (let i = 0; i < count; i++) {
      lexer.readToken(); // offset
      lexer.readToken(); // gen
      lexer.readToken(); // 'n' or 'f'
    }
  }

  // Parse trailer dictionary
  const trailerDict = lexer.parseDictionary();
  if (trailerDict instanceof PdfDict) {
    doc.trailer = trailerDict;
    const encrypt = trailerDict.get('/Encrypt');
    if (encrypt instanceof PdfRef) {
      doc.encryptRef = encrypt;
    }
  }
}

/**
 * Sequential full scanner for indirect objects and trailer.
 * 간접 객체 및 트레일러 전체 순차 스캐너.
 */
function scanObjectsSequentially(doc) {
  const bytes = doc.bytes;
  const text = new TextDecoder('latin1').decode(bytes);

  // Regex pattern for indirect objects: `N M obj`
  const objRegex = /(\d+)\s+(\d+)\s+obj/g;
  let match;

  while ((match = objRegex.exec(text)) !== null) {
    const num = parseInt(match[1], 10);
    const gen = parseInt(match[2], 10);
    const objOffset = match.index + match[0].length;

    const lexer = new PdfLexer(bytes);
    lexer.pos = objOffset;
    const data = lexer.parseValue();

    let stream = null;
    lexer.skipWhitespaceAndComments();
    if (lexer.pos < bytes.length && text.substr(lexer.pos, 6) === 'stream') {
      let streamLength = null;
      if (data instanceof PdfDict) {
        const lenVal = data.get('/Length');
        if (typeof lenVal === 'number') streamLength = lenVal;
      }
      const streamBytes = lexer.readStream(streamLength);
      if (streamBytes) {
        stream = new PdfStream(data instanceof PdfDict ? data : new PdfDict(), streamBytes);
      }
    }

    doc.setObject(num, gen, data, stream);
  }

  // Scan trailer dictionary / 트레일러 딕셔너리 스캔
  const trailerRegex = /trailer\s*<<([\s\S]*?)>>/g;
  let trailerMatch;
  while ((trailerMatch = trailerRegex.exec(text)) !== null) {
    const lexer = new PdfLexer(bytes);
    lexer.pos = trailerMatch.index + 7; // after 'trailer'
    const dict = lexer.parseDictionary();
    if (dict instanceof PdfDict) {
      doc.trailer = dict;
      const encrypt = dict.get('/Encrypt');
      if (encrypt instanceof PdfRef) {
        doc.encryptRef = encrypt;
      }
    }
  }
}
