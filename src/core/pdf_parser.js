/**
 * @file src/core/pdf_parser.js
 * @description High-performance Binary PDF Lexer, Tokenizer, and AST Parser.
 *              고성능 바이너리 PDF 렉서, 토크나이저 및 AST 파서.
 */

import { PdfRef, PdfString, PdfDict, PdfArray, PdfStream, PdfObject, PdfDocument } from './pdf_ast.js';

/**
 * Binary-safe Lexer and Tokenizer for PDF byte streams.
 * 바이너리 데이터와 텍스트가 혼합된 PDF 바이트 스트림을 안전하게 파싱하는 렉서.
 */
export class PdfLexer {
  /**
   * @param {Uint8Array} bytes - PDF file byte array / PDF 바이트 배열
   */
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
    this.length = bytes.length;
  }

  /**
   * Returns true if character byte is PDF whitespace (NUL, TAB, LF, FF, CR, SP).
   * 공백 문자 여부를 검사합니다.
   */
  isWhitespace(b) {
    return b === 0x00 || b === 0x09 || b === 0x0a || b === 0x0c || b === 0x0d || b === 0x20;
  }

  /**
   * Returns true if character byte is a PDF delimiter.
   * 구분자 문자 여부를 검사합니다.
   */
  isDelimiter(b) {
    return b === 0x28 || b === 0x29 || // ( )
           b === 0x3c || b === 0x3e || // < >
           b === 0x5b || b === 0x5d || // [ ]
           b === 0x7b || b === 0x7d || // { }
           b === 0x2f || b === 0x25;   // / %
  }

  /**
   * Skips all whitespaces and comments (% ... \r|\n).
   * 공백 및 주석 라인을 건너뜁니다.
   */
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

  /**
   * Reads next token as a string.
   * 다음 토큰을 문자열로 읽어옵니다.
   */
  nextToken() {
    this.skipWhitespaceAndComments();
    if (this.pos >= this.length) return null;

    const b = this.bytes[this.pos];

    // Check dictionary start '<<' or end '>>'
    if (b === 0x3c && this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x3c) { // '<<'
      this.pos += 2;
      return '<<';
    }
    if (b === 0x3e && this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x3e) { // '>>'
      this.pos += 2;
      return '>>';
    }

    // Name token `/Name`
    if (b === 0x2f) { // '/'
      const start = this.pos;
      this.pos++;
      while (this.pos < this.length) {
        const cur = this.bytes[this.pos];
        if (this.isWhitespace(cur) || this.isDelimiter(cur)) break;
        this.pos++;
      }
      return new TextDecoder('latin1').decode(this.bytes.subarray(start, this.pos));
    }

    // Single character delimiters `(`, `)`, `[`, `]`, `<`, `>`
    if (this.isDelimiter(b)) {
      this.pos++;
      return String.fromCharCode(b);
    }

    // Regular token (keywords, numbers, booleans)
    const start = this.pos;
    while (this.pos < this.length) {
      const cur = this.bytes[this.pos];
      if (this.isWhitespace(cur) || this.isDelimiter(cur)) break;
      this.pos++;
    }

    return new TextDecoder('latin1').decode(this.bytes.subarray(start, this.pos));
  }

  /**
   * Parses literal string `(...)` supporting escape sequences and nested parens.
   * 이스케이프 및 중첩 괄호를 지원하는 리터럴 문자열을 파싱합니다.
   */
  parseLiteralString() {
    const bytes = [];
    let depth = 1;

    while (this.pos < this.length && depth > 0) {
      const b = this.bytes[this.pos++];
      if (b === 0x5c) { // Backslash '\'
        if (this.pos >= this.length) break;
        const next = this.bytes[this.pos++];
        if (next === 0x6e) bytes.push(0x0a); // \n
        else if (next === 0x72) bytes.push(0x0d); // \r
        else if (next === 0x74) bytes.push(0x09); // \t
        else if (next === 0x62) bytes.push(0x08); // \b
        else if (next === 0x66) bytes.push(0x0c); // \f
        else if (next === 0x28) bytes.push(0x28); // \(
        else if (next === 0x29) bytes.push(0x29); // \)
        else if (next === 0x5c) bytes.push(0x5c); // \\
        else if (next >= 0x30 && next <= 0x37) { // Octal \ddd
          let octal = String.fromCharCode(next);
          for (let k = 0; k < 2; k++) {
            if (this.pos < this.length && this.bytes[this.pos] >= 0x30 && this.bytes[this.pos] <= 0x37) {
              octal += String.fromCharCode(this.bytes[this.pos++]);
            } else {
              break;
            }
          }
          bytes.push(parseInt(octal, 8));
        } else if (next === 0x0d) { // \<EOL> line continuation
          if (this.pos < this.length && this.bytes[this.pos] === 0x0a) this.pos++;
        } else if (next === 0x0a) {
          // ignore newline
        } else {
          bytes.push(next);
        }
      } else if (b === 0x28) { // '('
        depth++;
        bytes.push(b);
      } else if (b === 0x29) { // ')'
        depth--;
        if (depth > 0) bytes.push(b);
      } else {
        bytes.push(b);
      }
    }
    return new PdfString(new Uint8Array(bytes), false);
  }

  /**
   * Parses hexadecimal string `< ... >`.
   * 16진수 문자열 `< ... >`을 파싱합니다.
   */
  parseHexString() {
    let hexStr = '';
    while (this.pos < this.length) {
      const b = this.bytes[this.pos++];
      if (b === 0x3e) break; // '>'
      if (!this.isWhitespace(b)) {
        hexStr += String.fromCharCode(b);
      }
    }
    if (hexStr.length % 2 !== 0) {
      hexStr += '0';
    }
    const byteLen = hexStr.length / 2;
    const out = new Uint8Array(byteLen);
    for (let i = 0; i < byteLen; i++) {
      out[i] = parseInt(hexStr.substr(i * 2, 2), 16);
    }
    return new PdfString(out, true);
  }

  /**
   * Parses PDF dictionary `<< ... >>`.
   * PDF 딕셔너리 `<< ... >>`을 파싱합니다.
   */
  parseDict() {
    const dict = new PdfDict();
    while (this.pos < this.length) {
      this.skipWhitespaceAndComments();
      if (this.bytes[this.pos] === 0x3e && this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x3e) {
        this.pos += 2; // '>>'
        break;
      }
      const keyToken = this.nextToken();
      if (!keyToken || keyToken === '>>') break;
      if (!keyToken.startsWith('/')) continue;

      const value = this.parseObjectValue();
      dict.set(keyToken, value);
    }
    return dict;
  }

  /**
   * Parses array `[ ... ]`.
   * 배열 `[ ... ]`을 재귀적으로 파싱합니다.
   */
  parseArray() {
    const arr = new PdfArray();
    while (this.pos < this.length) {
      this.skipWhitespaceAndComments();
      if (this.bytes[this.pos] === 0x5d) { // ']'
        this.pos++;
        break;
      }
      const val = this.parseObjectValue();
      if (val === ']' || (val === null && this.bytes[this.pos - 1] === 0x5d)) break;
      arr.push(val);
    }
    return arr;
  }

  /**
   * Parses any generic PDF object value.
   * 임의의 PDF 구문 객체 값을 파싱합니다.
   */
  parseObjectValue() {
    this.skipWhitespaceAndComments();
    if (this.pos >= this.length) return null;

    const b = this.bytes[this.pos];

    if (b === 0x28) { // '(' Literal string
      this.pos++;
      return this.parseLiteralString();
    }
    if (b === 0x3c) { // '<' Hex string or '<<' Dict
      if (this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x3c) {
        this.pos += 2;
        return this.parseDict();
      }
      this.pos++;
      return this.parseHexString();
    }
    if (b === 0x5b) { // '[' Array
      this.pos++;
      return this.parseArray();
    }
    if (b === 0x5d) { // ']' End of array
      this.pos++;
      return ']';
    }

    const token = this.nextToken();
    if (token === null) return null;

    if (token === 'true') return true;
    if (token === 'false') return false;
    if (token === 'null') return null;
    if (token.startsWith('/')) return token;

    // Number or Indirect Reference `num gen R`
    if (/^[+-]?\d+$/.test(token)) {
      const savedPos = this.pos;
      this.skipWhitespaceAndComments();
      const secondToken = this.nextToken();
      if (secondToken !== null && /^\d+$/.test(secondToken)) {
        this.skipWhitespaceAndComments();
        const thirdToken = this.nextToken();
        if (thirdToken === 'R') {
          return new PdfRef(parseInt(token, 10), parseInt(secondToken, 10));
        }
      }
      // Revert if not an indirect reference `num gen R`
      this.pos = savedPos;
      return parseInt(token, 10);
    }

    // Floating point number
    if (/^[+-]?\d*\.\d+$/.test(token)) {
      return parseFloat(token);
    }

    return token;
  }

  /**
   * Parses a stream content according to dictionary /Length or endstream marker.
   * 스트림 데이터를 파싱합니다.
   */
  parseStream(dict) {
    if (this.bytes[this.pos] === 0x0d && this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x0a) {
      this.pos += 2;
    } else if (this.bytes[this.pos] === 0x0a || this.bytes[this.pos] === 0x0d) {
      this.pos++;
    }

    let length = dict.get('/Length');
    let streamBytes;

    if (typeof length === 'number' && length >= 0 && this.pos + length <= this.length) {
      streamBytes = this.bytes.slice(this.pos, this.pos + length);
      this.pos += length;
      this.skipWhitespaceAndComments();
      const endToken = this.nextToken();
      if (endToken !== 'endstream') {
        this.pos -= length;
        streamBytes = this.scanUntilEndstream();
      }
    } else {
      streamBytes = this.scanUntilEndstream();
    }

    return new PdfStream(dict, streamBytes);
  }

  /**
   * Scans binary stream until `endstream` keyword is found.
   * `endstream` 키워드를 만날 때까지 바이너리 데이터를 안전하게 슬라이스합니다.
   */
  scanUntilEndstream() {
    const start = this.pos;
    const endstreamMarker = new Uint8Array([0x65, 0x6e, 0x64, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d]); // 'endstream'
    let found = -1;

    for (let i = this.pos; i <= this.length - 9; i++) {
      let match = true;
      for (let j = 0; j < 9; j++) {
        if (this.bytes[i + j] !== endstreamMarker[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        found = i;
        break;
      }
    }

    if (found === -1) {
      found = this.length;
    }

    let end = found;
    if (end > start && this.bytes[end - 1] === 0x0a) end--;
    if (end > start && this.bytes[end - 1] === 0x0d) end--;

    const streamBytes = this.bytes.slice(start, end);
    this.pos = found + 9;
    return streamBytes;
  }
}

/**
 * Parses a PDF binary buffer into a structured PdfDocument AST model.
 * PDF 바이너리 버퍼를 구조화된 PdfDocument AST 모델로 파싱합니다.
 * @param {Uint8Array|ArrayBuffer} buffer - PDF file bytes / PDF 파일 바이트 배열
 * @returns {PdfDocument}
 */
export function parsePdf(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const doc = new PdfDocument(bytes);

  // 1. Parse Header Version / PDF 버전 파싱
  const headerStr = new TextDecoder('latin1').decode(bytes.subarray(0, 32));
  const versionMatch = headerStr.match(/%PDF-(\d+\.\d+)/);
  if (versionMatch) {
    doc.headerVersion = versionMatch[1];
  }

  // 2. Scan and parse all Indirect Objects (`num gen obj ... endobj`)
  // 모든 간접 객체 스캔 및 파싱
  const text = new TextDecoder('latin1').decode(bytes);
  const objRegex = /(\d+)\s+(\d+)\s+obj/g;
  let match;

  while ((match = objRegex.exec(text)) !== null) {
    const objNum = parseInt(match[1], 10);
    const genNum = parseInt(match[2], 10);
    const objStartPos = match.index + match[0].length;

    const lexer = new PdfLexer(bytes);
    lexer.pos = objStartPos;

    const data = lexer.parseObjectValue();
    let stream = null;

    lexer.skipWhitespaceAndComments();
    const token = lexer.nextToken();
    if (token === 'stream' && data instanceof PdfDict) {
      stream = lexer.parseStream(data);
    }

    doc.setObject(objNum, genNum, data, stream);
  }

  // 3. Scan and extract Trailer Dictionary (`trailer << ... >>`)
  // 트레일러 딕셔너리 스캔 및 추출
  const trailerIdx = text.lastIndexOf('trailer');
  if (trailerIdx !== -1) {
    const trailerLexer = new PdfLexer(bytes);
    trailerLexer.pos = trailerIdx + 7;
    const trailerDict = trailerLexer.parseObjectValue();
    if (trailerDict instanceof PdfDict) {
      doc.trailer = trailerDict;
      const enc = trailerDict.get('/Encrypt');
      if (enc instanceof PdfRef) {
        doc.encryptRef = enc;
      }
    }
  }

  // 3-B. Scan for modern PDF 1.5+ Cross-Reference Streams (`/Type /XRef`)
  for (const obj of doc.objects.values()) {
    if (obj.data instanceof PdfDict && obj.data.get('/Type') === '/XRef') {
      for (const [k, v] of obj.data.map.entries()) {
        if (!doc.trailer.has(k)) {
          doc.trailer.set(k, v);
        }
      }
      if (!doc.encryptRef && obj.data.has('/Encrypt')) {
        const enc = obj.data.get('/Encrypt');
        if (enc instanceof PdfRef) {
          doc.encryptRef = enc;
        }
      }
    }
  }

  // 3-C. Fallback check for Standard Encryption Dictionary object (/Filter /Standard, /V 1..5, has /U and /O)
  if (!doc.encryptRef) {
    for (const obj of doc.objects.values()) {
      if (obj.data instanceof PdfDict) {
        const filter = obj.data.get('/Filter');
        const v = obj.data.get('/V');
        if (typeof filter === 'string' && (filter === '/Standard' || filter.startsWith('/Adobe')) &&
            typeof v === 'number' && obj.data.has('/U') && obj.data.has('/O')) {
          doc.encryptRef = new PdfRef(obj.num, obj.gen);
          if (!doc.trailer.has('/Encrypt')) {
            doc.trailer.set('/Encrypt', doc.encryptRef);
          }
          break;
        }
      }
    }
  }

  return doc;
}
