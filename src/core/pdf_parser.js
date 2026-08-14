/**
 * @file src/core/pdf_parser.js
 * @description High-Performance Binary PDF Lexer, Parser, and Object Extractor.
 *              고성능 저수준 바이너리 PDF 렉서, 파서 및 객체 추출기.
 */

import {
  PdfRef,
  PdfString,
  PdfDict,
  PdfArray,
  PdfStream,
  PdfObject,
  PdfDocument
} from './pdf_ast.js';

export {
  PdfRef,
  PdfString,
  PdfDict,
  PdfArray,
  PdfStream,
  PdfObject,
  PdfDocument
};

/* ==========================================================================
 * PDF Binary Lexer Implementation / 바이너리 렉서 구현
 * ========================================================================== */

export class PdfLexer {
  /**
   * @param {Uint8Array} bytes
   */
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
      } else if (b === 0x25) { // '%' Comment line
        while (this.pos < this.length && this.bytes[this.pos] !== 0x0a && this.bytes[this.pos] !== 0x0d) {
          this.pos++;
        }
      } else {
        break;
      }
    }
  }

  peekByte() {
    return this.pos < this.length ? this.bytes[this.pos] : -1;
  }

  nextByte() {
    return this.pos < this.length ? this.bytes[this.pos++] : -1;
  }

  /**
   * Reads next token.
   * 다음 토큰을 읽습니다.
   * @returns {string|null}
   */
  nextToken() {
    this.skipWhitespaceAndComments();
    if (this.pos >= this.length) return null;

    const b = this.bytes[this.pos];

    // Multi-char delimiters
    if (b === 0x3c) { // '<' or '<<'
      if (this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x3c) {
        this.pos += 2;
        return '<<';
      }
    }
    if (b === 0x3e) { // '>' or '>>'
      if (this.pos + 1 < this.length && this.bytes[this.pos + 1] === 0x3e) {
        this.pos += 2;
        return '>>';
      }
    }

    // Single character delimiters
    if (b === 0x28 || b === 0x29 || b === 0x5b || b === 0x5d || b === 0x7b || b === 0x7d || b === 0x3c || b === 0x3e) {
      this.pos++;
      return String.fromCharCode(b);
    }

    // PDF Name: starts with '/'
    if (b === 0x2f) {
      this.pos++;
      let name = '/';
      while (this.pos < this.length) {
        const nb = this.bytes[this.pos];
        if (this.isWhitespace(nb) || this.isDelimiter(nb)) break;
        if (nb === 0x23 && this.pos + 2 < this.length) { // '#HEX' escape in Name
          const hex = String.fromCharCode(this.bytes[this.pos + 1], this.bytes[this.pos + 2]);
          const charCode = parseInt(hex, 16);
          if (!isNaN(charCode)) {
            name += String.fromCharCode(charCode);
            this.pos += 3;
            continue;
          }
        }
        name += String.fromCharCode(nb);
        this.pos++;
      }
      return name;
    }

    // Regular literal token
    let token = '';
    while (this.pos < this.length) {
      const nb = this.bytes[this.pos];
      if (this.isWhitespace(nb) || this.isDelimiter(nb)) break;
      token += String.fromCharCode(nb);
      this.pos++;
    }
    return token;
  }

  /**
   * Parses literal string `(...)`.
   * 리터럴 문자열 `(...)`을 파싱합니다.
   */
  parseLiteralString() {
    if (this.bytes[this.pos - 1] !== 0x28 && this.nextByte() !== 0x28) {
      return new PdfString(new Uint8Array(0));
    }

    const chunks = [];
    let depth = 1;

    while (this.pos < this.length && depth > 0) {
      const b = this.bytes[this.pos++];
      if (b === 0x5c) { // Escape '\'
        if (this.pos >= this.length) break;
        const esc = this.bytes[this.pos++];
        if (esc === 0x6e) chunks.push(0x0a); // \n
        else if (esc === 0x72) chunks.push(0x0d); // \r
        else if (esc === 0x74) chunks.push(0x09); // \t
        else if (esc === 0x62) chunks.push(0x08); // \b
        else if (esc === 0x66) chunks.push(0x0c); // \f
        else if (esc === 0x28) chunks.push(0x28); // \(
        else if (esc === 0x29) chunks.push(0x29); // \)
        else if (esc === 0x5c) chunks.push(0x5c); // \\
        else if (esc >= 0x30 && esc <= 0x37) { // Octal \ddd
          let octStr = String.fromCharCode(esc);
          if (this.pos < this.length && this.bytes[this.pos] >= 0x30 && this.bytes[this.pos] <= 0x37) {
            octStr += String.fromCharCode(this.bytes[this.pos++]);
            if (this.pos < this.length && this.bytes[this.pos] >= 0x30 && this.bytes[this.pos] <= 0x37) {
              octStr += String.fromCharCode(this.bytes[this.pos++]);
            }
          }
          chunks.push(parseInt(octStr, 8));
        } else if (esc === 0x0a || esc === 0x0d) {
          // Line continuation / 줄 바꿈 무시
          if (esc === 0x0d && this.pos < this.length && this.bytes[this.pos] === 0x0a) {
            this.pos++;
          }
        } else {
          chunks.push(esc);
        }
      } else if (b === 0x28) {
        depth++;
        chunks.push(b);
      } else if (b === 0x29) {
        depth--;
        if (depth > 0) chunks.push(b);
      } else {
        chunks.push(b);
      }
    }

    return new PdfString(new Uint8Array(chunks), false);
  }

  /**
   * Parses hexadecimal string `<...>`.
   * 16진수 문자열 `<...>`을 파싱합니다.
   */
  parseHexString() {
    let hex = '';
    while (this.pos < this.length) {
      const b = this.bytes[this.pos++];
      if (b === 0x3e) break; // '>'
      if (!this.isWhitespace(b)) {
        hex += String.fromCharCode(b);
      }
    }
    if (hex.length % 2 !== 0) hex += '0';
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16) || 0;
    }
    return new PdfString(bytes, true);
  }

  /**
   * Parses dictionary `<< ... >>`.
   * 딕셔너리 `<< ... >>`를 재귀적으로 파싱합니다.
   */
  parseDict() {
    const dict = new PdfDict();
    while (this.pos < this.length) {
      this.skipWhitespaceAndComments();
      if (this.pos + 1 < this.length && this.bytes[this.pos] === 0x3e && this.bytes[this.pos + 1] === 0x3e) {
        this.pos += 2;
        break;
      }
      const token = this.nextToken();
      if (!token || token === '>>') break;
      if (!token.startsWith('/')) continue;

      const val = this.parseObjectValue();
      dict.set(token, val);
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
      if (val === ']' || val === null && this.bytes[this.pos - 1] === 0x5d) break;
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
      const num = parseInt(token, 10);
      const savedPos = this.pos;
      const next1 = this.nextToken();
      if (next1 && /^\d+$/.test(next1)) {
        const next2 = this.nextToken();
        if (next2 === 'R') {
          return new PdfRef(num, parseInt(next1, 10));
        }
      }
      // Revert if not a reference
      this.pos = savedPos;
      return num;
    }

    if (/^[+-]?\d*\.\d+$/.test(token)) {
      return parseFloat(token);
    }

    return token;
  }

  /**
   * Parses stream data following a dictionary.
   * 딕셔너리 뒤에 오는 스트림 바이너리 데이터를 안전하게 추출합니다.
   * @param {PdfDict} dict
   * @returns {PdfStream}
   */
  parseStream(dict) {
    // Skip whitespaces immediately following keyword 'stream'
    let b = this.nextByte();
    if (b === 0x0d) { // \r
      if (this.peekByte() === 0x0a) this.nextByte(); // \n
    }

    const streamStart = this.pos;
    let streamEnd = -1;

    // Try resolving /Length from dictionary
    const lengthVal = dict.get('/Length');
    if (typeof lengthVal === 'number' && lengthVal >= 0 && streamStart + lengthVal <= this.length) {
      streamEnd = streamStart + lengthVal;
      this.pos = streamEnd;
    } else {
      // Fallback: Scan for '\nendstream' or '\rendstream' or 'endstream'
      const endstream = new TextEncoder().encode('endstream');
      for (let i = streamStart; i <= this.length - endstream.length; i++) {
        let match = true;
        for (let j = 0; j < endstream.length; j++) {
          if (this.bytes[i + j] !== endstream[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          streamEnd = i;
          // Trim preceding \r\n or \n or \r
          if (streamEnd > streamStart && this.bytes[streamEnd - 1] === 0x0a) {
            streamEnd--;
            if (streamEnd > streamStart && this.bytes[streamEnd - 1] === 0x0d) streamEnd--;
          } else if (streamEnd > streamStart && this.bytes[streamEnd - 1] === 0x0d) {
            streamEnd--;
          }
          this.pos = i + endstream.length;
          break;
        }
      }
    }

    if (streamEnd === -1) streamEnd = this.length;
    const streamBytes = this.bytes.slice(streamStart, streamEnd);
    return new PdfStream(dict, streamBytes);
  }
}

/* ==========================================================================
 * PDF Parser Top-Level Engine / PDF 파서 최상위 엔진
 * ========================================================================== */

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

  // Fallback check if any object is an /Encrypt dictionary
  if (!doc.encryptRef) {
    for (const obj of doc.objects.values()) {
      if (obj.data instanceof PdfDict && obj.data.has('/Filter') && obj.data.has('/V')) {
        doc.encryptRef = new PdfRef(obj.num, obj.gen);
        if (!doc.trailer.has('/Encrypt')) {
          doc.trailer.set('/Encrypt', doc.encryptRef);
        }
        break;
      }
    }
  }

  return doc;
}
