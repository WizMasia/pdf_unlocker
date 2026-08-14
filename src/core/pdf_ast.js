/**
 * @file src/core/pdf_ast.js
 * @description PDF Abstract Syntax Tree (AST) Data Structures & Object Model.
 *              PDF 표준 구문 트리(AST) 자료구조 및 객체 모델.
 */

/**
 * Represents an Indirect Reference in PDF (e.g. `3 0 R`).
 * PDF 간접 객체 참조 (`3 0 R`) 모델.
 */
export class PdfRef {
  /**
   * @param {number|string} num - Object Number / 객체 번호
   * @param {number|string} [gen=0] - Generation Number / 세대 번호
   */
  constructor(num, gen = 0) {
    this.num = Number(num);
    this.gen = Number(gen);
  }

  toString() {
    return `${this.num} ${this.gen} R`;
  }
}

/**
 * Represents a Binary/Literal or Hexadecimal String in PDF.
 * PDF 바이너리/리터럴 또는 16진수 문자열 (`(Text)` 또는 `<48656C6C6F>`) 모델.
 */
export class PdfString {
  /**
   * @param {Uint8Array|Array<number>|string} bytes - Raw string bytes / 원시 바이트
   * @param {boolean} [isHex=false] - Whether to format as hex string / 16진수 문자열 포맷 여부
   */
  constructor(bytes, isHex = false) {
    if (typeof bytes === 'string') {
      this.bytes = new TextEncoder().encode(bytes);
    } else if (bytes instanceof Uint8Array) {
      this.bytes = bytes;
    } else {
      this.bytes = new Uint8Array(bytes);
    }
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

    // Literal string with standard PDF escape sequences / 표준 이스케이프 문자열
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

/**
 * Represents a PDF Dictionary (`<< /Key Value >>`).
 * PDF 딕셔너리 (`<< /Key Value >>`) 모델.
 */
export class PdfDict {
  constructor() {
    this.map = new Map(); // Key: '/Name', Value: any
  }

  /**
   * Sets key-value pair. Ensures key starts with '/'.
   * 키-값 쌍을 저장합니다. (키 앞 슬래시 자동 보정)
   * @param {string} key
   * @param {*} val
   */
  set(key, val) {
    const k = key.startsWith('/') ? key : '/' + key;
    this.map.set(k, val);
  }

  /**
   * Retrieves value by key.
   * 키에 해당하는 값을 반환합니다.
   * @param {string} key
   * @returns {*}
   */
  get(key) {
    const k = key.startsWith('/') ? key : '/' + key;
    return this.map.get(k);
  }

  /**
   * Checks if dictionary has key.
   * 키 존재 여부를 확인합니다.
   * @param {string} key
   * @returns {boolean}
   */
  has(key) {
    const k = key.startsWith('/') ? key : '/' + key;
    return this.map.has(k);
  }

  /**
   * Deletes a key.
   * 키를 삭제합니다.
   * @param {string} key
   * @returns {boolean}
   */
  delete(key) {
    const k = key.startsWith('/') ? key : '/' + key;
    return this.map.delete(k);
  }

  /**
   * Returns iterator of [key, value] pairs.
   * @returns {IterableIterator<[string, *]>}
   */
  entries() {
    return this.map.entries();
  }

  /**
   * Clones dictionary.
   * @returns {PdfDict}
   */
  clone() {
    const c = new PdfDict();
    for (const [k, v] of this.map.entries()) {
      c.set(k, v);
    }
    return c;
  }
}

/**
 * Represents a PDF Array (`[ ... ]`).
 * PDF 배열 (`[ ... ]`) 모델.
 */
export class PdfArray {
  /**
   * @param {Array} [items=[]]
   */
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

  clone() {
    return new PdfArray([...this.items]);
  }
}

/**
 * Represents a PDF Stream (`stream ... endstream`).
 * PDF 스트림 데이터 (`stream ... endstream`) 모델.
 */
export class PdfStream {
  /**
   * @param {PdfDict} dict - Stream metadata dictionary / 스트림 메타데이터 딕셔너리
   * @param {Uint8Array} bytes - Raw stream bytes / 원시 스트림 바이트 배열
   */
  constructor(dict, bytes) {
    this.dict = dict instanceof PdfDict ? dict : new PdfDict();
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  }
}

/**
 * Represents an Indirect Object (`1 0 obj ... endobj`).
 * PDF 간접 객체 (`1 0 obj ... endobj`) 모델.
 */
export class PdfObject {
  /**
   * @param {number} num - Object Number / 객체 번호
   * @param {number} gen - Generation Number / 세대 번호
   * @param {*} data - AST Data (PdfDict, PdfArray, PdfString, number, etc.) / AST 데이터
   * @param {PdfStream|null} [stream=null] - Stream if present / 스트림 데이터
   */
  constructor(num, gen, data, stream = null) {
    this.num = Number(num);
    this.gen = Number(gen);
    this.data = data;
    this.stream = stream;
  }
}

/**
 * Complete In-Memory Representation of a PDF Document.
 * PDF 문서의 전체 메모리 모델.
 */
export class PdfDocument {
  /**
   * @param {Uint8Array} bytes - Source file binary bytes / 소스 파일 바이너리
   */
  constructor(bytes) {
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.headerVersion = '1.7';
    this.trailer = new PdfDict();
    this.encryptRef = null;
    this.objects = new Map(); // Key: `${num}_${gen}`, Value: PdfObject
  }

  /**
   * Retrieves an object by object number and generation.
   * 객체 번호와 세대 번호로 객체를 조회합니다.
   * @param {number} num
   * @param {number} [gen=0]
   * @returns {PdfObject|undefined}
   */
  getObject(num, gen = 0) {
    return this.objects.get(`${num}_${gen}`);
  }

  /**
   * Sets or updates an indirect object in document.
   * 간접 객체를 등록 또는 업데이트합니다.
   * @param {number} num
   * @param {number} gen
   * @param {*} data
   * @param {PdfStream|null} [stream=null]
   * @returns {PdfObject}
   */
  setObject(num, gen, data, stream = null) {
    const obj = new PdfObject(num, gen, data, stream);
    this.objects.set(`${num}_${gen}`, obj);
    return obj;
  }

  /**
   * Deletes an object by number.
   * 객체를 삭제합니다.
   * @param {number} num
   * @param {number} [gen=0]
   */
  deleteObject(num, gen = 0) {
    this.objects.delete(`${num}_${gen}`);
  }
}
