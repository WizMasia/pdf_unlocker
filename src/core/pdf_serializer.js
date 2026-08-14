/**
 * @file src/core/pdf_serializer.js
 * @description Lossless PDF Serializer and Rebuilder (Strips /Encrypt, recalculates XRef & offsets).
 *              무손실 PDF 직렬화기 및 재작성기 (/Encrypt 제거, 교차 참조 테이블 및 오프셋 재계산).
 */

import { PdfDict, PdfArray, PdfString, PdfRef, PdfStream } from './pdf_parser.js';

/**
 * Serializes an AST node value to a PDF compliant string/byte format.
 * 구문 트리 노드 값을 PDF 표준 문자열 표현으로 직렬화합니다.
 * @param {*} val - AST value node / 구문 트리 노드
 * @returns {string}
 */
export function serializeValue(val) {
  if (val === null || val === undefined) return 'null';
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  if (typeof val === 'number') return String(val);
  if (val instanceof PdfRef) return `${val.num} ${val.gen} R`;
  if (val instanceof PdfString) return val.toString();

  if (typeof val === 'string') {
    return val.startsWith('/') ? val : '/' + val;
  }

  if (val instanceof PdfArray) {
    let out = '[';
    for (let i = 0; i < val.length; i++) {
      out += (i > 0 ? ' ' : '') + serializeValue(val.get(i));
    }
    out += ']';
    return out;
  }

  if (val instanceof PdfDict) {
    let out = '<<\n';
    for (const [k, v] of val.entries()) {
      out += `  ${k} ${serializeValue(v)}\n`;
    }
    out += '>>';
    return out;
  }

  return String(val);
}

/**
 * Serializes a decrypted PdfDocument into a standard unencrypted PDF binary buffer.
 * 복호화된 PdfDocument를 표준 비암호화 PDF 바이너리 버퍼로 재작성합니다.
 * @param {PdfDocument} doc - Decrypted PDF document model / 복호화된 PDF 문서 모델
 * @returns {Uint8Array} Unencrypted valid PDF bytes / 비암호화 유효 PDF 바이트 배열
 */
export function serializePdf(doc) {
  const encNum = doc.encryptRef ? doc.encryptRef.num : (doc.trailer.get('/Encrypt') ? doc.trailer.get('/Encrypt').num : null);

  // 1. Clean trailer dictionary / 트레일러에서 /Encrypt 제거
  doc.trailer.delete('/Encrypt');
  doc.encryptRef = null;

  const headerStr = `%PDF-${doc.headerVersion || '1.6'}\n%\xE2\xE3\xCF\xD3\n`;
  const chunks = [new TextEncoder().encode(headerStr)];
  let currentOffset = chunks[0].length;

  // 2. Sort and serialize all objects except the old Encrypt dictionary
  // 이전 Encrypt 딕셔너리를 제외한 모든 객체를 번호순으로 정렬 및 직렬화
  const sortedObjects = [...doc.objects.values()]
    .filter(obj => obj.num !== encNum)
    .sort((a, b) => a.num - b.num);

  const offsets = new Map(); // Key: objNum, Value: byteOffset
  let maxObjNum = 0;

  for (const obj of sortedObjects) {
    maxObjNum = Math.max(maxObjNum, obj.num);
    offsets.set(obj.num, currentOffset);

    let objHeader = `${obj.num} ${obj.gen} obj\n`;
    let objBody = '';

    if (obj.stream) {
      // Ensure Length in stream dict matches decrypted stream bytes
      obj.stream.dict.set('/Length', obj.stream.bytes.length);
      objBody = serializeValue(obj.stream.dict) + '\nstream\n';
    } else {
      objBody = serializeValue(obj.data) + '\n';
    }

    const headerBytes = new TextEncoder().encode(objHeader + objBody);
    chunks.push(headerBytes);
    currentOffset += headerBytes.length;

    if (obj.stream) {
      // Append raw stream bytes + endstream
      chunks.push(obj.stream.bytes);
      currentOffset += obj.stream.bytes.length;

      const endStreamBytes = new TextEncoder().encode('\nendstream\nendobj\n');
      chunks.push(endStreamBytes);
      currentOffset += endStreamBytes.length;
    } else {
      const endObjBytes = new TextEncoder().encode('endobj\n');
      chunks.push(endObjBytes);
      currentOffset += endObjBytes.length;
    }
  }

  // 3. Build new Cross-Reference Table (xref)
  // 신규 교차 참조 테이블(xref) 작성
  const startXrefOffset = currentOffset;
  let xrefStr = `xref\n0 ${maxObjNum + 1}\n0000000000 65535 f \n`;

  for (let i = 1; i <= maxObjNum; i++) {
    const off = offsets.get(i);
    if (off !== undefined) {
      xrefStr += `${String(off).padStart(10, '0')} 00000 n \n`;
    } else {
      xrefStr += `0000000000 65535 f \n`;
    }
  }

  // 4. Update Trailer and write startxref / %%EOF
  // 트레일러 업데이트 및 startxref / %%EOF 작성
  doc.trailer.set('/Size', maxObjNum + 1);
  let trailerStr = `trailer\n${serializeValue(doc.trailer)}\nstartxref\n${startXrefOffset}\n%%EOF\n`;

  const xrefBytes = new TextEncoder().encode(xrefStr + trailerStr);
  chunks.push(xrefBytes);
  currentOffset += xrefBytes.length;

  // 5. Concatenate all chunks into a single Uint8Array
  // 모든 청크를 하나의 Uint8Array로 결합
  const finalPdf = new Uint8Array(currentOffset);
  let writeOffset = 0;
  for (const chunk of chunks) {
    finalPdf.set(chunk, writeOffset);
    writeOffset += chunk.length;
  }

  return finalPdf;
}
