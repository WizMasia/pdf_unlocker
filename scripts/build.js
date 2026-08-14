/**
 * @file scripts/build.js
 * @description Single-file HTML bundler that inlines all CSS and JS modules into dist/index.html.
 *              모든 CSS 및 JS 모듈을 dist/index.html로 인라인 결합하는 단일 파일 HTML 번들러.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const srcDir = path.join(rootDir, 'src');
const distDir = path.join(rootDir, 'dist');

/**
 * Strips ES module export / import statements for inline bundle compatibility.
 * 인라인 번들 호환성을 위해 ES 모듈 export / import 구문을 브라우저 단일 스크립트용으로 정리합니다.
 * @param {string} code - Source JS code / 원본 JS 코드
 * @returns {string} Cleaned code / 정제된 코드
 */
function cleanModuleCode(code) {
  return code
    // Remove import statements / import 구문 제거
    .replace(/^import\s+[\s\S]*?from\s+['"][^'"]+['"];?/gm, '')
    // Remove export default statements -> assign to const / export default 구문 치환
    .replace(/^export\s+default\s+/gm, '')
    // Remove export declarations -> keep declaration / export 키워드 제거
    .replace(/^export\s+(const|let|var|function|class|async\s+function)\s+/gm, '$1 ')
    // Remove named export blocks / named export 블록 제거 (e.g. export { a, b };)
    .replace(/^export\s*\{[\s\S]*?\};?/gm, '')
    .trim();
}

/**
 * Builds the standalone single HTML file.
 * 단일 독립형 HTML 파일을 빌드합니다.
 */
export function buildSingleFile() {
  if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
  }

  let html = fs.readFileSync(path.join(srcDir, 'index.html'), 'utf-8');

  // 1. Inline CSS / CSS 인라인 삽입
  const cssMatches = html.match(/<link\s+rel=["']stylesheet["']\s+href=["']([^"']+)["']\s*\/?>/gi) || [];
  for (const match of cssMatches) {
    const hrefMatch = match.match(/href=["']([^"']+)["']/i);
    if (hrefMatch && hrefMatch[1]) {
      const cssPath = path.join(srcDir, hrefMatch[1]);
      if (fs.existsSync(cssPath)) {
        const cssContent = fs.readFileSync(cssPath, 'utf-8');
        html = html.replace(match, `<style>\n/* Inlined: ${hrefMatch[1]} */\n${cssContent}\n</style>`);
      }
    }
  }

  // 2. Inline JS modules in specific dependency order / 정해진 의존성 순서대로 JS 모듈 인라인 삽입
  const jsModules = [
    'ui/i18n.js',
    'core/crypto.js',
    'core/pdf_ast.js',
    'core/pdf_parser.js',
    'core/pdf_security.js',
    'core/pdf_decryptor.js',
    'core/pdf_serializer.js',
    'ui/app.js'
  ];

  // Remove existing script tags pointing to src files / 기존 script 태그 제거
  html = html.replace(/<script\s+type=["']module["']\s+src=["'][^"']+["']><\/script>/gi, '');
  html = html.replace(/<script\s+src=["'][^"']+["']><\/script>/gi, '');

  let combinedJs = '/* ==========================================================================\n' +
                    ' * PDF Permission Master - Standalone Offline Bundle\n' +
                    ' * 100% Client-side, Zero Network Calls, Privacy Protected\n' +
                    ' * ========================================================================== */\n\n';

  for (const moduleRelPath of jsModules) {
    const fullPath = path.join(srcDir, moduleRelPath);
    if (fs.existsSync(fullPath)) {
      const rawCode = fs.readFileSync(fullPath, 'utf-8');
      const processedCode = cleanModuleCode(rawCode);
      combinedJs += `/* Module: ${moduleRelPath} */\n${processedCode}\n\n`;
    }
  }

  // Wrap in IIFE for clean scope isolation / 깔끔한 스코프 격리를 위해 IIFE로 감싸기
  const bundledScript = `<script>\n(function() {\n'use strict';\n\n${combinedJs}\n})();\n</script>`;

  // Insert before </body> / </body> 앞에 스크립트 삽입
  if (html.includes('</body>')) {
    html = html.replace('</body>', `${bundledScript}\n</body>`);
  } else {
    html += bundledScript;
  }

  const outputPath = path.join(distDir, 'index.html');
  fs.writeFileSync(outputPath, html, 'utf-8');
  console.log(`[Build Success] Standalone HTML created at: ${outputPath} (${(Buffer.byteLength(html, 'utf-8') / 1024).toFixed(2)} KB)`);
  return outputPath;
}

// Run when executed directly / 직접 실행 시 빌드 수행
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  buildSingleFile();
}
