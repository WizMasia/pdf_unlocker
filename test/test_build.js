/**
 * @file test/test_build.js
 * @description Unit tests for single-file HTML bundler.
 *              단일 파일 HTML 번들러 단위 테스트.
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildSingleFile } from '../scripts/build.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

console.log('Testing build script...');

const distHtmlPath = buildSingleFile();

assert.ok(fs.existsSync(distHtmlPath), 'dist/index.html should exist');
const htmlContent = fs.readFileSync(distHtmlPath, 'utf-8');

// Verification checks / 검증 조건
assert.ok(htmlContent.includes('<style>'), 'Should contain inline style tag');
assert.ok(!htmlContent.includes('<link rel="stylesheet" href="styles/main.css">'), 'Should not contain external CSS link');
assert.ok(htmlContent.includes('PDF Permission Unlocker'), 'Should contain app title');
assert.ok(htmlContent.includes('<script>'), 'Should contain inline script tag');

console.log('✅ Build script test passed successfully!');
