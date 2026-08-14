# PDF 권한 해제 모듈식 개발 및 단일 HTML 번들링 구현 계획 (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 개발 단계에서는 HTML, CSS, JS를 모듈식으로 분리하여 개발하고, 인쇄·복사·편집 등 각종 권한 제한 PDF를 자체 생성하여 완전한 무손실 해제 검증을 수행하며, 릴리즈 시 외부 의존성 없는 단일 독립형 HTML 파일로 결합하여 GitHub 퍼블릭 저장소 생성 및 v0.1.0 릴리즈를 배포.

**Architecture:** 개발 소스는 `src/` 하위에 HTML, CSS, 코어 엔진(Crypto, Parser, Decryptor, Serializer), UI(i18n, App)로 모듈화하여 개발하고, `test/generate_fixtures.js`로 다양한 권한 제한 테스트 PDF를 자동 생성하여 검증 후 `scripts/build.js`로 단일 `dist/index.html` 번들링. 최종 산출물을 GitHub 퍼블릭 저장소에 푸시하고 v0.1.0 릴리즈 태그 및 에셋 배포.

**Tech Stack:** HTML5, Vanilla CSS3, ES6+ JavaScript, Node.js (테스트 및 빌드용), GitHub CLI (`gh`).

---

### Task 1: 프로젝트 구조 초기화 및 빌드 스크립트 작성 (Project Setup & Build Tool)

**Files:**
- Create: `package.json`
- Create: `scripts/build.js`
- Create: `src/index.html`
- Create: `src/styles/main.css`
- Test: `test/test_build.js`

- [ ] **Step 1: 빌드 테스트 작성 (`test/test_build.js`)**
  - 모듈식 소스 파일들을 읽어 하나의 HTML 파일로 결합하는 로직 검증

- [ ] **Step 2: 프로젝트 패키지 설정 및 빌더 구현 (`package.json`, `scripts/build.js`)**
  - CSS 및 JS 모듈을 인라인으로 치환하여 `dist/index.html` 생성하는 빌드 스크립트

- [ ] **Step 3: 빌드 테스트 실행 및 통과 확인**
  - `node test/test_build.js`

---

### Task 2: 암호화 및 해시 코어 모듈 구현 (Crypto Engine)

**Files:**
- Create: `src/core/crypto.js`
- Test: `test/test_crypto.js`

- [ ] **Step 1: 암호화 단위 테스트 작성 (`test/test_crypto.js`)**
  - MD5, SHA-256 해시 검증
  - RC4 40/128-bit 스트림 암복호화 검증
  - AES-128-CBC / AES-256-CBC 복호화 검증

- [ ] **Step 2: 순수 JS 암호화 모듈 구현 (`src/core/crypto.js`)**
  - MD5, SHA-256, RC4, AES 구현 (Node.js 및 브라우저 공용 모듈 export)

- [ ] **Step 3: 테스트 실행 및 통과 확인**
  - `node test/test_crypto.js`

---

### Task 3: 권한 제한 테스트 PDF 픽스처 생성기 구현 (Test Fixture Generator)

**Files:**
- Create: `test/generate_fixtures.js`
- Output: `test/fixtures/*.pdf`

- [ ] **Step 1: 권한 비트별 테스트 PDF 생성 스크립트 작성 (`test/generate_fixtures.js`)**
  - 인쇄 제한 PDF (`test/fixtures/restricted_print.pdf`)
  - 클립보드 복사/추출 제한 PDF (`test/fixtures/restricted_copy.pdf`)
  - 수정/주석/양식 제한 PDF (`test/fixtures/restricted_modify.pdf`)
  - 전체 권한 제한 RC4-128 PDF (`test/fixtures/restricted_all_rc4.pdf`)
  - 전체 권한 제한 AES-128 PDF (`test/fixtures/restricted_all_aes.pdf`)
  - 열기 암호 설정 PDF (`test/fixtures/password_open.pdf`)
  - 비암호화 일반 PDF (`test/fixtures/unencrypted.pdf`)

- [ ] **Step 2: 테스트 픽스처 생성 실행 및 확인**
  - `node test/generate_fixtures.js`

---

### Task 4: PDF 저수준 파서 및 렉서 구현 (PDF Parser & Lexer)

**Files:**
- Create: `src/core/pdf_parser.js`
- Test: `test/test_pdf_parser.js`

- [ ] **Step 1: 파서 단위 테스트 작성 (`test/test_pdf_parser.js`)**
  - 생성된 테스트 픽스처 대상 토큰 렉싱 (Dictionaries, Arrays, Strings, Streams, Numbers)
  - 전통적 xref 테이블 및 PDF 1.5+ XRef Streams 디코딩
  - Trailer 및 `/Encrypt` 딕셔너리 파싱 검증

- [ ] **Step 2: PDF 저수준 파서 구현 (`src/core/pdf_parser.js`)**
  - 바이너리 토크나이저 및 재귀적 객체 파서
  - XRef 테이블/스트림 파서 및 객체 인덱스 맵 생성

- [ ] **Step 3: 테스트 실행 및 통과 확인**
  - `node test/test_pdf_parser.js`

---

### Task 5: Standard Security Handler & 복호화 엔진 구현 (Security Handler & Decryptor)

**Files:**
- Create: `src/core/pdf_decryptor.js`
- Test: `test/test_pdf_decryptor.js`

- [ ] **Step 1: 복호화 단위 테스트 작성 (`test/test_pdf_decryptor.js`)**
  - 생성된 권한 제한 픽스처 대상 복호화 및 권한 비트 해제 검증
  - R2, R3 (RC4) 키 유도 및 객체 복호화
  - R4 (AES-128) Crypt Filter 분석 및 복호화
  - 권한 비트(P) 분석 및 해제 확인

- [ ] **Step 2: PDF 복호화기 구현 (`src/core/pdf_decryptor.js`)**
  - 빈 패스워드 `""` 기반 파일 암호화 키(FEK) 파생 로직
  - 객체별 복호화 키 유도 및 모든 스트림/문자열 무손실 복호화

- [ ] **Step 3: 테스트 실행 및 통과 확인**
  - `node test/test_pdf_decryptor.js`

---

### Task 6: PDF 직렬화기 및 재작성기 구현 (PDF Serializer & Rebuilder)

**Files:**
- Create: `src/core/pdf_serializer.js`
- Test: `test/test_pdf_serializer.js`

- [ ] **Step 1: 직렬화 단위 테스트 작성 (`test/test_pdf_serializer.js`)**
  - Trailer에서 `/Encrypt` 항목 제거 검증
  - 신규 xref 테이블 및 startxref, %%EOF 생성 무결성 검증

- [ ] **Step 2: PDF 직렬화기 구현 (`src/core/pdf_serializer.js`)**
  - 복호화된 PDF 객체들을 바이너리 스트림으로 변환
  - 바이트 오프셋 계산 및 표준 비암호화 PDF Blob 생성

- [ ] **Step 3: 테스트 실행 및 통과 확인**
  - `node test/test_pdf_serializer.js`

---

### Task 7: UI 레이어 및 다국어 모듈 구현 (Modular UI Layer)

**Files:**
- Create: `src/ui/i18n.js`
- Create: `src/ui/app.js`
- Modify: `src/index.html`
- Modify: `src/styles/main.css`

- [ ] **Step 1: 다국어 사전 구현 (`src/ui/i18n.js`)**
  - 하드코딩 방지를 위한 한/영 UI 텍스트, 권한 설명, 안내 메시지 정의
- [ ] **Step 2: 모던 CSS 스타일링 (`src/styles/main.css`)**
  - HSL 컬러 시스템, 글래스모피즘, 드래그앤드롭 영역, 권한 뱃지, 프로그레스 바
- [ ] **Step 3: UI 컨트롤러 구현 (`src/ui/app.js`)**
  - 드래그 앤 드롭 이벤트, 파일 큐 관리, 실시간 권한 분석 인스펙터, 개별/일괄 다운로드

---

### Task 8: 릴리즈 번들링 및 종합 E2E 검증 (Release & Verification)

**Files:**
- Create: `test/run_e2e_tests.js`
- Create: `README.md`
- Output: `dist/index.html`

- [ ] **Step 1: 릴리즈 빌드 실행 (`node scripts/build.js`)**
  - 모든 CSS 및 JS가 인라인된 독립형 단일 파일 `dist/index.html` 생성
- [ ] **Step 2: 종합 E2E 테스트 실행 (`node test/run_e2e_tests.js`)**
  - 7가지 권한 제한 PDF 픽스처 전체 해제 및 무손실 무결성 검증
- [ ] **Step 3: `README.md` 및 `.gitignore` 작성**

---

### Task 9: GitHub 저장소 생성, 푸시 및 v0.1.0 릴리즈 배포 (GitHub Release)

- [ ] **Step 1: Git 저장소 초기화 및 커밋**
  - `git init`, `git add .`, `git commit -m "feat: initial release v0.1.0 - PDF Permission Unlocker"`
- [ ] **Step 2: GitHub 퍼블릭 리포지토리 생성 및 푸시**
  - `gh repo create pdf_unlocker --public --source=. --remote=origin --push`
- [ ] **Step 3: GitHub v0.1.0 릴리즈 생성 및 `dist/index.html` 첨부**
  - `gh release create v0.1.0 dist/index.html --title "v0.1.0 - PDF Permission Unlocker" --notes "Initial public release of 100% offline standalone PDF Permission Unlocker"`
