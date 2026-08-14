# PDF Permission Unlocker (PDF 권한 해제기)

> **100% Offline, Zero-Dependency, Lossless Client-Side PDF Security & Permission Removal Tool**  
> **외부 통신이 전혀 없는 100% 오프라인 무손실 PDF 보안 및 권한(인쇄/복사/수정) 해제 도구**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v0.1.0-emerald.svg)](https://github.com/)

---

## 🌟 주요 특징 (Key Features)

- 🔒 **100% 오프라인 & 프라이버시 보호 (Zero Network Calls)**:
  - 외부 서버나 CDN 라이브러리에 전혀 의존하지 않으며, 단일 HTML 파일(`dist/index.html`)만으로 브라우저 메모리 내에서 완전히 안전하게 동작합니다.
- ✨ **무손실 저수준 복호화 (Lossless Object-level Decryption)**:
  - 화면 캡처나 캔버스 재렌더링 방식의 해상도 저하/텍스트 유실 없이, 저수준 PDF 바이너리 객체(Stream & String)를 직접 복호화하고 `/Encrypt` 딕셔너리를 제거하여 원본 텍스트 검색, 폰트, 벡터 그래픽, 목차(북마크), 하이퍼링크를 100% 유지합니다.
- 🖨️ **모든 권한 제한 완전 해제 (Full Permissions Unlock)**:
  - **인쇄 금지 (Print Forbidden)** 해제
  - **클립보드 복사 / 텍스트 추출 금지 (Copy/Extract Forbidden)** 해제
  - **문서 내용 수정 및 양식/주석 편집 금지 (Modify/Annotate Forbidden)** 해제
- 🛡️ **표준 PDF 보안 핸들러 전면 지원**:
  - Standard Security Handler Rev 2, 3, 4, 5, 6 (RC4-40, RC4-128, AES-128, AES-256)
  - 열기 비밀번호(User Password)가 설정된 경우 패스워드 입력 후 무제한 PDF로 변환 지원
- 📦 **모듈식 개발 & 단일 파일 릴리즈 (Modular Dev & Single-File Bundle)**:
  - 개발 시에는 HTML, CSS, JS(Crypto, Parser, Decryptor, Serializer, UI, i18n)로 깔끔하게 분리하여 개발하고, 릴리즈 시 34KB 크기의 단일 독립 실행형 HTML 파일로 자동 번들링됩니다.

---

## 🚀 빠른 시작 (Quick Start)

### 1. 사용 방법 (단일 HTML 실행)
- `dist/index.html` 파일을 브라우저(Chrome, Safari, Edge, Firefox 등)로 더블 클릭하여 엽니다.
- 권한 제한된 PDF 파일을 드래그 앤 드롭합니다.
- **[모든 파일 일괄 해제]** 또는 파일별 **[권한 해제]** 버튼을 클릭하면 즉시 무제한 PDF가 다운로드됩니다.

### 2. 개발 및 테스트
```bash
# 1. 패키지 의존성 (Node.js v18+)
git clone https://github.com/WizMasia/pdf_unlocker.git
cd pdf_unlocker

# 2. 권한별 테스트 픽스처 생성 (7종)
npm run generate-fixtures

# 3. 전체 단위 테스트 실행
npm test

# 4. 종합 E2E 테스트 및 단일 HTML 번들 빌드
npm run test:e2e
npm run build
```

---

## 🏗️ 아키텍처 (Architecture)

```
pdf_unlocker/
├── src/                          # 개발 소스 (모듈화 구조)
│   ├── index.html                # UI 템플릿 마크업
│   ├── styles/
│   │   └── main.css              # HSL 기반 모던 디자인 시스템
│   ├── core/
│   │   ├── crypto.js             # MD5, SHA-256, RC4, AES-128/256 암복호화 엔진
│   │   ├── pdf_parser.js         # PDF 저수준 바이너리 렉서, 토크나이저, xref 파서
│   │   ├── pdf_decryptor.js      # Standard Security Handler R2~R6 및 객체 복호화기
│   │   └── pdf_serializer.js     # 비암호화 PDF 재작성기, 신규 xref 생성기
│   └── ui/
│       ├── i18n.js               # 다국어 리소스 (한국어/영어)
│       └── app.js                # UI 이벤트 핸들러, 파일 큐, 권한 인스펙터
├── scripts/
│   └── build.js                  # 모듈 소스를 단일 Standalone HTML로 번들링하는 빌더
├── test/
│   ├── generate_fixtures.js      # 권한별 테스트 PDF 생성기
│   ├── fixtures/                 # 생성된 테스트 PDF 픽스처 (7종)
│   ├── test_crypto.js            # 암호화 단위 테스트
│   ├── test_pdf_parser.js        # 파서 단위 테스트
│   ├── test_pdf_decryptor.js     # 복호화기 단위 테스트
│   ├── test_pdf_serializer.js    # 직렬화기 단위 테스트
│   └── run_e2e_tests.js          # 종합 E2E 통합 테스트
├── dist/
│   └── index.html                # 100% 독립 실행 가능한 단일 릴리즈 파일 (~34KB)
└── package.json
```

---

## 📜 라이선스 (License)

MIT License © 2026 PDF Permission Unlocker Authors.
