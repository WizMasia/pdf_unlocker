# PDF Permission Master (PDF 권한 관리 및 해제기)

> **100% Offline, Zero-Dependency, Lossless Client-Side PDF Permission Manager & Security Unlocker**  
> **외부 통신이 전혀 없는 100% 오프라인 무손실 PDF 권한 재조정(Change Permissions) 및 보안 해제 도구**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v0.2.0-emerald.svg)](https://github.com/)

---

## 🌟 주요 특징 (Key Features)

- 🔒 **100% 오프라인 & 프라이버시 보호 (Zero Network Calls)**:
  - 외부 서버나 CDN 라이브러리에 전혀 의존하지 않으며, 단일 HTML 파일(`dist/index.html`)만으로 브라우저 메모리 내에서 완전히 안전하게 동작합니다.
- ⚙️ **Stirling-PDF 스타일의 세부 권한 재조정 (Change Permissions)**:
  - **인쇄 권한 (Printing)**: 고품질 허용 / 저해상도(150dpi)만 허용 / 인쇄 금지
  - **내용 복사 및 텍스트 추출 (Copy & Extract)**: 클립보드 텍스트 및 그래픽 추출 제어
  - **문서 내용 수정 (Modify Content)**: 본문 텍스트 및 페이지 편집 제어
  - **주석 및 메모 작성 (Annotations & Comments)**: 주석/메모 추가 및 전자 서명 제어
  - **대화형 양식 입력 (Form Filling)**: 폼 필드 입력 및 저장 허용 여부 제어
  - **문서 조합 (Document Assembly)**: 페이지 삽입/삭제/회전 및 북마크 제어
  - **접근성 낭독 추출 (Accessibility)**: 시각 장애인을 위한 화면 낭독기 추출 제어
- 🛡️ **표준 PDF 보안 핸들러 (ISO 32000-1 Standard Security Handler)**:
  - 관리자 마스터 암호(Owner Password) 및 문서 열람 암호(User Password) 지원
  - AES-128 (Rev 4) 및 RC4-128 (Rev 3) 암호화 지원
- 🔓 **원클릭 무손실 완전 권한 해제 (Lossless 1-Click Unlock)**:
  - 저수준 PDF 바이너리 객체(Stream & String)를 직접 복호화하고 `/Encrypt` 딕셔너리를 제거하여 원본 텍스트 검색, 폰트, 벡터 그래픽, 목차(북마크), 하이퍼링크를 100% 유지하며 모든 제한을 해제합니다.
- 📦 **모듈식 개발 & 단일 파일 릴리즈 (Modular Dev & Single-File Bundle)**:
  - 개발 시에는 HTML, CSS, JS(Crypto, AST, Parser, Security, Serializer, UI, i18n)로 모듈화하여 개발하고, 릴리즈 시 독립 실행형 단일 HTML 파일(`dist/index.html`)로 자동 번들링됩니다.

---

## 🚀 빠른 시작 (Quick Start)

### 1. 사용 방법 (단일 HTML 실행)
- `dist/index.html` 파일을 브라우저(Chrome, Safari, Edge, Firefox 등)로 더블 클릭하여 엽니다.
- 상단 탭에서 **[⚙️ 권한 재조정]** 또는 **[🔓 권한 완전 해제]** 모드를 선택합니다.
- PDF 파일을 드래그 앤 드롭합니다.
- 권한을 설정한 후 **[권한 적용 및 다운로드]** 또는 **[모든 권한 일괄 적용]**을 클릭합니다.

### 2. 개발 및 테스트
```bash
# 1. 패키지 의존성 (Node.js v18+)
git clone https://github.com/WizMasia/pdf_unlocker.git
cd pdf_unlocker

# 2. 권한별 테스트 픽스처 생성
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
│   │   ├── crypto.js             # MD5, SHA-256, RC4, AES-128/256 CBC 암복호화 엔진
│   │   ├── pdf_ast.js            # PDF 표준 구문 트리(AST) 모델
│   │   ├── pdf_parser.js         # PDF 저수준 바이너리 렉서, 토크나이저, xref 파서
│   │   ├── pdf_security.js       # ISO 32000-1 표준 보안 핸들러 및 권한 제어 엔진
│   │   ├── pdf_decryptor.js      # 하위 호환 파사드 모듈
│   │   └── pdf_serializer.js     # PDF 바이너리 직렬화기 및 xref 빌더
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
│   ├── test_pdf_security.js      # 권한 제어 및 암호화 단위 테스트
│   ├── test_pdf_decryptor.js     # 복호화기 단위 테스트
│   ├── test_pdf_serializer.js    # 직렬화기 단위 테스트
│   └── run_e2e_tests.js          # 종합 E2E 통합 테스트
├── dist/
│   └── index.html                # 100% 독립 실행 가능한 단일 릴리즈 파일
└── package.json
```

---

## 📜 라이선스 (License)

MIT License © 2026 PDF Permission Master Authors.
