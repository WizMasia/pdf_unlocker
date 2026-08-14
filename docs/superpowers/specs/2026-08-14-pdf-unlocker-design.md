# PDF 권한 해제 원 페이지 웹 애플리케이션 설계서 (Design Specification)

## 1. 개요 (Overview)
- **목적**: 외부 네트워크 통신(CDN, 외부 서버) 없이 브라우저 로컬에서 단일 HTML 파일로 실행되며, 소유자 암호(Owner Password)로 인해 인쇄·복사·편집·주석 등의 권한이 제한된 PDF 파일의 권한을 무손실(Lossless)로 완벽하게 해제하는 웹 애플리케이션.
- **개발 및 배포 프로세스**:
  - **개발 모드 (Modular Development)**: HTML, CSS, JavaScript(Crypto, Parser, Decryptor, Serializer, UI, i18n)를 독립된 파일과 모듈 단위로 분리하여 유지보수성, 가독성, 단위 테스트 용이성을 극대화.
  - **릴리즈 빌드 (Single-File Release Bundle)**: 빌드 스크립트(`scripts/build.js`)를 통해 모든 HTML, CSS, JS를 완벽하게 인라인 결합하여 단일 독립형 `dist/index.html` (또는 배포용 `index.html`)로 자동 번들링.
- **주요 가치**:
  - **100% 오프라인 & 프라이버시**: 외부 서버 통신이 전혀 없는 순수 클라이언트 사이드 처리.
  - **무손실 복호화 (Lossless Decryption)**: 캔버스 재렌더링 방식이 아닌 저수준 객체 단위 복호화 및 `/Encrypt` 딕셔너리 제거로 원본 텍스트, 폰트, 벡터, 북마크, 메타데이터 100% 보존.
  - **권한 비트 완전 해제**: Adobe Acrobat 등 모든 PDF 뷰어에서 권한 제한 없이 인쇄, 복사, 페이지 추출, 양식 작성이 가능하도록 표준 비암호화 PDF로 재생성.

---

## 2. 모듈식 디렉토리 구조 및 아키텍처 (Project Architecture)

### 2.1 디렉토리 구조
```
pdf_unlocker/
├── src/                          # 개발 소스 (모듈화 구조)
│   ├── index.html                # UI 템플릿 마크업
│   ├── styles/
│   │   └── main.css              # 모던 CSS 스타일 (HSL 변수, 레이아웃, 애니메이션)
│   ├── core/
│   │   ├── crypto.js             # MD5, SHA-256, RC4, AES-128/256 암복호화 엔진
│   │   ├── pdf_parser.js         # PDF 저수준 렉서, 토크나이저, xref/stream 파서
│   │   ├── pdf_decryptor.js      # Standard Security Handler R2~R6 및 객체 복호화기
│   │   └── pdf_serializer.js     # 비암호화 PDF 재작성기, 신규 xref 생성기
│   └── ui/
│       ├── i18n.js               # 다국어 리소스 (한국어, 영어)
│       └── app.js                # UI 이벤트 핸들러, 파일 큐, 권한 인스펙터
├── scripts/
│   └── build.js                  # 모듈 소스를 단일 Standalone HTML로 번들링하는 스크립트
├── test/
│   ├── generate_fixtures.js      # 권한별 테스트용 PDF 자동 생성기
│   ├── fixtures/                 # 생성된 테스트 PDF 파일들
│   │   ├── restricted_print.pdf      # 인쇄 제한 PDF
│   │   ├── restricted_copy.pdf       # 텍스트 복사/클립보드 추출 제한 PDF
│   │   ├── restricted_modify.pdf     # 수정/편집/주석 제한 PDF
│   │   ├── restricted_all_rc4.pdf    # RC4-128 전체 권한 제한 PDF
│   │   ├── restricted_all_aes.pdf    # AES-128 전체 권한 제한 PDF
│   │   ├── password_open.pdf         # 열기 비밀번호 설정 PDF
│   │   └── unencrypted.pdf           # 비암호화 일반 PDF
│   ├── test_crypto.js            # 암호화 단위 테스트
│   ├── test_pdf_parser.js        # 파서 단위 테스트
│   ├── test_pdf_decryptor.js     # 복호화기 단위 테스트
│   ├── test_pdf_serializer.js    # 직렬화기 단위 테스트
│   └── run_e2e_tests.js          # 전체 E2E 통합 테스트
├── dist/                         # 빌드 결과물
│   └── index.html                # 100% 독립 실행 가능한 단일 릴리즈 파일
└── package.json
```

---

## 3. 핵심 기술 및 모듈 상세 (Technical Details)

### 3.1 코어 엔진 모듈 (Core Engine Layer)
- **`src/core/crypto.js`**:
  - MD5 (R2, R3, R4 키 파생용)
  - SHA-256 (R5, R6 키 파생용)
  - RC4 (40-bit 및 128-bit 스트림 암복호화)
  - AES-128-CBC / AES-256-CBC 복호화
- **`src/core/pdf_parser.js`**:
  - Header, Indirect Objects, Dictionaries, Arrays, Strings, Streams 파싱
  - 전통 `xref` 테이블 및 PDF 1.5+ 압축 `XRef Streams` 파싱
  - `Trailer` 및 `/Encrypt` 딕셔너리 추출
- **`src/core/pdf_decryptor.js`**:
  - Standard Security Handler (Rev 2, 3, 4, 5, 6)
  - 빈 열기 비밀번호(`""`)로 파일 암호화 키(FEK) 파생
  - 객체별 복호화 키 유도 및 모든 스트림/문자열 무손실 복호화
  - 권한 플래그(`P` bitmask) 분석
- **`src/core/pdf_serializer.js`**:
  - `Trailer`에서 `/Encrypt` 제거
  - 복호화된 객체 직렬화 및 바이트 오프셋 계산
  - 신규 무결성 교차 참조 테이블(`xref`) 및 `startxref` 생성
  - 유효한 비암호화 PDF Blob 생성

### 3.2 UI 및 다국어 모듈 (UI & i18n Layer)
- **`src/ui/i18n.js`**:
  - UI 텍스트, 권한 설명, 안내 메시지, 에러 메시지 중앙 관리 (하드코딩 방지)
  - 한국어(기본) 및 영어 지원
- **`src/ui/app.js`**:
  - 드래그 앤 드롭 및 다중 파일 큐 관리
  - 실시간 PDF 권한 분석 및 상태 뱃지 표시
  - 처리 진행률 표시 및 개별/일괄 다운로드
  - 열기 암호(User Password) 감지 시 모달 팝업

### 3.3 릴리즈 빌더 (Build & Bundling Process)
- **`scripts/build.js`**:
  - `src/index.html`을 읽어 `<link rel="stylesheet">`를 `src/styles/main.css` 내용으로 치환 (`<style>...</style>`).
  - `<script src="...">` 태그들을 해당 JS 모듈 코드로 순서대로 인라인 삽입 (`<script>...</script>`).
  - 외부 네트워크 의존성이 0인 완전한 독립형 `dist/index.html` 생성.

---

## 4. 테스트 케이스 및 검증 계획 (Test Fixtures & Verification)

### 4.1 권한별 테스트 픽스처 생성 (`test/generate_fixtures.js`)
1. **인쇄 제한 (`restricted_print.pdf`)**: `P` 비트 중 Bit 3(Print) 해제 (인쇄 불가)
2. **클립보드 복사 제한 (`restricted_copy.pdf`)**: `P` 비트 중 Bit 5(Extract/Copy) 해제 (텍스트/이미지 복사 불가)
3. **수정/편집/주석 제한 (`restricted_modify.pdf`)**: `P` 비트 중 Bit 4(Modify), Bit 6(Add/Modify Annotations) 해제
4. **전체 권한 제한 (RC4-128 / `restricted_all_rc4.pdf`)**: 소유자 암호 설정, 열기 암호 공백, 모든 권한 비트 차단
5. **전체 권한 제한 (AES-128 / `restricted_all_aes.pdf`)**: Crypt Filter `StdCF` AES-128 암호화, 모든 권한 차단
6. **열기 비밀번호 설정 (`password_open.pdf`)**: 파일 열람 시 패스워드 요구 문서
7. **비암호화 문서 (`unencrypted.pdf`)**: 암호화가 적용되지 않은 일반 문서

### 4.2 검증 프로세스
- **단위 테스트**: Node.js 환경에서 각 모듈별 단위 테스트 스크립트 실행
- **빌드 테스트**: `node scripts/build.js` 실행 후 `dist/index.html` 생성 무결성 검증
- **E2E 테스트**: `node test/run_e2e_tests.js`를 통해 위 7가지 테스트 픽스처를 자동 해제하고, 복호화된 결과물에서 `/Encrypt` 제거 여부, 텍스트 스트림 원본 무결성, 권한 해제 상태를 검증.
