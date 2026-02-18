<p align="center">
  <img src="frontend/public/secu.png" alt="KISA Security" width="80" />
</p>

<h1 align="center">🛡️ 현대 오토에버 모빌리티 SW스쿨 IT보안 3기 시스템 보안 자동화</h1>

<p align="center">
  <strong>2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 자동화 플랫폼</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/React-18.2-61DAFB?logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/TypeScript-5.3-3178C6?logo=typescript&logoColor=white" />
  <img src="https://img.shields.io/badge/Ansible-2.16-EE0000?logo=ansible&logoColor=white" />
  <img src="https://img.shields.io/badge/MySQL-8.x-4479A1?logo=mysql&logoColor=white" />
</p>

---

## 📋 프로젝트 개요

100대 이상의 서버를 대상으로 **KISA 보안 취약점 점검**부터 **조치**, **보고서 생성**까지 전 과정을 자동화하는 엔터프라이즈 보안 플랫폼입니다.

> 🏢 **현대 오토에버** IT보안팀 운영 환경에 최적화
> 📐 **2026 KISA 기술적 취약점 분석·평가 기준** 준수
> ⚡ 수작업 대비 **90% 이상 시간 절감**

---

## ✨ 주요 기능

### 🔍 자동 취약점 진단
- **UNIX 서버 점검** — U-01 ~ U-67 (40개 항목)
- **데이터베이스 점검** — D-01 ~ D-28 (MySQL / PostgreSQL)
- Ansible 기반 원격 병렬 실행으로 **수백 대 동시 스캔**
- JSON 형식 점검 결과 자동 파싱 및 DB 저장

### 🔧 원클릭 자동 조치
- 취약 항목 선택 후 **즉시 자동 보안 설정 적용**
- 서버별 / 항목별 세분화된 조치 실행
- 실시간 진행률 모니터링 + 성공/실패 리포트
- 조치 이력 전체 추적 (Remediation Log)

### 📊 대시보드 & 분석
- **Executive Summary** — 전체 보안 점수, 양호/취약 비율
- 서버별·카테고리별·중요도별 상세 분석
- 보안 점수 하위 Top 5 서버 자동 식별
- 점검 및 조치 이력 타임라인

### 📑 엑셀 보고서 자동 생성
- **5개 시트 구성** — 표지 / 대시보드 / 항목별 요약 / 자산 목록 / 서버별 상세
- 도넛 차트, 막대 그래프, 카테고리 분포 차트 포함
- UNIX/DB 구분 컬러코딩 + 시트 간 하이퍼링크
- 서버별 상세 시트에 점검 근거(evidence) 포함

### 🔐 보안 & 권한 관리
- **JWT 인증** (HS256, 2시간 만료)
- **RBAC** — 관리자(ADMIN) / 뷰어(VIEWER) 역할 분리
- PBKDF2-SHA256 비밀번호 해싱 (260,000 iterations)
- CIDR 기반 IP 접근 제어 미들웨어
- Ansible Vault 암호화 + Fernet AES DB 패스워드 암호화

### 📋 예외 관리
- 서버·항목 단위 예외 등록 (사유 + 유효기한)
- 단건/다건/전체 서버 일괄 예외 등록
- 만료 자동 관리

---

## 🏗️ 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                    👤 사용자 (브라우저)                        │
│                    React + TypeScript                        │
│                    :5173 (Vite Dev)                          │
└────────────────────────┬────────────────────────────────────┘
                         │ REST API
┌────────────────────────▼────────────────────────────────────┐
│              🖥️ Backend API Server                          │
│              FastAPI + Uvicorn (:8000)                      │
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │ Auth API │ │Asset API │ │ Scan API │ │ Fix API  │        │ 
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │Dashboard │ │Analysis  │ │Exception │ │ Report   │        │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │
└─────────┬────────────────────────┬──────────────────────────┘
          │                        │
┌─────────▼─────────┐  ┌──────────▼──────────────────────────┐
│  🗄️ MySQL 8.x     │  │  ⚙️ Job API (:8001)                 │
│  kisa_security DB  │  │  SQLite Queue + Worker Thread       │
│                    │  │                                     │
│  • servers         │  └──────────┬──────────────────────────┘
│  • kisa_items      │             │
│  • scan_history    │  ┌──────────▼──────────────────────────┐
│  • remediation_logs│  │  📡 Ansible Orchestration           │
│  • exceptions      │  │                                     │
│  • users           │  │  ┌─────────┐ ┌─────────┐            │
└────────────────────┘  │  │ scan_os │ │ scan_db │            │
                        │  │ fix_os  │ │ fix_db  │            │
                        │  └────┬────┘ └────┬────┘            │
                        └───────┼───────────┼─────────────────┘
                                │           │
                    ┌───────────▼───────────▼──────────┐
                    │  🖥️ 대상 서버 (200+ 대)            │
                    │                                   │
                    │  Rocky 9.7 + MySQL 8.0.4          │
                    │  Rocky 10.1 + PostgreSQL 16.11    │
                    │                                   │
                    │  📜 134개 OS 점검 스크립트          │
                    │  📜 24개 DB 점검 스크립트           │
                    └───────────────────────────────────┘
```

---

## 📁 프로젝트 구조

```
kisa-security-project/
│
├── 🐍 backend/                    # FastAPI 백엔드
│   ├── api/                       # REST API 라우터 (8개)
│   │   ├── auth.py                #   인증 (로그인/비밀번호)
│   │   ├── assets.py              #   자산 관리 (서버 CRUD)
│   │   ├── scan.py                #   취약점 점검 실행
│   │   ├── fix.py                 #   자동 조치 실행
│   │   ├── dashboard.py           #   대시보드 통계
│   │   ├── analysis.py            #   서버별 분석
│   │   ├── exceptions.py          #   예외 관리
│   │   └── reports.py             #   보고서 생성
│   ├── services/                  # 비즈니스 로직
│   │   ├── scan_service.py        #   스캔 오케스트레이션
│   │   ├── fix_service.py         #   조치 오케스트레이션
│   │   ├── asset_service.py       #   자산 등록/연결 테스트
│   │   └── encryption.py          #   Fernet 암호화
│   ├── core/                      # 보안 & 미들웨어
│   │   ├── security.py            #   PBKDF2 해싱
│   │   ├── deps.py                #   JWT 검증, RBAC
│   │   └── middleware.py          #   IP 필터링
│   ├── db/                        # 데이터베이스
│   │   ├── models.py              #   SQLAlchemy ORM
│   │   ├── connector.py           #   MySQL 커넥터
│   │   └── schema.sql             #   DDL
│   └── processors/                # 데이터 처리
│       ├── parse_scan_result.py   #   점검 결과 파싱
│       ├── parse_fix_result.py    #   조치 결과 파싱
│       ├── score_calculator.py    #   보안 점수 산출
│       └── generate_report.py     #   엑셀 보고서 생성
│
├── ⚛️ frontend/                    # React 프론트엔드
│   └── src/
│       ├── pages/                 # 페이지 컴포넌트 (9개)
│       │   ├── Login.tsx          #   로그인
│       │   ├── MainDashboard.tsx  #   메인 대시보드
│       │   ├── AssetRegister.tsx  #   서버 등록 (단건/CSV)
│       │   ├── AssetList.tsx      #   자산 목록
│       │   ├── AssetAnalysis.tsx  #   서버별 분석
│       │   ├── History.tsx        #   점검/조치 이력
│       │   └── ExceptionManagement.tsx  # 예외 관리
│       ├── components/            # 공통 컴포넌트
│       │   ├── TopNav.tsx         #   상단 네비게이션
│       │   ├── ScanProgressModal.tsx    # 점검 진행 모달
│       │   ├── RemediationModal.tsx     # 자동 조치 모달
│       │   └── ExceptionModal.tsx       # 예외 등록 모달
│       └── api/                   # API 클라이언트 (6개)
│
├── 📡 ansible/                    # Ansible 오케스트레이션
│   ├── playbooks/                 # 플레이북
│   │   ├── scan_os.yml            #   OS 취약점 점검
│   │   ├── scan_db.yml            #   DB 취약점 점검
│   │   ├── fix_os.yml             #   OS 자동 조치
│   │   └── fix_db.yml             #   DB 자동 조치
│   └── inventories/               # 호스트 인벤토리
│
├── 📜 scripts/                    # 점검/조치 쉘 스크립트
│   ├── os/                        # UNIX 점검 (134개)
│   │   ├── account/               #   계정 관리 (U-01~U-13)
│   │   ├── directory/             #   파일/디렉터리 (U-14~U-33)
│   │   ├── service/               #   서비스 관리 (U-34~U-63)
│   │   ├── patch/                 #   패치 관리 (U-64)
│   │   └── log/                   #   로그 관리 (U-65~U-67)
│   └── db/                        # DB 점검 (24개)
│       ├── mysql/                 #   MySQL 점검/조치
│       └── postgres/              #   PostgreSQL 점검/조치
│
├── ⚙️ api/                        # 내부 Job API (:8001)
├── 🔧 run.sh                     # 메인 실행 스크립트
├── 📋 API_SPEC.md                # API 명세서
└── 📋 ARCHITECTURE.md            # 아키텍처 문서
```

---

## 🚀 Quick Start

### 1️⃣ 환경 설정

```bash
# Python 가상환경 생성
python3 -m venv venv
source venv/bin/activate

# 백엔드 의존성 설치
pip install -r requirements.txt

# 프론트엔드 의존성 설치
cd frontend && npm install && cd ..
```

### 2️⃣ 데이터베이스 초기화

```bash
# MySQL 스키마 생성
mysql -u root -p < backend/db/schema.sql

# 초기 사용자 생성
python3 backend/seed_users.py
```

### 3️⃣ 서비스 시작

```bash
# 전체 시스템 시작 (API + Dashboard + Frontend)
./run.sh dashboard
```

| 서비스 | 포트 | 설명 |
|--------|------|------|
| **Frontend** | `:5173` | React 웹 대시보드 |
| **Backend API** | `:8000` | REST API 서버 |
| **Job API** | `:8001` | 내부 작업 큐 |

### 4️⃣ 점검 실행

```bash
# OS 취약점 전수 점검
./run.sh scan

# DB 취약점 점검
./run.sh scan-db

# 보안 점수 산출
./run.sh score
```

---

## 🔒 점검 항목 현황

### UNIX 서버 (40개 항목)

| 카테고리 | 항목 범위 | 항목 수 | 자동조치 |
|----------|-----------|---------|---------|
| 🔑 계정 관리 | U-01 ~ U-13 | 13개 | ✅ |
| 📂 파일 및 디렉터리 관리 | U-14 ~ U-33 | 20개 | ✅ |
| ⚙️ 서비스 관리 | U-34 ~ U-63 | 30개 | ✅ |
| 🩹 패치 관리 | U-64 | 1개 | ⚠️ |
| 📝 로그 관리 | U-65 ~ U-67 | 3개 | ✅ |

### 데이터베이스 (28개 항목)

| 카테고리 | 대상 DB | 항목 수 | 자동조치 |
|----------|---------|---------|---------|
| 🔑 계정 관리 | MySQL / PostgreSQL | 8개 | ✅ |
| 🚪 접근 제어 | MySQL / PostgreSQL | 8개 | ✅ |
| ⚙️ 옵션 관리 | MySQL / PostgreSQL | 8개 | ✅ |
| 🩹 패치 관리 | MySQL / PostgreSQL | 4개 | ⚠️ |

---

## 📈 보안 점수 산출 방식

```
보안 점수 = (양호 가중치 합 / 전체 가중치 합) × 100
```

| 중요도 | 가중치 | 배점 |
|--------|--------|------|
| 🔴 **상** (High) | 3 | 10점 |
| 🟡 **중** (Medium) | 2 | 8점 |
| 🔵 **하** (Low) | 1 | 6점 |

---

## 🗄️ 데이터베이스 스키마

```sql
-- 핵심 테이블 관계
servers (1) ──── (N) scan_history ──── (1) kisa_items
    │                                         │
    ├──── (N) remediation_logs ───────────────┘
    │
    └──── (N) exceptions
```

| 테이블 | 설명 | 주요 컬럼 |
|--------|------|----------|
| `servers` | 대상 서버 자산 | server_id, ip_address, os_type, db_type |
| `kisa_items` | KISA 점검 항목 (48개) | item_code, category, severity, auto_fix |
| `scan_history` | 점검 결과 이력 | status (양호/취약), raw_evidence (JSON) |
| `remediation_logs` | 조치 이력 | is_success, failure_reason |
| `exceptions` | 예외 처리 | reason, valid_date |
| `users` | 사용자 계정 | role (ADMIN/VIEWER), must_change_password |

---

## 🛠️ 기술 스택

### Backend

| 기술 | 버전 | 용도 |
|------|------|------|
| **Python** | 3.11 | 서버 런타임 |
| **FastAPI** | 0.115 | REST API 프레임워크 |
| **SQLAlchemy** | 2.x | ORM |
| **MySQL** | 8.x | 주 데이터베이스 |
| **PyJWT** | 2.x | JWT 인증 |
| **XlsxWriter** | 3.x | 엑셀 보고서 생성 |
| **Cryptography** | — | Fernet AES 암호화 |

### Frontend

| 기술 | 버전 | 용도 |
|------|------|------|
| **React** | 18.2 | UI 프레임워크 |
| **TypeScript** | 5.3 | 타입 안전성 |
| **Vite** | 5.0 | 빌드 도구 |
| **Axios** | 1.6 | HTTP 클라이언트 |
| **Recharts** | — | 대시보드 차트 |
| **React Router** | 6.20 | 클라이언트 라우팅 |

### Infrastructure

| 기술 | 용도 |
|------|------|
| **Ansible** | 원격 서버 오케스트레이션 |
| **Ansible Vault** | 비밀 정보 암호화 |
| **Bash** | 점검/조치 스크립트 (158개) |
| **SQLite** | 작업 큐 (Job API) |

---

## 👥 역할 & 권한

| 기능 | 🔑 ADMIN | 👁️ VIEWER |
|------|:--------:|:---------:|
| 대시보드 조회 | ✅ | ✅ |
| 서버별 분석 조회 | ✅ | ✅ |
| 점검/조치 이력 조회 | ✅ | ✅ |
| 예외 목록 조회 | ✅ | ✅ |
| 보고서 다운로드 | ✅ | ✅ |
| 서버 등록/삭제 | ✅ | ❌ |
| 취약점 점검 실행 | ✅ | ❌ |
| 자동 조치 실행 | ✅ | ❌ |
| 예외 등록/삭제 | ✅ | ❌ |

---

## 📄 API 문서

전체 API 명세는 [API_SPEC.md](API_SPEC.md)를 참고하세요.

| API 그룹 | 엔드포인트 수 | 기본 경로 |
|----------|:------------:|----------|
| 🔐 인증 | 3 | `/api/auth` |
| 🖥️ 자산 관리 | 6 | `/api/assets` |
| 🔍 점검 | 3 | `/api/scan` |
| 📊 대시보드 | 3 | `/api/dashboard` |
| 📈 분석 | 4 | `/api/analysis` |
| 🔧 조치 | 4 | `/api/fix` |
| 📋 예외 | 4 | `/api/exceptions` |
| 📑 보고서 | 1 | `/api/reports` |

---

<p align="center">
  <sub>© 2026 현대 오토에버 SW스쿨 IT보안 3기 · KISA 주요정보통신기반시설 기술적 취약점 분석·평가 자동화</sub>
</p>
