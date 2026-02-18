# KISA 보안 취약점 진단 시스템 - API 명세서

> Base URL: `http://<host>:8000`
> 인증 방식: JWT Bearer Token (`Authorization: Bearer <token>`)
> 공통 Content-Type: `application/json`

---

## 1. Authentication (`/api/auth`)

| Method | Endpoint | 설명 | 인증 | 권한 |
|--------|----------|------|------|------|
| POST | `/api/auth/login` | 로그인 (JWT 발급) | - | - |
| GET | `/api/auth/me` | 현재 사용자 정보 조회 | O | ALL |
| POST | `/api/auth/change-password` | 비밀번호 변경 | O | ALL |

### `POST /api/auth/login`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `username` | string | O | 사용자 ID |
| | `password` | string | O | 비밀번호 |
| **Response** | `access_token` | string | | JWT 토큰 |
| | `token_type` | string | | `"bearer"` |
| | `user` | object | | `{username, role, company}` |

### `GET /api/auth/me`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Response** | `username` | string | 사용자 ID |
| | `role` | string | `ADMIN` / `VIEWER` |
| | `company` | string | 소속 회사 |

### `POST /api/auth/change-password`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `old_password` | string | O | 현재 비밀번호 |
| | `new_password` | string | O | 새 비밀번호 (8~128자) |
| **Response** | `message` | string | | 성공 메시지 |

---

## 2. Assets (`/api/assets`)

| Method | Endpoint | 설명 | 인증 | 권한 |
|--------|----------|------|------|------|
| GET | `/api/assets` | 서버 목록 조회 | O | ADMIN |
| POST | `/api/assets` | 서버 등록 (단건) | O | ADMIN |
| POST | `/api/assets/bulk` | 서버 등록 (CSV 일괄) | O | ADMIN |
| DELETE | `/api/assets/{server_id}` | 서버 삭제 | O | ADMIN |
| POST | `/api/assets/test/ssh` | SSH 연결 테스트 | O | ADMIN |
| POST | `/api/assets/test/db-port` | DB 포트 연결 테스트 | O | ADMIN |
| POST | `/api/assets/test/db-login` | DB 로그인 테스트 | O | ADMIN |

### `GET /api/assets`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Response** | `[]` | array | 서버 목록 |
| | `[].server_id` | string | 서버 ID |
| | `[].hostname` | string | 호스트명 |
| | `[].ip_address` | string | IP 주소 |
| | `[].os_type` | string | OS 유형 |
| | `[].db_type` | string | DB 유형 |
| | `[].is_active` | boolean | 활성 여부 |

### `POST /api/assets`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `server_id` | string | O | 서버 고유 ID |
| | `ip_address` | string | O | IP 주소 |
| | `company` | string | O | 회사명 |
| | `hostname` | string | O | 호스트명 |
| | `ssh_port` | string | | SSH 포트 (기본 22) |
| | `os_type` | string | | OS 유형 |
| | `db_type` | string | | DB 유형 (`없음`, `PostgreSQL`, `MySQL`) |
| | `db_port` | int | | DB 포트 |
| | `db_user` | string | | DB 사용자 |
| | `db_passwd` | string | | DB 비밀번호 (Fernet 암호화 저장) |
| | `manager` | string | | 담당자 |
| | `department` | string | | 부서 |
| **Response** | | object | | 생성된 서버 정보 (201) |

### `POST /api/assets/bulk`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `servers` | array | O | `ServerCreate` 배열 |
| **Response** | `total` | int | | 전체 요청 수 |
| | `success_count` | int | | 성공 건수 |
| | `fail_count` | int | | 실패 건수 |
| | `results` | array | | 개별 결과 상세 |

### `DELETE /api/assets/{server_id}`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Path** | `server_id` | string | 삭제 대상 서버 ID |
| **Response** | `message` | string | 성공 메시지 |
| | `deleted_records` | object | `{scan_history, remediation_logs, exceptions}` 삭제 건수 |

### `POST /api/assets/test/ssh`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `ip_address` | string | O | IP 주소 |
| | `hostname` | string | O | 호스트명 |
| | `ssh_port` | string | O | SSH 포트 |
| **Response** | `success` | boolean | | 연결 성공 여부 |
| | `message` | string | | 결과 메시지 |

### `POST /api/assets/test/db-port`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `ip_address` | string | O | IP 주소 |
| | `db_port` | int | O | DB 포트 |
| **Response** | `success` | boolean | | 연결 성공 여부 |
| | `message` | string | | 결과 메시지 |

### `POST /api/assets/test/db-login`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `ip_address` | string | O | IP 주소 |
| | `db_type` | string | O | DB 유형 |
| | `db_port` | int | O | DB 포트 |
| | `db_user` | string | O | DB 사용자 |
| | `db_passwd` | string | O | DB 비밀번호 |
| **Response** | `success` | boolean | | 연결 성공 여부 |
| | `message` | string | | 결과 메시지 |

---

## 3. Scan (`/api/scan`)

| Method | Endpoint | 설명 | 인증 | 권한 |
|--------|----------|------|------|------|
| POST | `/api/scan/full` | 통합 점검 실행 (OS+DB) | O | ADMIN |
| GET | `/api/scan/progress/{job_id}` | 점검 진행률 조회 | O | ADMIN |
| GET | `/api/scan/result/{job_id}` | 점검 결과 요약 | O | ADMIN |

### `POST /api/scan/full`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `server_ids` | string[] | O | 점검 대상 서버 ID 목록 |
| | `scan_type` | string | O | 점검 유형 |
| **Response** | `job_id` | string | | 비동기 작업 ID |
| | `message` | string | | 안내 메시지 |
| | `total_servers` | int | | 대상 서버 수 |
| | `status` | string | | `"queued"` (HTTP 202) |

### `GET /api/scan/progress/{job_id}`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Path** | `job_id` | string | 작업 ID |
| **Response** | `job_id` | string | 작업 ID |
| | `status` | string | `queued` / `running` / `completed` / `failed` |
| | `progress` | int | 진행률 (0~100) |
| | `current_step` | string | 현재 단계 설명 |
| | `completed_servers` | int | 완료 서버 수 |
| | `total_servers` | int | 전체 서버 수 |

### `GET /api/scan/result/{job_id}`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Path** | `job_id` | string | 작업 ID |
| **Response** | | object | 점검 결과 요약 (서버별 양호/취약 건수 등) |

---

## 4. Dashboard (`/api/dashboard`)

| Method | Endpoint | 설명 | 인증 | 권한 |
|--------|----------|------|------|------|
| GET | `/api/dashboard/data` | 대시보드 통합 데이터 | O | ALL |

### `GET /api/dashboard/data`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Response** | `summary` | object | 전체 요약 (총 서버, 점검 항목, 양호/취약 등) |
| | `os_categories` | array | OS 카테고리별 양호/취약 통계 |
| | `db_categories` | array | DB 카테고리별 양호/취약 통계 |
| | `unresolved_count` | int | 미조치 취약점 수 |
| | `os_top_servers` | array | OS 취약 Top 5 서버 |
| | `db_top_servers` | array | DB 취약 Top 5 서버 |
| | `risk_distribution` | object | 위험도별 분포 (상/중/하) |
| | `vulnerability_ratio` | object | 취약/양호 비율 |

---

## 5. Analysis (`/api/analysis`)

| Method | Endpoint | 설명 | 인증 | 권한 |
|--------|----------|------|------|------|
| GET | `/api/analysis/servers` | 서버별 양호/취약 건수 목록 | O | ALL |
| GET | `/api/analysis/servers/{server_id}/results` | 서버 점검 결과 상세 | O | ALL |
| GET | `/api/analysis/servers/{server_id}/remediation` | 서버 조치 이력 | O | ALL |
| GET | `/api/analysis/history` | 전체 점검/조치 이력 | O | ALL |

### `GET /api/analysis/servers`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Response** | `[]` | array | 서버 목록 + 통계 |
| | `[].server_id` | string | 서버 ID |
| | `[].hostname` | string | 호스트명 |
| | `[].secure_count` | int | 양호 건수 |
| | `[].vulnerable_count` | int | 취약 건수 |
| | `[].exception_count` | int | 예외 건수 |

### `GET /api/analysis/servers/{server_id}/results`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Path** | `server_id` | string | 서버 ID |
| **Response** | `server_info` | object | 서버 정보 |
| | `os_results` | object | OS 점검 결과 (카테고리별 그룹) |
| | `db_results` | object | DB 점검 결과 (카테고리별 그룹) |

### `GET /api/analysis/servers/{server_id}/remediation`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Path** | `server_id` | string | 서버 ID |
| **Response** | `os_results` | object | OS 조치 이력 (카테고리별) |
| | `db_results` | object | DB 조치 이력 (카테고리별) |

### `GET /api/analysis/history`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Response** | `scans` | array | 점검 이력 리스트 |
| | `remediations` | array | 조치 이력 리스트 |

---

## 6. Fix (`/api/fix`)

| Method | Endpoint | 설명 | 인증 | 권한 |
|--------|----------|------|------|------|
| POST | `/api/fix/execute` | 자동 조치 실행 (단일 서버) | O | ADMIN |
| POST | `/api/fix/execute-batch` | 자동 조치 실행 (다중 서버) | O | ADMIN |
| POST | `/api/fix/affected-servers` | 취약 항목별 영향 서버 조회 | O | ALL |
| GET | `/api/fix/progress/{job_id}` | 조치 진행률 조회 | O | ADMIN |
| GET | `/api/fix/result/{job_id}` | 조치 결과 요약 | O | ADMIN |

### `POST /api/fix/execute`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `server_id` | string | O | 대상 서버 ID |
| | `item_codes` | string[] | O | 조치 항목 코드 목록 |
| **Response** | `job_id` | string | | 비동기 작업 ID |
| | `total_items` | int | | 조치 대상 항목 수 |
| | `status` | string | | `"queued"` (HTTP 202) |

### `POST /api/fix/execute-batch`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `server_ids` | string[] | O | 대상 서버 ID 목록 |
| | `item_codes` | string[] | O | 조치 항목 코드 목록 |
| **Response** | `job_id` | string | | 비동기 작업 ID |
| | `total_items` | int | | 조치 대상 항목 수 |
| | `status` | string | | `"queued"` (HTTP 202) |

### `POST /api/fix/affected-servers`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `item_codes` | string[] | O | 항목 코드 목록 |
| **Response** | `item_codes` | string[] | | 요청 항목 코드 |
| | `servers` | array | | 영향받는 서버 목록 |
| | `total_servers` | int | | 영향 서버 수 |
| | `total_fixable` | int | | 조치 가능 건수 |

### `GET /api/fix/progress/{job_id}`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Path** | `job_id` | string | 작업 ID |
| **Response** | `job_id` | string | 작업 ID |
| | `status` | string | `queued` / `running` / `completed` / `failed` |
| | `progress` | int | 진행률 (0~100) |
| | `message` | string | 현재 단계 메시지 |
| | `total_items` | int | 전체 항목 수 |

### `GET /api/fix/result/{job_id}`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Path** | `job_id` | string | 작업 ID |
| **Response** | `job_id` | string | 작업 ID |
| | `total_items` | int | 전체 항목 수 |
| | `success_count` | int | 성공 건수 |
| | `fail_count` | int | 실패 건수 |
| | `servers` | array | 서버별 결과 |
| | `items` | array | 항목별 결과 |
| | `improvement` | object | `{before_vuln, after_vuln, improved}` 개선 통계 |

---

## 7. Exceptions (`/api/exceptions`)

| Method | Endpoint | 설명 | 인증 | 권한 |
|--------|----------|------|------|------|
| GET | `/api/exceptions` | 예외 목록 조회 | O | ALL |
| POST | `/api/exceptions` | 예외 등록 (단건) | O | ADMIN |
| POST | `/api/exceptions/bulk` | 예외 등록 (일괄) | O | ADMIN |
| DELETE | `/api/exceptions/{exception_id}` | 예외 삭제 | O | ADMIN |

### `GET /api/exceptions`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Response** | `total` | int | 전체 예외 수 |
| | `active_count` | int | 활성 예외 수 |
| | `expired_count` | int | 만료 예외 수 |
| | `items` | array | 예외 상세 목록 |

### `POST /api/exceptions`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `server_id` | string | O | 서버 ID |
| | `item_code` | string | O | 항목 코드 |
| | `reason` | string | O | 예외 사유 |
| | `valid_date` | string | O | 만료일 (`YYYY-MM-DD HH:MM:SS`) |
| **Response** | `exception_id` | int | | 생성된 예외 ID (201) |
| | `message` | string | | 성공 메시지 |

### `POST /api/exceptions/bulk`

| 구분 | 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|------|
| **Request** | `item_code` | string | O | 항목 코드 |
| | `reason` | string | O | 예외 사유 |
| | `valid_date` | string | O | 만료일 |
| | `server_ids` | string[] / null | | 대상 서버 (null = 전체) |
| **Response** | `created_count` | int | | 생성 건수 |
| | `skipped_count` | int | | 스킵 건수 (중복 등) |
| | `total_servers` | int | | 대상 서버 수 |

### `DELETE /api/exceptions/{exception_id}`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Path** | `exception_id` | int | 예외 ID |
| **Response** | `message` | string | 성공 메시지 |

---

## 8. Reports (`/api/reports`)

| Method | Endpoint | 설명 | 인증 | 권한 |
|--------|----------|------|------|------|
| POST | `/api/reports/generate` | 엑셀 보고서 생성 및 다운로드 | O | ALL |

### `POST /api/reports/generate`

| 구분 | 필드 | 타입 | 설명 |
|------|------|------|------|
| **Request** | - | - | Body 없음 (인증 토큰만 필요) |
| **Response** | | binary | `.xlsx` 파일 다운로드 |
| | `Content-Type` | header | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |
| | `Content-Disposition` | header | `attachment; filename*=UTF-8''<회사명>_취약점진단결과_<timestamp>.xlsx` |

**에러 응답:**

| Status | 상황 | 응답 |
|--------|------|------|
| 404 | DB 연결 실패 / 활성 서버 없음 / 점검 결과 없음 | `{detail: "에러 메시지"}` |
| 500 | 보고서 생성 중 오류 | `{detail: "보고서 생성 중 오류가 발생했습니다: ..."}` |

**보고서 시트 구성:**

| 순서 | 시트명 | 내용 |
|------|--------|------|
| 1 | 표지 | 프로젝트 정보, 목차 |
| 2 | 대시보드 | 전체 요약, 차트, Top 5 하위 서버 |
| 3 | 항목별 요약 | UNIX/DB 항목별 통계, 취약 서버 리스트 |
| 4 | 자산 목록 | 서버 목록 (시트 하이퍼링크) |
| 5~N | [서버별 시트] | 서버 1대당 1시트, 샘플4 형식 상세 결과 |

---

## 공통 에러 응답

| Status | 설명 | 응답 형식 |
|--------|------|-----------|
| 400 | 잘못된 요청 (파라미터 오류 등) | `{detail: "에러 메시지"}` |
| 401 | 인증 실패 (토큰 없음/만료) | `{detail: "Not authenticated"}` |
| 403 | 권한 부족 (ADMIN 필요) | `{detail: "권한이 없습니다"}` |
| 404 | 리소스 없음 | `{detail: "에러 메시지"}` |
| 409 | 중복 충돌 (서버 ID 등) | `{detail: "에러 메시지"}` |
| 500 | 서버 내부 오류 | `{detail: "에러 메시지"}` |
