# KISA Security Project Architecture

## 1) Overview

이 프로젝트는 점검/조치 스크립트를 원격 서버에서 실행하고, 결과를 JSON으로 수집한 뒤 MySQL에 적재하여 Streamlit 대시보드로 조회하는 구조입니다.

```
[master-node]
  run.sh
    -> ansible/playbooks/*.yml 실행
      -> 대상 서버에서 scripts/* 실행
        -> JSON(stdout) 생성
    -> master-node(/tmp/audit/check|fix) 결과 저장
    -> backend/run_pipeline.py (scan|fix|score)
      -> MySQL(kisa_security) INSERT/집계
    -> dashboard(app.py) 조회
```

## 2) Main Components

- `run.sh`
  - 전체 실행 엔트리포인트 (`scan`, `scan-db`, `fix`, `fix-db`, `score`, `dashboard`)
- `ansible/`
  - 대상 서버 실행 오케스트레이션
  - 주요 플레이북: `scan_os.yml`, `fix_os.yml`, `scan_db.yml`, `fix_db.yml`
  - 인벤토리: `inventories/hosts.ini`, `inventories/group_vars/*.yml`
- `scripts/`
  - 실제 점검/조치 로직 (OS/DB 분리)
  - 예: `scripts/os/account/check_U01.sh`, `scripts/db/postgres/account/fix_D01.sh`
- `backend/`
  - 파서/DB 접근/점수 계산
  - `run_pipeline.py` -> `processors/parse_scan_result.py`, `processors/parse_fix_result.py`, `processors/score_calculator.py`
  - DB 스키마: `backend/db/schema.sql`
- `dashboard/`
  - Streamlit UI (`app.py`, `pages/*`, `components/*`)

## 3) Data Flow

### Scan Flow

1. `./run.sh scan` 또는 `./run.sh scan-db`
2. Ansible이 점검 스크립트를 대상 서버에서 실행
3. 스크립트가 JSON을 stdout으로 출력
4. 플레이북이 결과를 `/tmp/audit/check/*.json`에 저장
5. `python3 backend/run_pipeline.py scan`
6. `scan_history` 테이블 적재
7. 대시보드 조회

### Fix Flow

1. `./run.sh fix` 또는 `./run.sh fix-db`
2. Ansible이 조치 스크립트를 대상 서버에서 실행
3. 스크립트가 JSON을 stdout으로 출력 (`item_code`, `action_date`, `is_success`, `raw_evidence`)
4. 플레이북이 결과를 `/tmp/audit/fix/*.json`에 저장
5. `python3 backend/run_pipeline.py fix`
6. `remediation_logs` 테이블 적재
7. 대시보드 조회

## 4) Database Model (Current)

- 정적 테이블
  - `servers`, `kisa_items`, `users`, `exceptions`
- 동적 테이블
  - `scan_history` (점검 이력)
  - `remediation_logs` (조치 이력, `failure_reason` 포함)

## 5) Naming & Output Conventions

- 점검 결과 파일: `COMPANY_SERVERID_check_D01.json` 또는 `..._check_U01.json`
- 조치 결과 파일: `COMPANY_SERVERID_fix_D01.json` 또는 `..._fix_U01.json`
- 스크립트 JSON 필드:
  - Scan: `item_code`, `status`, `raw_evidence`, `scan_date`
  - Fix: `item_code`, `action_date`, `is_success`, `raw_evidence`

## 6) Operational Notes

- PostgreSQL 조치(`fix_D01.sh`)는 `NEW_SUPERUSER_PASSWORD` 없으면 `is_success=0`이 정상 동작입니다.
- 민감정보는 평문 커밋 금지:
  - `group_vars` + `ansible-vault` 사용 권장
  - Ansible 태스크에 `no_log: true` 적용 권장
- 결과 파일 권한/정리 이슈 방지를 위해:
  - localhost 결과 저장 태스크는 `delegate_to: localhost` + `become: no`
  - 정리 로직은 실패를 숨기지 않고 경고 출력

## 7) Current Structure Snapshot

```
ansible/
  inventories/
  playbooks/
backend/
  db/
  processors/
dashboard/
  components/
  pages/
scripts/
  os/
  db/
run.sh
```
