-- ============================================================
-- KISA Security Project - Schema Refactoring Rollback
-- 001_refactor_schema_rollback.sql
--
-- Purpose:
--   001_refactor_schema.sql migration을 되돌림
--
-- Warning:
--   - created_at, updated_at 컬럼 삭제 시 데이터 손실
--   - INT → VARCHAR 변환 시 기존 데이터 확인 필요
-- ============================================================

USE kisa_security;

-- ============================================================
-- 1. servers 테이블 스키마 원복
-- ============================================================

-- db_passwd를 다시 NOT NULL로 변경
-- WARNING: NULL 값이 있으면 실패할 수 있음
ALTER TABLE servers
  MODIFY COLUMN db_passwd LONGTEXT NOT NULL;

-- 포트 타입을 INT → VARCHAR로 원복
ALTER TABLE servers
  MODIFY COLUMN ssh_port VARCHAR(10) NOT NULL DEFAULT '22',
  MODIFY COLUMN db_port VARCHAR(10) NULL;

-- 타임스탬프 컬럼 삭제
ALTER TABLE servers
  DROP COLUMN created_at,
  DROP COLUMN updated_at;


-- ============================================================
-- 2. servers 테이블 인덱스 제거
-- ============================================================

ALTER TABLE servers
  DROP INDEX idx_company,
  DROP INDEX idx_db_type,
  DROP INDEX idx_is_active;


-- ============================================================
-- 3. scan_history 테이블 인덱스 제거
-- ============================================================

ALTER TABLE scan_history
  DROP INDEX idx_server_item,
  DROP INDEX idx_scan_date;


-- ============================================================
-- 4. remediation_logs 테이블 인덱스 제거
-- ============================================================

ALTER TABLE remediation_logs
  DROP INDEX idx_server_item,
  DROP INDEX idx_action_date;


-- ============================================================
-- Rollback 완료
-- ============================================================

SELECT '✅ Rollback 001_refactor_schema completed successfully' AS status;
