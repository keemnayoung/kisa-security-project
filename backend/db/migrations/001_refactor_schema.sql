-- ============================================================
-- KISA Security Project - Schema Refactoring Migration
-- 001_refactor_schema.sql
--
-- Purpose:
--   - servers 테이블 개선 (nullable db_passwd, INT ports, timestamps)
--   - 성능 최적화 인덱스 추가
--   - scan_history, remediation_logs 쿼리 최적화
--
-- Rollback: See 001_refactor_schema_rollback.sql
-- ============================================================

USE kisa_security;

-- ============================================================
-- 1. servers 테이블 스키마 개선
-- ============================================================

-- db_passwd를 NULLABLE로 변경 (DB 없는 서버도 등록 가능)
ALTER TABLE servers
  MODIFY COLUMN db_passwd LONGTEXT NULL;

-- 포트 타입을 VARCHAR → INT로 변경 (타입 안정성)
ALTER TABLE servers
  MODIFY COLUMN ssh_port INT NOT NULL DEFAULT 22,
  MODIFY COLUMN db_port INT NULL;

-- 감사 타임스탬프 추가
ALTER TABLE servers
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;


-- ============================================================
-- 2. servers 테이블 성능 인덱스 추가
-- ============================================================

-- 회사별 필터링 최적화 (대시보드, sync_inventory)
ALTER TABLE servers
  ADD INDEX idx_company (company);

-- DB 타입별 필터링 최적화 (group_vars 생성)
ALTER TABLE servers
  ADD INDEX idx_db_type (db_type);

-- 활성 서버 조회 최적화
ALTER TABLE servers
  ADD INDEX idx_is_active (is_active);


-- ============================================================
-- 3. scan_history 테이블 인덱스 추가
-- ============================================================

-- 최신 스캔 결과 조회 최적화 (server_id + item_code)
-- 대시보드에서 가장 많이 사용하는 쿼리 패턴
ALTER TABLE scan_history
  ADD INDEX idx_server_item (server_id, item_code);

-- 스캔 날짜 내림차순 정렬 최적화
ALTER TABLE scan_history
  ADD INDEX idx_scan_date (scan_date DESC);


-- ============================================================
-- 4. remediation_logs 테이블 인덱스 추가
-- ============================================================

-- 항목별 조치 이력 조회 최적화
ALTER TABLE remediation_logs
  ADD INDEX idx_server_item (server_id, item_code);

-- 최근 조치 내역 조회 최적화
ALTER TABLE remediation_logs
  ADD INDEX idx_action_date (action_date DESC);


-- ============================================================
-- Migration 완료
-- ============================================================

SELECT '✅ Migration 001_refactor_schema completed successfully' AS status;
