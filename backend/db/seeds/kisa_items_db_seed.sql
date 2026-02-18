-- Seed data for kisa_items (DBMS items).
-- NOTE:
-- - To avoid primary key collisions between PostgreSQL/MySQL items, item_code is namespaced:
--   - PostgreSQL: PG-D-xx
--   - MySQL:      MY-D-xx
-- - This script is idempotent via ON DUPLICATE KEY UPDATE.

USE kisa_security;

-- PostgreSQL 보안 점검
INSERT INTO kisa_items (item_code, category, title, severity, description, auto_fix, auto_fix_description, guide) VALUES
('PG-D-01','account','기본 계정의 비밀번호, 정책 등을 변경하여 사용(PostgreSQL)','상','기본/공용(슈퍼유저) 계정이 초기 상태로 운용되지 않도록 비밀번호 및 로그인 정책이 변경되어 있는지 점검.',0,'계정 권한 및 비번 변경은 서비스 연결에 직접적인 영향을 주므로 자동 조치를 제공하지 않습니다.','postgres 계정에 강력한 비밀번호를 설정하거나 운영상 불필요하면 NOLOGIN 처리를 해야 합니다.'),
('PG-D-02','account','데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용(PostgreSQL)','상','불필요하거나 미사용 계정이 제거 또는 로그인 잠금(NOLOGIN) 처리되어 있는지 점검.',0,'사용 중인 서비스 계정일 경우 즉시 장애로 이어지므로 수동 확인이 필요합니다.','미사용 계정을 식별하여 ALTER ROLE [계정] NOLOGIN; 또는 DROP ROLE 처리를 해야 합니다.'),
('PG-D-03','account','비밀번호의 사용기간 및 복잡도를 정책에 맞도록 설정(PostgreSQL)','상','비밀번호 만료(사용기간) 및 복잡도 정책이 기관 기준에 맞게 적용되어 있는지 점검.',0,'복잡도 강제 시 기존 앱의 재인증 실패 위험이 있어 수동 조치만 제공합니다.','password_encryption을 scram-sha-256으로 설정하고 VALID UNTIL을 사용해 만료일을 지정해야 합니다.'),
('PG-D-04','account','DB 관리자 권한을 꼭 필요한 계정에만 허용(PostgreSQL)','상','슈퍼유저 및 고권한(ROLE/DB 생성 등)이 최소 계정(역할)에만 부여되어 있는지 점검.',0,'권한 회수 시 운영 및 백업 작업이 중단될 수 있어 자동 조치를 제공하지 않습니다.','비승인 계정에서 NOSUPERUSER 등을 적용하고 역할 기반(Role-based)으로 운영해야 합니다.'),
('PG-D-05','account','비밀번호 재사용에 대한 제약 설정(PostgreSQL)','중','비밀번호 재사용 제한(이력/재사용 간격)이 정책에 따라 적용되어 있는지 점검.',0,'PostgreSQL은 기본적으로 재사용 이력 기능을 제공하지 않아 외부 인증 연동(PAM 등)이 필요하므로 자동 조치가 불가능합니다.','SSO/LDAP/PAM 등 외부 인증 시스템에서 재사용 제한 정책을 강제해야 합니다.'),
('PG-D-06','account','DB 사용자 계정을 개별적으로 부여하여 사용(PostgreSQL)','중','공용 계정 사용을 지양하고 사용자/서비스별 개별 계정 발급 및 권한 분리가 적용되어 있는지 점검.',0,'계정 분리는 앱 코드 수정을 동반하므로 자동 조치를 제공하지 않습니다.','개인/서비스별로 계정을 생성하고 그룹 역할을 통해 최소 권한만 부여해야 합니다.'),
('PG-D-07','account','root 권한으로 서비스 구동 제한(PostgreSQL)','중','DB 서비스 프로세스가 root가 아닌 전용 계정(postgres)으로 구동되는지 점검.',0,'설정 변경 및 소유권 작업 중 서비스 중단이 발생할 수 있어 수동 조치가 필요합니다.','systemd 유닛 파일 및 데이터 디렉터리 소유자를 postgres로 설정해야 합니다.'),
('PG-D-08','account','안전한 암호화 알고리즘 사용(PostgreSQL)','상','비밀번호 저장/인증 및 전송 구간에서 안전한 암호화 알고리즘이 사용되고 있는지 점검.',0,'인증 방식 변경 시 클라이언트 드라이버 호환성 문제가 발생할 수 있어 수동 조치가 필요합니다.','scram-sha-256 인증 방식을 사용하고 전송 구간 암호화(SSL)를 구성해야 합니다.'),
('PG-D-09','account','로그인 실패 시 잠금정책 설정(PostgreSQL)','중','로그인 실패 기반 잠금/차단 정책이 적용되어 있는지 점검.',0,'PostgreSQL 자체 기능보다는 외부 도구(fail2ban 등) 연동이 필요하므로 자동 조치를 제공하지 않습니다.','log_connections를 활성화하고 fail2ban 등을 사용해 IP 기반 차단을 구성해야 합니다.'),
('PG-D-10','access','원격에서 DB 서버로의 접속 제한(PostgreSQL)','상','원격 접속이 필요한 IP/대역으로만 제한되어 있는지 점검.',0,'잘못된 제한 시 원격 관리자의 접속이 차단되므로 자동 조치를 제공하지 않습니다.','pg_hba.conf 파일에서 허용할 IP 대역을 명확히 명시하고 listen_addresses를 제한해야 합니다.'),
('PG-D-11','access','비인가자의 시스템 테이블 접근 제한(PostgreSQL)','상','비인가 사용자가 시스템 영역 및 서버 기능성 권한에 과도하게 접근하지 못하도록 관리되는지 점검.',0,'모니터링 도구 등의 작동에 영향을 줄 수 있어 수동 확인이 필요합니다.','불필요한 pg_* 역할(server_files 등)을 비관리자 계정에서 회수해야 합니다.'),
('PG-D-14','access','주요 파일 접근 권한 설정(PostgreSQL)','중','데이터 디렉터리 및 주요 설정/키 파일의 소유자와 권한이 최소화되어 있는지 점검.',0,'파일 권한 미준수 시 DB 기동 자체가 실패할 수 있어 자동 조치를 제공하지 않습니다.','데이터 디렉터리는 700, 설정 파일은 600 권한으로 postgres 소유여야 합니다.'),
('PG-D-18','option','Role이 Public으로 설정되지 않도록 조정(PostgreSQL)','상','PUBLIC(전체 사용자)에게 과도한 권한이 부여되어 있지 않은지 점검.',0,'기본 권한 회수 시 앱의 스키마 접근이 불가능해질 수 있어 수동 조치가 필요합니다.','public 스키마의 CREATE 권한을 PUBLIC에서 회수하고 전용 스키마를 사용해야 합니다.'),
('PG-D-20','option','인가되지 않은 Object owner의 제한(PostgreSQL)','하','DB 객체의 소유자가 승인된 계정(역할)으로 일관되게 관리되는지 점검.',0,'소유자 변경 시 앱의 실행 권한 문제가 발생할 수 있어 수동 조치를 제공합니다.','객체 소유 현황을 조회하여 승인된 소유자 역할(app_owner 등)로 이관해야 합니다.'),
('PG-D-21','option','인가되지 않은 GRANT OPTION 사용 제한(PostgreSQL)','중','권한 재위임이 가능한 GRANT OPTION이 불필요하게 부여되지 않았는지 점검.',0,'권한 구조 변경 시 배포 프로세스에 영향을 줄 수 있어 자동 조치를 제공하지 않습니다.','ADMIN OPTION 및 WITH GRANT OPTION 부여 현황을 확인하여 불필요한 재위임 권한을 회수해야 합니다.'),
('PG-D-25','patch','보안 패치 및 벤더 권고 사항 적용(PostgreSQL)','상','보안 패치 및 권고사항이 주기적으로 적용되는지 점검.',0,'패치 적용은 서비스 중단 및 롤백 계획이 수반되어야 하므로 자동 조치를 제공하지 않습니다.','유지보수 창을 확보하여 최신 마이너/메이저 버전을 주기적으로 업데이트해야 합니다.'),
('PG-D-26','patch','감사 기록 설정(PostgreSQL)','상','감사 로그가 정책에 맞게 기록·보관·모니터링되는지 점검.',0,'로그 설정 변경 및 pgaudit 모듈 적용은 성능에 영향을 줄 수 있어 수동 조치가 필요합니다.','log_statement 설정을 적용하거나 정교한 감사가 필요할 경우 pgaudit을 구성해야 합니다.')
AS new
ON DUPLICATE KEY UPDATE
  category=new.category,
  title=new.title,
  severity=new.severity,
  description=new.description,
  auto_fix=new.auto_fix,
  auto_fix_description=new.auto_fix_description,
  guide=new.guide;

-- MySQL 보안 점검
INSERT INTO kisa_items (item_code, category, title, severity, description, auto_fix, auto_fix_description, guide) VALUES
('MY-D-01','account','기본 계정의 비밀번호 변경(MySQL)','상','root 계정이 초기 상태로 운용되지 않도록 비밀번호 및 로그인 정책이 변경되어 있는지 점검.',0,'root 비번 변경은 전체 시스템 마비를 초래할 수 있어 자동 조치를 제공하지 않습니다.','ALTER USER ''root''@''localhost'' IDENTIFIED BY ''강력한비밀번호''; 를 적용해야 합니다.'),
('MY-D-02','account','불필요한 계정 제거(MySQL)','상','익명 계정 및 test 데이터베이스 등 불필요한 요소가 제거되어 있는지 점검.',0,'삭제 전 의존성 확인이 필수적이므로 수동 조치를 제공합니다.','익명 계정 및 test DB를 DROP 명령어로 삭제해야 합니다.'),
('MY-D-03','account','비밀번호 만료 및 복잡도 설정(MySQL)','상','비밀번호 사용기간 및 복잡성 강제 정책 적용 여부 점검.',0,'정책 강제 시 기존 계정 잠김 위험이 있어 수동 조치만 제공합니다.','validate_password 컴포넌트를 설치하고 default_password_lifetime을 설정해야 합니다.'),
('MY-D-04','account','DB 관리자 권한 최소화(MySQL)','상','고권한(ALL PRIVILEGES, GRANT OPTION 등)이 최소 계정에만 부여되어 있는지 점검.',0,'권한 회수 시 운영 장애 위험이 있어 수동 조치가 권장됩니다.','*.* 범위의 고권한을 회수하고 필요한 스키마 단위로만 권한을 재부여해야 합니다.'),
('MY-D-06','account','개별 계정 부여 및 사용(MySQL)','중','공용 계정을 지양하고 사용자별 개별 계정 발급 여부 점검.',0,'계정 체계 변경은 앱 수정을 동반하므로 수동 조치가 필요합니다.','서비스별, 개인별로 계정을 분리 생성하고 최소 권한만 부여해야 합니다.'),
('MY-D-07','account','root 권한 구동 제한(MySQL)','중','MySQL 데몬이 일반 유저(mysql) 권한으로 실행되는지 점검.',0,'프로세스 소유권 변경은 서비스 재시작이 필요하므로 자동 조치를 제공하지 않습니다.','my.cnf 설정 및 데이터 디렉터리 소유자를 mysql로 정리해야 합니다.'),
('MY-D-08','account','안전한 암호화 알고리즘 사용(MySQL)','상','인증 플러그인 및 TLS 전송 구간 암호화 적용 여부 점검.',0,'암호화 강제 시 구형 클라이언트 접속 실패 위험이 있어 수동 조치가 필요합니다.','caching_sha2_password를 사용하고 require_secure_transport 설정을 활성화해야 합니다.'),
('MY-D-10','access','원격 접속 제한(MySQL)','상','불필요한 원격 접속(%) 허용 여부 및 bind-address 점검.',0,'접속 차단 시 서비스 중단 위험이 커서 자동 조치를 제공하지 않습니다.','bind-address를 특정하고 계정의 Host 필드를 특정 IP/대역으로 제한해야 합니다.'),
('MY-D-11','access','시스템 테이블 접근 관리(MySQL)','상','비인가 사용자의 mysql.* DB 접근 권한을 제한하는지 점검.',0,'권한 회수 시 운영 도구 오작동 가능성이 있어 수동 확인이 필요합니다.','일반 계정에서 mysql 스키마에 대한 권한을 회수해야 합니다.'),
('MY-D-21','option','GRANT OPTION 사용 제한(MySQL)','중','권한 재위임 기능이 불필요하게 부여되었는지 점검.',0,'권한 구조 변경 시 관리 프로세스 영향이 커서 자동 조치를 제공하지 않습니다.','WITH GRANT OPTION 부여 현황을 확인하여 불필요한 경우 회수해야 합니다.'),
('MY-D-25','patch','보안 패치 적용(MySQL)','상','최신 보안 패치 및 벤더 권고사항 적용 여부 점검.',0,'패치 작업은 서비스 안정성 검증이 우선이므로 자동 조치를 제공하지 않습니다.','주기적으로 버전을 확인하고 스테이징 환경 검증 후 패치를 적용해야 합니다.')
AS new
ON DUPLICATE KEY UPDATE
  category=new.category,
  title=new.title,
  severity=new.severity,
  description=new.description,
  auto_fix=new.auto_fix,
  auto_fix_description=new.auto_fix_description,
  guide=new.guide;

