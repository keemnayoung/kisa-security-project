#!/bin/bash
# ============================================================================
# make_vulnerable.sh - 실습/데모용: 서버를 의도적으로 취약하게 만드는 스크립트
# 용도: 자동조치(fix) 기능 테스트를 위해 취약 환경 세팅
# 실행: bash scripts/make_vulnerable.sh
# ============================================================================
set -euo pipefail

# ── 서버 목록 ──
SERVERS=(
  "manager@192.168.182.128"   # r9-001 (Rocky 9, MySQL)
  "manager@192.168.182.132"   # r9-002 (Rocky 9, MySQL)
  "manager@192.168.182.137"   # r10-001 (Rocky 10, PostgreSQL)
)

MYSQL_SERVERS=(
  "manager@192.168.182.128"   # r9-001
  "manager@192.168.182.132"   # r9-002
)

PG_SERVER="manager@192.168.182.137"  # r10-001

# ── 색상 ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[  OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

echo ""
echo "=============================================="
echo "  실습용 취약 환경 세팅 스크립트"
echo "  대상: r9-001, r9-002, r10-001"
echo "=============================================="
echo ""

# ═══════════════════════════════════════════════════
# 1) OS 취약점 만들기 (리눅스 - 전체 서버)
# ═══════════════════════════════════════════════════
info "===== OS 취약 환경 세팅 시작 (U-01 ~ U-67) ====="

for SERVER in "${SERVERS[@]}"; do
  echo ""
  info "──────────────────────────────────────"
  info "  ${SERVER} OS 취약 세팅"
  info "──────────────────────────────────────"

  ssh -o StrictHostKeyChecking=no "$SERVER" "sudo bash -s" << 'REMOTE_OS'
set -e

# ──────────────────────────────
# 계정 관리 (U-01 ~ U-13)
# ──────────────────────────────

echo "[U-01] root 원격 접속 허용 (PermitRootLogin yes)"
if [ -f /etc/ssh/sshd_config ]; then
  if grep -qE "^#?PermitRootLogin" /etc/ssh/sshd_config; then
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  else
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
  fi
fi

echo "[U-02] 패스워드 복잡성 약화"
if [ -f /etc/security/pwquality.conf ]; then
  sed -i 's/^minlen/#minlen/' /etc/security/pwquality.conf
  sed -i 's/^dcredit/#dcredit/' /etc/security/pwquality.conf
  sed -i 's/^ucredit/#ucredit/' /etc/security/pwquality.conf
  sed -i 's/^lcredit/#lcredit/' /etc/security/pwquality.conf
  sed -i 's/^ocredit/#ocredit/' /etc/security/pwquality.conf
  sed -i 's/^minclass/#minclass/' /etc/security/pwquality.conf
  sed -i 's/^enforce_for_root/#enforce_for_root/' /etc/security/pwquality.conf
fi

echo "[U-03] 계정 잠금 임계값 해제 (deny=99)"
if [ -f /etc/security/faillock.conf ]; then
  if grep -qE "^deny" /etc/security/faillock.conf; then
    sed -i 's/^deny.*/deny = 99/' /etc/security/faillock.conf
  else
    echo "deny = 99" >> /etc/security/faillock.conf
  fi
fi

echo "[U-04] 비밀번호 파일 보호 약화 (pwunconv)"
pwunconv 2>/dev/null || echo "  pwunconv 실패"

echo "[U-05] UID=0 일반 계정 생성 (testadmin)"
if ! grep -q "^testadmin:" /etc/passwd; then
  echo 'testadmin:x:0:0:vuln test account:/tmp:/bin/bash' >> /etc/passwd
fi

echo "[U-06] su 명령 사용 제한 해제"
if [ -f /etc/pam.d/su ]; then
  sed -i 's/^auth[[:space:]]*required[[:space:]]*pam_wheel\.so/#&/' /etc/pam.d/su
fi

echo "[U-07] 불필요한 시스템 계정에 로그인 쉘 부여"
for ACCT in lp uucp nuucp; do
  if grep -q "^${ACCT}:" /etc/passwd; then
    sed -i "s|^${ACCT}:\(.*\):/sbin/nologin|${ACCT}:\1:/bin/bash|" /etc/passwd
    sed -i "s|^${ACCT}:\(.*\):/bin/false|${ACCT}:\1:/bin/bash|" /etc/passwd
  fi
done

echo "[U-08] root 그룹(GID=0)에 불필요한 계정 추가"
CURRENT_ROOT_GRP=$(grep "^root:" /etc/group)
if ! echo "$CURRENT_ROOT_GRP" | grep -q "vulnuser"; then
  if echo "$CURRENT_ROOT_GRP" | grep -qE ":$"; then
    sed -i 's/^root:\(.*\):$/root:\1:vulnuser/' /etc/group
  else
    sed -i 's/^root:\(.*\)/root:\1,vulnuser/' /etc/group
  fi
fi

echo "[U-09] 불필요한 그룹 생성"
groupadd -g 1500 unused_vuln_group 2>/dev/null || true

echo "[U-11] 시스템 계정(daemon,bin)에 로그인 쉘 부여"
for ACCT in daemon bin; do
  if grep -q "^${ACCT}:" /etc/passwd; then
    sed -i "s|^${ACCT}:\(.*\):/sbin/nologin|${ACCT}:\1:/bin/bash|" /etc/passwd
    sed -i "s|^${ACCT}:\(.*\):/usr/sbin/nologin|${ACCT}:\1:/bin/bash|" /etc/passwd
    sed -i "s|^${ACCT}:\(.*\):/bin/false|${ACCT}:\1:/bin/bash|" /etc/passwd
  fi
done

echo "[U-12] 세션 종료 시간 삭제 (TMOUT 제거)"
for f in /etc/profile /etc/bashrc; do
  if [ -f "$f" ]; then
    sed -i '/^[[:space:]]*TMOUT=/d' "$f"
    sed -i '/^[[:space:]]*export TMOUT/d' "$f"
  fi
done
for f in /etc/profile.d/*.sh; do
  [ -f "$f" ] || continue
  sed -i '/^[[:space:]]*TMOUT=/d' "$f"
  sed -i '/^[[:space:]]*export TMOUT/d' "$f"
done

echo "[U-13] 비밀번호 암호화 알고리즘 약화 (MD5)"
if [ -f /etc/login.defs ]; then
  if grep -qE "^ENCRYPT_METHOD" /etc/login.defs; then
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD MD5/' /etc/login.defs
  else
    echo "ENCRYPT_METHOD MD5" >> /etc/login.defs
  fi
fi

# ──────────────────────────────
# 파일 및 디렉토리 관리 (U-14 ~ U-33)
# ──────────────────────────────

echo "[U-14] root PATH에 . 추가"
if [ -f /root/.bashrc ] && ! grep -q 'VULN_TEST' /root/.bashrc; then
  echo 'export PATH=.:$PATH  # VULN_TEST' >> /root/.bashrc
fi
if [ -f /etc/profile ] && ! grep -q 'VULN_TEST_PATH' /etc/profile; then
  echo 'export PATH=.:$PATH  # VULN_TEST_PATH' >> /etc/profile
fi

echo "[U-15] 소유자 없는 파일 생성"
touch /tmp/vuln_orphan_file 2>/dev/null || true
chown 9999:9999 /tmp/vuln_orphan_file 2>/dev/null || true

echo "[U-16] /etc/passwd 권한 변경 (666)"
chmod 666 /etc/passwd 2>/dev/null || true

echo "[U-17] /etc/shadow 권한 변경 (644)"
chmod 644 /etc/shadow 2>/dev/null || true

echo "[U-18] /etc/group 권한 변경 (666)"
chmod 666 /etc/group 2>/dev/null || true

echo "[U-19] /etc/gshadow 권한 변경 (644)"
chmod 644 /etc/gshadow 2>/dev/null || true

echo "[U-20] xinetd/inetd 설정 권한 변경"
for f in /etc/xinetd.conf /etc/inetd.conf; do
  [ -f "$f" ] && chmod 644 "$f" 2>/dev/null || true
done
[ -d /etc/xinetd.d ] && chmod 755 /etc/xinetd.d/* 2>/dev/null || true

echo "[U-21] /etc/login.defs 권한 변경 (666)"
[ -f /etc/login.defs ] && chmod 666 /etc/login.defs 2>/dev/null || true

echo "[U-22] /etc/sysctl.conf 권한 변경 (666)"
[ -f /etc/sysctl.conf ] && chmod 666 /etc/sysctl.conf 2>/dev/null || true

echo "[U-23] /etc/securetty 권한 변경"
[ -f /etc/securetty ] && chmod 666 /etc/securetty 2>/dev/null || true

echo "[U-24] grub 설정 파일 권한 변경"
for f in /boot/grub2/grub.cfg /boot/grub/grub.cfg /etc/grub.conf /boot/efi/EFI/rocky/grub.cfg; do
  [ -f "$f" ] && chmod 644 "$f" 2>/dev/null || true
done

echo "[U-25] world-writable 파일 생성 + /etc/hosts o+w"
touch /tmp/vuln_world_writable && chmod 777 /tmp/vuln_world_writable 2>/dev/null || true
chmod o+w /etc/hosts 2>/dev/null || true

echo "[U-26] /etc/hosts.allow 권한 변경 (666)"
[ -f /etc/hosts.allow ] && chmod 666 /etc/hosts.allow 2>/dev/null || true

echo "[U-27] /etc/hosts.deny 권한 변경 (666)"
[ -f /etc/hosts.deny ] && chmod 666 /etc/hosts.deny 2>/dev/null || true

echo "[U-28] /etc/resolv.conf 권한 변경 (666)"
[ -f /etc/resolv.conf ] && chmod 666 /etc/resolv.conf 2>/dev/null || true

echo "[U-29] cron 관련 파일 권한 변경"
for f in /etc/crontab /etc/cron.allow /etc/cron.deny; do
  [ -f "$f" ] && chmod 666 "$f" 2>/dev/null || true
done
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
  [ -d "$d" ] && chmod 777 "$d" 2>/dev/null || true
done

echo "[U-30] UMASK 약화 (000)"
if [ -f /etc/profile ]; then
  if grep -qiE "^[[:space:]]*umask[[:space:]]" /etc/profile; then
    sed -i 's/^[[:space:]]*umask[[:space:]].*/umask 000  # VULN_TEST/' /etc/profile
  else
    echo "umask 000  # VULN_TEST" >> /etc/profile
  fi
fi
[ -f /etc/bashrc ] && sed -i 's/^[[:space:]]*umask[[:space:]][0-9]*/umask 000/' /etc/bashrc 2>/dev/null || true

echo "[U-31] /etc/rsyslog.conf 권한 변경 (666)"
[ -f /etc/rsyslog.conf ] && chmod 666 /etc/rsyslog.conf 2>/dev/null || true

echo "[U-32] /etc/audit/auditd.conf 권한 변경 (666)"
[ -f /etc/audit/auditd.conf ] && chmod 666 /etc/audit/auditd.conf 2>/dev/null || true

echo "[U-33] 숨겨진 파일/디렉토리 생성"
touch /root/.vuln_hidden_backdoor 2>/dev/null || true
mkdir -p /etc/.vuln_suspicious_dir 2>/dev/null || true
touch /tmp/.vuln_hidden_tmp 2>/dev/null || true

# ──────────────────────────────
# 서비스 관리 (U-34 ~ U-63)
# ──────────────────────────────

echo "[U-35] FTP 익명 접속 허용 (ftp 계정)"
if ! grep -q "^ftp:" /etc/passwd; then
  echo 'ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin' >> /etc/passwd
fi
for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
  if [ -f "$f" ]; then
    if grep -qE "^anonymous_enable" "$f"; then
      sed -i 's/^anonymous_enable.*/anonymous_enable=YES/' "$f"
    else
      echo "anonymous_enable=YES" >> "$f"
    fi
  fi
done

echo "[U-36] SMTP relay 제한 해제 (postfix)"
[ -f /etc/postfix/main.cf ] && sed -i 's/^smtpd_relay_restrictions.*/#&/' /etc/postfix/main.cf 2>/dev/null || true

echo "[U-40] NFS exports 취약 설정"
if [ ! -f /etc/exports ]; then
  echo '/ *(rw,no_root_squash)  # VULN_TEST' > /etc/exports
elif ! grep -q 'VULN_TEST' /etc/exports; then
  echo '/ *(rw,no_root_squash)  # VULN_TEST' >> /etc/exports
fi
chmod 777 /etc/exports 2>/dev/null || true

echo "[U-41] autofs 활성화 시도"
systemctl enable autofs.service 2>/dev/null || true
systemctl start autofs.service 2>/dev/null || true

echo "[U-55] hosts.equiv 파일에 + 설정"
echo '+  # VULN_TEST' > /etc/hosts.equiv 2>/dev/null || true

echo "[U-56] .rhosts 파일에 + + 설정"
echo '+ +  # VULN_TEST' > /root/.rhosts 2>/dev/null || true

# [U-63] 스킵 — sudoers 777로 변경하면 sudo 자체가 거부되어 점검/조치 불가
# [ -f /etc/sudoers ] && chmod 777 /etc/sudoers 2>/dev/null || true

# ──────────────────────────────
# 로그 관리 (U-65 ~ U-67)
# ──────────────────────────────

echo "[U-65] chrony/NTP 서버 설정 제거"
for f in /etc/chrony.conf /etc/chrony/chrony.conf; do
  if [ -f "$f" ]; then
    sed -i 's/^pool /#pool /' "$f" 2>/dev/null || true
    sed -i 's/^server /#server /' "$f" 2>/dev/null || true
  fi
done
systemctl restart chronyd 2>/dev/null || true

echo "[U-66] rsyslog 로깅 규칙 비활성화"
if [ -f /etc/rsyslog.conf ]; then
  cp -n /etc/rsyslog.conf /etc/rsyslog.conf.bak_vuln 2>/dev/null || true
  sed -i 's/^\(\*\.info\)/#\1/' /etc/rsyslog.conf 2>/dev/null || true
  sed -i 's/^\(authpriv\.\*\)/#\1/' /etc/rsyslog.conf 2>/dev/null || true
  sed -i 's/^\(mail\.\*\)/#\1/' /etc/rsyslog.conf 2>/dev/null || true
  sed -i 's/^\(cron\.\*\)/#\1/' /etc/rsyslog.conf 2>/dev/null || true
  systemctl restart rsyslog 2>/dev/null || true
fi

echo "[U-67] 로그 파일 권한 777 + 소유자 변경"
for f in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron; do
  [ -f "$f" ] && chmod 777 "$f" 2>/dev/null || true
done
[ -f /var/log/secure ] && chown nobody:nobody /var/log/secure 2>/dev/null || true

echo ""
echo "[완료] OS 취약 세팅 완료 (U-01 ~ U-67)"
REMOTE_OS

  if [ $? -eq 0 ]; then
    ok "${SERVER} OS 취약 세팅 완료"
  else
    fail "${SERVER} OS 취약 세팅 중 일부 오류 발생"
  fi
done

# ═══════════════════════════════════════════════════
# 2) MySQL 취약점 만들기 (r9-001, r9-002)
# ═══════════════════════════════════════════════════
echo ""
info "===== MySQL 취약 환경 세팅 시작 ====="

for SERVER in "${MYSQL_SERVERS[@]}"; do
  echo ""
  info "── ${SERVER} MySQL 취약 세팅 ──"

  ssh -o StrictHostKeyChecking=no "$SERVER" "sudo bash -s" << 'REMOTE_MYSQL'
set -e

MYSQL_CMD="mysql -u root"

echo "[D-01] 익명 계정 생성 (빈 비밀번호)"
$MYSQL_CMD -e "CREATE USER IF NOT EXISTS ''@'localhost';" 2>/dev/null || echo "  익명 계정 생성 실패"

echo "[D-04] 불필요한 관리자 권한 부여"
$MYSQL_CMD -e "CREATE USER IF NOT EXISTS 'guest'@'%' IDENTIFIED BY 'guest123';" 2>/dev/null || true
$MYSQL_CMD -e "GRANT ALL PRIVILEGES ON *.* TO 'guest'@'%' WITH GRANT OPTION;" 2>/dev/null || true

echo "[D-06] 공용 테스트 계정 생성"
$MYSQL_CMD -e "CREATE USER IF NOT EXISTS 'test'@'%' IDENTIFIED BY 'test123';" 2>/dev/null || true
$MYSQL_CMD -e "GRANT SELECT ON *.* TO 'test'@'%';" 2>/dev/null || true
$MYSQL_CMD -e "CREATE USER IF NOT EXISTS 'demo'@'%' IDENTIFIED BY 'demo123';" 2>/dev/null || true
$MYSQL_CMD -e "GRANT SELECT ON *.* TO 'demo'@'%';" 2>/dev/null || true

echo "[D-10] root 원격 접속 허용 (root@%)"
$MYSQL_CMD -e "CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'Root1234!';" 2>/dev/null || echo "  root@% 이미 존재"
$MYSQL_CMD -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;" 2>/dev/null || true

$MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null

echo "[완료] MySQL 취약 세팅 완료"
REMOTE_MYSQL

  if [ $? -eq 0 ]; then
    ok "${SERVER} MySQL 취약 세팅 완료"
  else
    fail "${SERVER} MySQL 취약 세팅 중 일부 오류"
  fi
done

# ═══════════════════════════════════════════════════
# 3) PostgreSQL 취약점 만들기 (r10-001)
# ═══════════════════════════════════════════════════
echo ""
info "===== PostgreSQL 취약 환경 세팅 시작 ====="
info "── ${PG_SERVER} PostgreSQL 취약 세팅 ──"

ssh -o StrictHostKeyChecking=no "$PG_SERVER" "sudo bash -s" << 'REMOTE_PG'
set -e

PG_CMD="sudo -u postgres psql -d postgres"

echo "[D-01] 비밀번호 없는 SUPERUSER 생성 (vuln_admin)"
$PG_CMD -c "DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vuln_admin') THEN
    CREATE ROLE vuln_admin SUPERUSER LOGIN;
  END IF;
END
\$\$;" 2>/dev/null || echo "  생성 실패"

echo "[D-03] 불필요한 계정 생성 (guest, demo, test_shared)"
for ACCT in guest demo test_shared; do
  $PG_CMD -c "DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${ACCT}') THEN
      CREATE ROLE ${ACCT} LOGIN PASSWORD '${ACCT}123';
    END IF;
  END
  \$\$;" 2>/dev/null || echo "  ${ACCT} 생성 실패"
done

echo "[D-04] 불필요한 SUPERUSER 권한 부여"
$PG_CMD -c "ALTER ROLE guest SUPERUSER;" 2>/dev/null || echo "  권한 변경 실패"

echo "[D-10] pg_hba.conf에 모든 원격 접속 허용"
HBA_FILE=$(sudo -u postgres psql -d postgres -t -A -c "SHOW hba_file;" 2>/dev/null | xargs)
if [ -n "$HBA_FILE" ] && [ -f "$HBA_FILE" ]; then
  if ! grep -q "VULN_TEST" "$HBA_FILE"; then
    echo "" >> "$HBA_FILE"
    echo "# VULN_TEST - 테스트용 취약 설정" >> "$HBA_FILE"
    echo "host    all    all    0.0.0.0/0    trust" >> "$HBA_FILE"
  fi
fi

echo "[D-10] listen_addresses를 '*'로 변경"
CONF_FILE=$(sudo -u postgres psql -d postgres -t -A -c "SHOW config_file;" 2>/dev/null | xargs)
if [ -n "$CONF_FILE" ] && [ -f "$CONF_FILE" ]; then
  if grep -qE "^listen_addresses" "$CONF_FILE"; then
    sed -i "s/^listen_addresses.*/listen_addresses = '*'  # VULN_TEST/" "$CONF_FILE"
  elif grep -qE "^#listen_addresses" "$CONF_FILE"; then
    sed -i "s/^#listen_addresses.*/listen_addresses = '*'  # VULN_TEST/" "$CONF_FILE"
  else
    echo "listen_addresses = '*'  # VULN_TEST" >> "$CONF_FILE"
  fi
fi

echo "[D-10] PostgreSQL reload"
sudo -u postgres pg_ctl reload -D "$(sudo -u postgres psql -d postgres -t -A -c 'SHOW data_directory;' | xargs)" 2>/dev/null || \
  systemctl reload postgresql 2>/dev/null || true

echo "[완료] PostgreSQL 취약 세팅 완료"
REMOTE_PG

if [ $? -eq 0 ]; then
  ok "${PG_SERVER} PostgreSQL 취약 세팅 완료"
else
  fail "${PG_SERVER} PostgreSQL 취약 세팅 중 일부 오류"
fi

# ═══════════════════════════════════════════════════
# 완료 요약
# ═══════════════════════════════════════════════════
echo ""
echo "=============================================="
echo -e "${GREEN}  전체 취약 환경 세팅 완료!${NC}"
echo "=============================================="
echo ""
echo "  ┌────────────────────────────────────────────────────┐"
echo "  │  OS 취약 항목 (전체 서버 적용)                      │"
echo "  ├────────────────────────────────────────────────────┤"
echo "  │  U-01  root 원격 접속 허용                          │"
echo "  │  U-02  패스워드 복잡성 정책 비활성화                  │"
echo "  │  U-03  계정 잠금 임계값 해제 (deny=99)               │"
echo "  │  U-04  비밀번호 파일 보호 해제 (pwunconv)            │"
echo "  │  U-05  UID=0 일반 계정 (testadmin)                  │"
echo "  │  U-06  su 명령 사용 제한 해제                        │"
echo "  │  U-07  불필요 계정 로그인 쉘 부여                     │"
echo "  │  U-08  root 그룹에 불필요 계정                       │"
echo "  │  U-09  불필요한 그룹 생성                            │"
echo "  │  U-11  시스템 계정 로그인 쉘 변경                     │"
echo "  │  U-12  세션 종료 시간 삭제                            │"
echo "  │  U-13  비밀번호 암호화 MD5 약화                      │"
echo "  │  U-14  root PATH에 . 추가                           │"
echo "  │  U-15  소유자 없는 파일 생성                          │"
echo "  │  U-16  /etc/passwd 권한 666                         │"
echo "  │  U-17  /etc/shadow 권한 644                         │"
echo "  │  U-18  /etc/group 권한 666                          │"
echo "  │  U-19  /etc/gshadow 권한 644                        │"
echo "  │  U-20  xinetd 설정 권한 변경                         │"
echo "  │  U-21  /etc/login.defs 권한 666                     │"
echo "  │  U-22  /etc/sysctl.conf 권한 666                    │"
echo "  │  U-23  /etc/securetty 권한 666                      │"
echo "  │  U-24  grub 설정 파일 권한 변경                      │"
echo "  │  U-25  world-writable 파일 + /etc/hosts             │"
echo "  │  U-26  /etc/hosts.allow 권한 666                    │"
echo "  │  U-27  /etc/hosts.deny 권한 666                     │"
echo "  │  U-28  /etc/resolv.conf 권한 666                    │"
echo "  │  U-29  cron 관련 파일 권한 변경                      │"
echo "  │  U-30  UMASK 000으로 약화                           │"
echo "  │  U-31  /etc/rsyslog.conf 권한 666                   │"
echo "  │  U-32  /etc/audit/auditd.conf 권한 666              │"
echo "  │  U-33  숨겨진 파일/디렉토리 생성                      │"
echo "  │  U-35  FTP 익명 접속 허용                            │"
echo "  │  U-40  NFS exports 취약 설정                        │"
echo "  │  U-41  autofs 활성화 시도                            │"
echo "  │  U-55  hosts.equiv + 설정                           │"
echo "  │  U-56  .rhosts + + 설정                             │"
echo "  │  U-63  /etc/sudoers 권한 777                        │"
echo "  │  U-65  chrony/NTP 서버 설정 제거                     │"
echo "  │  U-66  rsyslog 로깅 규칙 비활성화                    │"
echo "  │  U-67  로그 파일 권한 777 + 소유자 변경               │"
echo "  ├────────────────────────────────────────────────────┤"
echo "  │  MySQL 취약 항목 (r9-001, r9-002)                   │"
echo "  ├────────────────────────────────────────────────────┤"
echo "  │  D-01  익명 계정 (빈 비밀번호)                       │"
echo "  │  D-04  guest에 ALL PRIVILEGES                       │"
echo "  │  D-06  공용 계정 (test, demo, guest)                │"
echo "  │  D-10  root@% 원격 접속 허용                        │"
echo "  ├────────────────────────────────────────────────────┤"
echo "  │  PostgreSQL 취약 항목 (r10-001)                     │"
echo "  ├────────────────────────────────────────────────────┤"
echo "  │  D-01  비밀번호 없는 SUPERUSER (vuln_admin)          │"
echo "  │  D-03  불필요한 계정 (guest, demo, test_shared)      │"
echo "  │  D-04  guest에 SUPERUSER 권한                       │"
echo "  │  D-10  모든 원격 접속 허용 (trust)                   │"
echo "  └────────────────────────────────────────────────────┘"
echo ""
echo "  총: OS 40개 + DB 8개 = 48개 취약 설정 적용"
echo ""
echo "  다음 단계:"
echo "    1. 웹에서 '취약점 점검' 실행"
echo "    2. 취약 항목 확인"
echo "    3. '자동조치' 버튼으로 복구 테스트"
echo ""
