#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-27
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-27"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/hosts.equiv /home/*/.rhosts"

CHECK_COMMAND='
# service check
(ps -ef | grep -E "rlogin|rsh|rexec|in\.rlogind|in\.rshd|in\.rexecd" | grep -v grep 2>/dev/null);
(command -v systemctl >/dev/null 2>&1 && (systemctl is-active --quiet rlogin.socket || systemctl is-enabled --quiet rlogin.socket) 2>/dev/null && echo "rlogin.socket=active_or_enabled");
(command -v systemctl >/dev/null 2>&1 && (systemctl is-active --quiet rsh.socket || systemctl is-enabled --quiet rsh.socket) 2>/dev/null && echo "rsh.socket=active_or_enabled");
(command -v systemctl >/dev/null 2>&1 && (systemctl is-active --quiet rexec.socket || systemctl is-enabled --quiet rexec.socket) 2>/dev/null && echo "rexec.socket=active_or_enabled");
(command -v ss >/dev/null 2>&1 && ss -ltnp 2>/dev/null | grep -E ":(512|513|514)\b");
# file check
( [ -f /etc/hosts.equiv ] && stat -c "%n owner=%U perm=%a" /etc/hosts.equiv );
find /home -name ".rhosts" -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%n owner=%U perm=%a" "{}" 2>/dev/null;
grep -nE "^[[:space:]]*\+" /etc/hosts.equiv 2>/dev/null;
find /home -name ".rhosts" -type f -exec grep -nE "^[[:space:]]*\+" {} \; 2>/dev/null
'

REASON_LINE=""
DETAIL_CONTENT=""
GUIDE_LINE=""

FOUND_VULN="N"
SERVICE_USED="NO"
SERVICE_EVIDENCE=""

json_escape() {
  echo "$1" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# 서비스 사용 여부 판정
PS_USED=$(ps -ef | grep -E 'rlogin|rsh|rexec|in\.rlogind|in\.rshd|in\.rexecd' | grep -v grep 2>/dev/null)
if [ -n "$PS_USED" ]; then
  SERVICE_USED="YES"
  SERVICE_EVIDENCE+="ps_match,"
fi

if command -v systemctl >/dev/null 2>&1; then
  for u in rlogin.socket rsh.socket rexec.socket rlogin.service rsh.service rexec.service; do
    if systemctl is-active --quiet "$u" 2>/dev/null || systemctl is-enabled --quiet "$u" 2>/dev/null; then
      SERVICE_USED="YES"
      SERVICE_EVIDENCE+="systemctl_${u},"
    fi
  done
fi

if command -v ss >/dev/null 2>&1; then
  if ss -ltnp 2>/dev/null | grep -Eq ':(512|513|514)\b'; then
    SERVICE_USED="YES"
    SERVICE_EVIDENCE+="ports_512_513_514_listen,"
  fi
fi

SERVICE_EVIDENCE=${SERVICE_EVIDENCE%,}
SERVICE_LINE="service_used=${SERVICE_USED}"
if [ -n "$SERVICE_EVIDENCE" ]; then
  SERVICE_LINE="${SERVICE_LINE}(by:${SERVICE_EVIDENCE})"
fi

# 점검 대상 파일 수집
RHOSTS_FILES=$(find /home -name ".rhosts" -type f 2>/dev/null)

# 현재 설정(DETAIL_CONTENT) 구성: 항상 전체 현황 표시
DETAIL_CONTENT="${SERVICE_LINE}"
if [ -f /etc/hosts.equiv ]; then
  HE_OWNER=$(stat -c %U /etc/hosts.equiv 2>/dev/null)
  HE_PERM=$(stat -c %a /etc/hosts.equiv 2>/dev/null)
  HE_PLUS=$(grep -nE '^[[:space:]]*\+' /etc/hosts.equiv 2>/dev/null | head -n 1)
  if [ -n "$HE_PLUS" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\nfile=/etc/hosts.equiv owner=${HE_OWNER} perm=${HE_PERM} plus=present(${HE_PLUS})"
  else
    DETAIL_CONTENT="${DETAIL_CONTENT}\nfile=/etc/hosts.equiv owner=${HE_OWNER} perm=${HE_PERM} plus=absent"
  fi
else
  DETAIL_CONTENT="${DETAIL_CONTENT}\nfile=/etc/hosts.equiv not_found"
fi

if [ -n "$RHOSTS_FILES" ]; then
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    O=$(stat -c %U "$f" 2>/dev/null)
    P=$(stat -c %a "$f" 2>/dev/null)
    PL=$(grep -nE '^[[:space:]]*\+' "$f" 2>/dev/null | head -n 1)
    if [ -n "$PL" ]; then
      DETAIL_CONTENT="${DETAIL_CONTENT}\nfile=${f} owner=${O} perm=${P} plus=present(${PL})"
    else
      DETAIL_CONTENT="${DETAIL_CONTENT}\nfile=${f} owner=${O} perm=${P} plus=absent"
    fi
  done < <(printf "%s\n" "$RHOSTS_FILES")
else
  DETAIL_CONTENT="${DETAIL_CONTENT}\nfile=/home/*/.rhosts not_found"
fi

# 취약 설정만 요약(어떠한 이유용)
VULN_SUMMARY=""

# 파일 기준 점검
for file in /etc/hosts.equiv $RHOSTS_FILES; do
  [ -f "$file" ] || continue

  OWNER=$(stat -c %U "$file" 2>/dev/null)
  PERM=$(stat -c %a "$file" 2>/dev/null)

  if ! [[ "$PERM" =~ ^[0-9]+$ ]]; then
    FOUND_VULN="Y"
    VULN_SUMMARY="${VULN_SUMMARY}${file} perm=read_fail;"
    continue
  fi

  PLUS_EXIST=$(grep -nE '^[[:space:]]*\+' "$file" 2>/dev/null | head -n 1)

  if [[ "$file" == "/etc/hosts.equiv" ]]; then
    if [ "$OWNER" != "root" ]; then
      FOUND_VULN="Y"
      VULN_SUMMARY="${VULN_SUMMARY}${file} owner=${OWNER};"
    fi
  else
    FILE_USER=$(basename "$(dirname "$file")")
    if [[ "$OWNER" != "$FILE_USER" && "$OWNER" != "root" ]]; then
      FOUND_VULN="Y"
      VULN_SUMMARY="${VULN_SUMMARY}${file} owner=${OWNER}(expected:${FILE_USER}_or_root);"
    fi
  fi

  if [ "$PERM" -gt 600 ]; then
    FOUND_VULN="Y"
    VULN_SUMMARY="${VULN_SUMMARY}${file} perm=${PERM}(>600);"
  fi

  if [ -n "$PLUS_EXIST" ]; then
    FOUND_VULN="Y"
    VULN_SUMMARY="${VULN_SUMMARY}${file} plus=${PLUS_EXIST};"
  fi
done

# 최종 판단 및 RAW_EVIDENCE(detail/guide) 구성
if [ "$SERVICE_USED" = "YES" ] && [ "$FOUND_VULN" = "Y" ]; then
  STATUS="FAIL"
  VULN_SUMMARY=${VULN_SUMMARY%;}
  REASON_LINE="${SERVICE_LINE} 상태에서 ${VULN_SUMMARY} 설정이 확인되어 이 항목에 대해 취약합니다."
  GUIDE_LINE=$'자동 조치:
  /etc/hosts.equiv 및 각 계정의 .rhosts 파일에 대해 소유자를 root 또는 해당 계정으로 설정하고 권한을 600으로 표준화하며 줄 시작 \'+\' 항목을 제거합니다.
  주의사항: 
  rlogin/rsh/rexec 기반 신뢰접속을 사용하던 레거시 자동화나 원격 관리가 중단될 수 있으므로 영향 범위를 확인한 뒤 적용합니다.'
else
  STATUS="PASS"
  if [ "$SERVICE_USED" = "NO" ]; then
    REASON_LINE="${SERVICE_LINE} 상태이며 '+' 항목이 없고 소유자/권한이 안전하게 제한되어 이 항목에 대해 양호합니다."
  else
    REASON_LINE="${SERVICE_LINE} 상태이며 '+' 항목이 없고 소유자/권한이 안전하게 제한되어 이 항목에 대해 양호합니다."
  fi
  GUIDE_LINE=""
fi

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(json_escape "$RAW_EVIDENCE")

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
