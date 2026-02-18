#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 김나영
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-01
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : root 계정 원격 접속 제한
# @Description : 원격 터미널 서비스를 통한 root 계정의 직접 접속 제한 여부 점검
# @Criteria_Good : 원격 접속 시 root 계정 접속을 제한한 경우
# @Criteria_Bad : 원격 접속 시 root 계정 접속을 허용한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-01"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 점검 대상 파일(대시보드 표기 편의를 위해 줄바꿈으로 구성)
TARGET_SSHD="/etc/ssh/sshd_config"
TARGET_PAM_LOGIN="/etc/pam.d/login"
TARGET_SECURETTY="/etc/securetty"
TARGET_FILES=$(cat <<EOF
$TARGET_SSHD
$TARGET_PAM_LOGIN
$TARGET_SECURETTY
EOF
)

# 점검 명령(설명용) - 값 자체가 문장별 줄바꿈을 갖도록 구성
CHECK_COMMAND=$(cat <<'CMD'
[SSH] /etc/ssh/sshd_config 존재 시: sshd -T | grep ^permitrootlogin
[Telnet] 활성 탐지: ss/netstat 23포트 LISTEN 또는 systemctl telnet.* active 또는 xinetd telnet(disable=no) 또는 inetd.conf telnet 엔트리
[Telnet] 활성 시 설정 확인: /etc/pam.d/login에 pam_securetty.so 적용 및 /etc/securetty에 pts/x 미존재
CMD
)

# 멀티라인 문자열을 "바깥 JSON 문자열"로 안전하게 담기 위한 escape
json_escape_multiline() {
  printf '%s' "$1" \
    | sed 's/\\/\\\\/g; s/"/\\"/g' \
    | sed ':a;N;$!ba;s/\n/\\n/g'
}

# 1) SSH 점검: /etc/ssh/sshd_config 존재 여부에 따라 sshd -T 기반 실적용 값 확인
SSH_RESULT="PASS"
SSH_VAL="unknown"
SSH_SSHD_CMD="available"
SSH_WEAK_REASON_LINE=""

if [ -f "$TARGET_SSHD" ]; then
  if command -v sshd >/dev/null 2>&1; then
    SSH_VAL="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{v=tolower($2)} END{print v}')"
    [ -z "$SSH_VAL" ] && SSH_VAL="unknown"
  else
    SSH_SSHD_CMD="missing"
    SSH_VAL="unknown"
  fi

  if [ "$SSH_VAL" = "no" ]; then
    SSH_RESULT="PASS"
  else
    SSH_RESULT="FAIL"
    SSH_WEAK_REASON_LINE="PermitRootLogin=${SSH_VAL}"
  fi
else
  SSH_RESULT="PASS"
  SSH_VAL="sshd_config_not_found"
  SSH_SSHD_CMD="unknown"
fi

# 2) Telnet 활성 여부 탐지 후, 활성일 때만 /etc/pam.d/login + /etc/securetty 설정 확인
TELNET_ACTIVE="no"
TELNET_DETECTION="none"
TELNET_DISABLE_VAL="unknown"

if command -v ss >/dev/null 2>&1; then
  if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '(:|\.)(23)$'; then
    TELNET_ACTIVE="yes"
    TELNET_DETECTION="port23_listening(ss)"
  fi
elif command -v netstat >/dev/null 2>&1; then
  if netstat -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '(:|\.)(23)$'; then
    TELNET_ACTIVE="yes"
    TELNET_DETECTION="port23_listening(netstat)"
  fi
fi

if [ "$TELNET_ACTIVE" = "no" ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet telnet.socket 2>/dev/null; then
    TELNET_ACTIVE="yes"
    TELNET_DETECTION="systemd:telnet.socket(active)"
  elif systemctl is-active --quiet telnet.service 2>/dev/null; then
    TELNET_ACTIVE="yes"
    TELNET_DETECTION="systemd:telnet.service(active)"
  fi
fi

if [ "$TELNET_ACTIVE" = "no" ] && [ -f /etc/xinetd.d/telnet ]; then
  TELNET_DISABLE_VAL="$(grep -i '^\s*disable\s*=' /etc/xinetd.d/telnet 2>/dev/null | tail -n 1 | awk -F= '{gsub(/[ \t]/,"",$2); print tolower($2)}')"
  [ -z "$TELNET_DISABLE_VAL" ] && TELNET_DISABLE_VAL="unknown"
  if [ "$TELNET_DISABLE_VAL" = "no" ]; then
    TELNET_ACTIVE="yes"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xinetd 2>/dev/null; then
      TELNET_DETECTION="xinetd:/etc/xinetd.d/telnet(disable=no), xinetd(active)"
    else
      TELNET_DETECTION="xinetd:/etc/xinetd.d/telnet(disable=no)"
    fi
  fi
fi

if [ "$TELNET_ACTIVE" = "no" ] && [ -f /etc/inetd.conf ]; then
  if grep -Ev '^\s*#' /etc/inetd.conf 2>/dev/null | grep -Eq '^\s*telnet\s'; then
    TELNET_ACTIVE="yes"
    TELNET_DETECTION="/etc/inetd.conf:telnet_entry"
  fi
fi

PAM_SECURETTY_STATUS="pam_login_not_found"
if [ -f "$TARGET_PAM_LOGIN" ]; then
  if grep -Eqi '^\s*auth\s+required\s+.*pam_securetty\.so' "$TARGET_PAM_LOGIN"; then
    PAM_SECURETTY_STATUS="present"
  else
    PAM_SECURETTY_STATUS="absent"
  fi
fi

SECURETTY_PTS_STATUS="securetty_not_found"
SECURETTY_PTS_LIST_CSV="securetty_not_found"
if [ -f "$TARGET_SECURETTY" ]; then
  SECURETTY_PTS_LIST="$(grep -Ev '^\s*#' "$TARGET_SECURETTY" 2>/dev/null | awk '{gsub(/[ \t]/,""); print}' | grep -E '^pts/' || true)"
  if [ -n "$SECURETTY_PTS_LIST" ]; then
    SECURETTY_PTS_STATUS="present"
    SECURETTY_PTS_LIST_CSV="$(echo "$SECURETTY_PTS_LIST" | paste -sd, -)"
  else
    SECURETTY_PTS_STATUS="absent"
    SECURETTY_PTS_LIST_CSV="none"
  fi
fi

TELNET_RESULT="PASS"
TELNET_WEAK_REASON_LINE=""
if [ "$TELNET_ACTIVE" = "no" ]; then
  TELNET_RESULT="PASS"
else
  if [ "$PAM_SECURETTY_STATUS" = "present" ] && [ "$SECURETTY_PTS_STATUS" = "absent" ]; then
    TELNET_RESULT="PASS"
  else
    TELNET_RESULT="FAIL"
    if [ "$PAM_SECURETTY_STATUS" != "present" ]; then
      TELNET_WEAK_REASON_LINE="pam_securetty=${PAM_SECURETTY_STATUS}"
    fi
    if [ "$SECURETTY_PTS_STATUS" != "absent" ]; then
      [ -n "$TELNET_WEAK_REASON_LINE" ] && TELNET_WEAK_REASON_LINE="${TELNET_WEAK_REASON_LINE}, "
      TELNET_WEAK_REASON_LINE="${TELNET_WEAK_REASON_LINE}securetty_pts=${SECURETTY_PTS_LIST_CSV}"
    fi
    if [ -z "$TELNET_WEAK_REASON_LINE" ]; then
      TELNET_WEAK_REASON_LINE="Telnet_active=${TELNET_ACTIVE}(${TELNET_DETECTION})"
    fi
  fi
fi

# 3) 최종 판정: SSH와 Telnet 결과를 종합
if [ "$SSH_RESULT" = "PASS" ] && [ "$TELNET_RESULT" = "PASS" ]; then
  STATUS="PASS"
else
  STATUS="FAIL"
fi

# DETAIL_CONTENT: 양호/취약과 관계없이 "현재 설정 값들만" (줄바꿈으로 구분)
DETAIL_CONTENT=$(cat <<EOF
ssh_sshd_config_exists=$([ -f "$TARGET_SSHD" ] && echo yes || echo no)
ssh_sshd_command=${SSH_SSHD_CMD}
ssh_permitrootlogin=${SSH_VAL}
telnet_active=${TELNET_ACTIVE}
telnet_detection=${TELNET_DETECTION}
xinetd_telnet_disable=${TELNET_DISABLE_VAL}
pam_securetty_in_${TARGET_PAM_LOGIN}=${PAM_SECURETTY_STATUS}
securetty_pts_entries_in_${TARGET_SECURETTY}=${SECURETTY_PTS_LIST_CSV}
EOF
)

# detail 첫 문장(한 문장, 줄바꿈 없음): 설정 값만으로 자연스럽게 이유+양호/취약
DETAIL_REASON_LINE=""
if [ "$STATUS" = "PASS" ]; then
  if [ "$TELNET_ACTIVE" = "no" ]; then
    DETAIL_REASON_LINE="PermitRootLogin=${SSH_VAL}, Telnet=inactive(${TELNET_DETECTION})로 설정되어 있어 이 항목에 대해 양호합니다."
  else
    DETAIL_REASON_LINE="PermitRootLogin=${SSH_VAL}, Telnet=active(${TELNET_DETECTION}), pam_securetty=${PAM_SECURETTY_STATUS}, securetty_pts=${SECURETTY_PTS_LIST_CSV}로 설정되어 있어 이 항목에 대해 양호합니다."
  fi
else
  WEAK_ONLY=""
  if [ "$SSH_RESULT" != "PASS" ]; then
    WEAK_ONLY="${SSH_WEAK_REASON_LINE}"
  fi
  if [ "$TELNET_RESULT" != "PASS" ]; then
    [ -n "$WEAK_ONLY" ] && WEAK_ONLY="${WEAK_ONLY}, "
    WEAK_ONLY="${WEAK_ONLY}${TELNET_WEAK_REASON_LINE}"
  fi
  [ -z "$WEAK_ONLY" ] && WEAK_ONLY="설정 확인 결과 일부 조건이 충족되지 않았습니다"
  DETAIL_REASON_LINE="${WEAK_ONLY}로 설정되어 있어 이 항목에 대해 취약합니다."
fi

# guide: 문장별 줄바꿈으로 구성 + 자동조치 위험 + 무엇을 어떻게(조치 방법)
GUIDE_LINE=$(cat <<EOF
이 항목에 대해서 원격 접속 설정을 자동으로 변경할 경우 관리자 접속 차단(락아웃) 및 운영 중 서비스 영향이 발생할 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 SSH는 /etc/ssh/sshd_config(또는 include된 설정)에서 PermitRootLogin을 no로 설정하고 sshd 설정을 재적용(예: systemctl reload sshd 또는 재시작)해 주시기 바랍니다.
Telnet을 사용 중이라면 Telnet 서비스를 비활성화하거나, /etc/pam.d/login에 pam_securetty.so를 적용하고 /etc/securetty에서 pts/ 항목을 제거해 주시기 바랍니다.
EOF
)

# RAW_EVIDENCE: 모든 값은 문장 단위 줄바꿈이 가능하며, detail은 "첫 문장(1줄) + 설정값(여러 줄)"
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$DETAIL_REASON_LINE
$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILES"
}
EOF
)

# DB 저장/재조회 및 파이썬 대시보드 복원을 위해 개행을 \n로 보존하며 문자열 escape
RAW_EVIDENCE_ESCAPED=$(json_escape_multiline "$RAW_EVIDENCE")

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
