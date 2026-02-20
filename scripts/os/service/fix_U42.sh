#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-18
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-42
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 RPC 서비스 비활성화
# @Description : 불필요한 RPC 서비스의 실행 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-42"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/*
systemd(rpc related services)"

UNNEEDED_RPC_SERVICES=(
  "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd"
  "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad"
  "kcms_server" "cachefsd"
)

RPC_UNITS_CANDIDATES=(
  "rpcbind.service"
  "rpcbind.socket"
  "rpc-statd.service"
  "rpc-statd-notify.service"
  "rpc-gssd.service"
  "rpc-svcgssd.service"
  "rpc-idmapd.service"
)

BACKUP_DIR="/var/backups/${ID}_backup"
TS="$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR" 2>/dev/null || true

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | egrep -n "^[[:space:]]*(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" | head -n 50 ) || echo "inetd_no_active_unneeded_rpc_lines_or_not_found";
if [ -d /etc/xinetd.d ]; then
  for f in /etc/xinetd.d/*; do
    [ -f "$f" ] || continue
    echo "$f" | grep -qE "\.bak_|\.orig$|~$" && continue
    egrep -qi "^[[:space:]]*service[[:space:]]+(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" "$f" 2>/dev/null || continue
    echo "xinetd_file:$f"
    grep -nEi "^[[:space:]]*service[[:space:]]+|^[[:space:]]*disable[[:space:]]*=" "$f" 2>/dev/null | head -n 30
  done
else
  echo "xinetd_dir_not_found"
fi;
(command -v systemctl >/dev/null 2>&1 && (
  for u in rpcbind.service rpcbind.socket rpc-statd.service rpc-statd-notify.service rpc-gssd.service rpc-svcgssd.service rpc-idmapd.service; do
    systemctl list-unit-files 2>/dev/null | awk "{print \$1}" | grep -qx "$u" || continue
    echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown) active=$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
  done
)) || echo "systemctl_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""
MODIFIED=0
FAIL_FLAG=0

# 유틸리티 함수 정의
append_err() {
  [ -n "$ACTION_ERR_LOG" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1" || ACTION_ERR_LOG="$1"
}

append_detail() {
  [ -n "$DETAIL_CONTENT" ] && DETAIL_CONTENT="${DETAIL_CONTENT}\n$1" || DETAIL_CONTENT="$1"
}

restart_inetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "inetd.service" || return 0
  systemctl restart inetd 2>/dev/null || append_err "systemctl restart inetd 실패"
}

restart_xinetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "xinetd.service" || return 0
  systemctl restart xinetd 2>/dev/null || append_err "systemctl restart xinetd 실패"
}

disable_systemd_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

# 기존 백업 파일 정리 및 권한 체크
if [ "$(id -u)" -eq 0 ] && [ -d /etc/xinetd.d ]; then
  mv -f /etc/xinetd.d/*.bak_* "$BACKUP_DIR"/ 2>/dev/null || true
fi

if [ "$(id -u)" -ne 0 ]; then
  FAIL_FLAG=1
  REASON_LINE="root 권한이 아니어서 서비스 설정 변경을 수행할 수 없는 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
  append_detail "current_uid: $(id -u)"
else

  # 1) inetd 기반 RPC 서비스 조치
  if [ -f "/etc/inetd.conf" ]; then
    INETD_NEED_RESTART=0
    for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
      if grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${svc}([[:space:]]|$)"; then
        cp -a /etc/inetd.conf "$BACKUP_DIR/inetd.conf.bak_${TS}" 2>/dev/null || append_err "inetd.conf 백업 실패"
        sed -i -E "s/^([[:space:]]*)(${svc})([[:space:]]|$)/\1#\2\3/" /etc/inetd.conf 2>/dev/null || append_err "inetd.conf ${svc} 주석 처리 실패"
        MODIFIED=1
        INETD_NEED_RESTART=1
      fi
    done
    [ "$INETD_NEED_RESTART" -eq 1 ] && restart_inetd_if_exists
  fi

  # 2) xinetd 기반 RPC 서비스 조치
  XINETD_CHANGED=0
  if [ -d "/etc/xinetd.d" ]; then
    for conf in /etc/xinetd.d/*; do
      [ -f "$conf" ] || continue
      echo "$conf" | grep -qE "\.bak_|\.orig$|~$" && continue

      MATCHED_SVC=""
      for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
        if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*service[[:space:]]+${svc}([[:space:]]|$)"; then
          MATCHED_SVC="$svc"
          break
        fi
      done
      [ -z "$MATCHED_SVC" ] && continue

      cp -a "$conf" "$BACKUP_DIR/$(basename "$conf").bak_${TS}" 2>/dev/null || append_err "$(basename "$conf") 백업 실패"

      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' "$conf" 2>/dev/null \
          || append_err "$(basename "$conf") disable=yes 변경 실패"
        XINETD_CHANGED=1
        MODIFIED=1
      else
        if ! grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*="; then
          awk -v SVC="$MATCHED_SVC" '
            BEGIN{inblk=0; has_disable=0}
            {
              line=$0
              if (line ~ /^[[:space:]]*service[[:space:]]+/) {
                inblk = (tolower(line) ~ ("^[[:space:]]*service[[:space:]]+" tolower(SVC) "([[:space:]]|$)")) ? 1 : 0
                has_disable=0
              }
              if (inblk==1 && tolower(line) ~ /^[[:space:]]*disable[[:space:]]*=/) { has_disable=1 }
              if (inblk==1 && line ~ /^[[:space:]]*}[[:space:]]*$/) {
                if (has_disable==0) { print "    disable = yes" }
                inblk=0
              }
              print line
            }
          ' "$conf" > "${conf}.tmp_${ID}" 2>/dev/null && mv -f "${conf}.tmp_${ID}" "$conf" 2>/dev/null \
            || append_err "$(basename "$conf") disable=yes 삽입 실패"
          XINETD_CHANGED=1
          MODIFIED=1
        fi
      fi
    done
  fi
  [ "$XINETD_CHANGED" -eq 1 ] && restart_xinetd_if_exists

  # 3) systemd 기반 RPC 서비스 조치
  for u in "${RPC_UNITS_CANDIDATES[@]}"; do
    disable_systemd_unit_if_exists "$u"
  done
fi

# 4) 조치 후 결과 검증 및 상태 수집
INETD_POST="inetd_conf_not_found"
if [ -f "/etc/inetd.conf" ]; then
  INETD_POST="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | egrep -n "^[[:space:]]*(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" | head -n 10)"
  [ -z "$INETD_POST" ] && INETD_POST="no_active_unneeded_rpc_lines"
fi
[ "$INETD_POST" != "no_active_unneeded_rpc_lines" ] && [ "$INETD_POST" != "inetd_conf_not_found" ] && FAIL_FLAG=1
append_detail "inetd_status: $INETD_POST"

XINETD_BAD=0
XINETD_POST_SUMMARY=""
if [ -d "/etc/xinetd.d" ]; then
  for conf in /etc/xinetd.d/*; do
    [ -f "$conf" ] || continue
    echo "$conf" | grep -qE "\.bak_|\.orig$|~$" && continue
    egrep -qi "^[[:space:]]*service[[:space:]]+(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" "$conf" 2>/dev/null || continue

    dis_line="$(grep -nEv '^[[:space:]]*#' "$conf" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
    [ -z "$dis_line" ] && dis_line="disable_setting_not_found"
    XINETD_POST_SUMMARY="${XINETD_POST_SUMMARY}$(basename "$conf"):${dis_line}; "

    grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)" && XINETD_BAD=1
    echo "$dis_line" | grep -qi "disable_setting_not_found" && XINETD_BAD=1
  done
else
  XINETD_POST_SUMMARY="xinetd_dir_not_found"
fi
[ -z "$XINETD_POST_SUMMARY" ] && XINETD_POST_SUMMARY="no_unneeded_rpc_xinetd_files"
append_detail "xinetd_status: $XINETD_POST_SUMMARY"
[ "$XINETD_BAD" -eq 1 ] && FAIL_FLAG=1

if command -v systemctl >/dev/null 2>&1; then
  for u in "${RPC_UNITS_CANDIDATES[@]}"; do
    systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u" || continue
    en="$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)"
    ac="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
    append_detail "${u}_status: enabled=$en, active=$ac"
    [ "$en" = "enabled" ] && FAIL_FLAG=1
    [ "$ac" = "active" ] && FAIL_FLAG=1
  done
else
  append_detail "systemctl_not_found"
fi

# 최종 판정 및 REASON_LINE 확정
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="불필요한 RPC 서비스를 주석 처리하거나 중지 및 비활성화하여 조치를 완료하여 이 항목에 대해 양호합니다."
else
  IS_SUCCESS=0
  [ -z "$REASON_LINE" ] && REASON_LINE="불필요한 RPC 서비스 관련 설정이 여전히 활성화 상태이거나 중지되지 않은 이유로 조치에 실패하여 여전히 이 항목에 대해 취약합니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n[Error_Log]\n$ACTION_ERR_LOG"
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF