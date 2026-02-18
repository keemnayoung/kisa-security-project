#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-50
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS Zone Transfer 설정
# @Description : allow-transfer 설정으로 Zone Transfer 제한 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-50"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

CHECK_COMMAND='
systemctl is-active named named-chroot 2>/dev/null;
pgrep -x named 2>/dev/null;
grep -nE "^[[:space:]]*include[[:space:]]+\"" /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options 2>/dev/null;
grep -nE "allow-transfer[[:space:]]*\\{" /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options 2>/dev/null;
grep -nE "^[[:space:]]*xfnets[[:space:]]+" /etc/named.boot /etc/bind/named.boot 2>/dev/null;
'

VULNERABLE=0
DETAIL_LINES=""
REASON_SETTING=""
VULN_SNIPPET=""

append_detail() {
  local line="$1"
  [ -z "$line" ] && return 0
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$line"
  else
    DETAIL_LINES="${DETAIL_LINES}\n$line"
  fi
}

add_target_file() {
  local f="$1"
  [ -z "$f" ] && return 0
  if [ -z "$TARGET_FILE" ]; then
    TARGET_FILE="$f"
  else
    TARGET_FILE="${TARGET_FILE}, $f"
  fi
}

is_named_running() {
  systemctl is-active --quiet named 2>/dev/null && return 0
  systemctl is-active --quiet named-chroot 2>/dev/null && return 0
  pgrep -x named >/dev/null 2>&1 && return 0
  return 1
}

collect_named_conf_files() {
  local -a seeds=("$@")
  local -a queue=()
  local -a out=()
  local -a seen=()
  local f dir inc inc_path already

  for f in "${seeds[@]}"; do
    [ -f "$f" ] && queue+=("$f")
  done

  while [ "${#queue[@]}" -gt 0 ]; do
    f="${queue[0]}"
    queue=("${queue[@]:1}")

    [ -f "$f" ] || continue

    already="N"
    for s in "${seen[@]}"; do
      [ "$s" = "$f" ] && already="Y" && break
    done
    [ "$already" = "Y" ] && continue

    seen+=("$f")
    out+=("$f")

    dir="$(dirname "$f")"
    while IFS= read -r inc; do
      [ -z "$inc" ] && continue
      if [[ "$inc" = /* ]]; then
        inc_path="$inc"
      else
        inc_path="${dir}/${inc}"
      fi
      [ -f "$inc_path" ] && queue+=("$inc_path")
    done < <(
      grep -hE '^[[:space:]]*include[[:space:]]+"' "$f" 2>/dev/null \
        | sed -E 's/.*"([^"]+)".*/\1/'
    )
  done

  printf '%s\n' "${out[@]}"
}

extract_allow_transfer_block() {
  local f="$1"
  awk '
    BEGIN{inblk=0; buf=""; found=0}
    /^[[:space:]]*#/ {next}
    {
      if(found==0 && $0 ~ /allow-transfer[[:space:]]*\{/){ inblk=1 }
      if(inblk==1){
        buf = buf $0 "\n"
        if($0 ~ /\}[[:space:]]*;/){
          found=1
          inblk=0
        }
      }
    }
    END{ if(found==1) printf "%s", buf }
  ' "$f" 2>/dev/null
}

is_wide_open_text() {
  echo "$1" | grep -qiE '(\bany\b[[:space:]]*;|\*|0\.0\.0\.0([[:space:]]*;|/0)|\:\:/0)'
}

is_explicit_none() {
  echo "$1" | grep -qiE 'allow-transfer[[:space:]]*\{[^}]*\bnone\b[[:space:]]*;[^}]*\}'
}

get_xfnets_line() {
  local f="$1"
  grep -nE '^[[:space:]]*xfnets[[:space:]]+' "$f" 2>/dev/null | head -n1
}

is_xfnets_wide_open() {
  echo "$1" | grep -qiE '(\bany\b|\*|0\.0\.0\.0(/0)?|\:\:/0)'
}

set_reason_setting_once() {
  local s="$1"
  [ -z "$s" ] && return 0
  [ -z "$REASON_SETTING" ] && REASON_SETTING="$s"
}

set_vuln_snippet_once() {
  local s="$1"
  [ -z "$s" ] && return 0
  [ -z "$VULN_SNIPPET" ] && VULN_SNIPPET="$s"
}

CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")
BOOT_CANDIDATES=("/etc/named.boot" "/etc/bind/named.boot")

if ! is_named_running; then
  STATUS="PASS"
  set_reason_setting_once "named=inactive"
  append_detail "[info] named_running=N"
  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
else
  append_detail "[info] named_running=Y"

  mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")

  XFNETS_FOUND=0
  XFNETS_WIDE=0
  XFNETS_GOOD=0

  for bf in "${BOOT_CANDIDATES[@]}"; do
    [ -f "$bf" ] || continue
    add_target_file "$bf"
    xline="$(get_xfnets_line "$bf")"
    if [ -n "$xline" ]; then
      XFNETS_FOUND=1
      if is_xfnets_wide_open "$xline"; then
        XFNETS_WIDE=1
        VULNERABLE=1
        append_detail "[check] $bf xfnets=WIDE_OPEN | $xline"
        set_vuln_snippet_once "xfnets_wide_open: $xline"
      else
        XFNETS_GOOD=1
        append_detail "[check] $bf xfnets=SET(restricted) | $xline"
        set_reason_setting_once "xfnets_restricted: $xline"
      fi
    fi
  done

  ALLOW_FOUND=0
  ALLOW_WIDE=0
  ALLOW_GOOD=0

  if [ "${#CONF_FILES[@]}" -gt 0 ]; then
    append_detail "[info] conf_files=$(printf "%s " "${CONF_FILES[@]}" | sed 's/[[:space:]]$//')"
    for cf in "${CONF_FILES[@]}"; do
      add_target_file "$cf"
      blk="$(extract_allow_transfer_block "$cf")"
      [ -z "$blk" ] && continue

      ALLOW_FOUND=1

      blk_one="$(echo "$blk" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
      if is_explicit_none "$blk"; then
        ALLOW_GOOD=1
        append_detail "[check] $cf allow-transfer=NONE(restricted) | $blk_one"
        set_reason_setting_once "allow-transfer_restricted: $cf | $blk_one"
      elif is_wide_open_text "$blk"; then
        ALLOW_WIDE=1
        VULNERABLE=1
        append_detail "[check] $cf allow-transfer=WIDE_OPEN | $blk_one"
        set_vuln_snippet_once "allow-transfer_wide_open: $cf | $blk_one"
      else
        ALLOW_GOOD=1
        append_detail "[check] $cf allow-transfer=SET(restricted?) | $blk_one"
        set_reason_setting_once "allow-transfer_restricted: $cf | $blk_one"
      fi
    done
  else
    append_detail "[info] conf_files=none"
  fi

  if [ "$ALLOW_FOUND" -eq 0 ] && [ "$XFNETS_FOUND" -eq 0 ]; then
    VULNERABLE=1
    set_vuln_snippet_once "allow-transfer=NOT_FOUND, xfnets=NOT_FOUND"
    append_detail "[check] allow-transfer=NOT_FOUND in all collected conf files"
    append_detail "[check] xfnets=NOT_FOUND in named.boot candidates"
  fi

  append_detail "[summary] allow_found=$ALLOW_FOUND allow_good=$ALLOW_GOOD allow_wide=$ALLOW_WIDE xfnets_found=$XFNETS_FOUND xfnets_good=$XFNETS_GOOD xfnets_wide=$XFNETS_WIDE"

  if [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    [ -z "$VULN_SNIPPET" ] && VULN_SNIPPET="zone_transfer_limit_not_confirmed"
  else
    STATUS="PASS"
    [ -z "$REASON_SETTING" ] && REASON_SETTING="zone_transfer_restricted"
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/named.conf, /etc/bind/named.conf.options, /etc/bind/named.conf, /etc/named.boot, /etc/bind/named.boot (and included files)"

if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="${REASON_SETTING}로 이 항목에 대해 양호합니다."
else
  REASON_LINE="${VULN_SNIPPET}로 이 항목에 대해 취약합니다."
fi

GUIDE_LINE="자동 조치 시 Secondary DNS 구성과 운영 정책에 따라 DNS 동기화 실패 또는 서비스 장애 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 설정 파일을 확인 후 allow-transfer 또는 xfnets를 Secondary DNS(또는 허용 IP)로만 제한하도록 조치해 주시기 바랍니다."

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

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g' \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
