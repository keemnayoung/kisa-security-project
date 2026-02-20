#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-51
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : allow-update / update-policy 설정이 과도 허용(any/*/0.0.0.0/0/::/0 또는 grant */any)인지 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-51"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")

CHECK_COMMAND='
systemctl is-active named named-chroot 2>/dev/null;
pgrep -x named 2>/dev/null;
grep -nE "^[[:space:]]*include[[:space:]]+\"" /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options 2>/dev/null;
'

json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

append_line() {
  local var_name="$1"
  local line="${2:-}"
  [ -z "$line" ] && return 0
  if [ -z "${!var_name:-}" ]; then
    printf -v "$var_name" "%s" "$line"
  else
    printf -v "$var_name" "%s\n%s" "${!var_name}" "$line"
  fi
}

add_target() {
  local f="${1:-}"
  [ -z "$f" ] && return 0
  if [ -z "$TARGET_FILE" ]; then
    TARGET_FILE="$f"
  else
    case ",$TARGET_FILE," in *",$f,"*) : ;; *) TARGET_FILE="${TARGET_FILE}, $f" ;; esac
  fi
}

is_named_running() {
  systemctl is-active --quiet named 2>/dev/null && return 0
  systemctl is-active --quiet named-chroot 2>/dev/null && return 0
  pgrep -x named >/dev/null 2>&1 && return 0
  return 1
}

collect_named_conf_files() {
  local -a queue=() out=()
  declare -A seen=()
  local f dir inc inc_path

  for f in "$@"; do [ -f "$f" ] && queue+=("$f"); done

  while [ "${#queue[@]}" -gt 0 ]; do
    f="${queue[0]}"; queue=("${queue[@]:1}")
    [ -f "$f" ] || continue
    [ -n "${seen["$f"]+x}" ] && continue
    seen["$f"]=1
    out+=("$f")

    dir="$(dirname "$f")"
    while IFS= read -r inc; do
      [ -z "$inc" ] && continue
      [[ "$inc" = /* ]] && inc_path="$inc" || inc_path="${dir}/${inc}"
      [ -f "$inc_path" ] && queue+=("$inc_path")
    done < <(grep -hE '^[[:space:]]*include[[:space:]]+"' "$f" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/')
  done

  printf '%s\n' "${out[@]}"
}

extract_update_blocks() {
  local f="$1"
  awk -v FILE="$f" '
    BEGIN{IGNORECASE=1; inblk=0; type=""; buf=""}
    function norm(s){gsub(/[[:space:]]+/," ",s); gsub(/^[[:space:]]+|[[:space:]]+$/,"",s); return s}
    {
      line=$0
      sub(/^[[:space:]]*#.*/,"",line)
      sub(/[[:space:]]*\/\/.*/,"",line)
      if(line ~ /^[[:space:]]*$/) next

      if(!inblk && line ~ /(allow-update|update-policy)[[:space:]]*\{/){
        inblk=1
        type=(line ~ /allow-update[[:space:]]*\{/ ? "allow-update" : "update-policy")
        buf=line
        if(line ~ /\}[[:space:]]*;/){
          print type "|" FILE "|" norm(buf)
          inblk=0; type=""; buf=""
        }
        next
      }

      if(inblk){
        buf = buf " " line
        if(line ~ /\}[[:space:]]*;/){
          print type "|" FILE "|" norm(buf)
          inblk=0; type=""; buf=""
        }
      }
    }
  ' "$f" 2>/dev/null
}

is_wide_open_allow() {
  local s="$1"
  echo "$s" | grep -qiE '\ballow-update[[:space:]]*\{[^}]*\bnone\b' && return 1
  echo "$s" | grep -qiE '(\bany\b|\*|0\.0\.0\.0(/0)?|::/0)' && return 0
  return 1
}

is_wide_open_policy() {
  local s="$1"
  echo "$s" | grep -qiE '\bgrant[[:space:]]+(\*|any)\b' && return 0
  echo "$s" | grep -qiE '\bgrant[[:space:]]+[^;]*\b(\*|any)\b' && return 0
  return 1
}

GUIDE_LINE=$'이 항목에 대해서 자동 조치 시 DNS 서비스 중단, 기존 업데이트 정책(TSIG/ACL) 및 연동 구성에 영향이 발생할 수 있어 수동 조치가 필요합니다.
관리자가 직접 확인 후 allow-update는 none 또는 허용 IP/TSIG로 제한하고, update-policy는 불필요 시 제거하거나 TSIG 기반으로만 grant 되도록 제한해 주시기 바랍니다.'

BAD_REASON_SNIPS=""
GOOD_REASON_SNIPS=""

if ! is_named_running; then
  STATUS="PASS"
  REASON_LINE="named 서비스가 비활성화되어 이 항목에 대해 양호합니다."
  DETAIL_CONTENT="named_status=inactive_or_not_running"
else
  mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")

  if [ "${#CONF_FILES[@]}" -eq 0 ]; then
    STATUS="FAIL"
    REASON_LINE="설정 파일을 확인할 수 없어 이 항목에 대해 취약합니다."
    DETAIL_CONTENT="conf_files=none"
  else
    found=0; bad=0; good=0
    shown=0; max_show=25

    for f in "${CONF_FILES[@]}"; do
      add_target "$f"

      while IFS= read -r rec; do
        [ -z "$rec" ] && continue
        found=1
        type="${rec%%|*}"; rest="${rec#*|}"; file="${rest%%|*}"; content="${rest#*|}"

        line_out="$file | $content"
        if [ "$shown" -lt "$max_show" ]; then
          append_line DETAIL_CONTENT "$line_out"
          shown=$((shown+1))
        fi

        if [ "$type" = "allow-update" ]; then
          if is_wide_open_allow "$content"; then
            bad=$((bad+1))
            append_line BAD_REASON_SNIPS "$line_out"
          else
            good=$((good+1))
            [ "$good" -le 3 ] && append_line GOOD_REASON_SNIPS "$line_out"
          fi
        else
          if is_wide_open_policy "$content"; then
            bad=$((bad+1))
            append_line BAD_REASON_SNIPS "$line_out"
          else
            good=$((good+1))
            [ "$good" -le 3 ] && append_line GOOD_REASON_SNIPS "$line_out"
          fi
        fi
      done < <(extract_update_blocks "$f")
    done

    if [ "$found" -eq 0 ]; then
      STATUS="PASS"
      REASON_LINE="allow-update와 update-policy가 설정되지 않아 이 항목에 대해 양호합니다."
      [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="allow-update/update-policy=not_found"
    elif [ "$bad" -gt 0 ]; then
      STATUS="FAIL"
      first_bad="$(printf "%s " "$BAD_REASON_SNIPS" | head -n 1)"
      [ -z "$first_bad" ] && first_bad="allow-update/update-policy=wide_open_detected"
      REASON_LINE="$first_bad 로 설정되어 이 항목에 대해 취약합니다."
    else
      STATUS="PASS"
      if [ -n "$GOOD_REASON_SNIPS" ]; then
        first_good="$(printf "%s " "$GOOD_REASON_SNIPS" | head -n 1)"
        REASON_LINE="$first_good 로 설정되어 이 항목에 대해 양호합니다."
      else
        REASON_LINE="allow-update와 update-policy가 과도 허용으로 설정되지 않아 이 항목에 대해 양호합니다."
      fi
    fi
  fi
fi

[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/named.conf, /etc/bind/named.conf.options, /etc/bind/named.conf (and included files)"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

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

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
