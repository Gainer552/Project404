#!/usr/bin/env bash
# detect_file_obfuscation_fixed.sh
# Defensive single-file analyzer — finds signs of packing, encoding, obfuscation, or LOTL indicators.
# Includes robustness fixes: multi-line base64 handling, hex/base64 disambiguation,
# LOTL word-boundaries, and small-file exclusions for string-profile heuristics.
#
# Usage: ./detect_file_obfuscation_fixed.sh
# Then enter a full path when prompted.

set -o errexit
set -o nounset
set -o pipefail

# --- Prompt user for file path ---
read -r -p "Enter full path of file to scan: " TARGET
if [[ ! -f "$TARGET" ]]; then
  echo "Error: '$TARGET' is not a valid file."
  exit 1
fi

# --- Config ---
# Be conservative with memory: when collapsing newlines we limit to a window
# (in bytes) to avoid slurping enormous files. For testing files this is fine.
COLLAPSE_LIMIT_BYTES=$((4 * 1024 * 1024))   # 4 MiB window when collapsing newlines
SAMPLE_BYTES=65536          # bytes read for entropy sampling (64 KiB)
ENTROPY_THRESHOLD=7.5
B64_MIN_LEN=200
HEX_MIN_LEN=240
MIN_SIZE_FOR_STRING_PROFILE=128   # don't apply few-strings heuristic to tiny files
STRINGS_CMD="${STRINGS_CMD:-strings}"

# --- Colors ---
if command -v tput >/dev/null 2>&1; then
  RED="$(tput setaf 1)"
  YELLOW="$(tput setaf 3)"
  GREEN="$(tput setaf 2)"
  BLUE="$(tput setaf 4)"
  MAG="$(tput setaf 5)"
  CYAN="$(tput setaf 6)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
else
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
  MAG='\033[0;35m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
fi

# --- Helpers ---
# cleanup not required; no tmpdir created persistently

log() { printf "%s\n" "$*"; }
err() { printf "%b[ERROR]%b %s\n" "$RED" "$RESET" "$*" >&2; }

# compute sampled Shannon entropy of bytes in file
entropy_sample() {
  local file="$1"
  if ! [ -r "$file" ]; then
    echo "0"
    return
  fi
  dd if="$file" bs="$SAMPLE_BYTES" count=1 2>/dev/null | \
    od -An -v -t u1 2>/dev/null | tr -s ' ' '\n' | awk '
    {
      if($1=="") next;
      a[$1]++
      total++
    }
    END{
      if(total==0){ print 0; exit }
      e=0
      for (i in a) {
        p = a[i]/total
        e += -p * (log(p)/log(2))
      }
      printf("%.6f\n", e)
    }'
}

# Extract a size-bounded, newline-collapsed window from file.
# This produces up to COLLAPSE_LIMIT_BYTES bytes of the file with newlines removed.
collapse_newlines_window() {
  local file="$1"
  # Use dd/head to limit bytes then tr to delete newlines; this avoids slurping the whole file.
  # If file smaller than limit, it's fine.
  dd if="$file" bs=1 count="$COLLAPSE_LIMIT_BYTES" 2>/dev/null | tr -d '\r\n'
}

# --- Heuristic checks ---

# packer signatures using strings; case-insensitive
check_packers() {
  local file="$1"
  # look for common packer/crypter tokens in initial strings
  $STRINGS_CMD -n 8 "$file" 2>/dev/null | tr '[:upper:]' '[:lower:]' | \
    grep -Eqi '(^|[^a-z0-9])(upx|mpress|aspack|themida|petite|crypter|pecompact|packed by|packed)' && return 0
  return 1
}

# ELF suspicious sections - only run on real ELF binaries
check_elf_sections() {
  local file="$1"
  command -v readelf >/dev/null 2>&1 || return 1
  readelf -S "$file" 2>/dev/null | grep -Eqi '\.upx|\.packed|\.rsrc|\.ndata|\.mpress|\.themida' && return 0
  return 1
}

# base64 detection - collapse newlines (size-bounded) then search for long runs
check_long_base64() {
  local file="$1" minlen=${2:-$B64_MIN_LEN}
  # Get collapsed window (bounded) to avoid large memory usage
  local sample
  sample=$(collapse_newlines_window "$file" 2>/dev/null || true)
  # Quick reject if sample shorter than minlen
  if [ "${#sample}" -lt "$minlen" ]; then
    return 1
  fi
  if printf '%s' "$sample" | grep -Pq "[A-Za-z0-9+/=]{$minlen,}"; then
    return 0
  fi
  return 1
}

# hex detection - collapse newlines and ensure base64-specific chars absent (disambiguation)
check_long_hex() {
  local file="$1" minlen=${2:-$HEX_MIN_LEN}
  local sample
  sample=$(collapse_newlines_window "$file" 2>/dev/null || true)
  if [ "${#sample}" -lt "$minlen" ]; then
    return 1
  fi
  # If base64-signature chars present (+ / =) then favor base64 (avoid flagging hex)
  if printf '%s' "$sample" | grep -q '[+/=]'; then
    return 1
  fi
  if printf '%s' "$sample" | grep -Pq "[A-Fa-f0-9]{$minlen,}"; then
    return 0
  fi
  return 1
}

# suspicious script patterns (base64 decode, eval, /dev/tcp, python -c, openssl enc -d)
check_script_obf() {
  local file="$1"
  grep -Ei -- 'base64[[:space:]]*-d|openssl\s+enc\s+-d|eval\s*\(|sh\s+-c|bash\s+-c|python\s+-c|perl\s+-e|node\s+-e|/dev/tcp|nc\s+-e' "$file" >/dev/null 2>&1
}

# LOTL/LOLBAS usage using word boundaries (avoid matching substrings inside words)
check_lolbas() {
  local file="$1"
  # Whitelist of common living-off-the-land binaries we want to detect as whole words.
  # Exclude very short tokens like 'sh' in the list to avoid false-positives; keep 'bash' and others that are likely standalone.
  grep -Pqi '\b(?:curl|wget|certutil|powershell|rundll32|mshta|regsvr32|python|perl|ruby|bash|awk|sed|nc|ncat|socat)\b' "$file" 2>/dev/null
}

# check for likely obfuscated strings (few printable strings)
check_string_profile() {
  local file="$1"
  local fsize
  fsize=$(stat -c%s -- "$file" 2>/dev/null || echo 0)
  # Skip tiny files to avoid false positives
  if [ "$fsize" -lt "$MIN_SIZE_FOR_STRING_PROFILE" ]; then
    return 1
  fi
  local scnt
  scnt=$($STRINGS_CMD -n 4 "$file" 2>/dev/null | wc -l || echo 0)
  [ "$scnt" -lt 10 ]
}

# --- Output helpers ---
print_header() {
  printf "%b| %-18s | %-60s | %-10s | %-8s | %s%b\n" \
    "$BOLD$CYAN" "Category" "Path" "Type" "Entropy" "Notes" "$RESET"
  printf "%b%s%b\n" "$CYAN" "$(printf -- '-%.0s' {1..140})" "$RESET"
}
print_row() {
  local color="$1"; shift
  printf "%b| %-18s | %-60s | %-10s | %-8s | %s%b\n" "$color" "$@""$RESET"
}

# --- Start analysis ---
printf "\n%bAnalyzing:%b %s\n\n" "$BOLD" "$RESET" "$TARGET"
print_header

# Gather basic metadata
ftype=$(file -b --mime-type "$TARGET" 2>/dev/null || echo "unknown")
size=$(stat -c "%s" "$TARGET" 2>/dev/null || echo "0")
entropy=$(entropy_sample "$TARGET")

# 1) Packager / crypter signature (strings)
if check_packers "$TARGET"; then
  print_row "$MAG" "Packers/Crypters" "$TARGET" "$ftype" "$entropy" "Packer signature detected (strings)"
fi

# 2) ELF suspicious sections — only if `file` reports ELF
if file "$TARGET" 2>/dev/null | grep -qi 'elf'; then
  if check_elf_sections "$TARGET"; then
    print_row "$YELLOW" "ELF SuspiciousSections" "$TARGET" "$ftype" "$entropy" "Unusual ELF section names"
  fi
fi

# 3) High entropy
awk -v e="$entropy" -v th="$ENTROPY_THRESHOLD" 'BEGIN{ exit !(e>th) }' && {
  print_row "$RED" "HighEntropy" "$TARGET" "$ftype" "$entropy" "Entropy > threshold (${ENTROPY_THRESHOLD})"
} || true

# 4) Few printable strings (skip tiny files)
if check_string_profile "$TARGET"; then
  print_row "$RED" "FewPrintableStrings" "$TARGET" "$ftype" "$entropy" "Very few printable strings (suspicious)"
fi

# 5) Long encoded blobs: base64 (handle multi-line) and hex (disambiguated)
if check_long_base64 "$TARGET" "$B64_MIN_LEN"; then
  print_row "$BLUE" "LongEncodedBlobs" "$TARGET" "$ftype" "$entropy" "Long Base64-like run (multi-line aware)"
else
  if check_long_hex "$TARGET" "$HEX_MIN_LEN"; then
    print_row "$BLUE" "LongEncodedBlobs" "$TARGET" "$ftype" "$entropy" "Long hex run"
  fi
fi

# 6) Script obfuscation patterns (text files)
if grep -Iq . "$TARGET" 2>/dev/null; then
  if check_script_obf "$TARGET"; then
    print_row "$GREEN" "ScriptObfuscation" "$TARGET" "$ftype" "$entropy" "Script-like obfuscation patterns"
  fi

  # 7) LOTL/LOLBAS usage (word-boundary matching)
  if check_lolbas "$TARGET"; then
    print_row "$CYAN" "LOTL/LOLBAS" "$TARGET" "$ftype" "$entropy" "Living-off-the-land commands mentioned (word-boundary)"
  fi
fi

printf "%b%s%b\n" "$CYAN" "$(printf -- '-%.0s' {1..140})" "$RESET"
printf "%bAnalysis complete.%b\n" "$BOLD" "$RESET"
printf "Entropy: %.3f (threshold %.1f) | File size: %s bytes | Type: %s\n\n" "$entropy" "$ENTROPY_THRESHOLD" "$size" "$ftype"
printf "Indicators shown above are heuristic; review manually before taking action.\n"

exit 0
