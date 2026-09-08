#!/usr/bin/env bash
set -euo pipefail

err()   { echo -e "\e[31m[error]\e[0m $*" >&2; exit 1; }
warn()  { echo -e "\e[33m[warn]\e[0m  $*" >&2; }
usage() { cat <<EOF
usage: $0 [--lang <lang>] [--base cfg] [--extra cfg] [--tail cfg] -- buildScript [args]
EOF
exit 1; }

# ---------------------------------------------------------------------
# Defaults + CLI
# ---------------------------------------------------------------------
PWD_ORIG=$PWD
code_lang=""
core=/var/tmp/opt/core

base_cfg="$core/BasePhobos.cfg"      # default (global union)
extra_cfgs=()                        # none by default
tail_cfg="$core/TailPhobos.cfg"

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--base)   base_cfg="$PWD_ORIG/$2"; shift 2;;
    -e|--extra)  extra_cfgs+=("$PWD_ORIG/$2"); shift 2;;
    -t|--tail)   tail_cfg="$PWD_ORIG/$2"; shift 2;;
    -l|--lang)   code_lang="$2"; shift 2;;
    --)          shift; break;;
    *) usage;;
  esac
done

# ---------------------------------------------------------------------
# Auto-select BaseLanguage-<lang>.cfg if available
# ---------------------------------------------------------------------
if [[ -n $code_lang ]]; then
    lang_cfg="$core/BaseLanguage-$code_lang.cfg"
    if [[ -f $lang_cfg ]]; then
        base_cfg=$lang_cfg
    fi
fi

# ---------------------------------------------------------------------
# Build-script path
# ---------------------------------------------------------------------
if [[ $# -gt 0 ]]; then
    build_script="$1"; shift
    [[ -f $build_script ]] || err "build script not found: $build_script"
else
    build_script="/var/tmp/script.sh"
    [[ -f $build_script ]] || err "default build script missing: $build_script"
fi

# ---------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------
readonly_paths=(); write_paths=(); tmpfs_paths=()
network_rules=(); timeout_s=0; mem_mb=0
restricted_cmds=()

# Timeout values are seconds: either a whole number, or seconds with
# millisecond precision written as exactly three decimal places.
# The value is handed to GNU timeout with an explicit seconds suffix below,
# so it is stored here without any unit conversion.
# An unusable value aborts instead of being ignored, because silently dropping
# it would run the build with no limit at all.
set_timeout_s() {
  local value=$1
  [[ $value =~ ^[[:space:]]*([0-9]+(\.[0-9]{3})?)[[:space:]]*$ ]] \
    || err "invalid timeout '$value': expected seconds, either whole or with exactly three decimals"
  local parsed=${BASH_REMATCH[1]}
  # Every accepted spelling of zero (0, 0.000, ...) leaves the timeout disabled.
  if [[ -z ${parsed//[0.]/} ]]; then
    timeout_s=0
  else
    timeout_s=$parsed
  fi
}

load_cfg() {
  local file=$1 section=
  [[ -f $file ]] || err "cfg not found: $file"
  while IFS= read -r ln || [[ -n $ln ]]; do
      ln=${ln%%#*}; [[ -z $ln ]] && continue
      if [[ $ln =~ ^\[(.*)\]$ ]]; then section=${BASH_REMATCH[1]}; continue; fi
      case $section in
        readonly)              readonly_paths+=("$ln") ;;
        write)                 write_paths+=("$ln") ;;
        tmpfs)                 tmpfs_paths+=("$ln") ;;
        network)               network_rules+=("$ln") ;;
        limits)
          # Separate if-statements: a section whose last line sets only one of
          # the two keys must still leave load_cfg with a success status.
          if [[ $ln =~ ^[[:space:]]*timeout[[:space:]]*=(.*)$ ]]; then set_timeout_s "${BASH_REMATCH[1]}"; fi
          if [[ $ln =~ mem_mb=([0-9]+) ]]; then mem_mb=${BASH_REMATCH[1]}; fi ;;
        restricted-commands)   restricted_cmds+=("$ln") ;;
      esac
  done < "$file"
}

# ---------------------------------------------------------------------
# Sandbox enablement check
# (We parse configs only if base+tail both exist; else fallback path.)
# ---------------------------------------------------------------------
sandbox_enabled=1
if [[ ! -f $base_cfg ]]; then
    warn "base cfg missing ($base_cfg) – disabling sandbox."
    sandbox_enabled=0
fi
if [[ ! -f $tail_cfg ]]; then
    warn "tail cfg missing ($tail_cfg) – disabling sandbox."
    sandbox_enabled=0
fi

if (( sandbox_enabled )); then
    load_cfg "$base_cfg"
    for c in "${extra_cfgs[@]}"; do load_cfg "$c"; done
else
    # Fallback: run build script directly (no bwrap, no timeout)
    cd /var/tmp/testing-dir 2>/dev/null || true
    printf '\e[34m[no-sandbox]\e[0m exec %q ' "$build_script" "$@"; echo
    exec "$build_script" "$@"
fi

# ---------------------------------------------------------------------
# Resolve restricted command paths (once)
# ---------------------------------------------------------------------
restricted_paths=()
if ((${#restricted_cmds[@]})); then
  for cmd in "${restricted_cmds[@]}"; do
      [[ -z $cmd ]] && continue
      # strip possible leading slash (/bin/ls) to allow bare names
      local_name=${cmd##*/}
      cmd_path=$(command -v "$local_name" 2>/dev/null || true)
      if [[ -n $cmd_path ]]; then
          cmd_path=$(readlink -f "$cmd_path" 2>/dev/null || echo "$cmd_path")
          restricted_paths+=("$cmd_path")
      else
          warn "restricted command '$cmd' not found in PATH"
      fi
  done
fi

# ---------------------------------------------------------------------
# Bubblewrap argument assembly
# ---------------------------------------------------------------------
bwrap_args=( --proc /proc --dev /dev )

for p in "${readonly_paths[@]}"; do bwrap_args+=( --ro-bind "$p" "$p" ); done
for p in "${write_paths[@]}";    do bwrap_args+=( --bind    "$p" "$p" ); done
for p in "${tmpfs_paths[@]}";    do bwrap_args+=( --tmpfs   "$p"     ); done

# append restricted-command masks (shadow earlier binds)
for p in "${restricted_paths[@]}"; do
    bwrap_args+=( --ro-bind /dev/null "$p" )
done

# tail flags (share-net, runtime chdir etc.)
if [[ -f $tail_cfg ]]; then
    while read -r line || [[ -n $line ]]; do
        read -ra parts <<<"$line"
        (( ${#parts[@]} )) || continue
        bwrap_args+=("${parts[@]}")
    done < "$tail_cfg"
fi

# ---------------------------------------------------------------------
# Network + limits (sandbox mode only)
# ---------------------------------------------------------------------
allowed_file="$core/allowedList.cfg"; : > "$allowed_file"

parse_hostport() {                       # $1 = host[:port] (IPv6 ok)
    local host port hostport=$1
    if [[ $hostport == \[*\]:* ]]; then  # [v6]:port
        host=${hostport%%]*}; host=${host#[}
        port=${hostport##*:}
    else
        host=${hostport%%:*}
        port=${hostport##*:}
    fi
    [[ $host == "$port" ]] && port=0
    echo "$host $port"
}

for rule in "${network_rules[@]}"; do
    [[ $rule =~ ^allow[[:space:]]+(.+)$ ]] || continue
    parse_hostport "${BASH_REMATCH[1]}" >> "$allowed_file"
done

export NETBLOCKER_CONF="$allowed_file"
export LD_PRELOAD="$core/libnetblocker.so"

timeout_cmd=( timeout --kill-after=5s "${timeout_s}s" )

cmd=( "${timeout_cmd[@]}" bwrap "${bwrap_args[@]}" -- "$build_script" "$@" )
printf '\e[34m[bwrap]\e[0m '; printf '%q ' "${cmd[@]}"; echo
ulimit -v $((mem_mb*1024*5))
exec "${cmd[@]}"
