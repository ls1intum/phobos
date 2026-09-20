#!/usr/bin/env bash
# shellcheck shell=bash
# The timeout contract: how a value is spelled, compared and read back.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
# Every variable here is read by the scripts that source the aggregate, never in
# this file, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034
# Timeout values are seconds: either a whole number, or seconds with
# millisecond precision written as exactly three decimal places.
# GNU timeout receives the value with an explicit seconds suffix, so no unit
# conversion happens after this point.
PHB_TIMEOUT_PATTERN='^[0-9]+(\.[0-9]{3})?$'

# A timeout in whole milliseconds, so two spellings of one value compare as numbers rather
# than as text. The pattern guarantees a digit before the point and exactly three after it,
# so both parts are read in base ten, never as octal, and never with an empty field.
timeout_to_ms() {
  local value="$1"
  local integer
  local fraction="0"
  if [[ "$value" == *.* ]]; then integer="${value%%.*}"; fraction="${value#*.}"; else integer="$value"; fi
  printf '%s' "$(( 10#$integer * PHB_MILLISECONDS_PER_SECOND + 10#$fraction ))"
}

# The inverse, canonical: whole seconds print without a fraction, so 2 and 2.000 come back as
# the one spelling and the written specification does not depend on which cfg named it.
ms_to_timeout() {
  local ms="$1"
  local seconds
  local fraction
  seconds=$(( ms / PHB_MILLISECONDS_PER_SECOND ))
  fraction=$(( ms % PHB_MILLISECONDS_PER_SECOND ))
  if (( fraction == 0 )); then printf '%s' "$seconds"; else printf '%d.%03d' "$seconds" "$fraction"; fi
}

# Prints the given EPOCHREALTIME value in whole microseconds. Every character that is not a
# digit is dropped, because bash writes the decimal separator of the current locale (a comma
# under de_DE), and EPOCHREALTIME always carries exactly six decimals, so the digits that are
# left are the microseconds.
epoch_realtime_microseconds() {
  printf '%s' "${1//[!0-9]/}"
}

# Answers whether a run that ended with the given GNU timeout status after the given number of
# microseconds was stopped by the given timeout. GNU timeout passes the command's own status
# through when it did not time out, and a command killed by someone else, the OOM killer among
# them, ends with the same 137 as the escalation, so the status alone decides nothing: only a
# 124 or a 137 that came no earlier than the timeout is one. The time is the wall clock
# (EPOCHREALTIME), so a clock stepped backwards during a run can make a real expiry look too
# short and be passed through without PHB-ETIMEOUT; the run itself is never extended by it.
run_reached_timeout() {
  local status="$1"
  local elapsed_microseconds="$2"
  local timeout_value="$3"
  local limit_microseconds
  (( status == PHB_TIMEOUT_EXPIRED_EXIT || status == PHB_TIMEOUT_KILLED_EXIT )) || return 1
  limit_microseconds=$(( $(timeout_to_ms "$timeout_value") * PHB_MICROSECONDS_PER_MILLISECOND ))
  (( elapsed_microseconds >= limit_microseconds ))
}
