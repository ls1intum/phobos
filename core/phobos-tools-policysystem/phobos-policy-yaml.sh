#!/usr/bin/env bash
# shellcheck shell=bash
# A strict subset of YAML in, flat records with line numbers out.
#
# A component of phobos-common.sh, which sources this file after phobos-policy-parse.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
#
# The subset is one document of block mappings, block sequences, the empty flow collections and
# one-line scalars, in LF-terminated UTF-8 without tabs. Everything else is refused
# with the file and the line rather than read one way, because a construct two YAML readers could
# read differently is exactly where a policy would grant one thing to Ares and another to Phobos.
# The reader can therefore only be wrong by refusing, never by reading a value differently.
# PARSE_LOCATION is set here and read by refuse_cfg in phobos-policy-parse.sh, never in this
# file, so SC2034 would fire on it by design.
# shellcheck disable=SC2034

# A key: letters and digits, starting with a letter, unquoted, which is the shape of every key of
# the Ares 2 schema. The letters are listed rather than written as a range, because a range is
# read in the collation order of the locale and could admit more than the ASCII letters.
YAML_KEY_PATTERN='^([ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789]*):(.*)$'
# The one spelling of a whole number every YAML reader reads alike: no sign, no leading zero.
YAML_PLAIN_INT_PATTERN='^(0|[123456789][0123456789]*)$'
# Anything else that begins like a number, which some YAML reader takes for an octal, a float, a
# sexagesimal or a number with underscores, and another for a string.
YAML_NUMBER_LIKE_PATTERN='^[-+.]?[0123456789]'
YAML_SPECIAL_FLOAT_PATTERN='^[-+]?\.(inf|nan)$'
# The boolean-like words of YAML 1.1 in lower case. Only true and false are read as booleans,
# and every other spelling of these is refused, since readers disagree on them.
YAML_BOOLEAN_LIKE_PATTERN='^(true|false|yes|no|on|off|y|n)$'
# A line of well-formed UTF-8 as RFC 3629 defines it, matched byte by byte in the C locale: no
# overlong form, no encoded surrogate, nothing above U+10FFFF. iconv is not used for this, since
# glibc's UTF-8 decoder accepts code points above U+10FFFF and the old five-byte forms.
YAML_WELL_FORMED_UTF8_PATTERN=$'^([\x01-\x7f]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee\xef][\x80-\xbf][\x80-\xbf]|\xed[\x80-\x9f][\x80-\xbf]|\xf0[\x90-\xbf][\x80-\xbf][\x80-\xbf]|[\xf1-\xf3][\x80-\xbf][\x80-\xbf][\x80-\xbf]|\xf4[\x80-\x8f][\x80-\xbf][\x80-\xbf])*$'
# The C1 controls, U+0080 to U+009F, as their UTF-8 bytes.
YAML_C1_CONTROL_PATTERN=$'\xc2[\x80-\x9f]'
# The bidirectional formatting characters U+202A to U+202E and U+2066 to U+2069, as their UTF-8
# bytes. They make a path read differently on a terminal from what it is.
YAML_BIDIRECTIONAL_PATTERN=$'\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]'

# Whether a line is well-formed UTF-8. Takes the line. Compares in the C locale, which it sets for
# itself alone, so that the pattern is read as bytes whatever the caller's locale is.
yaml_is_well_formed_utf8() {
  local LC_ALL=C
  [[ "$1" =~ $YAML_WELL_FORMED_UTF8_PATTERN ]]
}

# Sets yaml_concern to "control" when the text holds a C0 control, DEL or a C1 control, to
# "bidirectional" when it holds a bidirectional formatting character, and to nothing otherwise.
# Takes the text. Compares in the C locale, which it sets for itself alone. Assumes it runs inside
# read_yaml_subset, whose yaml_concern it sets.
yaml_find_unsafe_character() {
  local LC_ALL=C
  local text="$1"
  yaml_concern=""
  if [[ "$text" =~ [[:cntrl:]] || "$text" =~ $YAML_C1_CONTROL_PATTERN ]]; then
    yaml_concern="control"
  elif [[ "$text" =~ $YAML_BIDIRECTIONAL_PATTERN ]]; then
    yaml_concern="bidirectional"
  fi
}

# Refuses a value that holds a control character or a bidirectional formatting character. Takes
# the value as read. Assumes it runs inside read_yaml_subset, with PARSE_LOCATION naming the line,
# and that it is called plainly, so that a refusal ends the run.
yaml_refuse_unsafe_characters() {
  local text="$1"
  yaml_find_unsafe_character "$text"
  if [[ "$yaml_concern" == "control" ]]; then
    refuse_cfg "the value ${text@Q} holds a control character, which a value may not hold"
  fi
  if [[ "$yaml_concern" == "bidirectional" ]]; then
    refuse_cfg "the value ${text@Q} holds a bidirectional formatting character, which makes it read differently on a terminal from what it is"
  fi
}

# Refuses a file whose text a line-based reader cannot take as it is: a line that is not
# well-formed UTF-8, a carriage return or a tab anywhere, comments included. Asked before any
# line is read as YAML, so that the first such line is the one named. Takes the path of a readable
# file. Assumes it is called plainly, so that a refusal ends the run.
yaml_refuse_unreadable_lines() {
  local file="$1"
  local line
  local number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    number=$(( number + 1 ))
    PARSE_LOCATION="${file@Q}, line ${number}"
    if ! yaml_is_well_formed_utf8 "$line"; then
      refuse_cfg "this line is not valid UTF-8: it holds an invalid or overlong byte sequence, an encoded surrogate or a code point above U+10FFFF. Save the file as UTF-8"
    fi
    if [[ "$line" == *$'\r'* ]]; then
      refuse_cfg "this line contains a carriage return, which a Windows line ending leaves at its end and which would become part of the value. Save the file with LF line endings"
    fi
    if [[ "$line" == *$'\t'* ]]; then
      refuse_cfg "this line contains a tab character, which YAML does not accept as indentation and which this reader refuses everywhere. Indent and separate with spaces"
    fi
  done < "$file"
  PARSE_LOCATION=""
}

# Sets yaml_value_type to the type of one plain scalar, "bool", "null", "int" or "str", and
# refuses one that YAML readers resolve differently: a boolean-like word other than true and
# false, or a spelling a YAML 1.1 reader takes for a number. Takes the scalar. Assumes it runs
# inside read_yaml_subset, with PARSE_LOCATION naming the line, and that it is called plainly, so
# that a refusal ends the run.
yaml_plain_type() {
  local text="$1"
  case "$text" in
    true|false) yaml_value_type="bool"; return 0 ;;
    ""|"~"|null|Null|NULL) yaml_value_type="null"; return 0 ;;
  esac
  if [[ "${text,,}" =~ $YAML_BOOLEAN_LIKE_PATTERN ]]; then
    refuse_cfg "${text@Q} is read as a boolean by some YAML readers and as a string by others; write true or false, or quote it"
  fi
  if [[ "$text" =~ $YAML_PLAIN_INT_PATTERN ]]; then
    yaml_value_type="int"
    return 0
  fi
  if [[ "$text" =~ $YAML_NUMBER_LIKE_PATTERN || "${text,,}" =~ $YAML_SPECIAL_FLOAT_PATTERN ]]; then
    refuse_cfg "${text@Q} is ambiguous: YAML readers disagree on whether it is a number. Write a plain whole number without sign or leading zero, or quote it"
  fi
  yaml_value_type="str"
}

# Refuses a plain scalar that begins with a YAML indicator character, which covers anchors,
# aliases, tags, block scalars, flow collections other than the empty ones, directives and every
# reserved character. Takes the scalar. Assumes PARSE_LOCATION names its line and that it is
# called plainly, so that a refusal ends the run.
yaml_refuse_indicator() {
  local text="$1"
  local first="${1:0:1}"
  local advice="this reader accepts no anchor, alias, tag, block scalar or directive. Quote the value if it is meant as text"
  case "$first" in
    '&') refuse_cfg "${text@Q} starts with '&', which makes it an anchor in YAML; ${advice}" ;;
    '*') refuse_cfg "${text@Q} starts with '*', which makes it an alias in YAML; ${advice}" ;;
    '!') refuse_cfg "${text@Q} starts with '!', which makes it a tag in YAML; ${advice}" ;;
    '%') refuse_cfg "${text@Q} starts with '%', which makes it a directive in YAML; ${advice}" ;;
    '|'|'>') refuse_cfg "${text@Q} starts a block scalar; write the value on the line of its key, quoted if it needs to be" ;;
    '['|'{') refuse_cfg "${text@Q} is a flow collection, and only the empty [] and {} are accepted; write the items in block style, one '- item' per line" ;;
    '-'|'?'|':'|','|']'|'}'|'#'|"'"|'"'|'@'|'`') refuse_cfg "${text@Q} starts with the indicator character ${first@Q}, which YAML readers do not all read the same way at the start of a plain value; quote the value" ;;
  esac
}

# Reads the rest of a double-quoted scalar, the opening quote already taken off, into yaml_value,
# and what follows the closing quote into yaml_rest. Only the escapes \\ and \" are accepted,
# because every other escape stands for a character that some reader of the policy would see
# differently. Takes the text after the opening quote. Assumes it runs inside read_yaml_subset,
# with PARSE_LOCATION naming the line, and that it is called plainly, so that a refusal ends the run.
yaml_read_double_quoted() {
  local text="$1"
  local shown="\"$1"
  local index=0
  local character
  local next
  yaml_value=""
  while (( index < ${#text} )); do
    character="${text:index:1}"
    if [[ "$character" == '"' ]]; then
      yaml_rest="${text:index+1}"
      return 0
    fi
    if [[ "$character" == '\' ]]; then
      next="${text:index+1:1}"
      if [[ "$next" != '\' && "$next" != '"' ]]; then
        refuse_cfg "the escape '\\${next}' in ${shown@Q} is not accepted; a double-quoted value may use only \\\\ and \\\", so that no reader takes it for another character"
      fi
      yaml_value+="$next"
      index=$(( index + 2 ))
      continue
    fi
    yaml_value+="$character"
    index=$(( index + 1 ))
  done
  refuse_cfg "the double-quoted value ${shown@Q} is unterminated; a value has to end on the line it starts on"
}

# Reads the rest of a single-quoted scalar, the opening quote already taken off, into yaml_value,
# and what follows the closing quote into yaml_rest. Two quotes in a row stand for one. Takes the
# text after the opening quote. Assumes it runs inside read_yaml_subset, with PARSE_LOCATION naming
# the line, and that it is called plainly, so that a refusal ends the run.
yaml_read_single_quoted() {
  local text="$1"
  local shown="'$1"
  local index=0
  local character
  yaml_value=""
  while (( index < ${#text} )); do
    character="${text:index:1}"
    if [[ "$character" == "'" && "${text:index+1:1}" == "'" ]]; then
      yaml_value+="'"
      index=$(( index + 2 ))
      continue
    fi
    if [[ "$character" == "'" ]]; then
      yaml_rest="${text:index+1}"
      return 0
    fi
    yaml_value+="$character"
    index=$(( index + 1 ))
  done
  refuse_cfg "the single-quoted value ${shown@Q} is unterminated; a value has to end on the line it starts on"
}

# Refuses anything after the closing quote of a scalar but spaces and a comment, which YAML
# separates from the value by at least one space. Takes what followed the closing quote. Assumes
# PARSE_LOCATION names the line and that it is called plainly, so that a refusal ends the run.
yaml_refuse_text_after_quote() {
  local rest="$1"
  if [[ -n "$rest" && ! "$rest" =~ ^\ +# ]]; then
    refuse_cfg "${rest@Q} follows after the closing quote of a value; only a comment, after a space, may follow it"
  fi
}

# Reads one value, the text after "key: " or "- ", into yaml_value_type and yaml_value. The type
# is "none" for no value at all (nothing, or only a comment), "seq" or "map" for an empty flow
# collection, and a scalar type otherwise; a quoted scalar is always "str". A plain scalar ends
# where " #" starts a comment. Takes the text, without leading spaces. Assumes it runs inside
# read_yaml_subset, with PARSE_LOCATION naming the line, and that it is called plainly, so that a
# refusal ends the run.
yaml_read_value() {
  local text="$1"
  yaml_value=""
  yaml_rest=""
  case "$text" in
    ""|"#"*) yaml_value_type="none"; return 0 ;;
    '"'*) yaml_read_double_quoted "${text:1}"; yaml_refuse_text_after_quote "$yaml_rest"; yaml_value_type="str" ;;
    "'"*) yaml_read_single_quoted "${text:1}"; yaml_refuse_text_after_quote "$yaml_rest"; yaml_value_type="str" ;;
    *) yaml_read_plain "$text" ;;
  esac
  yaml_refuse_unsafe_characters "$yaml_value"
}

# Reads a plain scalar, or an empty flow collection, into yaml_value_type and yaml_value. A plain
# scalar holding ": " or ending in ":" is refused, since YAML reads it as a nested mapping. Takes
# the text, which starts with no quote and no comment. Assumes it runs inside read_yaml_subset,
# with PARSE_LOCATION naming the line, and that it is called plainly, so that a refusal ends the run.
yaml_read_plain() {
  local text="${1%% #*}"
  text="${text%"${text##*[! ]}"}"
  case "$text" in
    "[]"|"[ ]") yaml_value_type="seq"; return 0 ;;
    "{}"|"{ }") yaml_value_type="map"; return 0 ;;
  esac
  yaml_refuse_indicator "$text"
  if [[ "$text" == *": "* || "$text" == *":" ]]; then
    refuse_cfg "${text@Q} holds a ': ' or ends in ':', which YAML reads as a nested mapping; quote the value"
  fi
  yaml_plain_type "$text"
  if [[ "$yaml_value_type" != "null" ]]; then
    yaml_value="$text"
  fi
}

# Sets yaml_kind to "item" for a "- ..." line, to "key" for a "key: ..." or "key:" line, and to
# "other" for anything else, and sets yaml_key and yaml_after to the key and the text after its
# colon, or yaml_after to the text after "- ". Takes the line's content without indentation.
# Assumes it runs inside read_yaml_subset, whose variables it sets.
yaml_classify_line() {
  local content="$1"
  yaml_key=""
  yaml_after=""
  if [[ "$content" == "-" || "$content" == "- "* ]]; then
    yaml_kind="item"
    yaml_after="${content#-}"
    yaml_after="${yaml_after#"${yaml_after%%[! ]*}"}"
  elif [[ "$content" =~ $YAML_KEY_PATTERN && ( -z "${BASH_REMATCH[2]}" || "${BASH_REMATCH[2]}" == " "* ) ]]; then
    yaml_kind="key"
    yaml_key="${BASH_REMATCH[1]}"
    yaml_after="${BASH_REMATCH[2]# }"
    yaml_after="${yaml_after#"${yaml_after%%[! ]*}"}"
  else
    yaml_kind="other"
  fi
}

# Refuses a line that is neither a key nor a list item, saying what it looks like: a key of
# another shape, a construct that starts with an indicator, or a line with no key at all. Takes
# the line's content. Assumes PARSE_LOCATION names the line and that it is called plainly, so
# that the refusal ends the run.
yaml_refuse_unkeyed_line() {
  local content="$1"
  local key="${1%%:*}"
  if [[ "$content" == *": "* || "$content" == *":" ]]; then
    refuse_cfg "${key@Q} is not a key this reader accepts: a key is unquoted letters and digits starting with a letter, as every key of an Ares 2 policy is"
  fi
  yaml_refuse_indicator "$content"
  refuse_cfg "${content@Q} is neither a 'key: value' nor a '- item'; a value has to stay on the line of its key"
}

# Prints a path one step below another into yaml_child: ".key" or "[index]" below the root "."
# is the step itself, and below any other path it is appended. Takes the parent path and the
# step. Assumes it runs inside read_yaml_subset, whose yaml_child it sets.
yaml_child_path() {
  local parent="$1"
  local step="$2"
  if [[ "$parent" == "." ]]; then
    yaml_child="$step"
  else
    yaml_child="${parent}${step}"
  fi
}

# Appends one record, "<line>\t<path>\t<type>\t<value>", to the records file. Takes the line,
# the path, the type and the value. Assumes it runs inside read_yaml_subset, whose yaml_out names
# the records file.
yaml_record() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$yaml_out"
}

# Opens a mapping or a sequence at an indentation, under a path. Takes the indentation, the path
# and "map" or "seq". Assumes it runs inside read_yaml_subset, whose frame arrays it extends.
yaml_push_frame() {
  frame_indent+=( "$1" )
  frame_path+=( "$2" )
  frame_kind+=( "$3" )
  frame_next+=( 0 )
}

# Closes the innermost open mapping or sequence. Assumes it runs inside read_yaml_subset, whose
# frame arrays hold at least one frame.
yaml_pop_frame() {
  unset 'frame_indent[-1]' 'frame_path[-1]' 'frame_kind[-1]' 'frame_next[-1]'
}

# Opens the document's root from its first content line: a mapping for a key, a sequence for a
# list item, and a refusal for anything else. Takes the line number and the indentation. Assumes
# it runs inside read_yaml_subset after yaml_classify_line, and that it is called plainly, so that
# a refusal ends the run.
yaml_open_root() {
  local number="$1"
  local indent="$2"
  local content="$3"
  case "$yaml_kind" in
    key) yaml_push_frame "$indent" "." map; yaml_record "$number" "." map "" ;;
    item) yaml_push_frame "$indent" "." seq; yaml_record "$number" "." seq "" ;;
    *) yaml_refuse_unkeyed_line "$content" ;;
  esac
}

# Decides what the key left without a value on an earlier line holds, from the line after it: a
# block mapping or sequence when this line is indented deeper, a sequence when it is a list item
# at the key's own column, and null otherwise. A deeper line that is neither starts a multi-line
# scalar, which is refused. Takes the line number and the indentation. Assumes it runs inside
# read_yaml_subset after yaml_classify_line, and that it is called plainly, so that a refusal ends
# the run.
yaml_resolve_pending() {
  local indent="$1"
  (( yaml_pending )) || return 0
  yaml_pending=0
  if (( indent > yaml_pending_indent )) && [[ "$yaml_kind" == "key" ]]; then
    yaml_push_frame "$indent" "$yaml_pending_path" map
    yaml_record "$yaml_pending_line" "$yaml_pending_path" map ""
  elif (( indent >= yaml_pending_indent )) && [[ "$yaml_kind" == "item" ]]; then
    yaml_push_frame "$indent" "$yaml_pending_path" seq
    yaml_record "$yaml_pending_line" "$yaml_pending_path" seq ""
  elif (( indent > yaml_pending_indent )); then
    refuse_cfg "this line is indented below a key as a continuation line of its value would be; a value has to start on the line of its key and stay on it"
  else
    yaml_record "$yaml_pending_line" "$yaml_pending_path" null ""
  fi
}

# Closes every open mapping and sequence the line's indentation leaves, and refuses a line whose
# indentation matches none of those still open, one indented deeper than its context allows, a
# key where a list item belongs and a list item where a key belongs. A sequence written at its
# key's own column is closed by the next key at that column. Takes the indentation. Assumes it
# runs inside read_yaml_subset after yaml_classify_line, and that it is called plainly, so that a
# refusal ends the run.
yaml_align_frames() {
  local indent="$1"
  local top=$(( ${#frame_indent[@]} - 1 ))
  local closed=0
  while (( top >= 0 )) && (( frame_indent[top] > indent )); do
    yaml_pop_frame
    top=$(( top - 1 ))
    closed=1
  done
  if (( top < 0 )) || (( closed && frame_indent[top] < indent )); then
    refuse_cfg "this line's indentation matches no enclosing mapping or list"
  fi
  if (( frame_indent[top] < indent )); then
    refuse_cfg "this line is indented deeper than its context allows; a value has to stay on one line, so a continuation line is refused"
  fi
  [[ "$yaml_kind" != "other" ]] || return 0
  if [[ "${frame_kind[top]}" == "seq" && "$yaml_kind" == "key" ]]; then
    if (( top > 0 )) && (( frame_indent[top - 1] == indent )) && [[ "${frame_kind[top - 1]}" == "map" ]]; then
      yaml_pop_frame
    else
      refuse_cfg "a key stands where a list item was expected"
    fi
  elif [[ "${frame_kind[top]}" == "map" && "$yaml_kind" == "item" ]]; then
    refuse_cfg "a list item stands where a key was expected"
  fi
}

# Reads one "key: ..." line into the innermost mapping: refuses a key that mapping already holds,
# records a value on the line, or leaves the key pending when nothing follows its colon. Takes the
# line number, the key's column, the key and the text after its colon. Assumes it runs inside
# read_yaml_subset with a mapping innermost, and that it is called plainly, so that a refusal ends
# the run.
yaml_read_key() {
  local number="$1"
  local column="$2"
  local key="$3"
  local after="$4"
  local top=$(( ${#frame_indent[@]} - 1 ))
  local path
  yaml_child_path "${frame_path[top]}" ".${key}"
  path="$yaml_child"
  if [[ -n "${yaml_seen_key["$path"]:-}" ]]; then
    refuse_cfg "the key ${key@Q} appears twice in this mapping, first on line ${yaml_seen_key["$path"]}"
  fi
  yaml_seen_key["$path"]="$number"
  yaml_read_value "$after"
  if [[ "$yaml_value_type" == "none" ]]; then
    yaml_pending=1
    yaml_pending_path="$path"
    yaml_pending_line="$number"
    yaml_pending_indent="$column"
    return 0
  fi
  yaml_record "$number" "$path" "$yaml_value_type" "$yaml_value"
}

# Reads one "- ..." line into the innermost sequence: a mapping item when a key follows the dash,
# whose further keys sit at that key's column, and a scalar or an empty flow collection otherwise.
# A dash with nothing after it is refused. Takes the line number, the indentation and the line's
# content. Assumes it runs inside read_yaml_subset with a sequence innermost and after
# yaml_classify_line, and that it is called plainly, so that a refusal ends the run.
yaml_read_item() {
  local number="$1"
  local indent="$2"
  local content="$3"
  local top=$(( ${#frame_indent[@]} - 1 ))
  local index="${frame_next[top]}"
  local rest="$yaml_after"
  local column=$(( indent + ${#content} - ${#rest} ))
  local path
  frame_next[top]=$(( index + 1 ))
  yaml_child_path "${frame_path[top]}" "[${index}]"
  path="$yaml_child"
  if [[ -z "$rest" || "$rest" == "#"* ]]; then
    refuse_cfg "a '-' stands alone on this line; write the item on the line of its dash"
  fi
  yaml_classify_line "$rest"
  if [[ "$yaml_kind" == "key" ]]; then
    yaml_push_frame "$column" "$path" map
    yaml_record "$number" "$path" map ""
    yaml_read_key "$number" "$column" "$yaml_key" "$yaml_after"
    return 0
  fi
  yaml_read_value "$rest"
  yaml_record "$number" "$path" "$yaml_value_type" "$yaml_value"
}

# Handles a document marker line and says whether the line was one: "---" alone, or with only a
# comment, is accepted once before any content, and a second "---", one followed by content and
# any "..." are refused, since a policy is one document. Takes the indentation and the line's
# content. Assumes it runs inside read_yaml_subset, with PARSE_LOCATION naming the line, and that
# it is called plainly, so that a refusal ends the run.
yaml_read_document_marker() {
  local indent="$1"
  local content="$2"
  (( indent == 0 )) || return 1
  if [[ "$content" == "..." || "$content" == "... "* ]]; then
    refuse_cfg "the document end marker '...' is not accepted; a policy is one document"
  fi
  [[ "$content" == "---" || "$content" == "--- "* ]] || return 1
  if (( yaml_started || yaml_marker_seen )); then
    refuse_cfg "a second document starts here, and this reader accepts one document"
  fi
  if [[ "$content" != "---" && ! "$content" =~ ^---\ +# ]]; then
    refuse_cfg "content follows the document marker '---'; write the first key on its own line"
  fi
  yaml_marker_seen=1
}

# Reads a file in the YAML subset this policy system accepts and writes one record per node to the
# records file, "<line>\t<path>\t<type>\t<value>", in document order. The path is "." for the root
# and ".key" and "[index]" steps below it; the type is map, seq, str, int, bool or null; the value
# is empty for map, seq and null. Containers are recorded too, so an empty list is a seq record
# with no children. Everything outside the subset is refused with PHB-EPOLICY, the file and the
# line. Takes the file and the records file, which it truncates. Assumes the file was found
# readable, and that it is called plainly, never in a subshell, so that a refusal ends the run.
read_yaml_subset() {
  local file="$1"
  local yaml_out="$2"
  local -a frame_indent=()
  local -a frame_path=()
  local -a frame_kind=()
  local -a frame_next=()
  local -A yaml_seen_key=()
  local yaml_pending=0
  local yaml_pending_path=""
  local yaml_pending_line=0
  local yaml_pending_indent=0
  local yaml_started=0
  local yaml_marker_seen=0
  local yaml_kind=""
  local yaml_key=""
  local yaml_after=""
  local yaml_value=""
  local yaml_value_type=""
  local yaml_rest=""
  local yaml_child=""
  local yaml_concern=""
  local raw
  local content
  local indent
  local number=0
  refuse_binary_cfg "$file"
  yaml_refuse_unreadable_lines "$file"
  : > "$yaml_out"
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    number=$(( number + 1 ))
    PARSE_LOCATION="${file@Q}, line ${number}"
    content="${raw#"${raw%%[! ]*}"}"
    indent=$(( ${#raw} - ${#content} ))
    content="${content%"${content##*[! ]}"}"
    [[ -n "$content" && "$content" != "#"* ]] || continue
    yaml_read_document_marker "$indent" "$content" && continue
    yaml_classify_line "$content"
    if (( ! yaml_started )); then
      yaml_open_root "$number" "$indent" "$content"
      yaml_started=1
    fi
    yaml_resolve_pending "$indent"
    yaml_align_frames "$indent"
    case "$yaml_kind" in
      item) yaml_read_item "$number" "$indent" "$content" ;;
      key) yaml_read_key "$number" "$indent" "$yaml_key" "$yaml_after" ;;
      *) yaml_refuse_unkeyed_line "$content" ;;
    esac
  done < "$file"
  if (( yaml_pending )); then
    yaml_record "$yaml_pending_line" "$yaml_pending_path" null ""
  fi
  PARSE_LOCATION="${file@Q}"
  if (( ! yaml_started )); then
    refuse_cfg "the file holds no YAML content: every line is blank or a comment"
  fi
  PARSE_LOCATION=""
}
