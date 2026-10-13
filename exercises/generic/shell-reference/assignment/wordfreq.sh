#!/bin/bash
# The solution of the generic reference exercise: prints each word of the file $1 with how often it
# occurs, most frequent first, ties in alphabetical order, one "word count" per line.
set -euo pipefail
tr -cs '[:alpha:]' '\n' < "$1" | tr '[:upper:]' '[:lower:]' | grep -v '^$' | sort | uniq -c | sort -k1,1nr -k2,2 | awk '{ print $2, $1 }'
