#!/usr/bin/env bash
# Wait until every named artifact of this workflow run is uploaded. Stops
# early when a job whose name starts with the given prefix has finished
# without success, since its artifacts will never appear.
#
#   wait-for-artifacts.sh "<job name prefix>" <artifact>...
set -euo pipefail
prefix=$1
shift
deadline=$((SECONDS + 3600))
api="repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
while :; do
  names=" $(gh api "$api/artifacts?per_page=100" --jq '[.artifacts[].name] | join(" ")') "
  missing=()
  for artifact in "$@"; do
    case "$names" in
      *" $artifact "*) ;;
      *) missing+=("$artifact") ;;
    esac
  done
  if [ ${#missing[@]} -eq 0 ]; then
    exit 0
  fi
  failed=$(gh api "$api/jobs?per_page=100" --jq "[.jobs[] | select(.name | startswith(\"$prefix\")) | select(.status == \"completed\" and .conclusion != \"success\") | .name] | join(\", \")")
  if [ -n "$failed" ]; then
    echo "::error::$failed did not succeed, so ${missing[*]} will not appear"
    exit 1
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "::error::${missing[*]} did not appear within 60 minutes"
    exit 1
  fi
  sleep 20
done
