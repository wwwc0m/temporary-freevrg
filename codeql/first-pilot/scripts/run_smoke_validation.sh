#!/usr/bin/env bash
set -euo pipefail

# Re-run FreeVRG first-pilot QL smoke validation on Linux.
#
# Expected layout:
#   first-ql-validation-package/
#     qlpack.yml
#     queries/*.ql
#     minimal-validation-databases/db/<CVE>-<version>/
#     minimal-validation-databases/source/<CVE>-<version>/
#     minimal-validation-databases/results/
#     minimal-validation-databases/logs/
#
# Usage:
#   ./scripts/run_smoke_validation.sh --all
#   ./scripts/run_smoke_validation.sh queries/missing-array-bounds-check-on-network-controlled-index.ql
#
# Environment:
#   CODEQL=/path/to/codeql
#   ADDITIONAL_PACKS=/path/to/codeql-stdlib

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEQL_BIN="${CODEQL:-codeql}"
ADDITIONAL_PACKS="${ADDITIONAL_PACKS:-}"

DB_ROOT="$ROOT_DIR/minimal-validation-databases/db"
SOURCE_ROOT="$ROOT_DIR/minimal-validation-databases/source"
RESULTS_DIR="$ROOT_DIR/minimal-validation-databases/results"
LOGS_DIR="$ROOT_DIR/minimal-validation-databases/logs"
VALIDATION_DIR="$ROOT_DIR/validation"
SUMMARY="$VALIDATION_DIR/smoke-summary.tsv"
FAILURE_REPORT="$VALIDATION_DIR/smoke-failures.txt"

usage() {
  cat <<EOF
Usage:
  $(basename "$0") --all
  $(basename "$0") <query.ql> [<query.ql> ...]

Examples:
  $(basename "$0") --all
  $(basename "$0") queries/missing-array-bounds-check-on-network-controlled-index.ql
  $(basename "$0") queries/missing-minimum-length-check-on-network-protocol-packet.ql

Environment:
  CODEQL=/path/to/codeql
  ADDITIONAL_PACKS=/path/to/codeql-stdlib
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 2
}

require_command() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
}

resolve_query() {
  local input="$1"
  if [[ "$input" = /* ]]; then
    printf "%s\n" "$input"
  else
    printf "%s\n" "$ROOT_DIR/$input"
  fi
}

query_matrix() {
  local query_basename="$1"
  case "$query_basename" in
    missing-array-bounds-check-on-network-controlled-index.ql)
      cat <<'EOF'
CVE-2018-17161 vulnerable
CVE-2018-17161 fixed
CVE-2019-5604 vulnerable
CVE-2019-5604 fixed
CVE-2021-29631 vulnerable
CVE-2021-29631 fixed
EOF
      ;;
    missing-minimum-length-check-on-network-protocol-packet.ql)
      cat <<'EOF'
CVE-2020-7461 vulnerable
CVE-2020-7461 fixed
CVE-2021-29629 vulnerable
CVE-2021-29629 fixed
EOF
      ;;
    *)
      return 1
      ;;
  esac
}

count_sarif_results() {
  local sarif="$1"
  python3 - "$sarif" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
print(sum(len(run.get("results", [])) for run in data.get("runs", [])))
PY
}

write_failure_report() {
  python3 - "$SUMMARY" "$RESULTS_DIR" "$SOURCE_ROOT" "$FAILURE_REPORT" <<'PY'
import csv
import json
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
results_dir = Path(sys.argv[2])
source_dir = Path(sys.argv[3])
report_path = Path(sys.argv[4])

rows = []
with summary_path.open("r", encoding="utf-8", newline="") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))

failures = []
for row in rows:
    status = row.get("status")
    version = row.get("version")
    if version == "vulnerable" and status != "hit":
        failures.append(row)
    elif version == "fixed" and status != "clean":
        failures.append(row)
    elif status == "analyze_error":
        failures.append(row)

lines = []
if not failures:
    lines.append("SMOKE_RESULT=PASS")
else:
    lines.append("SMOKE_RESULT=FAIL")
    lines.append("Failures:")

for row in failures:
    cve = row["cve"]
    version = row["version"]
    query = row["query"]
    sarif_path = results_dir / f"{cve}-{version}.sarif"
    lines.append(f"- {query} / {cve} {version}: {row['status']} (results={row['result_count']})")

    if row["status"] == "miss":
        lines.append("  reason: vulnerable database produced no SARIF results")
        lines.append(f"  sarif: {sarif_path}")
        continue
    if row["status"] == "analyze_error":
        lines.append("  reason: codeql database analyze failed; inspect analyze log")
        continue
    if not sarif_path.exists():
        lines.append(f"  sarif: missing expected file {sarif_path}")
        continue

    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except Exception as exc:
        lines.append(f"  sarif: failed to read {sarif_path}: {exc}")
        continue

    shown = 0
    for run in data.get("runs", []):
        for result in run.get("results", []):
            msg = result.get("message", {}).get("text", "").replace("\n", " ")
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                uri = art.get("uri", "<unknown>")
                line = region.get("startLine")
                col = region.get("startColumn")
                lines.append(f"  location: {uri}:{line}:{col}")
                if msg:
                    lines.append(f"  message: {msg}")
                src_path = source_dir / f"{cve}-{version}" / uri
                if line and src_path.exists():
                    try:
                        src_lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
                        start = max(1, line - 2)
                        end = min(len(src_lines), line + 2)
                        lines.append("  source:")
                        for n in range(start, end + 1):
                            marker = ">" if n == line else " "
                            lines.append(f"    {marker} {n:4}: {src_lines[n - 1]}")
                    except Exception as exc:
                        lines.append(f"  source: failed to read {src_path}: {exc}")
                shown += 1
                if shown >= 3:
                    break
            if shown >= 3:
                break
        if shown >= 3:
            break
    if shown == 0:
        lines.append(f"  sarif: no locations found in {sarif_path}")

report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(lines[0])
if failures:
    print(f"Failure report: {report_path}")
    sys.exit(1)
PY
}

run_analyze() {
  local cve="$1"
  local version="$2"
  local query="$3"
  local query_base
  query_base="$(basename "$query")"
  local db="$DB_ROOT/${cve}-${version}"
  local out="$RESULTS_DIR/${cve}-${version}.sarif"
  local log="$LOGS_DIR/analyze-${cve}-${version}.log"

  if [[ ! -f "$db/codeql-database.yml" ]]; then
    echo "ERROR: missing CodeQL database: $db" | tee "$log"
    printf "%s\t%s\t%s\tERROR\tmissing_database\n" "$cve" "$version" "$query_base" >> "$SUMMARY"
    return 1
  fi

  echo "  - $query_base :: $cve $version"
  if "$CODEQL_BIN" database analyze "$db" "$query" \
      --format=sarif-latest \
      --output="$out" \
      --rerun \
      "${codeql_args[@]}" >"$log" 2>&1; then
    local n
    n="$(count_sarif_results "$out")"
    local status
    if [[ "$version" == "vulnerable" ]]; then
      if [[ "$n" -gt 0 ]]; then status="hit"; else status="miss"; fi
    elif [[ "$version" == "fixed" ]]; then
      if [[ "$n" -eq 0 ]]; then status="clean"; else status="still_reports"; fi
    else
      status="unknown_version"
    fi
    printf "%s\t%s\t%s\t%s\t%s\n" "$cve" "$version" "$query_base" "$n" "$status" >> "$SUMMARY"
  else
    printf "%s\t%s\t%s\tERROR\tanalyze_error\n" "$cve" "$version" "$query_base" >> "$SUMMARY"
    echo "ERROR: analyze failed for $cve $version. See $log"
    return 1
  fi
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

require_command python3
if ! command -v "$CODEQL_BIN" >/dev/null 2>&1 && [[ ! -x "$CODEQL_BIN" ]]; then
  die "codeql not found. Set CODEQL=/path/to/codeql or add codeql to PATH."
fi

queries=()
if [[ "$1" == "--all" ]]; then
  shift
  [[ $# -eq 0 ]] || die "--all does not accept extra query arguments"
  queries=(
    "$ROOT_DIR/queries/missing-array-bounds-check-on-network-controlled-index.ql"
    "$ROOT_DIR/queries/missing-minimum-length-check-on-network-protocol-packet.ql"
  )
else
  for input in "$@"; do
    queries+=("$(resolve_query "$input")")
  done
fi

mkdir -p "$RESULTS_DIR" "$LOGS_DIR" "$VALIDATION_DIR"

codeql_args=()
if [[ -n "$ADDITIONAL_PACKS" ]]; then
  codeql_args+=(--additional-packs "$ADDITIONAL_PACKS")
fi

echo "[1/3] CodeQL version"
"$CODEQL_BIN" version

echo
echo "[2/3] Compile query"
for query in "${queries[@]}"; do
  [[ -f "$query" ]] || die "query file not found: $query"
  query_base="$(basename "$query")"
  if ! query_matrix "$query_base" >/dev/null; then
    die "no smoke validation matrix is defined for query: $query_base"
  fi
  echo "  - $query_base"
  "$CODEQL_BIN" query compile --check-only "${codeql_args[@]}" -- "$query"
done

echo
echo "[3/3] Analyze minimal vulnerable/fixed databases"
printf "cve\tversion\tquery\tresult_count\tstatus\n" > "$SUMMARY"

analyze_errors=0
for query in "${queries[@]}"; do
  query_base="$(basename "$query")"
  while read -r cve version; do
    [[ -n "$cve" ]] || continue
    run_analyze "$cve" "$version" "$query" || analyze_errors=1
  done < <(query_matrix "$query_base")
done

echo
echo "Smoke summary:"
if command -v column >/dev/null 2>&1; then
  column -t -s $'\t' "$SUMMARY"
else
  cat "$SUMMARY"
fi

echo
if write_failure_report; then
  smoke_status=0
else
  smoke_status=1
fi

echo
echo "Wrote summary: $SUMMARY"
echo "Wrote failure report: $FAILURE_REPORT"
echo "Wrote SARIF results: $RESULTS_DIR"
echo "Wrote analyze logs: $LOGS_DIR"

if [[ "$analyze_errors" -ne 0 ]]; then
  exit 1
fi
exit "$smoke_status"
