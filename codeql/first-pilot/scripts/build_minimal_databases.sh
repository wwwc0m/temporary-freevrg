#!/usr/bin/env bash
set -euo pipefail

# Build the minimal vulnerable/fixed CodeQL C/C++ databases used by the first-pilot
# mechanism validation. The source roots are intentionally tiny harnesses, so a
# direct single-file compiler command is sufficient and avoids the FreeBSD build
# system.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEQL_BIN="${CODEQL:-codeql}"
CC_BIN="${CC:-}"
SOURCE_ROOT="$ROOT_DIR/minimal-validation-databases/source"
DB_ROOT="$ROOT_DIR/minimal-validation-databases/db"
LOGS_DIR="$ROOT_DIR/minimal-validation-databases/logs"
OBJECTS_DIR="$ROOT_DIR/minimal-validation-databases/objects"
FORCE=0

usage() {
  cat <<EOF
Usage:
  $(basename "$0") [--force]

Environment:
  CODEQL=/path/to/codeql
  CC=/path/to/cc
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

if ! command -v "$CODEQL_BIN" >/dev/null 2>&1 && [[ ! -x "$CODEQL_BIN" ]]; then
  die "codeql not found. Set CODEQL=/path/to/codeql or add codeql to PATH."
fi
[[ -d "$SOURCE_ROOT" ]] || die "source root not found: $SOURCE_ROOT"

if [[ -z "$CC_BIN" ]]; then
  for candidate in cc gcc clang; do
    if command -v "$candidate" >/dev/null 2>&1; then
      CC_BIN="$candidate"
      break
    fi
  done
fi

if [[ -z "$CC_BIN" ]]; then
  die "C compiler not found. Install clang/gcc or run with CC=/path/to/compiler."
fi

mkdir -p "$DB_ROOT" "$LOGS_DIR" "$OBJECTS_DIR"

echo "[1/2] CodeQL version"
"$CODEQL_BIN" version

echo
echo "[2/2] Build minimal databases"
shopt -s nullglob
jobs=("$SOURCE_ROOT"/*)
[[ ${#jobs[@]} -gt 0 ]] || die "no source harness directories found under $SOURCE_ROOT"

for source_dir in "${jobs[@]}"; do
  [[ -d "$source_dir" ]] || continue
  name="$(basename "$source_dir")"
  db_dir="$DB_ROOT/$name"
  log_path="$LOGS_DIR/create-$name.log"

  if [[ -f "$db_dir/codeql-database.yml" && "$FORCE" -eq 0 ]]; then
    {
      echo "=== $name ==="
      echo "database=$db_dir"
      echo "STATUS=SKIPPED existing_database use --force to rebuild"
    } > "$log_path"
    echo "  - SKIP $name"
    continue
  fi

  if [[ "$FORCE" -eq 1 && -d "$db_dir" ]]; then
    rm -rf "$db_dir"
  fi

  echo "  - CREATE $name"
  {
    echo "=== $name ==="
    echo "source=$source_dir"
    echo "database=$db_dir"
    echo "build_mode=manual-command"
    echo "compiler=$CC_BIN"
    echo "codeql=$CODEQL_BIN"
    "$CODEQL_BIN" database create "$db_dir" \
      --language=cpp \
      --source-root "$source_dir" \
      --command "$CC_BIN -std=c11 -include stddef.h -c harness.c -o $OBJECTS_DIR/$name.o"
    echo "STATUS=OK"
  } > "$log_path" 2>&1
done

echo
echo "Databases: $DB_ROOT"
echo "Logs: $LOGS_DIR"
