#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src/main/java"
OUT_DIR="$SCRIPT_DIR/target/manual-classes"
JAR_PATH="$SCRIPT_DIR/target/iso8583-sender-manual.jar"
MAIN_CLASS="com.example.iso8583.Iso8583Sender"

JAVAC_OPTS=(-d "$OUT_DIR")
if javac --help 2>&1 | grep -q -- "--release"; then
  JAVAC_OPTS=(--release 8 "${JAVAC_OPTS[@]}")
else
  JAVAC_OPTS=(-source 1.8 -target 1.8 "${JAVAC_OPTS[@]}")
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

find "$SRC_DIR" -name "*.java" -print0 \
  | xargs -0 -r javac "${JAVAC_OPTS[@]}"

mkdir -p "$(dirname "$JAR_PATH")"
jar cfe "$JAR_PATH" "$MAIN_CLASS" -C "$OUT_DIR" .

echo "Created $JAR_PATH"
