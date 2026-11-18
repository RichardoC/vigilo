#!/usr/bin/env bash
# Generate $CODEX_HOME/config.toml from template + environment variables.
#   Usage: config_codex.sh [template] [output]
#     template  defaults to /app/configs/codex.template.toml
#     output    defaults to $CODEX_HOME/config.toml
set -e

TEMPLATE_FILE="${1:-/app/configs/codex.template.toml}"
OUTPUT_DIR="${CODEX_HOME:-$HOME/.codex}"
OUTPUT_FILE="${2:-$OUTPUT_DIR/config.toml}"

# -------------------------
# Defaults
# -------------------------
: "${CODEX_MEDIUM_MODEL:=gpt-5-codex}"
: "${CODEX_REASONING_EFFORT:=medium}"
: "${CODEX_WIRE_API:=responses}"
: "${CODEX_BASE_URL:=https://api.openai.com/v1}"

# Normalise the base URL. Strip surrounding whitespace FIRST: a stray space or a
# CR from a CRLF .env otherwise gets baked into config.toml and defeats the /v1
# check below — e.g. ".../openai/v1 " fails the "*/v1" glob, so "/v1" is appended
# a second time, yielding ".../openai/v1 /v1/responses" and a 404.
CODEX_BASE_URL="${CODEX_BASE_URL#"${CODEX_BASE_URL%%[![:space:]]*}"}"
CODEX_BASE_URL="${CODEX_BASE_URL%"${CODEX_BASE_URL##*[![:space:]]}"}"
# Codex posts to {base_url}/responses, so the version path must be present.
case "$CODEX_BASE_URL" in
  */v1 | */v1/ ) : ;;
  * ) CODEX_BASE_URL="${CODEX_BASE_URL%/}/v1" ;;
esac
export CODEX_BASE_URL

if [ ! -f "$TEMPLATE_FILE" ]; then
  echo "ERROR: template not found: $TEMPLATE_FILE" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
# The container entrypoint renders this file as root before dropping to the scanner
# user, and the grey-box wrapper renders it again as scanner: remove the old copy
# first (the directory is world-writable) so the second render can replace it.
rm -f "$OUTPUT_FILE"
cp "$TEMPLATE_FILE" "$OUTPUT_FILE"

# Replace ${VAR} references with environment values.
for var in CODEX_BASE_URL CODEX_WIRE_API CODEX_REASONING_EFFORT \
           CODEX_MEDIUM_MODEL; do
  value="${!var}"
  value_escaped=$(printf '%s' "$value" | sed 's/[\/&]/\\&/g')
  sed -i "s|\${$var}|$value_escaped|g" "$OUTPUT_FILE" 2>/dev/null || \
  sed -i '' "s|\${$var}|$value_escaped|g" "$OUTPUT_FILE"
done

# Always readable by the agent user, whoever rendered it (the entrypoint renders it
# as root; a root-run `docker exec` would otherwise leave it root-only). It holds
# no secret: the API key is read from the environment (env_key in the template).
chmod 0644 "$OUTPUT_FILE" 2>/dev/null || true

echo "Codex config generated: $OUTPUT_FILE"
