#!/usr/bin/env bash
# Re-render the README diagrams (still image = last frame) into docs/images/.
# Manim is NOT a project dependency; it runs in an isolated uv environment.
#   usage: docs/diagrams/render.sh [scene ...]     (default: all five)
set -euo pipefail
cd "$(dirname "$0")"
if command -v brew >/dev/null 2>&1; then   # build flags for pycairo / manimpango
  export PKG_CONFIG_PATH="$(brew --prefix cairo)/lib/pkgconfig:$(brew --prefix pango)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
fi
OUT="$(mktemp -d)"
declare -A FILES=(
  [ModesOverview]="modes_overview.py:modes-overview"
  [WhiteboxFlow]="whitebox_flow.py:whitebox-flow"
  [WhiteboxDetail]="whitebox_detail.py:whitebox-detail"
  [GreyboxDetail]="greybox_detail.py:greybox-detail"
  [GreyboxScheduler]="greybox_scheduler.py:greybox-scheduler"
)
SCENES=("$@"); [ ${#SCENES[@]} -gt 0 ] || SCENES=(ModesOverview WhiteboxFlow WhiteboxDetail GreyboxDetail GreyboxScheduler)
for scene in "${SCENES[@]}"; do
  src="${FILES[$scene]%%:*}"; name="${FILES[$scene]##*:}"
  uv run --no-project --with manim manim -s --media_dir "$OUT" "$src" "$scene" >/dev/null
  cp "$(find "$OUT" -name "${scene}*.png" | head -1)" "../images/${name}.png"
  echo "wrote docs/images/${name}.png"
done
