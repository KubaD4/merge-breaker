#!/bin/sh
# Runs each AI-written attack script with a hard timeout. Output is parsed by the control plane.
cd /work/repo || exit 1
for f in /attacks/*.mjs; do
  [ -e "$f" ] || continue
  n=$(basename "$f" .mjs)
  echo "MB_BEGIN $n"
  timeout -s KILL 8 node "$f" > /tmp/out.txt 2>&1
  rc=$?
  head -c 6000 /tmp/out.txt
  echo ""
  echo "MB_END $n exit=$rc"
done
