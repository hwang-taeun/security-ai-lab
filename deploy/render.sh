#!/usr/bin/env bash
# deploy.conf → /etc/secgw/*, /etc/systemd/system/secgw-* 생성
set -euo pipefail
cd "$(dirname "$0")"
python3 render.py "$@"
if [[ "${1:-}" != "--out" ]]; then
  nft -c -f /etc/secgw/secgw.nft && echo "nftables 문법 확인: OK"
  systemctl daemon-reload
  echo "적용: sudo ./secgw.sh reload"
fi
