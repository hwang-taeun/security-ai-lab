#!/usr/bin/env bash
# secgw 운영 명령 모음
#   ./secgw.sh reload        deploy.conf 반영 (render → 재시작)
#   ./secgw.sh status        서비스 상태 + 자원 제한/사용량
#   ./secgw.sh check         설정·모델 검사 (서비스를 건드리지 않음)
#   ./secgw.sh blocks        지금 막고 있는 IP
#   ./secgw.sh unblock IP    차단 해제
set -euo pipefail
cd "$(dirname "$0")"
set -a; source ./deploy.conf; set +a
UNITS=(secgw-nft secgw-ips secgw-waf-ai secgw-waf secgw-ips-ai secgw-ddos-ai)

reload() {
  ./render.sh
  systemctl daemon-reload
  for u in "${UNITS[@]}"; do systemctl enable --quiet "$u"; systemctl restart "$u"; done
  status
}

status() {
  printf '%-16s %-8s %8s %10s %10s %10s\n' SERVICE STATE CPUQUOTA MEM_NOW MEM_HIGH MEM_MAX
  for u in "${UNITS[@]}"; do
    eval "$(systemctl show "$u" -p ActiveState -p CPUQuotaPerSecUSec -p MemoryCurrent -p MemoryHigh -p MemoryMax \
            | sed 's/^\([A-Za-z]*\)=\(.*\)$/\1="\2"/')"
    h() { [[ "$1" =~ ^[0-9]+$ ]] && numfmt --to=iec "$1" || echo "${1:--}"; }
    q="${CPUQuotaPerSecUSec:-infinity}"; [[ "$q" == infinity ]] || q="$(awk -v s="${q%s}" 'BEGIN{printf "%d%%", s*100}')"
    printf '%-16s %-8s %8s %10s %10s %10s\n' "$u" "$ActiveState" "$q" "$(h "$MemoryCurrent")" "$(h "$MemoryHigh")" "$(h "$MemoryMax")"
  done
  echo; systemctl show secgw.slice -p CPUQuotaPerSecUSec -p MemoryMax -p MemoryCurrent | sed 's/^/secgw.slice  /'
}

check() {
  local ok=0
  python3 render.py --out /tmp/secgw-check >/dev/null && echo "[OK] deploy.conf 값 검사" || ok=1
  nft -c -f /tmp/secgw-check${SECGW_ETC}/secgw.nft && echo "[OK] nftables 문법" || ok=1
  suricata -T -c /etc/suricata/suricata.yaml --include /tmp/secgw-check${SECGW_ETC}/suricata-secgw.yaml \
           --set "vars.address-groups.HOME_NET=${HOME_NET}" >/dev/null 2>&1 && echo "[OK] Suricata 설정·룰" || { echo "[!!] Suricata 설정 검사 실패"; ok=1; }
  "${SECGW_HOME}/bin/caddy" validate --config /tmp/secgw-check${SECGW_ETC}/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
           && echo "[OK] Caddyfile (Coraza CRS PL${CRS_PARANOIA})" || { echo "[!!] Caddyfile 검사 실패"; ok=1; }
  for m in waf ips ddos; do
    "${SECGW_HOME}/venv/bin/python" ai/check_bundle.py "${SECGW_HOME}/models/$m" "$m-ai" || ok=1
  done
  ip -br link show "$WAN_IFACE" >/dev/null 2>&1 && echo "[OK] 인터페이스 $WAN_IFACE" || { echo "[!!] 인터페이스 $WAN_IFACE 없음"; ok=1; }
  ip -br addr | grep -qw "$SERVICE_IP" && echo "[OK] 서비스 IP $SERVICE_IP" || { echo "[!!] 이 장비에 $SERVICE_IP 가 없음"; ok=1; }
  return $ok
}

blocks() {
  for s in ddos_block ai_block; do echo "== $s"; nft list set inet secgw "$s" | sed -n '/elements/,/}/p'; done
  echo; nft list chain inet secgw input | grep -E 'counter|comment' | sed 's/^\s*/  /'
}

unblock() { for s in ddos_block ai_block; do nft delete element inet secgw "$s" "{ $1 }" 2>/dev/null && echo "$s 에서 $1 해제"; done; true; }

case "${1:-status}" in
  reload) reload ;; status) status ;; check) check ;; blocks) blocks ;; unblock) unblock "${2:?IP}" ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac
