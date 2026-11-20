#!/usr/bin/env bash
# secgw 설치 — Rocky Linux 9 (root 로 실행)
#
#   1) deploy.conf 를 이 장비에 맞게 고친다
#   2) models/ 에 Colab 에서 받은 waf·ips·ddos 묶음을 푼다 (models/README.md)
#   3) sudo ./install.sh
#
# 여러 번 실행해도 안전하게 만들었다 (이미 있는 것은 건너뜀).
set -euo pipefail
cd "$(dirname "$0")"
set -a; source ./deploy.conf; set +a
[[ $EUID -eq 0 ]] || { echo "root 로 실행하세요: sudo ./install.sh"; exit 1; }
GO_VERSION="1.25.4"          # Coraza v3 는 Go 1.25 이상 필요
step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }

step "1/8 모델 묶음 확인 (없으면 설치 중단)"
for m in waf ips ddos; do
  [[ -f "models/$m/meta.json" ]] || { echo "models/$m/meta.json 없음 — models/README.md 참고"; exit 1; }
done
PY_REQ=$(python3 - <<'PY'
import json
v = {}
for m in ('waf', 'ips', 'ddos'):
    v.update(json.load(open(f'models/{m}/meta.json'))['versions'])
# 학습한 Colab 과 같은 버전을 깐다 — 특히 scikit-learn 은 버전이 다르면 모델이 다르게 동작할 수 있음
print(f"scikit-learn=={v['scikit-learn']} numpy=={v['numpy']}")
PY
)
echo "학습 환경 버전: $PY_REQ"

step "2/8 패키지 (EPEL, Suricata 8 COPR, nftables, Python 3.11)"
dnf -y -q install epel-release dnf-plugins-core
dnf -y -q copr enable @oisf/suricata-8.0
dnf -y -q install suricata nftables conntrack-tools python3.11 python3.11-pip jq tar curl policycoreutils-python-utils

step "3/8 계정·폴더"
id caddy >/dev/null 2>&1 || useradd -r -s /sbin/nologin -d /var/lib/caddy caddy
id secgw >/dev/null 2>&1 || useradd -r -s /sbin/nologin secgw
usermod -aG secgw suricata; usermod -aG secgw caddy
install -d -m 0755 "$SECGW_HOME"/{bin,ai,models} "$SECGW_ETC"
install -d -m 2775 -g secgw "$SECGW_LOG"
install -d -o caddy -g caddy /var/lib/caddy

step "4/8 Caddy + Coraza 빌드 (Go $GO_VERSION, xcaddy)"
if [[ ! -x "$SECGW_HOME/bin/caddy" ]]; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
  export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH
  go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
  xcaddy build --with github.com/corazawaf/coraza-caddy/v2 --output "$SECGW_HOME/bin/caddy"
fi
"$SECGW_HOME/bin/caddy" list-modules | grep -q coraza && echo "caddy: coraza 모듈 포함"

step "5/8 Python 가상환경 (학습과 같은 버전)"
[[ -x "$SECGW_HOME/venv/bin/python" ]] || python3.11 -m venv "$SECGW_HOME/venv"
"$SECGW_HOME/venv/bin/pip" -q install --upgrade pip
"$SECGW_HOME/venv/bin/pip" -q install $PY_REQ joblib onnxruntime aiohttp orjson

step "6/8 프로그램·모델 복사"
cp -r ai/* "$SECGW_HOME/ai/"
for m in waf ips ddos; do rm -rf "$SECGW_HOME/models/$m"; cp -r "models/$m" "$SECGW_HOME/models/$m"; done
chown -R root:secgw "$SECGW_HOME"; chmod -R g+rX "$SECGW_HOME"
for m in waf ips ddos; do "$SECGW_HOME/venv/bin/python" "$SECGW_HOME/ai/check_bundle.py" "$SECGW_HOME/models/$m" "$m-ai"; done

step "7/8 ET Open 룰 (+ 소음 룰 끄기)"
install -m 0644 suricata/disable.conf /etc/suricata/disable.conf
suricata-update --disable-conf /etc/suricata/disable.conf --no-test

step "8/8 SELinux·firewalld·설정 생성·서비스 시작"
semanage fcontext -a -t bin_t "$SECGW_HOME/bin(/.*)?" 2>/dev/null || true
restorecon -R "$SECGW_HOME"
if systemctl is-active -q firewalld; then
  firewall-cmd -q --permanent --add-port="${HTTP_PORT}/tcp" --add-port="${HTTPS_PORT}/tcp" && firewall-cmd -q --reload
fi
./secgw.sh reload
echo; ./secgw.sh check || true
