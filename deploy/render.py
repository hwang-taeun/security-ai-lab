#!/usr/bin/env python3
"""deploy.conf 의 값으로 templates/ 를 채워 설정 파일·systemd 유닛을 만든다.

  사용: sudo ./render.sh            (실제 위치에 설치)
        ./render.sh --out ./out     (미리보기: 지정 폴더에만 생성)
"""
import argparse, ipaddress, os, re, string, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

def load_conf(path):
    # bash 로 읽어서 export 된 값을 받는다 (주석·세미콜론·따옴표 처리를 bash 에 맡김)
    out = subprocess.run(['bash', '-c', f'set -a; source "{path}"; env -0'], capture_output=True, check=True).stdout
    env = dict(kv.split('=', 1) for kv in out.decode().split('\0') if '=' in kv)
    keys = re.findall(r'^\s*([A-Z_][A-Z0-9_]*)=', open(path, encoding='utf-8').read(), re.M)
    keys += re.findall(r';\s*([A-Z_][A-Z0-9_]*)=', open(path, encoding='utf-8').read())
    return {k: env[k] for k in keys}

def mem_bytes(s):
    m = re.fullmatch(r'(\d+)([KMG]?)', s.strip().upper())
    if not m:
        raise ValueError(f'메모리 값 형식 오류: {s} (예: 512M, 2G)')
    return int(m.group(1)) * {'': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3}[m.group(2)]

def check(c):
    """잘못된 값으로 서비스가 뜨지 않는 일을 막기 위한 사전 검사"""
    errs = []
    for k in ('SERVICE_IP',):
        try: ipaddress.ip_address(c[k])
        except ValueError: errs.append(f'{k}={c[k]} 은 IP 주소가 아님')
    for k in ('MGMT_NET',):
        for n in c[k].split(','):
            try: ipaddress.ip_network(n.strip(), strict=False)
            except ValueError: errs.append(f'{k} 의 {n} 은 네트워크 대역이 아님')
    for ip in filter(None, (x.strip() for x in c['WHITELIST_IPS'].split(','))):
        try: ipaddress.ip_network(ip, strict=False)
        except ValueError: errs.append(f'WHITELIST_IPS 의 {ip} 형식 오류')
    for k in ('HTTP_PORT', 'HTTPS_PORT', 'SSH_PORT', 'DDOS_RATE_PER_SEC', 'DDOS_BURST', 'DDOS_CONN_MAX', 'CRS_PARANOIA', 'IPS_QUEUE'):
        if not c[k].isdigit(): errs.append(f'{k}={c[k]} 은 숫자여야 함')
    if c['CRS_PARANOIA'] not in '1234': errs.append('CRS_PARANOIA 는 1–4')
    if c['TLS_MODE'] not in ('acme', 'internal', 'off'): errs.append('TLS_MODE 는 acme | internal | off')
    if c['AI_MODE'] not in ('block', 'monitor'): errs.append('AI_MODE 는 block | monitor')
    total_cpu = int(c['TOTAL_CPU'].rstrip('%'))
    parts_cpu = sum(int(c[k].rstrip('%')) for k in ('WAF_CPU', 'WAF_AI_CPU', 'IPS_CPU', 'IPS_AI_CPU', 'DDOS_AI_CPU'))
    if parts_cpu > total_cpu * 1.5:
        errs.append(f'서비스별 CPU 합계 {parts_cpu}% 가 전체 상한 {total_cpu}% 보다 너무 큼')
    parts_mem = sum(mem_bytes(c[k]) for k in ('WAF_MEM', 'WAF_AI_MEM', 'IPS_MEM', 'IPS_AI_MEM', 'DDOS_AI_MEM'))
    if parts_mem > mem_bytes(c['TOTAL_MEM']):
        errs.append(f'서비스별 메모리 합계 {parts_mem // 1024**2}M 가 전체 상한 {c["TOTAL_MEM"]} 보다 큼')
    if errs:
        sys.exit('deploy.conf 오류:\n  - ' + '\n  - '.join(errs))

def derived(c):
    d = dict(c)
    for k in ('WAF', 'WAF_AI', 'IPS', 'IPS_AI', 'DDOS_AI'):
        d[f'{k}_MEM_HIGH'] = f'{mem_bytes(c[k + "_MEM"]) * 9 // 10 // 1024**2}M'   # 90% 부터 회수 시작
    wl = [x.strip() for x in c['WHITELIST_IPS'].split(',') if x.strip()]
    d['WHITELIST_ELEMENTS'] = f'elements = {{ {", ".join(wl)} }}' if wl else ''
    if c['TLS_MODE'] == 'off':
        d['CADDY_SITE'] = f'http://{c["SERVER_NAME"]}:{c["HTTP_PORT"]}'
        d['CADDY_GLOBAL_TLS'] = 'auto_https off'
    else:
        d['CADDY_SITE'] = f'{c["SERVER_NAME"]}:{c["HTTPS_PORT"]}'
        d['CADDY_GLOBAL_TLS'] = f'http_port {c["HTTP_PORT"]}\n\thttps_port {c["HTTPS_PORT"]}'
    return d

TARGETS = {   # 템플릿 → 설치 위치
    'Caddyfile.tmpl': '{SECGW_ETC}/Caddyfile',
    'suricata-secgw.yaml.tmpl': '{SECGW_ETC}/suricata-secgw.yaml',
    'secgw.nft.tmpl': '{SECGW_ETC}/secgw.nft',
    'systemd/secgw.slice.tmpl': '/etc/systemd/system/secgw.slice',
    'systemd/secgw-nft.service.tmpl': '/etc/systemd/system/secgw-nft.service',
    'systemd/secgw-waf.service.tmpl': '/etc/systemd/system/secgw-waf.service',
    'systemd/secgw-waf-ai.service.tmpl': '/etc/systemd/system/secgw-waf-ai.service',
    'systemd/secgw-ips.service.tmpl': '/etc/systemd/system/secgw-ips.service',
    'systemd/secgw-ips-ai.service.tmpl': '/etc/systemd/system/secgw-ips-ai.service',
    'systemd/secgw-ddos-ai.service.tmpl': '/etc/systemd/system/secgw-ddos-ai.service',
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--conf', default=str(HERE / 'deploy.conf'))
    ap.add_argument('--out', help='미리보기 폴더 (지정하면 실제 위치 대신 여기에 생성)')
    a = ap.parse_args()
    c = load_conf(a.conf)
    check(c)
    d = derived(c)
    if c['TLS_MODE'] == 'internal':   # Caddy 사이트 블록 안에 tls internal 추가
        d['CADDY_SITE'] = f'{c["SERVER_NAME"]}:{c["HTTPS_PORT"]}'
    written = []
    for tmpl, dest in TARGETS.items():
        text = string.Template((HERE / 'templates' / tmpl).read_text(encoding='utf-8')).substitute(d)
        if tmpl == 'Caddyfile.tmpl' and c['TLS_MODE'] == 'internal':
            text = text.replace(f'\tbind {c["SERVICE_IP"]}\n', f'\tbind {c["SERVICE_IP"]}\n\ttls internal\n', 1)
        dest = dest.format(**c)
        path = Path(a.out) / dest.lstrip('/') if a.out else Path(dest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        written.append(str(path))
    # AI 서비스 공통 환경변수
    env = {k: c[k] for k in ('AI_MODE', 'AI_BLOCK_MINUTES', 'WAF_AI_THRESHOLD', 'IPS_AI_THRESHOLD', 'DDOS_AI_THRESHOLD',
                             'DDOS_AI_DELAY_SEC', 'WAF_AI_LISTEN', 'BACKEND_URL', 'HOME_NET', 'WHITELIST_IPS', 'SECGW_LOG')}
    envp = Path(a.out) / c['SECGW_ETC'].lstrip('/') / 'ai.env' if a.out else Path(c['SECGW_ETC']) / 'ai.env'
    envp.write_text(''.join(f'{k}="{v}"\n' for k, v in env.items()), encoding='utf-8')
    written.append(str(envp))
    print('생성한 파일:'); [print('  ', w) for w in written]

if __name__ == '__main__':
    main()
