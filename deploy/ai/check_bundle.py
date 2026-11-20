#!/usr/bin/env python3
"""모델 묶음 검사: python check_bundle.py /opt/secgw/models/waf waf-ai"""
import sys, contextlib, io
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import load_bundle
d, svc = sys.argv[1], sys.argv[2]
try:
    with contextlib.redirect_stdout(io.StringIO()):
        meta = load_bundle(d, svc)
except SystemExit as e:
    print(f'[!!] {svc} 모델: {e}'); sys.exit(1)
# IPS·DDoS 특성은 Suricata 흐름 기록(eve.json)에서 나오므로, Suricata 버전이 다르면 필드 값이 달라질 수 있음
want = str(meta.get('versions', {}).get('suricata', '')).split()[0] if meta.get('versions', {}).get('suricata') else ''
if want and svc in ('ips-ai', 'ddos-ai'):
    import shutil, subprocess
    if shutil.which('suricata'):
        have = subprocess.run(['suricata', '-V'], capture_output=True, text=True).stdout.split('version')[-1].split()[0]
        if have.split('.')[:2] != want.split('.')[:2]:
            print(f'[!!] {svc}: Suricata 버전 불일치 — 학습 {want} / 장비 {have} (흐름 기록 필드가 달라 판정이 틀어질 수 있음)'); sys.exit(1)
exp = next((v for k, v in meta.get('expected_test', {}).items() if '0.1%' in k), None)
perf = f", 시험 집합 탐지 {exp['detection_rate']:.1%} · 오탐 {exp['false_positive_rate']:.3%}" if exp else ''
print(f"[OK] {svc} 모델 {meta['created_utc'][:10]} 학습본, 파일 해시 {len(meta['files'])}개 일치, 기준값 {meta['thresholds']['block']:.4g}{perf}")
