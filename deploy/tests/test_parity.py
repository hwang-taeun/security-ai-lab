#!/usr/bin/env python3
"""학습-서비스 특성 일치 시험 (모델 없이 실행 가능)

노트북 코드로 계산해 둔 기대값(fixtures/*_expected.json)과
장비 서비스 코드(ai/features.py)가 같은 eve.json 에서 같은 특성을 만드는지 비교한다.
특성이 하나라도 다르면 모델은 에러 없이 틀린 판정을 하므로, 서비스 코드를 고칠 때마다 돌린다.

  python3 tests/test_parity.py
"""
import gzip, json, sys
from pathlib import Path
import numpy as np, orjson
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'ai'))
from features import WindowBuilder, flow_record, ips_features

def eve(name):
    with gzip.open(HERE / 'fixtures' / name, 'rb') as f:
        for line in f:
            e = orjson.loads(line)
            if e.get('event_type') == 'flow':
                yield e

def report(title, feats, a, b):
    d = np.abs(np.asarray(a) - np.asarray(b)).max(axis=0)
    bad = [f for f, x in zip(feats, d) if x > 1e-6]
    print(f'{title}: {len(a)}건 × 특성 {len(feats)}개 — ' + ('모두 일치' if not bad else f'불일치 {bad}'))
    return not bad

ok = True
exp = json.load(open(HERE / 'fixtures' / 'ips_expected.json'))
meta = {'features': exp['features'], 'categories': exp['categories']}
got, want = [], []
for e in eve('ips_eve_sample.json.gz'):
    k = str(e['flow_id'])
    if k in exp['expected']:
        got.append(ips_features(flow_record(e), meta)); want.append(exp['expected'][k])
ok &= report('IPS  흐름 특성', exp['features'], got, want)

exp = json.load(open(HERE / 'fixtures' / 'ddos_expected.json'))
wb = WindowBuilder(exp['window_sec'], delay=0)
for e in eve('ddos_eve_sample.json.gz'):
    wb.add(flow_record(e))
svc = {f'{s}|{w}': [float(f[c]) for c in exp['features']] for s, w, f in wb.ready(now=float('inf'))}
keys = [k for k in exp['expected'] if k in svc]
ok &= len(keys) == len(exp['expected'])
ok &= report('DDoS 구간 특성', exp['features'], [svc[k] for k in keys], [exp['expected'][k] for k in keys])
print('결과:', '통과' if ok else '실패'); sys.exit(0 if ok else 1)
