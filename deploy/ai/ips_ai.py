#!/usr/bin/env python3
"""ips-ai: Suricata eve.json 의 흐름 기록을 학습한 GBDT로 판정 → 공격이면 출발지 IP를 nftables ai_block 에 추가

  운영:  ips_ai.py --bundle /opt/secgw/models/ips --eve /var/log/secgw/eve.json
  시험:  ips_ai.py --bundle ... --replay sample_eve.json --dry-run
"""
import argparse, sys, time, warnings
from pathlib import Path
import joblib, numpy as np, orjson
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Blocker, follow, load_bundle, log, replay, threshold
from features import flow_record, ips_features

warnings.filterwarnings('ignore', message='X does not have valid feature names')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bundle', required=True)
    ap.add_argument('--eve')
    ap.add_argument('--replay', help='시험용 eve.json (처음부터 끝까지 읽고 끝냄)')
    ap.add_argument('--dry-run', action='store_true', help='nft 명령을 실행하지 않고 기록만')
    ap.add_argument('--batch', type=int, default=256)
    a = ap.parse_args()

    meta = load_bundle(a.bundle, 'ips-ai')
    model = joblib.load(Path(a.bundle) / 'gbdt.joblib')
    thr = threshold(meta, 'IPS_AI_THRESHOLD')
    blocker = Blocker('ips-ai', dry_run=a.dry_run)
    log('start', service='ips-ai', threshold=thr, mode=blocker.mode, source=a.replay or a.eve)

    src = replay(a.replay) if a.replay else follow(a.eve)
    rows, X, n_seen, n_hit, t_last = [], [], 0, 0, time.time()

    def flush():
        nonlocal rows, X, n_hit
        if not X:
            return
        scores = model.predict_proba(np.asarray(X, dtype=np.float64))[:, 1]
        for r, s in zip(rows, scores):
            if s >= thr:
                n_hit += 1
                blocker.block(r['src_ip'], float(s), f"flow {r['proto']} {r['src_ip']}:{r['src_port']} -> {r['dest_ip']}:{r['dest_port']} app={r['app_proto']}")
        rows, X = [], []

    for line in src:
        if line is None:                       # 새 줄이 없을 때 모아 둔 것 처리
            flush()
            if a.replay:
                break
            if time.time() - t_last > 60:
                log('stats', service='ips-ai', flows=n_seen, detected=n_hit); t_last = time.time()
            continue
        e = orjson.loads(line)
        if e.get('event_type') != 'flow':
            continue
        r = flow_record(e)
        rows.append(r); X.append(ips_features(r, meta)); n_seen += 1
        if len(X) >= a.batch:
            flush()
    flush()
    log('done', service='ips-ai', flows=n_seen, detected=n_hit)


if __name__ == '__main__':
    main()
