#!/usr/bin/env python3
"""ddos-ai: 흐름 기록을 출발지 IP × WIN초 구간으로 묶어 GBDT(A', HTTP 비율 제외)로 판정 → ai_block 에 추가

즉시 대응은 nftables 의 R1(초당 새 연결)·R2(동시 연결) 룰이 하고,
이 서비스는 그 기준 아래로 들어오는 공격(예: 느린 공격)을 구간 단위로 한 번 더 판정한다.
"""
import argparse, os, sys, time, warnings
from pathlib import Path
import joblib, numpy as np, orjson
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Blocker, follow, load_bundle, log, replay, threshold
from features import WindowBuilder, ddos_vector, flow_record

warnings.filterwarnings('ignore', message='X does not have valid feature names')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bundle', required=True)
    ap.add_argument('--eve')
    ap.add_argument('--replay')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--dump-windows', help='시험용: 판정한 구간 특성을 JSON 줄로 저장')
    a = ap.parse_args()

    meta = load_bundle(a.bundle, 'ddos-ai')
    model = joblib.load(Path(a.bundle) / 'gbdt_nohttp.joblib')
    thr = threshold(meta, 'DDOS_AI_THRESHOLD')
    delay = float(os.environ.get('DDOS_AI_DELAY_SEC', '120'))
    wb = WindowBuilder(int(meta['window_sec']), delay)
    blocker = Blocker('ddos-ai', dry_run=a.dry_run)
    dump = open(a.dump_windows, 'w') if a.dump_windows else None
    log('start', service='ddos-ai', threshold=thr, window_sec=meta['window_sec'], delay_sec=delay, mode=blocker.mode)

    n_win = n_hit = 0
    def judge(final=False):
        nonlocal n_win, n_hit
        ready = wb.ready(now=None if (a.replay and not final) else (float('inf') if final else time.time()))
        if not ready:
            return
        X = np.asarray([ddos_vector(f, meta) for _, _, f in ready], dtype=np.float64)
        scores = model.predict_proba(X)[:, 1]
        for (src, w, f), s in zip(ready, scores):
            n_win += 1
            if dump:
                dump.write(orjson.dumps({'src_ip': src, 'w': w, **f, 'score': float(s)}).decode() + '\n')
            if s >= thr:
                n_hit += 1
                blocker.block(src, float(s), f"window {meta['window_sec']}s new_conn={f['new_conn']} "
                                             f"srv_concurrent={f['srv_concurrent']} dur_mean={f['dur_mean']:.1f}s")

    src = replay(a.replay) if a.replay else follow(a.eve)
    t_last = 0.0
    for line in src:
        if line is None:
            judge()
            if a.replay:
                break
            continue
        e = orjson.loads(line)
        if e.get('event_type') == 'flow':
            wb.add(flow_record(e))
        if time.time() - t_last > 1:
            judge(); t_last = time.time()
    judge(final=True)
    log('done', service='ddos-ai', windows=n_win, detected=n_hit)


if __name__ == '__main__':
    main()
