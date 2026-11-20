"""학습 노트북과 **똑같이** 특성을 만드는 코드.

장비에서 특성을 조금이라도 다르게 계산하면(단위, 순서, 문자열 번호) 모델은 에러 없이 틀린 판정을 한다.
그래서 노트북의 계산을 한 줄씩 옮기고, tests/test_parity.py 로 노트북 결과와 같은지 확인한다.

  - IPS : ids_lab_phase2.ipynb  8번 셀 (흐름 1건 → 특성 18개)
  - DDoS: ddos_lab_phase3.ipynb 6번 셀 (출발지 IP × WIN초 구간 → 특성)
  - WAF : waf_lab_phase1.ipynb  7·8번 셀 (요청 → 텍스트 → 바이트 번호)
"""
from datetime import datetime
from urllib.parse import unquote_plus
import numpy as np

PROTO_NUM = {'TCP': 6, 'UDP': 17, 'ICMP': 1}


def _flags(h):
    try:
        return int(h, 16)
    except (TypeError, ValueError):
        return 0


def _dt(s):
    # Suricata: 2017-07-07T15:56:01.123456+0000
    return datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%f%z') if s else None


def flow_record(e):
    """eve.json flow 이벤트 → 노트북 5번 셀과 같은 필드"""
    fl, tcp = e.get('flow', {}), e.get('tcp', {})
    start, end = _dt(fl.get('start')), _dt(fl.get('end'))
    return {
        'src_ip': e.get('src_ip'), 'src_port': e.get('src_port', 0) or 0, 'dest_ip': e.get('dest_ip'),
        'dest_port': e.get('dest_port', 0) or 0, 'proto': e.get('proto'), 'app_proto': e.get('app_proto', 'none'),
        'pkts_ts': fl.get('pkts_toserver', 0), 'pkts_tc': fl.get('pkts_toclient', 0),
        'bytes_ts': fl.get('bytes_toserver', 0), 'bytes_tc': fl.get('bytes_toclient', 0),
        't0': start.timestamp() if start else None, 't1': end.timestamp() if end else None,
        # 지속 시간은 시각 차이를 마이크로초 단위로 정확히 (float 시각끼리 빼면 오차가 생겨 pps 가 달라짐)
        'duration': (end - start).total_seconds() if (start and end) else 0.0,
        'state': fl.get('state', ''), 'reason': fl.get('reason', ''),
        'flags_ts': _flags(tcp.get('tcp_flags_ts')), 'flags_tc': _flags(tcp.get('tcp_flags_tc')),
        'tcp_state': tcp.get('state', ''),
    }


# ── IPS : 흐름 1건 → 특성 ─────────────────────────────────────────────
def ips_features(r, meta):
    cats = meta['categories']
    dur = max(r['duration'], 0.0)
    ps, pc = r['pkts_ts'], r['pkts_tc']
    v = {
        'proto': PROTO_NUM.get(r['proto'], 0), 'dest_port': r['dest_port'], 'src_port_eph': int(r['src_port'] >= 1024),
        'pkts_ts': ps, 'pkts_tc': pc, 'bytes_ts': r['bytes_ts'], 'bytes_tc': r['bytes_tc'], 'duration': dur,
        'bpp_ts': r['bytes_ts'] / max(ps, 1), 'bpp_tc': r['bytes_tc'] / max(pc, 1), 'pkt_ratio': pc / max(ps, 1),
        'flags_ts': r['flags_ts'], 'flags_tc': r['flags_tc'],
    }
    for c in ('app_proto', 'state', 'reason', 'tcp_state'):
        val = '' if r[c] is None else str(r[c])
        v[c] = cats[c].index(val) if val in cats[c] else -1       # 학습 때 없던 값 = -1 (pandas 와 같음)
    v['pps'] = (ps + pc) / max(dur, 1e-3)
    return [float(v[f]) for f in meta['features']]


# ── DDoS : 출발지 IP × WIN초 구간 → 특성 ──────────────────────────────
class WindowBuilder:
    """흐름 기록을 받아 두었다가, 구간 끝 + delay 가 지나면 그 구간의 특성을 만든다.

    흐름 기록은 연결이 끝나야 나오므로 delay 만큼 기다린다. 그래도 그 시점까지 끝나지 않은
    아주 긴 연결은 동시 연결 수에서 빠진다 (즉시 대응은 nftables R2 룰이 맡음).
    """
    def __init__(self, win, delay):
        self.win, self.delay = win, delay
        self.flows = {}          # src → list of flow dicts
        self.pending = set()     # (src, w) 아직 판정 안 한 구간
        self.clock = 0.0
        self.done_upto = -1      # 이 번호까지의 구간은 이미 판정함 (늦게 온 흐름은 동시 연결 계산에만 사용)

    def add(self, r):
        if r['t0'] is None or r['t1'] is None:
            return
        r = dict(r, w=int(r['t0'] // self.win), dur=max(r['t1'] - r['t0'], 0.0))
        self.flows.setdefault(r['src_ip'], []).append(r)
        if r['w'] > self.done_upto:
            self.pending.add((r['src_ip'], r['w']))
        self.clock = max(self.clock, r['t1'])

    def ready(self, now=None):
        clock = max(self.clock, now or 0)
        done = sorted(k for k in self.pending if (k[1] + 1) * self.win + self.delay <= clock)
        out = []
        for src, w in done:
            self.pending.discard((src, w))
            self.done_upto = max(self.done_upto, w)
            out.append((src, w, self._window(src, w)))
        self._purge(clock)
        return out

    def _window(self, src, w):
        fl = self.flows[src]
        cur = [f for f in fl if f['w'] == w]
        tend = (w + 1) * self.win
        conc = sum(1 for f in fl if f['t0'] < tend and f['t1'] >= tend)
        by_dst = {}
        for f in cur:
            by_dst.setdefault(f['dest_ip'], 0)
            by_dst[f['dest_ip']] += 1
        srv_conc = max(sum(1 for f in fl if f['dest_ip'] == d and f['t0'] < tend and f['t1'] >= tend) for d in by_dst)
        n = len(cur)
        mean = lambda k: sum(f[k] for f in cur) / n
        return {
            'new_conn': n, 'concurrent': conc, 'srv_new_conn': max(by_dst.values()), 'srv_concurrent': srv_conc,
            'dst_ips': len(by_dst), 'dst_ports': len({f['dest_port'] for f in cur}),
            'no_reply': sum(f['pkts_tc'] == 0 for f in cur) / n,
            'syn_only': sum((f['flags_ts'] & 0x02) > 0 and (f['flags_ts'] & 0x10) == 0 for f in cur) / n,
            'rst': sum(((f['flags_tc'] | f['flags_ts']) & 0x04) > 0 for f in cur) / n,
            'http': sum(f['app_proto'] == 'http' for f in cur) / n,
            'pkts_ts_mean': mean('pkts_ts'), 'pkts_tc_mean': mean('pkts_tc'),
            'bytes_ts_mean': mean('bytes_ts'), 'bytes_tc_mean': mean('bytes_tc'),
            'bytes_ts_sum': sum(f['bytes_ts'] for f in cur), 'dur_mean': mean('dur'), 'dur_max': max(f['dur'] for f in cur),
        }

    def _purge(self, clock):
        if clock == float('inf'):
            self.flows.clear(); return
        oldest = min((w for _, w in self.pending), default=int(clock // self.win)) * self.win
        for src in list(self.flows):
            keep = [f for f in self.flows[src] if f['t1'] >= oldest or f['w'] * self.win >= oldest]
            if keep:
                self.flows[src] = keep
            else:
                del self.flows[src]


def ddos_vector(win_feats, meta):
    return [float(win_feats[f]) for f in meta['features']]


# ── WAF : 요청 → 텍스트 → 바이트 번호 ────────────────────────────────
def waf_text(method, path_qs, body):
    s = f'{method} {path_qs} {body}'
    return s + ' || ' + unquote_plus(s, encoding='latin-1')


def waf_encode(texts, max_len=512):
    arr = np.zeros((len(texts), max_len), dtype=np.int64)
    for i, t in enumerate(texts):
        b = t.encode('latin-1', errors='replace')[:max_len]
        arr[i, :len(b)] = np.frombuffer(b, dtype=np.uint8).astype(np.int64) + 1
    return arr
