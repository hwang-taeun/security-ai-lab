"""secgw AI 서비스 공통 — 모델 묶음 검증, 차단(nftables), eve.json 따라 읽기, 판정 로그"""
import hashlib, ipaddress, json, os, subprocess, sys, time
from importlib import metadata
from pathlib import Path


def log(event, **kw):
    """journald 로 가는 한 줄 JSON 로그"""
    print(json.dumps({'ts': time.strftime('%Y-%m-%dT%H:%M:%S'), 'event': event, **kw}, ensure_ascii=False), flush=True)


# ── 1. 모델 묶음 검증 ───────────────────────────────────────────────────
def load_bundle(bundle_dir, service, strict_versions=('scikit-learn',)):
    """meta.json 을 읽고 (1) 서비스 이름 (2) 파일 해시 (3) 학습 때 라이브러리 버전을 확인한다.

    Colab에서 학습한 모델을 장비로 옮길 때 가장 흔한 사고는
      - 다른 서비스의 모델을 넣거나, 전송 중 파일이 깨지거나,
      - scikit-learn 버전이 달라 모델이 조용히 다르게 동작하는 것이다.
    그래서 시작할 때 셋 다 확인하고, 틀리면 서비스를 띄우지 않는다.
    """
    d = Path(bundle_dir)
    meta = json.loads((d / 'meta.json').read_text(encoding='utf-8'))
    if meta.get('service') != service:
        sys.exit(f'[{service}] 다른 서비스의 모델입니다: meta.service={meta.get("service")}')
    for f, want in meta['files'].items():
        got = hashlib.sha256((d / f).read_bytes()).hexdigest()
        if got != want:
            sys.exit(f'[{service}] 파일 해시 불일치: {f} (전송 중 손상 또는 다른 학습본)')
    trained = meta.get('versions', {})
    if os.environ.get('SECGW_SKIP_VERSION_CHECK') == '1':   # 시험용 (운영에서는 쓰지 않음)
        strict_versions = ()
    for pkg in strict_versions:
        if pkg in trained:
            try:
                here = metadata.version(pkg)
            except metadata.PackageNotFoundError:
                sys.exit(f'[{service}] {pkg} 가 설치되지 않음 (학습 버전 {trained[pkg]})')
            if here.split('.')[:2] != str(trained[pkg]).split('.')[:2]:
                sys.exit(f'[{service}] {pkg} 버전 불일치: 학습 {trained[pkg]} / 장비 {here} — install.sh 로 맞추세요')
    log('model_loaded', service=service, created=meta.get('created_utc'), dataset=meta.get('dataset'),
        thresholds=meta.get('thresholds'), files=list(meta['files']))
    return meta


def threshold(meta, env_key):
    v = os.environ.get(env_key, 'meta')
    return float(meta['thresholds']['block']) if v in ('', 'meta') else float(v)


# ── 2. 차단: nftables 의 ai_block 집합에 넣기 (시간이 지나면 자동 해제) ──────
class Blocker:
    def __init__(self, service, set_name='ai_block', dry_run=False):
        self.service, self.set_name = service, set_name
        self.mode = os.environ.get('AI_MODE', 'block')
        self.minutes = int(os.environ.get('AI_BLOCK_MINUTES', '10'))
        self.dry_run = dry_run or os.environ.get('SECGW_DRY_RUN') == '1'
        self.home = [ipaddress.ip_network(n.strip(), strict=False)
                     for n in os.environ.get('HOME_NET', '').strip('[]').split(',') if n.strip()]
        self.white = [ipaddress.ip_network(n.strip(), strict=False)
                      for n in os.environ.get('WHITELIST_IPS', '').split(',') if n.strip()]
        self.recent = {}          # 같은 IP를 연달아 넣지 않도록

    def skip_reason(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return 'not_ip'
        if a.version != 4:
            return 'ipv6'
        if any(a in n for n in self.white):
            return 'whitelist'
        if any(a in n for n in self.home):
            return 'home_net'      # 내부 주소는 차단하지 않고 기록만
        return None

    def block(self, ip, score, reason):
        why = self.skip_reason(ip)
        if why:
            log('detect_no_block', service=self.service, ip=ip, score=round(score, 4), reason=reason, skip=why)
            return False
        now = time.time()
        if now - self.recent.get(ip, 0) < 30:
            return False
        self.recent[ip] = now
        action = 'monitor' if self.mode == 'monitor' else ('dry_run' if self.dry_run else 'block')
        if action == 'block':
            cmd = ['nft', 'add', 'element', 'inet', 'secgw', self.set_name, f'{{ {ip} timeout {self.minutes}m }}']
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                log('block_error', service=self.service, ip=ip, error=r.stderr.strip())
                return False
        log('block' if action == 'block' else action, service=self.service, ip=ip, score=round(score, 4),
            reason=reason, minutes=self.minutes)
        return True


# ── 3. eve.json 따라 읽기 (tail -F 처럼 로테이션도 따라감) ───────────────
def follow(path, from_start=False, poll=0.2):
    f, ino = None, None
    while True:
        if f is None:
            try:
                f = open(path, 'rb')
                ino = os.fstat(f.fileno()).st_ino
                if not from_start:
                    f.seek(0, os.SEEK_END)
            except FileNotFoundError:
                time.sleep(1); continue
        line = f.readline()
        if line:
            if line.endswith(b'\n'):
                yield line
            else:                       # 아직 다 안 써진 줄
                f.seek(-len(line), os.SEEK_CUR); time.sleep(poll)
            continue
        try:
            if os.stat(path).st_ino != ino:   # logrotate 로 파일이 바뀜
                f.close(); f, from_start = None, True; continue
        except FileNotFoundError:
            pass
        yield None                       # 대기 신호 (모아 둔 것 처리할 기회)
        time.sleep(poll)


def replay(path):
    """시험용: 파일을 처음부터 끝까지 한 번 읽고 끝냄"""
    with open(path, 'rb') as f:
        for line in f:
            yield line
    yield None
