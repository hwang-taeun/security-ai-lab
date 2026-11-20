#!/usr/bin/env python3
"""waf-ai 게이트: Coraza(CRS)를 통과한 요청을 문자 CNN(ONNX)으로 한 번 더 판정하고, 정상이면 백엔드로 전달

  클라이언트 → Caddy + Coraza(룰) → [이 게이트: AI] → 백엔드 웹 서버

  - 판정 입력은 노트북과 같은 텍스트:  "{method} {path?query} {body}" + " || " + URL 디코딩본
  - 기준값은 meta.json 의 값(검증 집합 오탐 0.1%)을 그대로 사용
  - 막을 때는 TF-IDF 모델로 "어떤 글자 조각 때문인지" 상위 5개를 로그에 남김 (설명 가능성)
"""
import argparse, os, sys, time, uuid
from pathlib import Path
import aiohttp
from aiohttp import web
import joblib, numpy as np, onnxruntime as ort
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import load_bundle, log, threshold
from features import waf_encode, waf_text

HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers',
       'transfer-encoding', 'upgrade', 'host', 'content-length'}
MAX_BODY = 1024 * 1024

BLOCK_PAGE = """<!doctype html><meta charset="utf-8"><title>요청이 차단되었습니다</title>
<body style="font-family:sans-serif;max-width:560px;margin:60px auto;color:#1f2933">
<h2>요청이 차단되었습니다</h2><p>보안 정책에 따라 이 요청은 처리되지 않았습니다.</p>
<p>정상적인 이용인데 차단되었다면 아래 번호를 관리자에게 알려 주세요.</p>
<p style="font-family:monospace;background:#f1f3f4;padding:8px">요청 번호: {rid}</p></body>"""


class Gate:
    def __init__(self, bundle, backend):
        self.meta = load_bundle(bundle, 'waf-ai', strict_versions=('scikit-learn',))
        self.max_len = int(self.meta['input']['max_len'])
        self.sess = ort.InferenceSession(str(Path(bundle) / 'char_cnn.onnx'), providers=['CPUExecutionProvider'])
        expl = Path(bundle) / 'tfidf_lr.joblib'
        self.explainer = joblib.load(expl) if expl.exists() else None
        self.ngram_names = self.explainer['vectorizer'].get_feature_names_out() if self.explainer else None
        self.thr = threshold(self.meta, 'WAF_AI_THRESHOLD')
        self.mode = os.environ.get('AI_MODE', 'block')
        self.backend = backend.rstrip('/')
        self.client = None

    def score(self, text):
        logit = self.sess.run(None, {'bytes': waf_encode([text], self.max_len)})[0][0]
        return float(1 / (1 + np.exp(-logit)))

    def explain(self, text, k=5):
        if not self.explainer:
            return []
        vec, clf = self.explainer['vectorizer'], self.explainer['classifier']
        x = vec.transform([text])
        contrib = x.multiply(clf.coef_[0]).tocsr()
        idx = contrib.indices[np.argsort(contrib.data)[::-1][:k]]
        return [str(self.ngram_names[i]) for i in idx]

    async def handle(self, req: web.Request):
        t0 = time.perf_counter()
        rid = uuid.uuid4().hex[:12]
        body = await req.content.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            return web.Response(status=413, text='request body too large')
        text = waf_text(req.method, req.path_qs, body.decode('latin-1'))
        s = self.score(text)
        client = req.headers.get('X-Secgw-Client') or req.remote
        if s >= self.thr:
            log('waf_ai_detect', rid=rid, client=client, score=round(s, 4), threshold=round(self.thr, 4),
                action='block' if self.mode == 'block' else 'monitor',
                request=f'{req.method} {req.path_qs}'[:300], top_ngrams=self.explain(text))
            if self.mode == 'block':
                return web.Response(status=403, text=BLOCK_PAGE.format(rid=rid), content_type='text/html',
                                    headers={'X-Secgw-Block': 'waf-ai', 'X-Secgw-Request-Id': rid})
        # 백엔드로 전달
        headers = {k: v for k, v in req.headers.items() if k.lower() not in HOP}
        headers['X-Forwarded-For'] = client
        headers['X-Secgw-Score'] = f'{s:.4f}'
        try:
            async with self.client.request(req.method, self.backend + req.path_qs, headers=headers, data=body,
                                           allow_redirects=False) as r:
                payload = await r.read()
                out = web.Response(status=r.status, body=payload,
                                   headers={k: v for k, v in r.headers.items() if k.lower() not in HOP})
        except aiohttp.ClientError as e:
            log('backend_error', rid=rid, error=str(e))
            return web.Response(status=502, text='backend unavailable')
        log('waf_ai_pass', rid=rid, client=client, score=round(s, 4), status=out.status,
            ms=round((time.perf_counter() - t0) * 1000, 1)) if os.environ.get('WAF_AI_LOG_PASS') == '1' else None
        return out

    async def health(self, req):
        return web.json_response({'service': 'waf-ai', 'threshold': self.thr, 'mode': self.mode,
                                  'model_created': self.meta['created_utc'], 'backend': self.backend})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bundle', required=True)
    ap.add_argument('--listen', default=os.environ.get('WAF_AI_LISTEN', '127.0.0.1:8081'))
    ap.add_argument('--backend', default=os.environ.get('BACKEND_URL', 'http://127.0.0.1:8080'))
    a = ap.parse_args()
    gate = Gate(a.bundle, a.backend)
    host, port = a.listen.rsplit(':', 1)

    async def on_start(app):
        gate.client = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30), auto_decompress=False)
    async def on_stop(app):
        await gate.client.close()

    app = web.Application(client_max_size=MAX_BODY + 1)
    app.on_startup.append(on_start); app.on_cleanup.append(on_stop)
    app.router.add_get('/__secgw/health', gate.health)
    app.router.add_route('*', '/{tail:.*}', gate.handle)
    log('start', service='waf-ai', listen=a.listen, backend=a.backend, threshold=gate.thr, mode=gate.mode)
    web.run_app(app, host=host, port=int(port), access_log=None, print=None)


if __name__ == '__main__':
    main()
