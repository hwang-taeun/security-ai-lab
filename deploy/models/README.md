# models/ — Colab 에서 내보낸 모델 묶음을 여기에 풉니다

각 노트북의 마지막 "장비로 옮길 모델 내보내기" 셀이 `*_model_bundle.zip` 을 내려받습니다.

```bash
cd deploy
for f in ~/Downloads/{waf,ips,ddos}_model_bundle.zip; do python3 -c "import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall('models')" "$f"; done
ls models/*/meta.json        # models/waf, models/ips, models/ddos
```

| 폴더 | 파일 | 서비스 |
|---|---|---|
| `waf/` | `char_cnn.onnx`, `tfidf_lr.joblib`, `meta.json` | secgw-waf-ai |
| `ips/` | `gbdt.joblib`, `meta.json` | secgw-ips-ai |
| `ddos/` | `gbdt_nohttp.joblib`, `meta.json` | secgw-ddos-ai |

모델 파일도 학습 결과물로 저장소에 함께 올립니다 (합쳐 수십 MB 이내). 서비스는 시작할 때 `meta.json` 의 해시·버전을 확인하고, 다르면 뜨지 않습니다.
