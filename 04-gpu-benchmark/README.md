# 04. CPU vs GPU 성능 비교

1~3단계(WAF · IPS · DDoS) 탐지 모델을 **같은 데이터, 같은 하이퍼파라미터**로 CPU와 GPU에서 학습·추론해
학습 시간, 추론 처리량, 단건 지연 시간을 비교하고 목표 트래픽 기준 **필요 자원(용량 산정)** 을 계산한다.

## 파일 구성

```
04-gpu-benchmark/
├── 04_cpu_vs_gpu_benchmark.ipynb   # Colab 노트북 (실행 본체)
├── README.md                       # 구조·실행 방법 (이 문서)
├── NOTES.md                        # 코드 설명·측정 시 주의사항
└── results/                        # 노트북 실행 후 다운로드한 결과를 압축 해제
    ├── env.json                    # CPU/GPU/드라이버/CUDA/라이브러리 버전
    ├── benchmark_raw.csv           # 측정값 원본 (stage, model, device, metric, value)
    ├── benchmark_summary.csv       # 단계·모델·장치별 요약표
    ├── speedup.csv                 # CPU 대비 GPU 배율 (GPU 런타임일 때만)
    ├── capacity_plan.csv           # 목표 트래픽 기준 필요 대수 · 1대 기준 예상 사용률
    ├── throughput_by_batch.png     # 배치 크기별 처리량 그래프
    ├── train_time.png              # 학습 시간 비교 그래프
    └── SUMMARY.md                  # 결론 자동 요약
```

## 비교 대상

| 모델 | CPU | GPU |
|---|---|---|
| XGBoost | `device="cpu"`, `tree_method="hist"` | `device="cuda"` |
| MLP (PyTorch) | CPU FP32 | CUDA FP32, CUDA FP16(AMP) |

측정 지표: 학습 시간(s), macro F1, 배치 크기(1 / 64 / 1024 / 16384)별 처리량(rows/s), batch=1 지연 p50·p99(ms)

## 실행 방법

1. Colab에서 노트북 열기 → `런타임 > 런타임 유형 변경 > T4 GPU`
2. (선택) 1~3단계 특징 CSV를 `/content/data/`에 업로드
   - 파일명: `waf_features.csv`, `ips_features.csv`, `ddos_features.csv`
   - 숫자형 특징 컬럼 + `label` 컬럼
   - 없으면 같은 규모의 합성 데이터로 대체
3. `런타임 > 모두 실행` → 마지막 셀에서 `gpu_benchmark_results.zip` 자동 다운로드
4. 9번 셀의 `TARGET_RPS`, `SERVER_CORES`, `COST_*_HR` 값을 운영 조건에 맞게 바꿔 다시 실행
5. 동작만 빠르게 확인하려면 2번 셀에서 `QUICK = True`

## 데이터 출처 — 합성 vs 실제

| 구분 | 조건 | 결과 해석 |
|---|---|---|
| synthetic | `/content/data/`에 CSV 없음 | **속도 비교 전용.** F1은 CPU/GPU 결과가 같은지 확인하는 용도이며 탐지 성능이 아님 |
| real | 1~3단계 특징 CSV 업로드 | 속도 + 실제 탐지 성능(F1) 모두 비교 가능 |

어떤 데이터로 돌렸는지는 노트북 2번 셀 출력과 `SUMMARY.md`의 "전제" 항목에 자동 기록된다.

### 1~3단계 노트북에서 특징 CSV 내보내기

각 단계 노트북에서 모델 학습 직전의 특징 행렬 `X`(숫자형)와 라벨 `y`가 있는 위치에 아래 셀을 추가해 실행한다.

```python
import pandas as pd
from google.colab import files

STAGE_FILE = "waf_features.csv"    # IPS: ips_features.csv / DDoS: ddos_features.csv
X_dense = X.toarray() if hasattr(X, "toarray") else X    # TF-IDF 등 희소행렬이면 밀집 변환
df = pd.DataFrame(X_dense)
df.columns = [f"f{i}" for i in range(df.shape[1])]
df["label"] = list(y)
df.to_csv(STAGE_FILE, index=False)
files.download(STAGE_FILE)
```

> TF-IDF처럼 특징 수가 수천 개 이상이면 CSV가 커진다. 그때는 `SelectKBest` 등으로 상위 수백 개만 남기거나 샘플 수를 줄여 내보낸다.

## 해석 시 전제

- **CPU 수치는 추정치다.** Colab CPU는 vCPU 2개라서 CPU에 불리한 비교다. 서버 환산은
  `코어당 처리량 × SERVER_CORES × CPU_SCALING_EFF(기본 0.7)`로 계산한다.
  완전 선형 확장(1.0)은 낙관치이므로 보정 계수를 둔다. 실제 서버에서 측정하면 이 값을 실측으로 대체할 수 있다
- **GPU 수치는 실측이다** (Tesla T4 1장)
- 측정 범위는 **모델 연산만**이다. 실서비스의 로그 파싱·특징 추출(TF-IDF 등) 시간은 포함하지 않는다
- 결과는 하드웨어·라이브러리 버전에 따라 달라지므로 `env.json`과 함께 제시한다
