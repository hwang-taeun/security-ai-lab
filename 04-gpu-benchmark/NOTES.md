# 코드 설명 · 측정 시 주의사항

## 1. GPU 시간 측정은 동기화가 필수

CUDA 연산은 **비동기**로 실행된다. 파이썬은 커널을 GPU에 던지고 바로 다음 줄로 넘어가기 때문에,
그냥 `time.perf_counter()`로 재면 실제 연산 시간보다 훨씬 짧게 나온다.

```python
torch.cuda.synchronize(); t = time.perf_counter()
fn()
torch.cuda.synchronize(); elapsed = time.perf_counter() - t
```

`sync()` 함수는 GPU가 없을 때 아무것도 하지 않으므로 CPU/GPU 측정 코드를 하나로 쓸 수 있다.

## 2. 워밍업 후 반복 측정

- 첫 호출에는 CUDA 컨텍스트 생성, 커널 로딩, 메모리 할당이 포함되어 느리다 → `warmup` 회 버리고 측정
- 처리량은 `repeat` 회의 **중앙값**을 쓴다 (평균은 튀는 값에 약함)
- 지연 시간은 200회 측정해 **p50 / p99** — 운영에서는 평균보다 꼬리 지연(p99)이 SLA를 결정한다

## 3. XGBoost

| 항목 | 내용 |
|---|---|
| `device="cuda"` | XGBoost 2.0 이후 GPU 지정 방식 (`gpu_hist`는 구버전 표기) |
| `inplace_predict()` | DMatrix를 만들지 않고 바로 예측 → 추론 측정에 오버헤드가 적음 |
| `cupy` 입력 | GPU 모델에 numpy를 넘기면 매번 CPU→GPU 복사가 일어나고 `Falling back to prediction using DMatrix due to mismatched devices` 경고가 뜬다. Colab에는 cupy가 기본 설치되어 있어 GPU 배열로 넘긴다 |
| `to_dev(X, dev)` | 장치가 `cuda`이고 cupy가 있으면 `cp.asarray(X)`, 아니면 그대로 반환 |
| `xgb_predict()` | F1 계산용 예측. `inplace_predict` 결과(확률)를 numpy로 되돌린 뒤 이진은 `> 0.5`, 다중 분류는 `argmax`로 클래스화. 학습·추론 측정 모두 같은 경로를 써서 경고 없이 GPU에서 처리 |

## 4. PyTorch MLP

- 학습 데이터를 **미리 전부 GPU에 올리고** 인덱스로 배치를 자른다 → DataLoader 전송 병목 제거, 순수 연산 비교
- `torch.autocast(..., dtype=torch.float16)` + `GradScaler` = AMP(혼합 정밀도). T4의 Tensor 코어를 쓰는 경로
- 추론은 `torch.inference_mode()` — 그래디언트 추적을 끄므로 `no_grad()`보다 약간 빠름
- `model.eval()`로 Dropout 비활성화

## 5. 용량 산정 공식

```
CPU 1대 처리량 = (측정 처리량 ÷ Colab 코어 수) × SERVER_CORES × CPU_SCALING_EFF   ← 추정
GPU 1대 처리량 = 측정 처리량                                                     ← 실측

필요 대수      = ceil( 목표 건수/초 ÷ (1대 처리량 × HEADROOM) ),  최소 1
예상 사용률(%) = 목표 건수/초 ÷ (1대 처리량 × 필요 대수) × 100
```

- `CPU_SCALING_EFF`: 코어를 늘려도 처리량이 정확히 비례하지 않는 것(메모리 대역폭, 스레드 경합)을 반영하는 보정 계수. 0.6~0.8 권장
- `HEADROOM`(0.7): 평균 사용률을 70% 이하로 유지하도록 여유를 둔다. 트래픽 급증·장애 시 페일오버 대비
- 필요 대수가 1이고 사용률이 매우 낮다면, 그 트래픽 규모에서는 **해당 장치가 과잉**이라는 뜻이다
- `BATCH_FOR_PLAN`은 실서비스에서 요청을 모아 한 번에 추론하는 크기. 배치가 클수록 처리량은 오르지만 대기 지연이 생긴다
- WAF 인라인 차단처럼 요청마다 즉시 판정해야 하면 batch=1 지연(p99)으로 판단하고,
  IPS·DDoS처럼 플로우 로그를 모아 분석하면 큰 배치 처리량으로 판단한다

## 6. 예상되는 경향 (결과 해석 가이드)

- **batch=1**: GPU 커널 실행·전송 오버헤드 때문에 CPU가 비슷하거나 더 빠를 수 있다
- **큰 배치**: GPU 처리량 이점이 커진다. 특히 MLP + FP16
- **XGBoost 학습**: 데이터가 클수록(수십만 행 이상) GPU 이점이 뚜렷하다
- 실측이 이 경향과 다르면 `env.json`의 GPU 할당 여부(`gpu: null`)부터 확인

## 7. 합성 데이터 표시

- `load_stage()`가 반환하는 `src`(`real` / `synthetic`)를 `SRC`에 모은다
- 합성 데이터 단계가 있으면 2번 셀에서 경고를 출력하고, `SUMMARY.md` "전제" 항목에 단계별 데이터 출처를 기록한다
- `make_classification`은 선형 결합 위주의 데이터라 MLP가 유리하게 나온다. 합성 데이터에서의 MLP > XGBoost F1 차이는 실제 보안 데이터에서는 재현되지 않을 수 있다
