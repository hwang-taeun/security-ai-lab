# 결과 요약 (Tesla T4 / CPU 2코어)

## 전제
- 데이터: WAF=synthetic, IPS=synthetic, DDoS=synthetic
  - synthetic 단계의 F1은 탐지 성능이 아니라 CPU/GPU 결과 일치 확인용 (속도 비교 전용)
- CPU 측정은 Colab vCPU 2개 기준. 서버 환산은 코어당 처리량 × 32코어 × 효율 70% (추정치)
- 측정 범위는 모델 연산만 (로그 파싱·특징 추출 시간 제외)

## 단계·모델별 최적 장치
- **DDoS / MLP**: 학습 최단 `cuda`, 단건 지연 최저 `cpu`, 대량 배치 처리량 최고 `cuda+fp16`
- **DDoS / XGBoost**: 학습 최단 `cuda`, 단건 지연 최저 `cpu`, 대량 배치 처리량 최고 `cuda`
- **IPS / MLP**: 학습 최단 `cuda`, 단건 지연 최저 `cpu`, 대량 배치 처리량 최고 `cuda+fp16`
- **IPS / XGBoost**: 학습 최단 `cuda`, 단건 지연 최저 `cpu`, 대량 배치 처리량 최고 `cuda`
- **WAF / MLP**: 학습 최단 `cuda`, 단건 지연 최저 `cpu`, 대량 배치 처리량 최고 `cuda+fp16`
- **WAF / XGBoost**: 학습 최단 `cuda`, 단건 지연 최저 `cpu`, 대량 배치 처리량 최고 `cuda`

> 단건(batch=1) 요청은 GPU 전송·커널 실행 오버헤드 때문에 CPU가 유리할 수 있고, 배치가 커질수록 GPU 이점이 커진다. 인라인 차단(WAF)은 지연, 로그·플로우 분석(IPS·DDoS)은 처리량 기준으로 판단한다.

## 용량 산정 (batch=1024, 최대 사용률 70%)
- DDoS / MLP / cpu: 32코어 서버 1대, 예상 사용률 2.64% (환산(효율 70%))
- DDoS / MLP / cuda: GPU Tesla T4 1대, 예상 사용률 3.32% (실측)
- DDoS / MLP / cuda+fp16: GPU Tesla T4 1대, 예상 사용률 4.82% (실측)
- DDoS / XGBoost / cpu: 32코어 서버 1대, 예상 사용률 28.39% (환산(효율 70%))
- DDoS / XGBoost / cuda: GPU Tesla T4 1대, 예상 사용률 30.59% (실측)
- IPS / MLP / cpu: 32코어 서버 1대, 예상 사용률 0.66% (환산(효율 70%))
- IPS / MLP / cuda: GPU Tesla T4 1대, 예상 사용률 0.89% (실측)
- IPS / MLP / cuda+fp16: GPU Tesla T4 1대, 예상 사용률 1.29% (실측)
- IPS / XGBoost / cpu: 32코어 서버 1대, 예상 사용률 19.26% (환산(효율 70%))
- IPS / XGBoost / cuda: GPU Tesla T4 1대, 예상 사용률 41.23% (실측)
- WAF / MLP / cpu: 32코어 서버 1대, 예상 사용률 0.08% (환산(효율 70%))
- WAF / MLP / cuda: GPU Tesla T4 1대, 예상 사용률 0.08% (실측)
- WAF / MLP / cuda+fp16: GPU Tesla T4 1대, 예상 사용률 0.13% (실측)
- WAF / XGBoost / cpu: 32코어 서버 1대, 예상 사용률 0.39% (환산(효율 70%))
- WAF / XGBoost / cuda: GPU Tesla T4 1대, 예상 사용률 0.86% (실측)