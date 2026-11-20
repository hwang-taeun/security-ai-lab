# security-ai-lab — 룰 기반 보안 탐지 vs AI 탐지 비교

같은 트래픽을 **룰 기반 보안 엔진**과 **AI 모델**에 똑같이 넣고, 처음 보는 시험 집합에서 탐지율·오탐률을 비교한 Google Colab 실험입니다.
WAF · IPS · DDoS 세 단계로 나눠 진행했습니다.

- 포트폴리오 설명 페이지: https://hwang-taeun.github.io/projects/security-ai-lab/
- 실행 환경: Google Colab (T4 GPU), Python 3.13, scikit-learn 1.6, PyTorch 2.14

## 결과 요약

| 단계 | 룰 기반 | 데이터 | 룰 | AI | 핵심 발견 |
|---|---|---|---|---|---|
| [1. WAF](waf/) | OWASP Coraza v3.8.1 + CRS 4.25 | CSIC 2010 HTTP 요청 | 27.3% (오탐 0.03%) | 91.8% (오탐 0.03%) | 차이는 "이 사이트에서만 비정상인 값"에서 발생. SQLi·XSS 등 실제 공격은 둘 다 ≈100% |
| [2. IPS](ips/) | Suricata 8.0.8 + ET Open | CIC-IDS2017 금요일 pcap 8.8 GB | 0.1% (ET 심각도 1–2) | 99.7% (오탐 0.02%) | 경보 141만 건 중 99.9%가 패킷 품질 경보. 학습에서 뺀 공격은 AI도 0–26% |
| [3. DDoS](ddos/) | 임계값 룰 (hashlimit·connlimit 방식) | CIC-IDS2017 수·금 pcap 22 GB | 97.8% (오탐 13.9%) | 97.8% (오탐 0.09%) | 느린 공격은 동시 연결 룰로만 잡힘. 룰 오탐의 80%가 내부 서버 1대 |

**결론**: 룰은 시그니처가 있는 공격과 양으로 드러나는 공격을 학습 없이 잡고 이유를 설명할 수 있습니다.
지도 학습 AI는 본 적 있는 공격을 매우 잘 잡지만, 처음 보는 공격은 배운 공격과 닮았을 때만 잡습니다 (IPS 0–26% vs DDoS 88–100%).
대체가 아니라 함께 쓰는 관계입니다.

## 폴더 구성

```
security-ai-lab/
├── waf/    waf_lab_phase1.ipynb   + results/  (비교표, ROC, 공격 계열별, 사례 CSV)
├── ips/    ids_lab_phase2.ipynb   + results/  (비교표, 공격 종류별, 오탐 경보 목록, 처음 보는 공격)
└── ddos/   ddos_lab_phase3.ipynb  + results/  (비교표, 웹서버 관점, 탐지 시간, 구간 데이터)
```

각 `results/summary.json`에 라이브러리·엔진 버전, 룰셋 해시, 임계값, 전체 수치가 기록돼 있습니다.

## 다시 실행하기

1. https://colab.research.google.com → **파일 → 노트 업로드** → 단계별 `.ipynb` 선택
2. **런타임 → 런타임 유형 변경 → T4 GPU**
3. **런타임 → 모두 실행** — 데이터셋 내려받기, 엔진 설치·빌드, 학습, 결과 zip 내려받기까지 자동

| 단계 | 소요 시간(대략) | 디스크 |
|---|---|---|
| WAF | 15–25분 (Go·Coraza 빌드 포함) | 1 GB 미만 |
| IPS | 10–15분 | 약 20 GB |
| DDoS | 약 30분 | 약 25 GB |

- IPS 노트북은 첫 셀의 `IDS_DAY`(기본 `Friday`)로 다른 요일을 분석할 수 있습니다.
- ET Open 룰은 매일 바뀌므로 실행일에 따라 IPS 결과가 조금 달라질 수 있습니다 (사용한 룰 해시는 `ips/results/summary.json`).

## 데이터셋 (저장소에 포함하지 않음)

노트북이 실행 중에 직접 내려받습니다. 원본 크기와 배포 조건 때문에 이 저장소에는 넣지 않았습니다.

| 데이터셋 | 출처 | 노트북이 받는 곳 |
|---|---|---|
| HTTP DATASET CSIC 2010 | Spanish National Research Council (CSIC) | GitHub 공개 미러 |
| CIC-IDS2017 (pcap, GeneratedLabelledFlows) | Canadian Institute for Cybersecurity, UNB — https://www.unb.ca/cic/datasets/ids-2017.html | Hugging Face `bencorn/CICIDS2017` |

## 해석할 때 주의할 점

- 공개 데이터셋 한 곳·하루치 안에서 무작위로 나눈 결과라, 다른 환경에서 같은 숫자가 나오지 않습니다.
- CIC-IDS2017 원본 라벨에는 알려진 오류가 있습니다. IPS 단계는 모호한 흐름(11%)을 빼고, DDoS 단계는 CIC 공개 공격 일정표로 라벨을 다시 붙였습니다.
- AI가 데이터셋의 특징을 지름길로 쓰는 경우를 확인했습니다 (WAF: 사이트 전용 파라미터 이름, DDoS: HTTP 비율). 각 단계 결과에 순열 중요도와 지름길을 뺀 모델 결과를 함께 남겼습니다.
- 무료 룰셋(ET Open)과 기본 설정 위주로 비교했습니다. 유료 룰셋이나 환경에 맞춘 튜닝·예외 처리를 하면 룰 쪽 결과는 달라집니다.
