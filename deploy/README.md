# deploy — WAF · IPS · DDoS 를 한 장비에 올리기 (Rocky Linux 9)

1–3단계에서 비교한 **룰 엔진**과 **학습한 AI 모델**을 실제 서비스 장비 한 대에 함께 올리는 구성입니다.

```
클라이언트
   │
   ▼  nftables (secgw-nft)       ① 예외 IP · 차단 목록 · R1 초당 새 연결 · R2 동시 연결      ← DDoS 룰
   ▼  NFQUEUE → Suricata (secgw-ips)   ET Open 인라인 검사                                     ← IPS 룰
   ▼  Caddy + Coraza CRS (secgw-waf)   HTTPS 종료, OWASP CRS                                   ← WAF 룰
   ▼  waf-ai 게이트 (secgw-waf-ai)     문자 CNN(ONNX)으로 재판정                              ← WAF AI
   ▼  백엔드 웹 서버 (BACKEND_URL)

   Suricata eve.json ──▶ ips-ai  (흐름 1건 판정)          ─┐
                    └──▶ ddos-ai (IP × 10초 구간 판정)     ─┴▶ nftables ai_block 에 IP 추가 (10분 뒤 자동 해제)
```

## 다른 장비에 설치할 때: `deploy.conf` 한 파일만

| 구역 | 값 | 바꾸는 경우 |
|---|---|---|
| [1] 네트워크 | `WAN_IFACE`, `SERVICE_IP`, `HTTP_PORT`, `HTTPS_PORT`, `SERVER_NAME`, `BACKEND_URL`, `HOME_NET`, `MGMT_NET`, `WHITELIST_IPS` | **장비마다 반드시** |
| [2] 자원 제한 | `TOTAL_*`, `WAF_*`, `WAF_AI_*`, `IPS_*`, `IPS_AI_*`, `DDOS_AI_*` (CPU %, 메모리) | 장비 사양에 따라 |
| [3] 룰 기준값 | `CRS_PARANOIA`, `DDOS_RATE_PER_SEC`, `DDOS_CONN_MAX` … | 서비스 트래픽에 맞춰 튜닝 |
| [4] AI 판정 | `AI_MODE`(block/monitor), 기준값, 차단 시간 | 처음엔 monitor 로 1–2주 |
| [5] 내부 값 | 내부 포트, 설치 경로 | 보통 그대로 |

`render.sh` 가 이 값으로 아래 파일을 **만들어 냅니다**. 생성 파일을 직접 고치지 마세요 (다음 render 때 덮어씀).

| 생성 파일 | 내용 |
|---|---|
| `/etc/secgw/Caddyfile` | 서비스 IP·포트·도메인, Coraza CRS 편집증 수준, 백엔드 연결 |
| `/etc/secgw/suricata-secgw.yaml` | NFQUEUE 인라인, eve.json(경보+흐름) 출력 |
| `/etc/secgw/secgw.nft` | 관리망·예외 IP, 차단 목록, R1·R2 임계값 룰, IPS 큐 |
| `/etc/systemd/system/secgw*.{slice,service}` | 서비스별 `CPUQuota`·`MemoryHigh`·`MemoryMax` |
| `/etc/secgw/ai.env` | AI 서비스 공통 설정 |

```bash
vi deploy.conf              # 값 수정
./render.sh --out /tmp/p    # (선택) 무엇이 바뀌는지 미리보기
sudo ./secgw.sh check       # 값·문법·모델 검사
sudo ./secgw.sh reload      # 반영
```

## 처음 설치

```bash
# 1. Colab 에서 받은 모델 묶음 풀기 (models/README.md)
# 2. deploy.conf 수정
sudo ./install.sh           # 패키지·Caddy+Coraza 빌드·Python 환경·룰·서비스까지
sudo ./secgw.sh status      # 서비스 상태와 자원 제한/사용량
```

## 학습한 모델을 장비로 옮기는 과정 (이식)

1. **Colab — 내보내기**: 각 노트북 마지막 셀이 모델을 파일로 저장합니다. WAF CNN 은 PyTorch 없이 CPU 에서 돌도록 ONNX 로 바꾸고, 바꾼 뒤 점수가 같은지(차이 < 1e-4) 확인합니다.
2. **meta.json**: 기준값(검증 집합 오탐 0.1%), 특성 순서, 문자열→숫자 변환표, 학습 때 라이브러리 버전, 파일 SHA-256 을 함께 저장합니다.
3. **장비 — 같은 버전 설치**: `install.sh` 가 meta.json 의 `scikit-learn`·`numpy` 버전을 읽어 그대로 설치합니다.
4. **장비 — 같은 특성 계산**: `ai/features.py` 는 노트북의 특성 계산을 그대로 옮긴 코드입니다. `tests/test_parity.py` 가 노트북 결과와 한 자리까지 같은지 확인합니다.
5. **장비 — 시작할 때 검증**: 서비스 이름·파일 해시·라이브러리 버전이 하나라도 다르면 서비스가 뜨지 않습니다.
6. **처음엔 monitor**: `AI_MODE="monitor"` 로 1–2주 기록만 하며, 이 사이트의 정상 트래픽에서 오탐이 얼마나 나는지 본 뒤 block 으로 바꿉니다. 학습 데이터(CSIC 2010, CIC-IDS2017)는 이 사이트가 아니기 때문입니다.

## 운영 명령

| 명령 | 하는 일 |
|---|---|
| `./secgw.sh status` | 서비스 상태, CPU 상한, 메모리 사용/상한 |
| `./secgw.sh check` | deploy.conf 값, nftables·Suricata·Caddyfile 문법, 모델 해시·버전, 인터페이스·IP |
| `./secgw.sh blocks` | 지금 막고 있는 IP와 룰별 차단 횟수 |
| `./secgw.sh unblock 1.2.3.4` | 차단 해제 |
| `journalctl -u secgw-waf-ai -f` | AI 판정 로그 (점수, 차단 사유 글자 조각) |

## 알려진 한계

- **ddos-ai 는 즉시 대응용이 아닙니다.** Suricata 흐름 기록은 연결이 끝나야 나오므로 구간을 `DDOS_AI_DELAY_SEC`(기본 120초) 늦게 판정합니다. 즉시 차단은 nftables R1·R2 가 맡고, AI 는 그 기준 아래로 들어오는 공격을 한 번 더 잡습니다.
- **HTTPS 는 IPS 가 내용을 못 봅니다.** 암호화된 HTTP 내용은 Caddy 가 복호화한 뒤 WAF(룰+AI)가 봅니다. IPS 는 HTTP 이외 프로토콜과 연결 수준 공격을 담당합니다.
- 모델은 공개 데이터셋으로 학습했습니다. 실제 사이트에서는 그 사이트 로그로 다시 학습해야 1–3단계 수준의 성능을 기대할 수 있습니다.
