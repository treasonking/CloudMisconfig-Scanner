# CloudMisconfig-Scanner

AWS 환경에서 자주 발생하는 보안 오구성을 자동으로 탐지하는 경량 진단 도구입니다.

## 주요 기능 (MVP)
- S3 버킷 보안 점검
  - 공개 노출(ACL/Policy/Public Access Block)
  - 서버 측 암호화 설정
- IAM 보안 점검
  - 사용자 MFA 미설정
  - 와일드카드 관리자 정책(Action=`*`, Resource=`*`)
- Security Group 보안 점검
  - `0.0.0.0/0`, `::/0` 대상 SSH/RDP/DB 포트 노출
- 리포트 출력
  - 콘솔 요약
  - JSON 저장 (`reports/scan-YYYYMMDD-HHMMSS.json`)
  - HTML 저장 (`reports/scan-YYYYMMDD-HHMMSS.html`)

## CLI 실행

### 1) 의존성 설치
```bash
python -m pip install -r requirements.txt
```

### 2) 스캔 실행
```bash
python app/main.py scan --profile default --region ap-northeast-2
```

또는 기본값으로 실행:
```bash
python app/main.py
```

## Web API 실행 (FastAPI)
```bash
uvicorn app.web:app --reload --port 8000
```

엔드포인트:
- `GET /scan?profile=default&region=ap-northeast-2`
- `GET /results`
- `GET /report/{filename}`

## 현재 체크 ID
- `AWS.S3.PublicExposure`
- `AWS.S3.EncryptionEnabled`
- `AWS.IAM.UserMFA`
- `AWS.IAM.WildcardPolicy`
- `AWS.EC2.SG.PublicIngress`

## 프로젝트 구조
```text
cloudmisconfig-scanner/
├─ app/
│  ├─ main.py
│  ├─ web.py
│  └─ templates/
│     └─ report.html.j2
├─ scanner/
│  ├─ core/
│  ├─ providers/aws/
│  ├─ checks/
│  └─ reporting/
├─ reports/
├─ tests/
├─ requirements.txt
└─ README.md
```

## 진행 현황
- 완료: 1~13단계 핵심 범위
  - 인증 연결, 공통 구조, S3/IAM/SG 점검, 위험도/권고사항, JSON/HTML, CLI, FastAPI 최소 API
- 다음 권장 단계
  - 서비스별 부분 실패 UI/응답 표준화 강화
  - 시나리오 기반 테스트 코드 확장
  - GitHub Actions CI + 린트/테스트 자동화
