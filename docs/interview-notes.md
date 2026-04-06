# Interview Notes

## 1) 왜 이 프로젝트를 했나요?
클라우드 사고 원인의 상당수가 코드 취약점뿐 아니라 설정 실수에서 발생하기 때문에, 대표적인 AWS 보안 오구성을 자동 탐지하는 도구를 구현했습니다.

## 2) 어떤 항목을 점검하나요?
- S3 공개 노출/암호화
- IAM MFA 미설정/와일드카드 과권한
- Security Group 공개 인바운드(SSH/RDP/DB)

## 3) 차별점은 무엇인가요?
- 단순 조회가 아니라 `위험도 + 근거(evidence) + 권고사항(recommendation)`까지 함께 제공
- CLI, API, HTML 리포트까지 연결해 실제 점검 흐름으로 시연 가능
- 서비스별 상태(`SUCCESS/FAILED/PARTIAL`)로 부분 실패를 명시

## 4) 어려웠던 점과 해결
- IAM 정책 문서 파싱 복잡도: Allow/Action/Resource 구조를 정규화해 와일드카드 규칙 탐지
- 서비스별 예외처리: 실패한 서비스만 `FAILED`로 처리하고 전체 스캔은 계속 진행
- 결과 공통화: 모든 체크 결과를 단일 Finding 스키마로 통합

## 5) 향후 개선
- 멀티 계정 AssumeRole 스캔
- 룰 카탈로그 확장(CloudTrail, RDS, KMS)
- 알림 연동(Slack/Email)
- 권한 부족 항목에 대한 상세 원인 분류 및 재시도 전략
