# 20단계 오늘 할 일 체크리스트

1. Python/가상환경/패키지 상태 확인
2. AWS 인증 상태 확인 (profile 또는 env)
3. `python app/main.py scan --profile default` 실행
4. `reports/` JSON/HTML 파일 생성 확인
5. `python -m pytest -q` 실행
6. 필요 시 `uvicorn app.web:app --reload --port 8000`으로 대시보드 점검
