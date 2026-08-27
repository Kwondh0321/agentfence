# AgentFence

한국어 | [English](README.en.md)

AgentFence는 MCP와 AI 에이전트 설정 파일을 로컬에서 검사하는 보안 도구입니다. 실제 비밀값, 과도한 파일시스템 권한, 범용 셸 실행, 와일드카드 Origin, 평문 HTTP, 토큰 패스스루, 버전이 고정되지 않은 `npx` 패키지를 탐지합니다.

모델이나 API 키 없이 동작하며 텍스트·JSON·SARIF 보고서를 지원합니다.

## 설치 및 사용

```bash
git clone https://github.com/Kwondh0321/agentfence.git
cd agentfence
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install .
agentfence .
agentfence .mcp.json --format sarif --output agentfence.sarif
```

기본값은 `high` 이상 발견 시 종료 코드 1을 반환합니다. `--fail-on medium`, `--fail-on low`, `--fail-on none`으로 기준을 바꿀 수 있습니다.

## 검사 규칙

| 규칙 | 심각도 | 검사 내용 |
| --- | --- | --- |
| AF001 | Critical | 인증정보로 보이는 필드의 실제 값 |
| AF002 | High | 범용 셸 실행 |
| AF003 | High | 지나치게 넓은 파일시스템 범위 |
| AF004 | High | 와일드카드 Origin 허용 |
| AF005 | Critical | 토큰 패스스루 |
| AF006 | Medium | 외부 평문 HTTP 주소 |
| AF007 | Medium | 버전이 고정되지 않은 `npx` 패키지 |

AgentFence 결과는 검토 신호이며 서버의 안전성을 보증하지 않습니다.

## 개발

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
agentfence examples/mcp.json --fail-on none
```

## 라이선스

MIT
