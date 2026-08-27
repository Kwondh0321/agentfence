# 변경 기록 / Changelog

이 프로젝트는 [Keep a Changelog](https://keepachangelog.com/)의 구조와 [Semantic Versioning](https://semver.org/) 원칙을 따릅니다.

## [Unreleased]

### 한국어

- MCP 설정 탐색 범위를 의도된 파일과 `.codex/config.toml`로 제한해 무관한 전역 설정의 오탐을 제거했습니다.
- `npx`의 `latest`, `next`, `canary`, 버전 범위를 고정 버전으로 인정하지 않도록 검사 정확도를 높였습니다.
- 심볼릭 링크 설정과 출력 I/O 실패를 안전하게 처리합니다.
- 한국어·영어 설치법, SARIF 예제, 기여·보안 문서와 이슈 템플릿을 정비했습니다.

### English

- Limited discovery to intended MCP files and `.codex/config.toml`, removing false positives from unrelated global configuration.
- Treats `latest`, `next`, `canary`, and ranges passed to `npx` as mutable rather than pinned.
- Rejects symlinked configuration and reports output I/O failures cleanly.
- Completed bilingual setup, SARIF examples, contributor guidance, security policy, and issue templates.

### 검증 / Validation

- 6 regression tests, Ruff checks, clean wheel build and install, installed-CLI smoke test, representative invalid-config failure, and GitHub Actions.

[Unreleased]: https://github.com/Kwondh0321/agentfence/compare/v0.1.0...HEAD
