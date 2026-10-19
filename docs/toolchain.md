# 도구 버전과 재배포 주의

설치는 [실행 가이드](how-to-run.md)를 따릅니다. 구현의 첫 Windows 실험 경로는 아래 버전에 고정합니다.

| 구성 요소 | 버전·식별자 | 용도 |
|---|---|---|
| Kagura | `ac2136ee0408677cf7cdee55307e9b16edd5f4d5` | 소스에서 `kagura-opt`와 런타임 빌드 |
| LLVM/Clang | 22.1.0 Windows 개발 배포본 | LLVM IR 생성·변환 도구 링크·EXE 빌드 |
| REA | npm `rea-agents@6.5.0` | 게시된 Windows 패키지로 MCP 서버 실행 |
| REA 대응 소스 | `3b79af28e80785afce9f5998d8f03289402a1847` | 출처와 버전 기록; Windows에서 소스 빌드한 것이 아님 |
| Ghidra | 12.1.4 | REA의 무료 분석 제공자 |
| Node | 22.19.0 | 프로젝트 내부 REA 실행 런타임 |
| JDK | 기존 64비트 21 이상 | 검증 환경은 Microsoft OpenJDK 21.0.10.7 |

LLVM·Node·Ghidra 다운로드는 스크립트에 고정된 SHA-256과 비교한 뒤 추출합니다. Kagura는 고정 커밋과 추적 파일 변경 여부를 검사합니다. 설치된 전체 디렉터리를 매번 재해시하는 공급망 검증은 아닙니다. 첫 REA 설치의 전이 의존성은 npm이 해석하며 `.tools/rea/runtime/package-lock.json`에 결과를 저장합니다. 재현 시 이 lockfile도 보존해야 합니다.

Windows의 Kagura 경로는 Clang 플러그인 DLL을 억지로 로드하지 않고, 핵심 C++를 LLVM IR로 만든 뒤 정적 링크된 `kagura-opt`로 변환하여 EXE로 링크합니다. 기존 Visual Studio C++ 도구와 Windows SDK는 사용하지만 새 전역 설치나 영구 PATH 변경은 하지 않습니다.

## 라이선스와 배포

- Kagura는 MIT입니다. 원본 `LICENSE`를 보존합니다.
- REA 패키지의 `LICENSE`, `THIRD_PARTY_NOTICES.md`, `licenses/`를 확인합니다.
- LLVM은 자체 라이선스와 LLVM 예외, Node는 번들 구성 요소 고지, Ghidra는 `LICENSE`, `licenses/`, `GPL/`, `bom.json` 등 구성 요소별 고지가 있습니다.
- 기존 Visual Studio·Windows SDK·JDK와 모델 계정은 별도 사용 조건을 따릅니다.

`.tools/` 전체가 MIT라고 표시하거나, 사용자 보유 도구를 재배포할 권한이 있다고 가정하면 안 됩니다. 현재는 도구 배포물을 저장소에 포함하지 않고 사용자의 PC에 다운로드합니다.

## 확인된 운영상 주의

- LLVM 실행 파일만 있는 일반 설치에는 Kagura 링크에 필요한 개발 헤더·라이브러리가 없을 수 있습니다. 개발 배포본을 사용합니다.
- Ghidra 함수 목록·디컴파일 결과는 REA의 `normalized_result` 안에 들어갈 수 있습니다. transport의 오류·한계·원시 응답을 별도 보존합니다.
- PowerShell JSON은 UTF-8 BOM이 있을 수 있으므로 소비자는 `utf-8-sig`로 읽습니다.
- Windows와 macOS는 별도 검증 대상입니다. 이 구현의 Windows 결과를 macOS 지원 증거로 쓰지 않습니다.
