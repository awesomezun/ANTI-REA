# How to run the first protection and recovery experiment

Windows PC에서 C++ 샘플을 보호하고 REA 공격·비공개 판정 보고서를 만듭니다. [옵션과 판정 기준](reference.md), [도구 버전](toolchain.md)을 함께 확인하세요.

## 준비

Python 3.11+, Git, Visual Studio의 C++ 데스크톱 개발 도구·Windows SDK·CMake/Ninja, 64비트 JDK 21+, 로그인된 Claude Code CLI가 필요합니다. 실행할 프로젝트는 고정 로컬 디스크에 두세요. 첫 설치는 LLVM 개발 배포본과 Ghidra 등 대용량 파일을 받습니다.

## 첫 실행

1. 저장소 루트에서 로컬 도구를 준비합니다.

   ```powershell
   python -m antirea bootstrap
   python -m antirea doctor
   ```

   설치 매니페스트의 `kagura_ready`, `rea_ready`와 Claude CLI 위치가 표시됩니다. 이것만으로 공격 환경 검증이 끝난 것은 아닙니다.

2. 같은 예산으로 두 공격을 실행합니다.

   ```powershell
   python -m antirea run --attack-seconds 600 --budget-usd 5 --cases 1024
   ```

   실행 디렉터리, 빌드 단계, 기능 비교, 무보호·보호 공격의 진행 상태가 출력됩니다. 보호가 깨지면 공격 비교로 넘어가지 않습니다.

3. 출력된 실행 디렉터리의 `report.md`를 엽니다. 보호 적용 여부, 기능 일치 수, 각 공격의 실제 REA 호출·시간·비용·후보 정확도를 확인합니다. `completed`는 보호 성공 표시가 아닙니다.

## 난독화와 VM을 결합해 비교하기

```powershell
python -m antirea run --protection layered --attack-seconds 600 --budget-usd 5 --cases 1024
```

무보호·VM 단독·강화 조합의 세 바이너리를 같은 상수로 빌드하고, 세 공격 세션을 각각 새로 실행합니다. 각 세션에 시간·비용 한도가 적용됩니다. 강화 조합은 핵심 함수에 FLA·SUB·CO 후 VM을 적용하고 VM 실행기도 난독화합니다. 실제 적용·기능 보존을 통과해야 공격을 시작합니다.

완료 후 새로운 입력으로 재검증하고 실행 비용도 측정할 수 있습니다.

```powershell
python scripts/verify_run.py .runs/<실행-ID> --cases 4096
python scripts/benchmark_run.py .runs/<실행-ID>
```

두 번째 명령은 같은 4,096개 입력으로 조건별 워밍업 1회와 측정 7회를 실행해 `performance.json`을 만듭니다. 모든 출력과 바이너리 해시를 검사합니다. 중앙값에는 프로세스 시작·텍스트 입출력 시간이 포함되며, 기존 파일은 `--overwrite` 없이는 덮어쓰지 않습니다. 모델을 다시 호출하지 않습니다.

## 핵심 주변으로 보호 범위 넓히기

핵심 주변으로 범위를 확장하는 별도 샘플 비교는 다음 명령을 사용합니다. 보호 강도는 VM으로 고정하고, 핵심 함수만 선택했을 때와 호출·데이터 관계에서 발견한 주변 함수까지 선택했을 때를 비교합니다.

```powershell
python -m antirea run --protection scoped --attack-seconds 600 --budget-usd 5 --cases 1024
```

선정 이유와 제외한 공개 표현 경계는 각 빌드의 `scope.json`에서 확인합니다. `needs_review`이면 관련 간접 호출·전역 데이터·경계 검토 문제를 해결해야 하며, 누락된 보호를 성공으로 처리하지 않습니다. 이 실행을 재개할 때도 `--protection scoped`를 지정합니다. [정책과 제한](reference.md#보호-범위-선정)을 먼저 확인하세요.

## 미완료 실행 이어가기

원인을 수정한 후 **원래와 같은 공격 제한**으로 이어가세요. 새 공격 세션은 이전 후보 분석 내용을 전달받지 않습니다.

```powershell
python -m antirea run --resume .runs/<실행-ID> --attack-seconds 600 --budget-usd 5 --cases 1024
```

서로 다른 제한이나 도구 버전으로 비교하려면 새 `run`을 시작하세요. 재시도 기록은 별도 attempt 디렉터리에 남습니다.

강화 조합 실행을 재개할 때도 `--protection layered`를 지정해야 합니다. 실행 코드가 바뀌었다면 새 실행을 만들어야 합니다.

## 개발 검증

```powershell
python -m unittest discover -s tests -v
```

단위 테스트는 판정·실패 처리·MCP 경계를 검사하며 실제 모델 공격은 실행하지 않습니다. 실제 통합 결과는 `run` 보고서로 확인합니다.

도구 설치 후 아래 검사는 범위 비교의 세 조건을 실제로 빌드하고, 공개 점검용 상수에 대한 독립 계산식과 4,096개 입력을 비교합니다. 모델 호출은 하지 않으며 REA 공격 평가를 대신하지 않습니다.

```powershell
$env:ANTI_REA_CONTEXT_BUILD_TESTS = '1'
python -m unittest discover -s tests -p test_context_build.py -v
```

## 문제 해결

| 증상 | 확인·조치 |
|---|---|
| C++/SDK/CMake 도구 없음 | Visual Studio Installer에서 필요한 C++ 개발 구성 요소를 설치한 뒤 bootstrap을 다시 실행합니다. 자동으로 시스템 설치를 변경하지 않습니다. |
| JDK를 찾지 못함 | `powershell -File scripts/bootstrap_rea.ps1 -JavaHome 'C:\실제\JDK\경로'`로 전체 JDK를 지정합니다. |
| 다운로드 체크섬 불일치 | 네트워크·파일 손상 여부를 확인합니다. 스크립트는 파일을 보존하고 중단하므로 해당 파일을 확인 없이 덮어쓰지 않습니다. |
| 빌드 오류·VM 미적용 | `defender/build-*.stderr.log`, `build-*.stdout.log`, 변환 후 IR을 확인합니다. 이름만 protected인 결과는 인정하지 않습니다. |
| 모델 로그인·한도 문제 | 해당 공격의 `attacker.stderr.log`와 결과를 확인하고 사용 중인 Claude CLI의 로그인·계정을 복구합니다. |
| REA 오류·Ghidra 분석 시간 초과 | 해당 공격의 `rea/` 요청 로그와 `server.stderr.log`를 확인합니다. 도구 오류는 방어 성공이 아닙니다. |
| 후보 거부·실행 오류 | 후보가 [허용된 독립 계산 형식](reference.md)을 지켰는지 확인합니다. 임의 코드를 직접 실행해서 우회하지 마세요. |

현재는 자체 샘플과 Windows 빌드만 구현됐습니다. 임의 애플리케이션을 보호하려면 별도의 빌드 어댑터·기능 계약·평가 과제를 추가해야 합니다.
