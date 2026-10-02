# TapCode

**설치:** [Microsoft Edge 추가 기능](https://microsoftedge.microsoft.com/addons/detail/abkbmjpkelobbfnnjlaochbihpjnbgom) (심사 중, 게시 후 열림)

TOTP/HOTP 인증 코드 생성 Edge 확장.
키는 **암호화(PBKDF2-SHA256 → AES-256-GCM)** 된 뒤에만 저장·전송된다. 별도 암호 입력·잠금은 없다.

| 모드 | 암호화 키 |
|---|---|
| 서버 동기화 | WebDAV 아이디·비밀번호에서 만든다. 다른 PC 에서도 같은 아이디·비밀번호만 넣으면 열린다. 서버 파일만으로는 못 푼다 |
| 프로필 저장 | 처음 설정 때 만든 무작위 256비트 키 (프로필 저장소에 보관) |

잠금이 없으므로 이 브라우저 프로필을 쓸 수 있는 사람은 코드를 볼 수 있다 (휴대폰 OTP 앱을 잠금 없이 쓰는 것과 같음).

```
extension/   Edge 확장 (MV3). 외부 라이브러리는 QR 해독용 jsQR(Apache-2.0, vendor/jsqr) 하나
server/      금고용 최소 WebDAV 서버 (Node 18+, 의존성 없음)
test/        node test/run.mjs — RFC 벡터, 암호화, QR 파싱, WebDAV 동기화/충돌 테스트
```

## 저장 방식 (처음 실행은 묻지 않고 프로필 저장, 설정에서 서버 동기화로 전환)
| 방식 | 저장 위치 | 서버 반영 |
|---|---|---|
| 서버 동기화 (WebDAV) | 브라우저 프로필 + WebDAV 파일 | **계정을 추가·편집·삭제하면 바로 업로드** (백그라운드, 팝업을 닫아도 계속) + 하루 지나면 자동 1회 |
| 이 브라우저 프로필에만 저장 | 브라우저 프로필 (`chrome.storage.local`) | 없음 (서버 통신 0) |

- WebDAV 인증: 아이디·비밀번호 (`Authorization: Basic`). 비밀번호 보호를 위해 `https://` 주소만 허용 (개발용 localhost 제외)
- 저장된 비밀번호는 설정 화면에 다시 표시하지 않는다 (변경할 때만 새로 입력, 비워 두면 그대로)
- 주소는 폴더까지만 입력. 금고 파일 이름은 아이디·비밀번호로 자동 생성 (아래 참고)
- 마지막 동기화가 하루를 넘으면 브라우저 시작·페이지 로드·팝업 열기 때 자동으로 한 번 동기화한다 (alarms 권한 없음).
  자동 동기화가 실패하면(서버 오류, 양쪽 모두 바뀐 충돌 포함) 동기화 버튼이 성공할 때까지 자동으로 다시 시도하지 않는다.
  마지막 동기화 시각·실패 원인은 설정 화면에 표시 (이 기기에만 저장, `syncState`)
- 서버에 연결할 때 한쪽이 비어 있거나 양쪽 계정이 같으면 묻지 않는다: 이 기기에 계정이 없으면 서버 금고를 받고,
  서버 금고가 비었으면 이 기기 금고를 올리고, 계정 내용이 같으면(순서 무관) 바로 연결한다. 평소 동기화의 충돌도 내용이 같으면 묻지 않는다.
- 충돌 감지: `ETag` + `If-Match`. 바로 업로드·자동 동기화 중 두 기기 모두 바뀌었으면 묻지 않고 미동기화로 남기고,
  메인 화면에 실패 원인, 설정의 "동기화" 버튼에 빨간 점을 표시한다. 그 버튼을 누르면 어느 쪽을 쓸지 묻는다.
  (메인 화면의 동기화 아이콘은 없음. 다른 PC 변경은 설정의 동기화, 다음 저장, 하루 지나면 자동으로 받는다)
- 서버 금고가 이 접속 정보로 풀리지 않으면(다른 계정·비밀번호로 만든 금고) 가져오지 않는다.
- 비밀번호를 바꾸면 설정 → 서버 접속 정보 변경에서 새 비밀번호를 넣는다.
  금고를 새 키로 다시 암호화해 올리고, 다른 PC 는 새 비밀번호를 넣으면 다시 열린다.
- 1.3.0 의 토큰 설정은 이 기기에서 계속 열리고, 동기화하려면 아이디·비밀번호로 다시 연결한다 (금고를 새 키로 다시 올림)

## QR 스캔
- 팝업 ＋ → 화면에서 QR 스캔 → 페이지에서 QR 영역 드래그 (클릭만 하면 화면 전체, Esc 취소)
- 팝업 ＋ → QR 이미지: 저장해 둔 QR 이미지 파일로 추가 (스캔이 안 되는 edge:// 페이지 등)
- 일반 `otpauth://` QR 과 Google Authenticator "계정 내보내기"(`otpauth-migration://`) QR 지원, 중복은 건너뜀
- 사이트에서 스캔한 QR 은 그 사이트(대표 도메인)가 자동 입력 대상으로 지정된다

## 백업 (설정 → 백업)
- **OTP 내보내기**: `tapcode-backup-날짜.txt` 로 저장 (한 줄에 otpauth URI 하나, 다른 OTP 앱으로 옮기기 가능). 시크릿 키가 평문이므로 안전하게 보관
- **OTP 가져오기**: 위 파일 또는 otpauth URI 가 줄마다 있는 텍스트 파일. 중복은 건너뛰고, 서버 모드면 바로 업로드

## 단축키
| 키 | 동작 |
|---|---|
| `Alt+X` | 현재 사이트에 맞는 계정 코드를 입력칸에 자동 입력 |
| (기본 없음) | 팝업 열기 — `edge://extensions/shortcuts` 에서 지정 가능 |

- 팝업에서 계정 블록 클릭 = 코드 복사 + 현재 탭 입력칸에 입력. 그 사이트가 계정에 저장돼 있지 않으면 **현재 주소를 계정에 저장** → 다음부터 `Alt+X` 로 바로 입력
- 사이트 매칭: 계정의 "자동 입력할 사이트"(여러 개 가능, 하위 도메인 포함, 편집 모드 🔗 에서 수정) → 없으면 서비스명이 사이트 이름과 같을 때
  (`GitHub` ↔ `github.com`). `github.com.evil.io` 같은 주소에는 매칭되지 않는다.
- 입력칸 탐색: 포커스된 칸 → `autocomplete="one-time-code"` → 이름/ID/placeholder 에 otp·code·인증 등 → 한 글자씩 나뉜 칸
- 단축키는 **처음 설치할 때만** 지정된다. 이미 설치돼 있었다면 제거 후 다시 로드하거나
  `edge://extensions/shortcuts` 에서 지정 (설정 화면의 "단축키 변경" 버튼).
  `Alt+Shift+X`, `Alt+Shift+Z` 는 Edge 가 기본 지정을 거부해서 쓰지 않음.

## WebDAV 서버 (`server/`)
```powershell
# 비밀번호 생성
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
# 실행 (아이디마다 별도 금고, 쉼표로 여러 명. 비밀번호에 쉼표 불가)
$env:VAULT_USERS = "alice:비밀번호1,bob:비밀번호2"; node server/server.js
# → 127.0.0.1:8787 에서 대기. 리버스 프록시로 https://my-server/ (443) → http://127.0.0.1:8787 연결
```
| 요청 | 응답 |
|---|---|
| `GET /<폴더>/<파일 이름>.json` | 200 + `ETag` / 404 (아직 없음) |
| `PUT` + `If-Match: <etag>` 또는 `If-None-Match: *` | 201/204 + 새 `ETag` / 412 (그 사이 바뀜) / 400 (암호화된 금고 형식 아님) |
| `MKCOL`, `OPTIONS`, `HEAD` | WebDAV 클라이언트 호환용 |

인증은 `Basic` (아이디:비밀번호). 서버 메모리에도 비밀번호는 해시로만 둔다. 운영 시 HTTPS 리버스 프록시(nginx/Caddy) 뒤에서 실행.

## 확장 설치 (개발)
`edge://extensions` → 개발자 모드 → 압축 풀린 확장 로드 → **`extension` 폴더** 선택

## 서버 주소
기본 서버 주소는 없다. 서버 동기화를 고르면 사용자가 WebDAV 폴더 주소(예: `https://my-server/setting/tabCode`)와 아이디·비밀번호를 직접 입력한다.
연결할 때 그 도메인만 실행 중에 권한을 요청한다 (`optional_host_permissions`, 고정 `host_permissions` 없음).
금고 파일은 그 아래 `<파일 이름>.json`. 파일 이름은 아이디·비밀번호에서 PBKDF2(600k)로 만든 32자리 16진수라
계정마다 파일이 달라 서로 덮어쓰지 않고, 서버 로그·폴더 목록에 아이디·비밀번호가 드러나지 않는다.
예전에 `…/vault.json` 처럼 파일까지 적은 설정은 그 폴더로 보고, 다음 동기화 때 새 파일로 올라간다(예전 파일은 남음).

## Edge 추가 기능 스토어 제출 체크리스트
- [ ] 서버 동기화는 사용자 서버를 쓰는 선택 기능으로 안내 (심사용 서버 불필요, 인증 메모 참고)
- [ ] 개인정보처리방침 공개 URL 등록 (PRIVACY.md 수정해 게시)
- [ ] 공개 범위: Hidden
- [ ] 패키징: `Compress-Archive -Path extension\* -DestinationPath syncotp.zip`
- [ ] 권한 사유 기재: `activeTab`·`scripting` = 단축키/스캔을 누른 탭에만 입력·영역선택 스크립트 주입,
      `captureVisibleTab`(activeTab) = 사용자가 선택한 QR 영역 캡처, `storage` = 암호화된 금고 저장.
      `<all_urls>` 는 요청하지 않음

### Notes for certification (인증 메모) 예시
```
TOTP/HOTP authenticator. Secrets are encrypted client-side (WebCrypto PBKDF2-SHA256
600k + AES-256-GCM). Storage: browser profile only, or the user's own WebDAV file.

Test (profile mode, no server needed):
1. Open the popup. It starts in profile-only storage right away (no setup, no password).
2. ＋ → paste otpauth://totp/Test:demo?secret=JBSWY3DPEHPK3PXP&issuer=Test → codes appear.
3. ＋ → "화면에서 QR 스캔" on a page showing a 2FA QR code, drag over it → account added.
4. On a login page with an OTP field, Alt+X fills the code.

Server sync is optional and requires the user's own WebDAV server
(user enters URL + username/password, HTTPS only). All core features work in profile mode
without any server. No default server; no data leaves the device in profile mode.
No remote code is loaded; a server only stores/returns the encrypted JSON file.
```

## 반려 피하려고 지킨 것
- 접속 정보를 코드에 하드코딩하지 않음 (사용자 입력), 테스트 계정 프리셋 없음
- 원격 코드 실행 없음, 서버는 암호문 JSON 만 주고받음, 코드 난독화/번들링 없음
- jsQR 는 원본(비압축) 그대로 포함, 라이선스 파일 동봉
- 이름·아이콘은 기존 Authenticator 와 다름, 코드는 새로 작성
