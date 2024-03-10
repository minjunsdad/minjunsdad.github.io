---
layout: post
title:  "Windows cmd 명령어 모음"
---

## **1 cmd commands**

모든 명령어는 win + R키나 cmd 명령창에서 실행하실 수 있습니다. 아랫쪽에 sysinternals 와 nirsoft 명령어 목록도 있습니다.

### **1.1 .msc**

**1.1.1 eventvwr.msc(이벤트뷰어)**

**1.1.2 gpedit.msc(로컬 그룹 정책 설정)**

**1.1.3 secpol.msc(로컬 보안 설정)**

**1.1.4 wmimgmt.msc(WMI 관리자)**

**1.1.5 certlm.msc (인증서관리자 - 로컬컴퓨터)**

**1.1.6 certmgr.msc(인증서관리자 - 현재사용자)**

**1.1.7 fsmgmt.msc(공유폴더)**

**1.1.8 lusrmgr.msc(로컬 사용자 및 그룹)**

**1.1.9 printmanagement.msc(프린터 관리)**

**1.1.10 wf.msc(방화벽고급관리자)**

**1.1.11 devmgmt.msc (장치 관리자)(= hdwwiz.cpl)**

**1.1.12 compmgmt.msc(컴퓨터관리)**

**1.1.13 perfmon.msc(성능모니터)**

**1.1.14 taskschd.msc(작업 스케쥴러)**

**1.1.15 comexp.msc (구성요소 COM,COM+,DCOM 서비스)(= dcomcnfg.exe)**

### **1.2 .exe**

### **1.2.1 type.exe (파일 내용 확인)(리눅스 cat과 같은 명령어)**

edward.txt 파일의 내용을 cmd창에 표시합니다

```
type edward.txt

```

### **1.2.2 takeown.exe (파일 권한 부여)**

20130202.png 파일의 소유자를 현재 계정으로 설정합니다

```
takeown.exe /f C:\Users\gyurs\Downloads\20130202.png

```

20130202.png 파일의 소유자를 Administrators 그룹으로 넘깁니다

```
takeown.exe /f C:\Users\gyurs\Downloads\20130202.png /A

```

Downloads 폴더 안에 있는 모든 파일의 권한을 Administrators 그룹으로 넘깁니다 Administrators 그룹으로 넘김, 모든 하위파일까지 적용, 중간에 읽기 권한없는 폴더를 만나도 권한을 부여하고 계속 실행

```
takeown.exe /f C:\Users\gyurs\Downloads\* /A /r /d y

```

### **1.2.3 attrib.exe (파일 속성 설정 도구)**

edward.txt 파일의 속성을 숨김, 읽기전용, 시스템파일로 변경합니다

```
attrib.exe +h +r +s edward.txt

```

edward.txt 파일의 숨김, 읽기전용, 시스템파일 속성을 해제합니다

```
attrib.exe -h -r -s edward.txt

```

현재 cmd창이 가리키는 폴더와 하위파일,폴더를 전부 숨김, 읽기전용, 시스템파일로 변경합니다

```
attrib.exe +h +r +s /s /d

```

### **1.2.4 icacls.exe (파일의 사용권한 설정 도구)**

test.txt 파일의 권한 중 edward 계정이 파일의 모든 권한을 획득합니다

```
icacls.exe C:\Users\edward\Downloads\test.txt /grant edward:F

```

20130202.png파일의 권한 중 edward 계정의 모든 접근을 거부합니다 (쓰기, 읽기, 수정,삭제…)

```
icacls.exe C:\Users\edward\Downloads\20130202.png /deny edward:F

```

20130203.png 파일의 권한 상속을 제거합니다

```
icacls.exe C:\Users\edward\Downloads\20130203.png /inheritance:R

```

fire.txt 파일의 권한 중 edward 계정이 가지고 있는 모든 권한을 제거합니다 (edward 계정은 해당 파일에 어떤 수정도 못합니다)

```
icacls.exe C:\Users\edward\Downloads\fire.txt /remove:g edward

```

fire.txt 파일의 권한 중 edward 계정이 가지고 있는 모든 접근 제한들을 제거합니다

```
icacls.exe C:\Users\edward\Downloads\fire.txt /remove:d edward

```

Downloads 파일 안에 있는 모든 파일과 폴더를 edward는 접근할 수 없게 합니다

```
icacls.exe C:\Users\edward\Downloads\* /deny edward:F /T /C

```

모든 변경사항을 DEFAULT 값으로 되돌립니다

```
icacls.exe C:\Users\edward\Downloads\* /reset

```

modify.txt 파일의 권한을 확인합니다

```
icacls.exe C:\Users\edward\Downloads\modify.txt

```

modify.txt 파일의 권한을 edward 계정에게 오직 읽기 권한만 줍니다 (쓰기, 삭제 등등 불가)(상속이 안되어있는 경우에만)

```
icacls.exe C:\Users\edward\Downloads\modify.txt /grant edward:R

```

### **1.2.5 fc.exe (두 개의 파일이 같은지 다른지 확인해주는 프로그램)**

aa.txt와 bb.txt 파일이 같은지 다른지 검사합니다 (다른 부분의 라인번호 출력하기)

```
fc.exe /n aa.txt bb.txt

```

**1.2.6 ver.exe (윈도우 버전 확인)**

### **1.2.7 findstr.exe (문자열 검색)**

create 구문이 oracledatabase_admin2.sql 파일안에 있는지 검색합니다 라인수, 파일이름, 대소문자를 구분없이

```
findstr.exe /n /s /i create oracledatabase_admin2.sql

```

C드라이브의 모든 파일 중 create 구문이 들어간 파일을 검색합니다

```
findstr.exe /n /s /i create c:\*

```

gyurs 유저 폴더 안에서 create 구문을 검색하고 결과를 result.txt에 저장합니다

```
findstr.exe /n /s /i create c:\users\gyurs\* > result.txt

```

### **1.2.8 w32tm.exe (Windows Time 서비스 설정)**

현재의 TimeZone을 확인합니다

```
w32tm.exe /tz

```

현재 로컬컴퓨터의 시간을 동기화합니다

```
w32tm.exe /resync

```

1601년 1월 1일부터 지난 시간(초)를 계산해 날짜를 표시해줍니다(NT 시스템 시간)

```
w32tm.exe /ntte 131028948948477834

```

1900년 1월 1일부터 지난 시간(초)를 계산해 날짜를 표시해줍니다 (NTP 시스템 시간)

```
w32tm.exe /ntpte 3763314900

```

### **1.2.9 schtasks.exe (윈도우 스케쥴러)(예약작업)(taskschd.msc로 쉽게 확인가능합니다)**

현재 등록된 모든 예약작업을 확인합니다

```
schtasks.exe /query /fo LIST /v | more

```

Ashley라는 이름으로 매주 월요일 아침 8시마다 시스템계정으로 calc.exe 프로그램을 실행합니다

```
schtasks.exe /create /tn "Ashley" /tr "c:\windows\system32\calc.exe" /sc weekly /d MON /st 08:00:00 /ru "System"

```

ashley2라는 이름으로 1분마다 notepad.exe 프로그램을 최고권한으로 실행합니다

```
schtasks.exe /create /tn ashley2 /tr "c:\windows\system32\notepad.exe" /sc minute /mo 1 /rl highest

```

ashley3라는 이름으로 최고권한으로 실행해서1분마다 hello라는 메세지창을 출력합니다

```
schtasks.exe /create /tn ashley3 /tr "c:\windows\system32\msg.exe * /v /w hello" /sc minute /mo 1 /rl highest

```

ashley라는 이름의 예약작업을 강제로 삭제합니다

```
schtasks.exe /delete /tn ashley /f

```

생성한 ashley라는 예약작업의 계정 (SID)를 확인합니다

```
schtasks.exe /ShowSid /TN "\ashley

```

### **1.2.10 ipconfig.exe (IP 주소 확인 + a)**

현재 컴퓨터의 IP 주소를 확인합니다

```
ipconfig.exe

```

IP를 사용하지 않습니다 (인터넷을 사용하지 않습니다)

```
ipconfig.exe /release

```

IP를 다시 사용합니다

```
ipconfig.exe /renew

```

현재 컴퓨터의 모든 DNS 주소 테이블을 초기화합니다

```
ipconfig.exe /flushdns

```

### **1.2.11 netstat.exe (포트 확인 도구)**

현재 컴퓨터가 통신하고 있는 모든 IP 주소 + 포트 + 프로그램 이름을 확인합니다 (-b 옵션은 관리자권한 필요)

```
netstat.exe -abno

```

### **1.2.12 tracert.exe (라우터 확인 도구)**

내 컴퓨터가 naver.com 서버까지 도달하기 위해 거치는 라우터들의 정보를 표시해줍니다 (라우터까지 도달하는 시간도 표시)

```
tracert.exe naver.com

```

### **1.2.13 pathping.exe (라우터 확인 도구 (old version))**

내 컴퓨터가 naver.com 서버까지 도달하기 위해 거치는 라우터들의 정보를 표시해줍니다

```
pathping.exe naver.com

```

**1.2.14 winmgmt.exe (WMI 관리도구)**

### **1.2.15 color.exe (프롬프트 색상을 바꿉니다)**

흰 색상에 검정글씨로 바꿉니다

```
color f0

```

**1.2.16 fsquirt.exe (블루투스를 이용한 파일 송수신)**

### **1.2.17 getmac.exe (MAC주소를 출력하는 프로그램)**

MAC주소를 자세히 확인합니다

```
getmac.exe /v

```

### **1.2.18 cls.exe (cmd창 깨끗하게 정리해주는 도구)**

### **1.2.19 nbtstat.exe (NETBIOS 프로토콜 확인)**

현재 캐시에 저장된 NBT 상태를 확인합니다

```
nbtstat.exe -c

```

저장된 NBT 세션들의 목록을 보여줍니다

```
nbtstat.exe -S

```

**1.2.20 label.exe (디스크 볼륨레이블 지정)**

### **1.2.21 pnputil.exe (pnp 디바이스 열거/설치/삭제)**

c:\drivers에 모든 패키지를 추가합니다

```
pnputil.exe -a c:\drivers\*.inf

```

패키지를 열거합니다

```
pnputil.exe -e

```

**1.2.22 psr.exe (단계레코더)**

**1.2.23 qprocess.exe (tasklist의 단순형 프로그램)**

**1.2.24 launchtm.exe (작업관리자)(taskmgr.exe와 동일합니다)**

**1.2.25 makecab.exe (cab 파일 만들기)**

**1.2.26 narrator.exe (음성지원 나레이터)**

**1.2.27 ping.exe (ping을 날리는 프로그램)**

**1.2.28 pathping.exe (ping + 패킷이 전달되는 루트를 추적합니다)**

**1.2.29 ftp.exe (ftp 클라이언트 프로그램)**

**1.2.30 useraccountcontrolsettings.exe (UAC 세팅)**

**1.2.31 bdehdcfg.exe (bitlocker 드라이브 준비도구)**

**1.2.32 dfrgui.exe (디스크 조각 모음)**

**1.2.33 changepk.exe (윈도우즈 제품키 입력)**

**1.2.34 certutil.exe (인증서 유틸리티)**

### **1.2.35 diskpart.exe (디스크 파티션 설정)**

disk들의 목록을 확인합니다

```
diskpart> list disk

```

disk0를 선택합니다

```
diskpart> select disk 0

```

disk 내부의 volume 목록을 확인합니다

```
diskpart> list volume

```

volume 1번은 선택합니다

```
diskpart> select volume 1

```

(위 명령어 후) volume의 드라이브 명칭을 F: 로 변경합니다

```
diskpart> assign letter=F

```

**1.2.36 eventcreate.exe (사용자 지정 이벤트 생성)**

### **1.2.37 chkntfs.exe (디스크검사 예약)**

`chkntfs.exe c: /c`

### **1.2.38 chkdsk.exe (디스크 검사)**

D드라이브를 검사하고 에러가 나면 복구합니다

```
chkdsk.exe D: /f /r

```

### **1.2.39 sfc.exe (시스템 파일 복구)**

시스템파일을 검사하고 이상이 있으면 복구합니다

```
sfc.exe /scannow

```

시스템파일을 검사만 합니다

```
sfc.exe /verifyonly

```

**1.2.40 mdsched.exe (메모리체크 도구)(재시작하면서 메모리를 체크한다)**

**1.2.41 certreq.exe (요청을 인증기관으로 제출하는 유틸리티)**

**1.2.42 mrt.exe(악성소프트웨어 제거도구)**

**1.2.43 cprintui.exe(프린터 UI)**

**1.2.44 sigverif.exe(File Signature Verification Tool)**

**1.2.45 resmon.exe(리소스 모니터)**

### **1.2.46 robocopy.exe (견고한 파일복사)**

desktop에 있는 파일들을 c:\test에 복사합니다 비어있는 디렉토리 제외, Multi Thread 20개 사용, 복사실패 시 1번 재시도, 대기시간 1초, 7개의 하위디렉토리 복사

```
robocopy.exe C:\Users\edward\Desktop c:\test /S /MT:20 /R:1 /W:1 /LEV:7

```

### **1.2.47 xcopy.exe (파일복사 프로그램)**

deskop에 있는 파일들을 c:\test에 복사합니다 하위 디렉토리, 오류가 생겨도 계속 복사, 조용히 복사, 겹치는 파일 묻지 않고 복사, 특성을 복사, 숨겨진파일과 시스템파일 모두 복사합니다

```
xcopy.exe C:\Users\edward\Desktop c:\test /s /c /q /y /k /h

```

WebcacheV01.dat 파일을 바탕화면에 복사합니다 (taskhost, dllhost 프로세스를 먼저 종료해야합니다)

```
xcopy.exe /s /h /i /y "%Localappdata%\Microsoft\Windows\Webcache\*.dat" %userprofile%\desktop

```

**1.2.48 copy.exe (간단한 파일복사)**

**1.2.49 charmap.exe(문자표)**

**1.2.50 wbemtest.exe(WMI 테스터)**

**1.2.51 magnify.exe(돋보기)**

### **1.2.52 setx.exe**

path 환경변수를 영구적으로 설정합니다

```
setx.exe path "%path%;경로" /m

```

### **1.2.53 shutdown.exe (컴퓨터 종료)**

컴퓨터를 바로 강제로 종료합니다

```
shutdown.exe /s /t 0 /f

```

컴퓨터를 100초 뒤에 강제로 종료합니다

```
shutdown.exe /s /t 100 /f

```

컴퓨터를 바로 강제로 재시작합니다

```
shutdown.exe /r /t 0 /f

```

컴퓨터를 로그오프합니다

```
shutdown.exe /l

```

**1.2.54 tlntsvr.exe (텔넷서버실행) (추가기능 설치에서 telnet을 설치해야합니다)**

### **1.2.55 tlntadmn.exe (텔넷서버관리) (윈도우8부터는 없어진듯합니다)**

### **1.2.56 wbadmin.exe(윈도우 백업관리자)**

C drive의 모든 파일(시스템파일포함)을 D drive로 백업합니다

```
wbadmin START BACKUP -include:C: -backupTarget:D:

```

C drive의 모든 파일(시스템파일포함)을 D drive로 백업합니다 (콘솔창에 결과를 띄우지 않습니다)

```
wbadmin START BACKUP -include:C: -backupTarget:D:  -quiet

```

### **1.2.57 fsutil.exe(디스크 구성 도구)**

C 드라이브의 여유공간을 확인합니다

```
fsutil volume diskfree c:

```

**1.2.58 fltmc.exe(필터 드라이버 로딩 언로딩 목록 보기)**

**1.2.59 cleanmgr.exe(디스크 정리)**

**1.2.60 sndvol.exe (스피크 볼륨 콘트롤)**

**1.2.61 wevtutil.exe(이벤트로그 수집도구)**

**1.2.62 slidetoshutdown.exe (화면을 슬라이드해서 종료)**

### **1.2.63 esentutl.exe(서버데이터베이스 관리 도구)**

해당 .dat 파일의 상태를 확인합니다

```
esentutl.exe /mh WebCacheV01.dat

```

해당 .dat 파일이 dirty shutdown 상태이면 clean shutdown 상태로 고쳐줍니다

```
esentutl.exe /p WebCacheV01.dat

```

**1.2.64 mmc.exe (콘솔 루터)**

**1.2.65 msconfig.exe (시스템 구성요소 유틸리티)**

**1.2.66 mstsc.exe (원격 데스크톱 연결)**

**1.2.67 odbcad32.exe(odbc 데이터 원본 관리자)**

**1.2.68 wuapp.exe(윈도우 업데이트)**

**1.2.69 dxdiag.exe (다이렉트X 정보)**

**1.2.70 msinfo32.exe (시스템 정보)**

**1.2.71 slui.exe (라이센스 등록)**

### **1.2.72 slmgr.exe (라이센스 등록2)**

```
slmgr.exe /ipk /dlv /ato

```

**1.2.73 osk.exe (화상 키보드)**

**1.2.74 wmplayer.exe (미디어 플레이어)**

**1.2.75 mkdir.exe (디렉토리 만들기)**

### **1.2.76 mklink.exe (바로가기 폴더 만들기)**

aaa 폴더의 바로가기 폴더 bbb를 만듭니다

```
mklink.exe /d c:/bbb c:/aaa

```

**1.2.77 taskmgr.exe (작업 관리자)**

**1.2.78 cmd.exe (명령 프롬프트)**

**1.2.79 explorer.exe (윈도우 탐색기)**

**1.2.80 rstrui.exe(시스템복원)**

**1.2.81 systeminfo.exe(시스템정보)**

### **1.2.82 taskkill.exe (프로세스 종료)**

메모장 프로세스를 강제로 자식노드까지 전부 종료합니다

```
taskkill.exe /f /im "notepad.exe" /t

```

PID가 1000보다 큰 모든 프로세스들을 종료합니다

```
taskkill.exe /fi "pid gt 1000" /f

```

### **1.2.83 tasklist.exe (프로세스 목록)**

svchost.exe 프로그램의 서비스목록을 확인합니다

```
tasklist /svc /fi "imagename eq svchost.exe"

```

특정 서비스의 정보를 확인합니다

```
tasklist.exe /svc /fi "services eq <servicename>"

```

explorer 라는 이름이 들어가는 프로그램 목록을 확인합니다

```
tasklist.exe | find /i "explorer"

```

tasklist.exe 프로그램이 사용하는 dll 목록을 확인합니다

```
tasklist.exe /m /fi "imagename eq tasklist.exe"

```

### **1.2.84 timeout.exe (지정된 시간을 기다리는 프로그램)**

100초동안 잠시 cmd창을 멈춤니다

```
timeout.exe /t 100 /nobreak

```

**1.2.85 tskill.exe (간단한 프로세스 종료 프로그램)**

**1.2.86 systempropertiesadvanced.exe (시스템속성 - 고급)**

**1.2.87 systempropertiesdataexecutionprevention.exe (시스템속성 - 데이터실행방지 dep)**

**1.2.88 systempropertiescomputername.exe (시스템속성 - 컴퓨터이름)**

**1.2.89 systempropertieshardware.exe (시스템속성 - 장치관리자)**

**1.2.90 systempropertiesperformance.exe (시스템속성 - 성능옵션)**

**1.2.91 systempropertiesremote.exe (시스템속성 - 원격)**

### **1.2.92 gpupdate.exe(그룹 정책 업데이트)**

```
gpupdate.exe /force

```

### **1.2.93 cmdkey.exe(자격증명 저장 관리)**

`cmdkey.exe /add:<targetname> /user:<username> /pass:<password>`

### **1.2.94 find.exe (특정 문자열 찾기)**

mysql_ed.sql 파일에서 create가 들어간 구문을 찾습니다

```
find.exe mysql_ed.sql "create" /n /i

```

abc.txt 파일의 라인 수를 셉니다

```
find.exe /c /v abc.txt ""

```

현재 동작하는 프로세스 중 대소문자를 구분하지 않고 sql 글자가 들어간 구문을 검색합니다

```
tasklist.exe | find.exe /i "sql"

```

**1.2.95 optionalfeatures.exe(윈도우 기능 켜기/끄기)**

**1.2.96 forfiles.exe (하위파일까지 전체탐색)(루프돌리는 배치파일 만들 때 유용)**

**1.2.97 regedit.exe (레제스트리 GUI 편집도구)**

**1.2.98 regsvr32.exe (COM 모듈 등록/해제)**

**1.2.99 cleanmgr.exe(Disk Clean Up)**

### **1.2.100 rundll32.exe**

절전 모드

```
rundll32.exe powrprof.dll SetSuspendState 0,1,0

```

환경 변수

```
rundll32.exe sysdm.cpl EditEnvironmentVariables

```

화면 잠금

```
rundll32.exe user32.dll LockWorkStation

```

자격증명 저장 관리

```
rundll32.exe keymgr.dll KRShowKeyMgr

```

**1.2.101 runas.exe (권한상승 후 프로그램 실행)**

**1.2.102 snippingtool.exe(캡처도구)**

**1.2.103 dcomcnfg.exe(구성요소 COM,COM+,DCOM 서비스)(=comexp.msc)**

**1.2.104 winver.exe(윈도우버전)**

### **1.2.105 where.exe (Linux find와 비슷한 명령어, 검색명령어)**

바탕화면에서 edw로 시작하는 파일을 전부 검색합니다

```
where.exe edw* /r c:\users\gyurs\Desktop\

```

**1.2.106 control.exe (제어판)**

**1.2.107 sc.exe (서비스컨트롤 명령어)**

### **1.2.108 soundrecorder.exe (음성 녹음기)**

### **1.2.109 powercfg.exe (전원옵션 명령어)**

최대 절전모드를 해제합니다

```
powercfg.exe /hibernate off

```

절전모드에서 깨울 수 있는 기기들의 목록을 보여줍니다

```
powercfg.exe /devicequery s1_supported

```

현재 컴퓨터에 설정된 전원관리 방법을 확인합니다

```
powercfg.exe /a

```

컴퓨터의 전원소비에 대한 보고서를 만들어줍니다

```
powercfg.exe /energy

```

### **1.2.110 reg.exe (레지스트리 추가/수정 명령어)**

해당 레지스트리 값을 추가합니다 (psexec을 사용하기 위해)

```
reg.exe add hklm\software\microsoft\windows\currentversion\policies\system /v LocalAccountTokenFilterPolicy /t reg_dword /d 1 /f

```

UAC 세팅을 해제합니다 (재부팅 필요)

```
reg.exe add hklm\software\microsoft\windows\currentversion\policies\system /v EnableLua /t reg_dword /d 0 /f

```

IPC-의 기본공유를 해제합니다

```
reg.exe add hkey_local_machine\system\currentcontrolset\control\lsa\ /v RestrictAnonymous /t reg_dword /d 2 /f

```

ADMIN-, C-의 기본공유를 해제합니다

```
reg.exe add hkey_local_machine\system\currentcontrolset\services\lanmanserver\parameters /v AutoshareWks /t reg_dword /d 0 /f

```

### **1.2.111 net.exe (네트워크 설정 명령어)**

- net stats 시스템 마지막 부팅시간을 확인합니다
    
    ```
    net stats work
    
    ```
    
- net share IPC- 자동공유를 중지합니다 (C-, ADMIN-도 삭제할 수 있습니다)
    
    ```
    net.exe share IPC- /delete
    
    ```
    
    IPC- 자동공유를 다시 설정합니다
    
    ```
    net.exe share IPC- /grant:gyurse,full
    
    ```
    

- net user ashley 라는 계정을 생성합니다. 비밀번호는 qwer1234 fullname은 Iron Man, comment는 hello guys, 계정은 활성화상태입니다
    
    ```
    net.exe user ashley qwer1234 /add /fullname:"Iron Man" /comment:"hello guys" /active:yes
    
    ```
    
    ashley의 자세한 정보를 확인합니다
    
    ```
    net.exe user ashley
    
    ```
    
    ashley 계정을 삭제합니다
    
    ```
    net.exe user ashley /delete
    
    ```
    

- net localgroup ashleygroup 이라는 이름의 localgroup을 생성합니다 comment도 같이 생성합니다
    
    ```
    net.exe localgroup ASHLEYGROUP /add /comment:"here is ashley world"
    
    ```
    
    ashley 계정을 ASHLEYGROUP 그룹에 추가시킵니다
    
    ```
    net.exe localgroup ASHLEYGROUP ashley /add
    
    ```
    
- net use localhost의 컴퓨터 자체에 계정명 ashley, 패스워드 qwer1234로 접속합니다 (사용자와 연결이 아닙니다)
    
    ```
    net.exe use \\localhost\IPC- /user:ashley qwer1234
    
    ```
    
    localhost의 share라는 폴더에 계정명/패스워드로 접속합니다
    
    ```
    net.exe use \\localhost\share /user:ashley qwer1234
    
    ```
    
- net time localhost의 시간을 확인할 수 있습니다
    
    ```
    net time \\localhost
    
    ```
    

### **1.2.112 msg.exe (네트워크 사용자들에게 메세지 보내는 명령어)**

컴퓨터의 모든 사용자들에게 5초동안 유효한 hello guys 메세지를 보냅니다

```
msg.exe * /v /time:5 hello guys

```

localhost의 모든 세션 사용자들에게 hello guys2 메세지를 보냅니다

```
msg.exe * /server:localhost /v /w hello guys2

```

### **1.2.113 subst.exe (디렉토리, 주소를 가상 드라이브로 치환해주는 명령어)**

c:\temp경로를 X: 드라이브로 치환합니다

```
subst.exe X: C:\temp\

```

X 드라이브에 접속합니다

```
cmd> X:

```

해당 치환경로를 삭제합니다

```
subst.exe X: /d

```

### **1.2.114 netsh.exe (IP, 방화벽 등등 네트워크 설정 명령어 )**

- netsh advfirewall (cmd> wf를 통해 확인할 수 있습니다) 새로운 방화벽 허용룰을 추가합니다 이름은 TCP-445이고 tcp 445번 포트의 접속을 허용합니다
    
    ```
    netsh.exe advfirewall firewall add rule name="TCP-445" dir=in action=allow protocol=tcp localport=445
    
    ```
    
    tcp-445라는 이름을 가진 방화벽 정책을 확인합니다
    
    ```
    netsh.exe advfirewall firewall show rule name="tcp-445"
    
    ```
    
    현재 방화벽 설정을 파일로 저장하고 나중에 가져올 수 있습니다
    
    ```
    netsh.exe advfirewall export c:\advfirewallpolicy.wfw
    netsh.exe advfirewall import c:\advfirewallpolicy.wfw
    
    ```
    
    현재 방화벽 설정을 볼 수 있습니다
    
    ```
    netsh.exe advfirewall firewall show rule name=all | more
    
    ```
    
    2000 - 3000 번 포트 접속을 막습니다
    
    ```
    netsh.exe advfirewall firewall add rule name="Block_2000_3000" dir=in action=block protocol=tcp localport=2000-3000
    
    ```
    
- netsh interface 네트워크 인터페이스 목록을 확인합니다
    
    ```
    netsh.exe interface show interface
    
    ```
    
    모든 네트워크 인터페이스 목록을 확인합니다
    
    ```
    netsh.exe interface dump
    
    ```
    
    원격포트가 443번인 모든 ipv4 tcp 연결을 확인합니다
    
    ```
    netsh.exe interface ipv4 show tcpconnections remoteport=443
    
    ```
    
    ipv4 프로토콜의 여러 매개변수들을 확인합니다
    
    ```
    netsh.exe interface ipv4 show global
    
    ```
    
    현재 네트워크카드의 IP 관련된 설정을 확인합니다
    
    ```
    netsh.exe interface ipv4 show config
    
    ```
    
    IP를 DHCP로 설정합니다
    
    ```
    netsh.exe interface ip set address name ="Ethernet" source=dhcp
    netsh.exe interface ip set dns "Ethernet" dhcp
    
    ```
    

### **1.2.115 sihost.exe (explorer.exe 다시 시작하는 프로그램)**

### **1.2.116 smartscreensetting.exe (smartscreen on/off 하는 명령어)**

### **1.2.117 systemreset.exe (시스템초기화 명령어)**

### **1.2.118 sdclt.exe (백업 & 복구 관리자)**

### **1.2.119 quser.exe (현재 사용자 출력)**

### **1.2.120 logoff.exe (현재 계정 로그오프)**

### **1.2.121 dism.exe (배포 이미지 서비스 및 관리도구)**

Winsxs 폴더를 정리합니다. 구성요소저장소에 있는 모든 구성요소의 교체된 버전이 제거됩니다

```
dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase

```

### **1.3 .cpl**

**1.3.1 powercfg.cpl(전원옵션)**

**1.3.2 firewall.cpl(방화벽 관리)**

**1.3.3 desk.cpl(디스플레이)**

**1.3.4 appwiz.cpl(프로그램추가/제거)**

**1.3.5 main.cpl(마우스)**

**1.3.6 mmsys.cpl(사운드 및 오디오장치)**

**1.3.7 hdwwiz.cpl (장치관리자)(= devmgmt.msc)**

**1.3.8 sysdm.cpl(시스템속성)**

**1.3.9 inetcpl.cpl(인터넷속성)**

**1.3.10 netplwiz.cpl(사용자계정2) (= control userpasswords2)**

**1.3.11 ncpa.cpl(네트워크 연결)**

**1.3.12 wscui.cpl(관리센터)**

**1.3.13 timedate.cpl(날짜 시간 속성)**

**1.3.14 control /name Microsoft.NetworkandSharingCenter(네트워크 공유센터)**

**1.3.15 control desktop(개인 설정)**

**1.3.16 control /name Microsoft.Troubleshooting(문제해결)**

**1.3.17 control userpasswords(사용자 계정)**

**1.3.18 control userpasswords2 (사용자계정2) (= netplwiz)**

**1.3.19 control printers(장치 및 프린터)**

**1.3.20 control folders(폴더옵션)**

**1.3.21 control keyboard(키보드 옵션)**

**1.3.22 control admintools(관리 도구)**

### **1.4 command**

**1.4.1 ms-settings (윈도우10 설정 창 열기)**

### **1.4.2 dir (디렉토리 목록 확인)**

숨겨진 파일, 시스템 파일 등 모든 파일을 확인합니다

```
dir /a

```

디렉토리에 붙은 PROGRA~1 같은 별칭들을 확인합니다

```
dir /x

```

간단하게 이름만 확인합니다

```
dir /b

```

내컴퓨터의 모든 파일을 하위디렉토리까지 전부 확인해서 myallfiles.txt로 저장합니다

```
dir /s c:\ > myallfiles.txt

```

해당 디렉토리에서 edw로 시작하는 파일만 확인합니다

```
dir /a /x edw*

```

해당 디렉토리의 소유자를 확인합니다

```
dir /q

```

### **1.4.3 cd (디렉토리 이동)**

c 드라이브로 이동합니다

```
cd c:\

```

사용자 계정폴더로 이동합니다

```
cd %userprofile%

```

### **1.4.4 date (날짜)**

현재 날짜를 확인합니다

```
date /t

```

### **1.4.5 time (시간)**

현재 시간을 확인합니다

```
time /t

```

### **1.4.6 chcp (cmd창 언어)**

cmd창 언어코드를 한글로 설정합니다

```
chcp 949

```

cmd창 언어코드를 영어로 설정합니다

```
chcp 437

```

### **1.4.7 start (파일 또는 폴더 열기)**

현재 cmd창이 가리키는 폴더를 엽니다

```
start .

```

edward.txt라는 파일을 메모장으로 생성합니다

```
start notepad edward.txt

```

**1.4.8 tree (디렉토리 구조 확인)**

### **1.5 sysinternals & nirsoft**

### **1.5.1 sysinternals**

### **1.5.1.1 psexec.exe (원격명령어 실행 도구)**

원격컴퓨터에서 실행해야할 명령어들 ADMIN-, IPC- 공유가 설정되어있어야 합니다

```
net.exe share

```

타겟컴퓨터에 해당 레지스트리 값을 추가합니다

```
reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

```

타겟컴퓨터에 445번 포트를 개방합니다

```
netsh.exe advfirewall firewall add rule name="TCP-445" dir=in action=allow protocol=tcp localport=445

```

타겟컴퓨터 Start -> Run -> secpol.msc -> Local Policies -> Security Options -> Network Access: Sharing > and security model for local accounts > Classic – local users authenticate as themselves

내컴퓨터, psexec 명령어를 사용합니다

```
psexec \\172.30.1.15 -u <hostname> -p <password> <command>

```

### **1.5.1.2 autorunsc.exe (자동실행 목록 확인)**

service 자동시작프로그램들을 확인합니다 띄어쓰기로 구분, 서비스목록만 확인, EULA 서약 자동 확인

```
autorunsc.exe -ct -a s /accepteula

```

컴퓨터 시작시 동작하는 프로그램들을 확인합니다 띄어쓰기로 구분, 시간형식 timestamp로, 로그온목록만 확인, EULA 서약 자동 확인

```
autorunsc.exe -ct -t -a lb /accepteula

```

### **1.5.2 nirsoft**

### **1.5.2.1 nircmd.exe (nirsoft cmd)**

프로그램을 hide 모드로 실행합니다

```
nircmd.exe exec hide <processname>

```

컴퓨터 음량을 최대치로 설정합니다

```
nircmd.exe setsysvolume 65535

```

컴퓨터의 음량을 음소거합니다

```
nircmd.exe mutesysvolume 1

```

chrome.exe 프로그램의 볼륨을 제거합니다

```
nircmd.exe changeappvolume chrome.exe -1

```

컴퓨터의 밝기를 최저로 합니다

```
nircmd.exe setbrightness 0

```

cmd 프로그램을 관리자권한으로 엽니다

```
nircmd.exe elevate cmd

```

주파수가 500 정도인 소리를 2초동안 냅니다

```
nircmd.exe beep 500 2000

```

explorer.exe 프로세스를 강제로 재시작합니다

```
nircmd.exe restartexplorer

```

cdrom을 엽니다

```
nircmd.exe cdrom open

```

시스템에서 로그아웃하거나 종료합니다

```
nircmd.exe exitwin logoff
nircmd.exe exitwin poweroff force

```

시스템을 잠급니다

```
nircmd.exe lockws

```

시스템을 절전모드로 합니다

```
nircmd.exe standby

```

시스템을 강제로 최대절전모드로 합니다

```
nircmd.exe hibernate force

```

컴퓨터의 화면을 끕니다

```
nircmd.exe monitor off

```

휴지통을 비웁니다

```
nircmd.exe emptybin

```

현재화면을 스크린샷으로 찍어서 해당 계정 폴더에 pic.png 파일로 저장합니다

```
nircmd.exe savescreenshot %userprofile%\pic.png

```

현재 화면을 10번씩 5초단위로 찍어서 scr~.png이름으로 저장합니다

```
nircmd.exe loop 10 5000 savescreenshot %userprofile%\scr~-loopcount-.png

```

마우스를 우클릭하게 합니다

```
nircmd.exe sendmouse right click

```

마우스를 더블클릭하게 합니다

```
nircmd.exe sendmouse left dblclick

```

마우스를 (30,-20)픽셀만큼 이동합니다

```
nircmd.exe sendmouse move 30 -20

```

A를 타이핑합니다

```
nircmd.exe sendkey A press

```

ctrl 키를 계속 누른상태로 유지합니다 (shift, esc 가능)

```
nircmd.exe sendkey ctrl down

```

hello라는 이름의 메세지 창을 2초 간격으로 3번 생성합니다

```
nircmd.exe loop 3 2000 infobox "hello" "message"

```

open calc?라는 물음창이 뜨고 확인을 누르면 calc.exe를 생성합니다

```
nircmd.exe qbox "open calc?" "message" "calc.exe"
```
