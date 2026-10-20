@echo off
setlocal EnableDelayedExpansion

:: ── Site Scout Extension Auto-Installer ──
:: Works on Windows 10/11 with Chrome, Edge, or Brave.

set "SCOUT_URL=__SCOUT_URL__"
set "EXT_DIR=%LOCALAPPDATA%\SiteScoutExtension"
set "PROFILE_DIR=%LOCALAPPDATA%\SiteScoutProfile"
set "ZIP=%TEMP%\site-scout-ext.zip"

echo.
echo  Site Scout Extension Installer
echo  ================================
echo.

:: Download zip
echo  [1/4] Downloading extension...
curl -sL "%SCOUT_URL%/extension.zip" -o "%ZIP%"
if not exist "%ZIP%" (
  echo  ERROR: Download failed. Check your connection and try again.
  pause & exit /b 1
)

:: Extract
echo  [2/4] Extracting...
if exist "%EXT_DIR%" rd /s /q "%EXT_DIR%"
mkdir "%EXT_DIR%"
powershell -NoProfile -Command "Expand-Archive -Path '%ZIP%' -DestinationPath '%EXT_DIR%' -Force"
del "%ZIP%" 2>nul

if not exist "%EXT_DIR%\manifest.json" (
  echo  ERROR: Extraction failed.
  pause & exit /b 1
)

:: Create dedicated profile dir (avoids conflict with running Chrome)
if not exist "%PROFILE_DIR%" mkdir "%PROFILE_DIR%"

:: Find browser
echo  [3/4] Finding browser...
set "BROWSER="
set "BROWSER_NAME="

for %%P in (
  "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"
  "%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"
  "%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe"
) do (
  if exist "%%~P" if "!BROWSER!"=="" (
    set "BROWSER=%%~P"
    set "BROWSER_NAME=Chrome"
  )
)

if "!BROWSER!"=="" (
  for %%P in (
    "%PROGRAMFILES(X86)%\Microsoft\Edge\Application\msedge.exe"
    "%PROGRAMFILES%\Microsoft\Edge\Application\msedge.exe"
  ) do (
    if exist "%%~P" if "!BROWSER!"=="" (
      set "BROWSER=%%~P"
      set "BROWSER_NAME=Edge"
    )
  )
)

if "!BROWSER!"=="" (
  for %%P in (
    "%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"
    "%PROGRAMFILES%\BraveSoftware\Brave-Browser\Application\brave.exe"
  ) do (
    if exist "%%~P" if "!BROWSER!"=="" (
      set "BROWSER=%%~P"
      set "BROWSER_NAME=Brave"
    )
  )
)

if "!BROWSER!"=="" (
  echo  ERROR: No supported browser found (Chrome / Edge / Brave).
  pause & exit /b 1
)

:: Write Start Menu shortcut using the dedicated profile
echo  [4/4] Creating shortcut and launching...
set "SHORTCUT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Site Scout Session.lnk"
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT%'); $s.TargetPath = '!BROWSER!'; $s.Arguments = '--user-data-dir=\"%PROFILE_DIR%\" --load-extension=\"%EXT_DIR%\" --no-first-run \"%SCOUT_URL%/cookies\"'; $s.Description = 'Site Scout with cookie helper'; $s.Save()"

echo.
echo  Opening !BROWSER_NAME! with Site Scout extension...
echo  (Uses a separate browser profile so your main Chrome is not affected)
echo.

:: Launch with dedicated profile — works even if Chrome is already open
start "" "!BROWSER!" --user-data-dir="%PROFILE_DIR%" --load-extension="%EXT_DIR%" --no-first-run "%SCOUT_URL%/cookies"

echo  Done!
echo  - The extension is active in this window.
echo  - A "Site Scout Session" shortcut was added to your Start Menu.
echo  - Use that shortcut next time — no need to run this installer again.
echo.
timeout /t 4 >nul
