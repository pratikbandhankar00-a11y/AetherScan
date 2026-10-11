@echo off
setlocal
cd /d "%~dp0"

REM Check for javaw in oracleJdk-27 first, otherwise fall back to system PATH
if exist "%~dp0oracleJdk-27\bin\javaw.exe" (
    start "" "%~dp0oracleJdk-27\bin\javaw.exe" -jar "%~dp0AetherScan.jar"
    exit /b 0
)

where javaw >nul 2>nul
if %ERRORLEVEL% equ 0 (
    start "" javaw -jar "%~dp0AetherScan.jar"
    exit /b 0
)

where java >nul 2>nul
if %ERRORLEVEL% equ 0 (
    start "" java -jar "%~dp0AetherScan.jar"
    exit /b 0
)

echo [ERROR] No Java runtime (javaw.exe or java.exe) found on your system!
echo Please install Java or add JDK/JRE to your system PATH.
pause
exit /b 1
