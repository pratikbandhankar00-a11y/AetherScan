@echo off
setlocal
cd /d "%~dp0"

echo ===================================================
echo   NetPulse / AetherScan - Standalone Build Script
echo ===================================================

REM Detect javac and jar
set "JAVAC_CMD="
set "JAR_CMD="

if exist "%~dp0oracleJdk-27\bin\javac.exe" (
    set "JAVAC_CMD=%~dp0oracleJdk-27\bin\javac.exe"
    set "JAR_CMD=%~dp0oracleJdk-27\bin\jar.exe"
) else (
    where javac >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        set "JAVAC_CMD=javac"
        set "JAR_CMD=jar"
    )
)

if "%JAVAC_CMD%"=="" (
    echo [ERROR] Neither oracleJdk-27 nor system javac was found.
    pause
    exit /b 1
)

echo [1/3] Compiling Java classes with %JAVAC_CMD%...
"%JAVAC_CMD%" -encoding UTF-8 *.java
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Compilation failed!
    pause
    exit /b 1
)

echo [2/3] Writing manifest.txt...
echo Main-Class: AetherScanGUI> manifest.txt

echo [3/3] Packaging into AetherScan.jar with %JAR_CMD%...
"%JAR_CMD%" cfm AetherScan.jar manifest.txt *.class
if %ERRORLEVEL% neq 0 (
    echo [ERROR] JAR packaging failed!
    pause
    exit /b 1
)

echo.
echo ===================================================
echo   BUILD SUCCESSFUL! Generated: AetherScan.jar
echo   You can now double-click 'run.bat' to launch!
echo ===================================================
pause
