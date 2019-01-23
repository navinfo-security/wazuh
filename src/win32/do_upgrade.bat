:: Copyright (C) 2015-2019, Wazuh Inc.
:: January 22, 2019

@ECHO off

:: Get current version

SET /P curversion=<VERSION
ECHO %DATE%%TIME% INFO: Wazuh remote upgrade started. Current version is %curversion% >> upgrade\upgrade.log

:: Create backup

ECHO %DATE%%TIME% INFO: Generating backup. >> upgrade\upgrade.log

IF EXIST %temp%\backup DEL /S /Q %temp%\backup
IF EXIST %temp%\backup RMDIR /S /Q %temp%\backup

IF EXIST backup DEL /S /Q backup
IF EXIST backup RMDIR /S /Q backup

MKDIR %temp%\backup
XCOPY /E * %temp%\backup
MKDIR backup
XCOPY /E %temp%\backup\* backup
DEL /S /Q %temp%\backup
RMDIR /S /Q %temp%\backup

:: Kill remaining installer process

TASKLIST /FI "IMAGENAME eq msiexec.exe" 2>NUL | FIND /I /N "msiexec.exe" > NUL
IF "%ERRORLEVEL%"=="0" (
    ECHO %DATE%%TIME% INFO: Stopping msiexec process. >> upgrade\upgrade.log
    TASKKILL /F /IM msiexec.exe
)

:: Close the Agent Manager UI

TASKLIST /FI "IMAGENAME eq win32ui.exe" 2>NUL | FIND "win32ui.exe" > NUL
IF "%ERRORLEVEL%"=="0" (
    ECHO %DATE%%TIME% INFO: Closing Agent Manager UI. >> upgrade\upgrade.log
    TASKKILL /F /IM win32ui.exe
)

:: Launch the installer

IF EXIST upgrade\upgrade_result DEL /Q upgrade\upgrade_result
ECHO %DATE%%TIME% INFO: Starting new version installer. >> upgrade\upgrade.log

FOR %%G IN (wazuh-agent*.msi) DO %%G /quiet /norestart /log installer.log

:: Wait for the installer to finish

SET counter=5

:L1
SET /P newversion=<VERSION
IF "%curversion%"=="%newversion%" (
    IF %counter% NEQ 0 (
        SLEEP 2 2> NUL || ping -n 2 127.0.0.1 > NUL
        SET /A counter=%counter%-1
        GOTO L1
    )
)

ECHO %DATE%%TIME% INFO: Installer finished. Checking connection status. >> upgrade\upgrade.log

:: Expect state to connected, or restore

SET counter=5

:L2
FIND "status='connected'" ossec-agent.state
IF "%ERRORLEVEL%"=="1" (
    IF %counter% NEQ 0 (
        SLEEP 2 2> NUL || ping -n 2 127.0.0.1 > NUL
        SET /A counter=%counter%-1
        GOTO L2
    ) ELSE (
        NET STOP wazuh
        XCOPY /E /Y backup\* .
        NET START wazuh
        ECHO %DATE%%TIME% ERROR: Upgrade failed: agent cannot connect. Rolling back to previous version. >> upgrade\upgrade.log
        ECHO 2 > upgrade\upgrade_result
        EXIT
    )
)

ECHO %DATE%%TIME% INFO: Upgrade finished successfully. New version is %newversion%. >> upgrade\upgrade.log
ECHO 0 > upgrade\upgrade_result
