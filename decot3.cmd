@echo off
FOR /F %%I IN ('DIR *.ROM /O:D /B') DO SET ROM_FILE=%%I
FOR /F %%I IN ('DIR *.BIN /O:D /B') DO SET BIN_FILE=%%I

echo ----------------------------------------------------------------------------------
echo Folder: %cd%
rem echo bin = %BIN_FILE%
rem echo rom = %ROM_FILE%
call decotools decrypt3 %BIN_FILE% %ROM_FILE%

