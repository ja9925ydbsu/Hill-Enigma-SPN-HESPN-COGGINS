@echo off
py -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
py -m unittest -v test_mds_rotor_study.py
if errorlevel 1 exit /b 1
py run_mds_rotor_study.py --profile smoke --out smoke_results
pause
