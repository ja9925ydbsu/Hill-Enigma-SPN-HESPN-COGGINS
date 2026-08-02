param(
    [ValidateSet("smoke", "standard", "paper")]
    [string]$Profile = "smoke",
    [string]$Output = "mds_rotor_study_results"
)

$ErrorActionPreference = "Stop"
Write-Host "Python version:"
py --version
Write-Host "Installing/checking requirements..."
py -m pip install -r requirements.txt
Write-Host "Running $Profile study..."
py run_mds_rotor_study.py --profile $Profile --out $Output
