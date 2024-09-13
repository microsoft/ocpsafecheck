# Copyright (c) Microsoft Corporation.
#
# This script checks the validity of ocpsafe.json 
#
# Parameters:
#   location    Location of the directory to crawl
#   ocpLogName  Name of the output file

param
(
    [Parameter(Mandatory=$true)][String]$location,
    [Parameter(Mandatory=$false)][String]$ocpLogOutput
)

# Check PowerShell version

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 or higher."
    exit 1
}

# Set default log location

if ($ocpLogOutput -eq "") {
    $ocpLogName = $location + "\" + "ocpresults.json"
} else {
    $ocpLogName = $ocpLogOutput
}

# if the file exists then append a number

if ((Test-Path -Path $ocpLogName) -and ($ocpLogOutput -eq "")) {

    # Get the directory and filename without extension

    $directory = [System.IO.Path]::GetDirectoryName($ocpLogName)
    $fileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($ocpLogName)
    $extension = [System.IO.Path]::GetExtension($ocpLogName)

    # Initialize the counter

    $counter = 1

    # Generate a new filename with a number appended

    do {
        $newFileName = "$fileNameWithoutExtension.$counter$extension"
        $newFilePath = [System.IO.Path]::Combine($directory, $newFileName)
        $counter++
    } while (Test-Path -Path $newFilePath)

    # Rename the file

    if ($ocpLogOutput -eq "") {
        $ocpLogName = $location + "\" + $newFileName
    } else {
        $ocpLogName = $ocpLogOutput
    }
    Write-Output "File renamed to $newFileName"

} else {
    Write-Output "File does not exist."
}

# Set up variables

$ocpSafeRepo = "https://github.com/opencomputeproject/OCP-Security-Safe"
$workingDirectory = $PWD

# Get current directory

$TempFolderName = "TempOCP" + (Get-Date -Format 'yyyyMMdd')
$TempFolderPath = Join-Path $env:SystemDrive $TempFolderName
if ((Test-Path $TempFolderPath)) {
    Remove-Item -Path $TempFolderPath -Recurse -Force
}

# Create temp folder

New-Item -Path $TempFolderPath -ItemType Directory
New-Item -Path $TempFolderPath\OCPRepo -ItemType Directory
New-Item -Path $TempFolderPath\Content -ItemType Directory
New-Item -Path $TempFolderPath\Content\Stuff -ItemType Directory
New-Item -Path $TempFolderPath\JSONOutput -ItemType Directory

# Clone OCP safe repo

git clone $ocpSafeRepo $TempFolderPath\OCPRepo

# Copy collateral to the temporary location

robocopy "${location}" "${TempFolderPath}\\Content\\Stuff" /s /mt:8

# Run OCP script

$JSONOutputFile = "OCPAuditReport_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".json"
& $PSScriptRoot\ocpCheckfromFile2.ps1 -OCPSafeGitRepo $TempFolderPath\OCPRepo -ArtifactPath $TempFolderPath\Content -WorkingDirectory $PSScriptRoot -Required Required -JSONOutput $TempFolderPath\JSONOutput\$JSONOutputFile

# Read in JSON output

$ocpReport = Get-Content -Path $TempFolderPath\JSONOutput\$JSONOutputFile | ConvertFrom-Json

$ocpReport | ForEach-Object {
    [PSCustomObject] $Binary = $_

    $oldValue = "$TempFolderPath\Content\Stuff"
    $Binary.WorkingDirectory = $Binary.WorkingDirectory.replace("$oldvalue","$location")
    $Binary.OCPSafePath = $Binary.OCPSafePath.replace("$oldvalue","$location")
}

# Change back to working directory

cd $workingDirectory

# Clean up temp directory 

Remove-Item -Path $TempFolderPath -Recurse -Force

# Write successful cases

$count = 0
$ocpReport | ForEach-Object {
      [PSCustomObject] $Binary = $_
      if ($Binary.Error -eq "") {
          $count++
      }
}

if ($count -gt 0) {
    Write-Host "OCP pass results" -ForegroundColor blue

    $ocpReport | ForEach-Object {
        [PSCustomObject] $Binary = $_
        if ($Binary.Error -eq "") {
            echo $Binary
        }
    }
}

# Write failure cases

$count = 0
$ocpReport | ForEach-Object {
      [PSCustomObject] $Binary = $_
      if ($Binary.Error -ne "") {
          $count++
      }
}
if ($count -gt 0) {
    Write-Host "OCP failures" -Foregroundcolor Red

    $ocpReport | ForEach-Object {
        [PSCustomObject] $Binary = $_
        if ($Binary.Error -ne "") {
            echo $Binary
        }
    }
}

# Write out JSON report

$ocpReport | Out-File -FilePath $ocpLogName

# Write Results

Write-Host "Summary" -ForegroundColor blue
Write-Host

if ($lastExitcode -eq 0) {
   Write-Host "OCP Check Successful. Results are in $ocpLogName" -ForegroundColor Green
} else {
   Write-Host "OCP Check Failed. Results are in $ocpLogName" -ForegroundColor Red
}
