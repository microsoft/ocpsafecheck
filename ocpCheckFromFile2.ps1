# Copyright (c) Microsoft Corporation.
#
# This is the inner script called by ocpCheckFromFile.ps1 that checks ocpsafe.json

param
(
    [Parameter(Mandatory=$false, ParameterSetName='Pester')]
    [bool] $isUnderTest = $true, 
    [Parameter(Mandatory=$true, ParameterSetName='OcpCheck', Position=0)]
    [string] $OCPSafeGitRepo,
    [Parameter(Mandatory=$true, ParameterSetName='OcpCheck', Position=1)]
    [string] $ArtifactPath,
    [Parameter(Mandatory=$true, ParameterSetName='OcpCheck', Position=2)]
    [string] $WorkingDirectory,
    [Parameter(Mandatory=$true, ParameterSetName='OcpCheck', Position=3)]
    [string] $Required,
    [Parameter(Mandatory=$true, ParameterSetName='OcpCheck', Position=4)]
    [string] $JSONOutput)

[int] $exitCodeSuccess = 0

[int] $exitCodeError = 1

[string] $ocpsafeFilename = 'ocpsafe.json'

[string] $algorithmSha384 = 'SHA384'

[string] $algorithmSha512 = 'SHA512'

function Get-JsonPropertyInt {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject] $document,
        [Parameter(Mandatory = $true)]
        [string] $propertyName
    )

    [int] $value = 0

    if ($document.PSObject.Properties.Name -contains $propertyName) {
        $value = [int]$document.$propertyName
    }

    return $value
}

function Get-FileHashLower {
    param (
        [Parameter(Mandatory = $true)]
        [string] $filePath,
        [Parameter(Mandatory = $true)]
        [string] $algorithm
    )

    [Microsoft.PowerShell.Commands.FileHashInfo] $fileHashInfo = `
        Get-FileHash $filePath -Algorithm $algorithm
                
    return $fileHashInfo.Hash.ToLower()
}

function Get-PartialFileHashLower {
    param (
        [Parameter(Mandatory = $true)]
        [string] $filePath,
        [Parameter(Mandatory = $true)]
        [int] $start,
        [Parameter(Mandatory = $true)]
        [int] $end,
        [Parameter(Mandatory = $true)]
        [string] $algorithm
    )

    if ($end -lt $start) {
        throw "End ($end) should be greather than Start ($start)"
    }

    [int] $numberOfBytesToRead = $end + 1
    [System.IO.FileInfo] $fileInfo = Get-Item -Path $filePath -ErrorAction Stop
    [int64] $totalByteCount = $fileInfo.Length

    if ($numberOfBytesToRead -gt $totalByteCount) {
        throw "Number of bytes to read `$end+1 ($numberOfBytesToRead) is greater than total file size ($totalByteCount)"
    }

    [byte[]] $buffer = Get-Content `
        -Path $filePath `
        -TotalCount $numberOfBytesToRead `
        -AsByteStream `
        -ErrorAction Stop
    [byte[]] $trimmedBuffer = $buffer[$start..$end]        
    [System.Security.Cryptography.HashAlgorithm] $hashAlgorithm = `
        [System.Security.Cryptography.HashAlgorithm]::Create($algorithm)
    [byte[]] $hash = $hashAlgorithm.ComputeHash($trimmedBuffer)
    [string] $hashtext = -join ($hash | ForEach-Object { $_.ToString('x2') })

    return $hashtext.ToLower()
}

if ($PSCmdlet.ParameterSetName -eq 'Pester') {
    Write-Host "Exiting (`$PSCmdlet.ParameterSetName -eq $($PSCmdlet.ParameterSetName -eq 'Pester')"
    
    exit $exitCodeSuccess
}

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 or higher. Exiting..."
    exit 1
}


Write-Host 'Checking OCP Safe Content'
Write-Host OCPSafeGitRepo = $OCPSafeGitRepo
Write-Host ArtifactPath = $ArtifactPath
Write-Host WorkingDirectory = $WorkingDirectory
Write-Host Required = $Required
Write-Host JSONOutput = $JSONOutput

# Install OCP dependent Python libraries from OCP safe repo

py.exe -m pip install -r $OCPSafeGitRepo\shortform_report-main\requirements.txt
py.exe -m pip freeze

# Initialize variables.  If $success = true then return exit 0 else exit 1

$success = $true

# This will be an array of all documents processed w/ status that will be returned
# in the final JSON document

$processeddocs = @() 

# Get date and time

$date = Get-Date
$formattedDate = $date.ToString("yyyy-MM-dd HH:mm:ss")

[int] $notAssigned = 0

# Iterate through all directories and if an ocpsafe.json exists then verify hash

Get-ChildItem -Path $ArtifactPath -Recurse -Directory | ForEach-Object {
    $compDir = $_.FullName
    cd $compDir

    if (Test-Path -Path $ocpsafeFilename -PathType Leaf) {
        [int] $fileCount = 0 
        $ocpSafeJson = Get-Content -Raw -Path "$compDir\$ocpsafeFilename" | 
                                                ConvertFrom-Json
        $ocpSafeJson.OCPSafeDocuments | ForEach-Object {
            [PSCustomObject] $Binary = $_
            [string] $Name = $Binary.BinaryName
            [string] $errtext = ''
            [string] $SHA384FileHash = ''
            [string] $SHA512FileHash = ''            
            <#
                {
                    "OCPSafeDocuments": [
                    {
                        "BinaryName": "helloworld.txt",
                        "Start": 0,
                        "End": 39,            
            #>
            [int] $start = Get-JsonPropertyInt $Binary 'Start'
            [int] $end = Get-JsonPropertyInt $Binary 'End'

            Write-Host "$name ($fileCount): Hash start ($start), end ($end)"
            if ($end -ne $notAssigned) {
                $SHA384FileHash = Get-PartialFileHashLower $name $start $end $algorithmSha384
                $SHA512FileHash = Get-PartialFileHashLower $name $start $end $algorithmSha512           
            }

            else {
                # Retrieve the hash from the binary specified in the JSON and convert to lower case for consistency
                $SHA384FileHash = Get-FileHashLower $Name $algorithmSha384
                $SHA512FileHash = Get-FileHashLower $Name $algorithmSha512
            }

            # Retrieve the hash from the ocpsafe.json document
            [string] $SHA384JSONHash = $Binary.SHA2384Hash.ToLower().Replace('0x', '')
            [string] $SHA512JSONHash = $Binary.SHA2512Hash.ToLower().Replace('0x', '')

            # Add new fields to OCP safe document for reporting
            $Binary | Add-Member -MemberType NoteProperty -Name "WorkingDirectory" -Value "${compDir}"
            $Binary | Add-Member -MemberType NoteProperty -Name "OCPSafeSHA384Verified" -Value $false
            $Binary | Add-Member -MemberType NoteProperty -Name "OCPSafeSHA512Verified" -Value $false
            $Binary | Add-Member -MemberType NoteProperty -Name "ShortformDocumentValid" -Value $false
            $Binary | Add-Member -MemberType NoteProperty -Name "ShortformSHA384Verified" -Value $false
            $Binary | Add-Member -MemberType NoteProperty -Name "ShortformSHA512Verified" -Value $false
            $Binary | Add-Member -MemberType NoteProperty -Name "OCPSafePath" -Value "${compDir}\ocpsafe.json"
            $Binary | Add-Member -MemberType NoteProperty -Name "Error" -Value ""
            $Binary | Add-Member -MemberType NoteProperty -Name "ProcessDate" -value "$formattedDate"            

            # Compare hash to JSON
            if ($SHA384JSONHash -ne $SHA384FileHash) {
               $errtext += 'sha384 ocpsafe.json mismatch'
            } else {
               $Binary.OCPSafeSHA384Verified = $true
            }

            if ($SHA512JSONHash -ne $SHA512FileHash) {
               if ($errtext -ne '') {
                   $errtext += ','
               }
               $errtext += 'sha512 ocpsafe.json mismatch'
            } else {
               $Binary.OCPSafeSHA512Verified = $true
            }

            # Process OCP safe document
            try
            {
                $ocpSafeDocument = $Binary.ShortFormDocument
                $ocpSafeJWS = $Binary.ShortformJWS
                $ocpSafeCertificate = $Binary.ShortformCertificate

                if (($ocpSafeDocument -ne '') -and ($ocpSafeJWS -ne '') -and ($ocpSafeCertificate -ne '')) {

                    # Extract shortform document
                    $cmd = "py ${WorkingDirectory}\extractocpjson.py --publickey ${OCPSafeGitRepo}/${ocpSafeCertificate} --signedreport ${OCPSafeGitRepo}/${ocpSafeJWS}"
                    $ocpSafeDocumentRaw = Invoke-Expression "$cmd" 
                    if ($lastExitCode -eq 0) {
                      
                        # Verify hashes 
                        $ocpSafeDocumentJson = ConvertFrom-Json -InputObject $ocpSafeDocumentRaw
                        $ocpSafeDevice = $ocpSafeDocumentJson.device
                        $ocpSafeDocumentSHA384Hash = $ocpSafeDevice.fw_hash_sha2_384
                        $ocpSafeDocumentSHA512Hash = $ocpSafeDevice.fw_hash_sha2_512
                        $ocpSafeDocumentSHA384Hash = $ocpSafeDocumentSHA384Hash.replace('0x','').ToLower()
                        $ocpSafeDocumentSHA512Hash = $ocpSafeDocumentSHA512Hash.replace('0x','').ToLower()
                        $Binary.ShortformDocumentValid = $true

                        if ($ocpSafeDocumentSHA384Hash -ne $SHA384FileHash) {
                            if ($errtext -ne '') {
                                $errtext += ','
                            }
                            $errtext += 'sha384 short form document mismatch'
                        } else {
                            $Binary.ShortformSHA384Verified = $true
                        }

                        if ($ocpSafeDocumentSHA512Hash -ne $SHA512FileHash) {
                            if ($errtext -ne '') {
                                $errtext += ','
                            }
                            $errtext += 'sha512 short form document mismatch'
                        } else {
                            $Binary.ShortformSHA512Verified = $true
                        }
                    } else {
                        if ($errtext -ne '') {
                            $errtext += ','
                        }
                        $errtext += 'python script failed'
                    }
                } else {
                    if ($errtext -ne '') {
                        $errtext += ','
                    }
                    $errtext += 'missing OCP prerequisites'
                }
            } catch {
                if ($errtext -ne '') {
                    $errtext += ','
                }
                $errtext += 'could not process shortform document'
            }

            $Binary.Error = $errtext

            if ($errtext -ne '') {
               if (${Required} -eq 'Required') {
                   Write-Warning "Failure in ${compDir}\ocpsafe.json: ${errtext}"
                   $success = $false
               } else {
                   Write-Host "Failure in ${compDir}\ocpsafe.json: ${errtext}"
               }
            } else {
               Write-Host "Success ${compDir}\ocpsafe.json"
            }

            $processeddocs += $binary
            $fileCount++
        }
    }
}

# Output results to JSON file

$processeddocs | ConvertTo-Json | Out-File -FilePath "${JSONOutput}"

if ($success -eq $true) {
    exit $exitCodeSuccess
} else {
    exit $exitCodeError
}
