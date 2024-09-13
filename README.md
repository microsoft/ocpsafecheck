# OCPCheck Compliance tool

This tool crawls a directory location and will check the validity of the OCPSafe.JSON against the OCP Safe Shortform report in https://github.com/opencomputeproject/OCP-Security-Safe

# Prerequisites

1.	Install Powershell v7, by entering in a windows powershell window winget search Microsoft.PowerShell
2.	If you are not using your machine for git and python then download the clients from https://git-scm.com/downloads and https://www.python.org/

# To Run

1.  Open a powershell 7 window (pwsh)
2.  Run the script .\ocpCheckFromFile.ps1.  Parameters are:
  a. -location which is the location of the artifacts to scan
  b. -ocpLogOutput which is the output name of the JSON containing the results.  If the parameter is not supplied, the results will be placed in a file called ocpresults.json which will be placed in a directory specified by -location

