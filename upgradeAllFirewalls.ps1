<#
.SYNOPSIS
    Automates the Upgrade/reboot process for School firewalls
.DESCRIPTION
    This script is designed to be run as a scheduled task to update school firewalls outside of business hours to shorten the window between the core firewall/panorama update, and the school firewall update
.NOTES
    File Name      : upgradeAllFirewalls.ps1
    Version        : 0.5
    Creation Date  : 2021-08-23
    Author         : Matthew Armitage
    Prerequisite   : PowerShell V5.1
.PARAMETER PanoramaFQDN
    Fully Qualified Domainname of target Panorama Server
.PARAMETER FirewallCSV
    CSV file with name, ip address, serial number, and canary status for all firewalls
.PARAMETER SoftwareVersion
    the current approved software release version for the school firewalls (automated tasks should read this from a text file)
.PARAMETER apikey
    This is the api key for the panorama server. See https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key.html
.INPUTS 
    Four parameters. CSV file needs columns name,ip,serial,canary. Canary column needs to be 'true' or 'false', and sets which firewalls to run the process on before pushing the update to the remaining firewalls. If there are no canary firewalls specified, script goes to parallel upgrades directly.
.OUTPUTS
    Process outcomes, error if failure detected.
.EXAMPLE
    Regular execution to install software version 10.0.1 to firewalls listed in 'CSVFilePath.csv' by connecting through 'panorama.example.com'
    upgradeAllFirewalls -FirewallCSV "CSVFilePath.csv" -PanoramaFQDN "panorama.example.com" -SoftwareVersion "10.0.1"
        Verbose execution to install software version 10.0.1 to firewalls listed in 'CSVFilePath.csv' by connecting through 'panorama.example.com'. Shows all steps, and not just script output.
    upgradeAllFirewalls -FirewallCSV "CSVFilePath.csv" -PanoramaFQDN "panorama.example.com" -SoftwareVersion "10.0.1" -Verbose
.CHANGELOG
    2021-08-28
    The code to catch XMI-API errors for the reboot XML-API request was failing, as the firewall immediately calls for a restart, and Invoke-Restmethod then throws a unable to read from socket error
    Changed the command to add a timeout of 15 seconds as recommended here and set ErrorAction Silently Continue https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-5.1
    Also added a try-catch block to keep going when this returned an error
    2021-08-28
    Removed Function Explanation Comment Blocks - The Start-Job process in the parallel execution section has a ScriptBlock and an InitalizationScript. The initalizationscript contains all the functions to pass to the jobs, but apparently has a limit of 32768 characters. Function total chars were over the limit, so comment blocks were trimmed.
    This could use a better work around as the current char count is ~11000, and the comment blocks only added ~50 lines, but removing them allowed the jobs to proceed so ¯\_(ツ)_/¯
    The error for future reference was "An error occurred while starting the background process. Error reported: The filename or extension is too long."
#>
[cmdletbinding()]
param (
    [parameter (Mandatory=$true,HelpMessage='Path to CSV File with firewalls listed by name,IP,serial,canary')]
    [String]$FirewallCSV,
    [parameter (Mandatory=$true,HelpMessage='Fully Qualified Domain Name of Panorama Server')]
    [String]$PanoramaFQDN,
    [parameter (Mandatory=$true,HelpMessage='Software version to install on firewall set')]
    [String]$SoftwareVersion,
    [parameter (Mandatory=$true,HelpMessage='API Key from Panorama Server')]
    [String]$apikey
)
#########################
# This code removes SSL Certificate Checks
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
# This code allows TLS 1.0,1.1,and 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
#########################
function checkSoftwareUpdate {
    param (
        [String]$panoramaUrl,
        [String]$panoramaApiKey,
        [String]$firewallSerial,
        [String]$firewallName
        )
    Write-Verbose "Starting Software Release Check on $firewallName"
    $response = Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<request><system><software><check></check></software></system></request>&target=$firewallSerial&key=$panoramaApiKey"
    $msg = $response.response.msg.line
    $status = $response.response.status
    if ($status -eq "error"){
        throw "API Error Response: $msg"
    }
    else {
        Write-Verbose "Successfully Updated Software Library"
        return "Successfully Updated Software Library"
    }
}	
function downloadSoftwareUpdate {
    param (
        [String]$panoramaUrl,
        [String]$panoramaApiKey,
        [String]$firewallSerial,
        [String]$SoftwareVersion,
        [String]$firewallName
        )
    Write-Verbose "Starting Software Release Check on $firewallName"
    #Get Software Library info from Firewall
    $response = Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<request><system><software><info></info></software></system></request>&target=$firewallSerial&key=$panoramaApiKey"
    $msg = $response.response.msg.line
    $status = $response.response.status
    $softwareLibrary = $response.response.result.'sw-updates'.versions.entry
    Write-Verbose "Checking if Software Release is downloaded on $firewallName"
    #Check if the specified verison exists in the library
    $versionIsDownloaded = $softwareLibrary | Where-Object { $_.downloaded -eq "yes"} | Where-Object { $_.version -eq "$SoftwareVersion"}
    if ($status -eq "error"){
        throw "API Error Response: $msg"
    }
    if ($null -ne $versionIsDownloaded){
        Write-Verbose "Software is already in the Firewall Library"
        return "Software is already in the Firewall Library"
    }
    Write-Verbose "Downloading $SoftwareVersion on $firewallName"
    # Download the specified version to the library
    $response = Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<request><system><software><download><version>$SoftwareVersion</version></download></software></system></request>&target=$firewallSerial&key=$panoramaApiKey"
    $msg = $response.response.msg.line
    $status = $response.response.status
    if ($status -eq "error"){
        throw "API Error Response: $msg"
    }
    else {
        # Get the Job ID for the download
        $jobid = $response.response.result.job
        # Check the status of the job
        $downloadJobStatus = Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<show><jobs><id>$jobid</id></jobs></show>&target=$firewallSerial&key=$panoramaApiKey"
        $i = 0
        Write-Verbose "Checking software download job on $firewallName"
        While ( $downloadJobStatus.response.result.job.status -notlike "FIN"){
            Write-Verbose "Download job still in progress on $firewallName, checking again in 30 seconds, attempt number $i"
            Start-Sleep -Seconds 30
            # Check the status of the job again
            $downloadJobStatus = Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<show><jobs><id>$jobid</id></jobs></show>&target=$firewallSerial&key=$panoramaApiKey"
            # start a counter to make sure this doesn't run forever
            $i++
            if ($i -eq 40){
                Write-Verbose "Waited for 20 Minutes, download should have completed before now, throwing error"
                throw "Download took too long"
            }
        ### NEED ERROR CHECKING FOR FAILED JOBS HERE ###
        }
        Write-Verbose "Software Download Job Succeeded"
        return "Software Download Job Succeeded"
    }
}	
function installSoftwareUpdate {
    param (
        [String]$panoramaUrl,
        [String]$panoramaApiKey,
        [String]$firewallSerial,
        [String]$SoftwareVersion,
        [String]$firewallName,
        [String]$Canary
        )
    # Check the installed version on the firewall, throw error if already installed
    Write-Verbose "Starting Software install on $firewallName"
    if ($Canary -eq "true"){
        Write-Verbose "$firewallName is Canary Device, Errors in this step will exit code"
    }
    Write-Verbose "Checking if firewall is already running $SoftwareVersion on $firewallName"
    $response = Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<show><system><info></info></system></show>&target=$firewallSerial&key=$panoramaApiKey"
    $msg = $response.response.msg.line
    $status = $response.response.status
    $installedSoftwareVersion = $response.response.result.system.'sw-version'
    if ($status -eq "error"){
        throw "API Error Response: $msg"
    }
    if ($installedSoftwareVersion -eq $SoftwareVersion) {
        if ($Canary -eq "true"){
            Write-Verbose "Software Version Already Installed"
            throw "Software Version Already Installed"
        }
        else {
            Write-Verbose "Software Version Already Installed"
            return "Software Version Already Installed"
        }
    }
    Write-Verbose "Installing $SoftwareVersion on $firewallName"
    # Install the specified software version
    $response = Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<request><system><software><install><version>$SoftwareVersion</version></install></software></system></request>&target=$firewallSerial&key=$panoramaApiKey"
    $msg = $response.response.msg.line
    $status = $response.response.status
    if ($status -eq "error"){
        throw "API Error Response: $msg"
    }
    else {
        # Get the Job ID for the download
        $jobid = $response.response.result.job
        # Check the status of the job
        Write-Verbose "Checking software install job on $firewallName"
        $installJobStatus = Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<show><jobs><id>$jobid</id></jobs></show>&target=$firewallSerial&key=$panoramaApiKey"
        $i = 0
        While ( $installJobStatus.response.result.job.status -notlike "FIN"){
            Write-Verbose "Install job still in progress on $firewallName, checking again in 30 seconds, attempt number $i"
            Start-Sleep -Seconds 30
            # Check the status of the job again
            $installJobStatus = Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<show><jobs><id>$jobid</id></jobs></show>&target=$firewallSerial&key=$panoramaApiKey"
            # start a counter to make sure this doesn't run forever
            $i++
            if ($i -eq 40){
                Write-Verbose "Waited for 20 Minutes, install should have completed before now, throwing error"
                throw "Install took too long"
            }
        ### NEED ERROR CHECKING FOR FAILED JOBS HERE ###
        }
        return "Software Install Job Succeeded"
    }
}	
function rebootFirewall {
    param (
        [String]$panoramaUrl,
        [String]$panoramaApiKey,
        [String]$firewallSerial,
        [String]$firewallIP,
        [String]$firewallName
        )
    Write-Verbose "Rebooting $firewallName"
     try{
        Invoke-RestMethod -URI "https://$panoramaUrl/api/?type=op&cmd=<request><restart><system></system></restart></request>&target=$firewallSerial&key=$panoramaApiKey" -TimeoutSec 15 -DisableKeepAlive -ErrorAction SilentlyContinue
    }
    catch{
        Write-Verbose "Invoke-Restmethod threw expected error because the firewall started the reboot immediately and did not send response"
    }
    Write-Verbose "Waiting 60 seconds for firewall start reboot"
    Start-Sleep -Seconds 60
    Write-Verbose "Checking to make sure firewall is not responding, and therefore reboot command should have been successful"
    $upYet = Test-Connection -Count 1 -ComputerName "$firewallIP" -Quiet
    if ($upYet){
        throw "Firewall did not start reboot successfully"
    }
    Write-Verbose "Firewall did not respond, and presumably is rebooting"
    Write-Verbose "Starting network connection test to  $firewallName at $firewallIP until it responds again"
    $i = 0
    do {
        Start-Sleep -Seconds 60
        # Check the status of the job again
        $error.Clear()
        try {
            $upYet = Test-Connection -Count 1 -ComputerName "$firewallIP" -Quiet
        }
        catch {
            throw $error
        }
        # start a counter to make sure this doesn't run forever
        $i++
        if ($i -gt 60) {
            Write-Verbose "Waited for 60 Minutes, reboot should have completed before now, throwing error"
            throw "Firewall didn't respond after reboot within 60 minutes"
            break
        }
        Write-Verbose "$firewallName has not yet responded at $firewallIP, Check number $i of 60"
    }
    until ($upYet)
    return "Ping succeeded"
}
function upgradeFirewall {
    param (
        [String]$panoramaUrl,
        [String]$panoramaApiKey,
        [String]$firewallSerial,
        [String]$firewallName,
        [String]$firewallIP,
        [String]$SoftwareVersion,
        [String]$Canary
        )
    # Update the software library, throw error description on failure
    Write-Verbose "Starting Firewall upgrade step 1, Check Software Update on $firewallName"
    try{
	    $softwareUpdateOutput = checkSoftwareUpdate -panoramaUrl $panoramaUrl -panoramaApiKey $panoramaApiKey -firewallSerial $firewallSerial -firewallName $firewallName
    }
    catch{
        throw "Failed to check for updates on " + $firewallName + ":"
    }
	# Download the specified software version, throw error description on failure
    Write-Verbose "Starting Firewall upgrade step 2, Download Software Update on $firewallName"
    try{
	    $downloadSoftwareUpdateOutput = downloadSoftwareUpdate -panoramaUrl $panoramaUrl -panoramaApiKey $panoramaApiKey -firewallSerial $firewallSerial -SoftwareVersion $SoftwareVersion -firewallName $firewallName
    }
    catch{
        throw "Failed to download update on " + $firewallName + ":"
    }
	# Install the specified software version, throw error description on failure
    Write-Verbose "Starting Firewall upgrade step 3, Install Software Update on $firewallName"
    try{
	    $installSoftwareUpdateOutput = installSoftwareUpdate -panoramaUrl $panoramaUrl -panoramaApiKey $panoramaApiKey -firewallSerial $firewallSerial -SoftwareVersion $SoftwareVersion -Canary $Canary -firewallName $firewallName
    }
    catch{
        throw "Failed to install updates on " + $firewallName + ":"
    }
	# Reboot the firewall and test until it is responding to ping.
    
    if ($installSoftwareUpdateOutput -ne "Software Version Already Installed") {
        Write-Verbose "Starting Firewall upgrade step 4, Reboot on $firewallName"
        try{
            $rebootFirewallOutput = rebootFirewall -panoramaUrl $panoramaUrl -panoramaApiKey $panoramaApiKey -firewallSerial $firewallSerial -firewallIP $firewallIP -firewallName $firewallName
        }
        catch{
            throw "Reboot failed on " + $firewallName + ":"
        }
    }
    else{
        Write-Verbose "$firewallName already has desired software version $SoftwareVersion installed, skipping reboot step 4."
        $rebootFirewallOutput = "Reboot Skipped"
    }
	# Returns success on function success
    Write-Verbose "All Upgrade steps complete on $firewallName"
    return $softwareUpdateOutput + " on " + $firewallName + "`n" + "$downloadSoftwareUpdateOutput" + " on " + $firewallName + "`n" + $installSoftwareUpdateOutput + " on " + $firewallName + "`n" + $rebootFirewallOutput + " on " + $firewallName
	# Returns error on function failure
}
function failureAlert {
    param (
        [String]$firewallName,
        [String]$errorMessage
    )
	#################################
    # THIS CODE IS NOT YET IMPLEMENTED
    #################################
}
function main {
    #This is the core function of the script
    param (
        [String]$Panorama,
        [String]$FirewallList,
        [String]$Version,
        [String]$apikey
    )
    Write-Verbose "Firewall Upgrade Starting"
    # Read firewalls.csv for all firewalls and canary flag
    if (!(Test-Path -Path $FirewallList -include *.csv)){
        Write-Error "Firewall CSV not found"
        exit 1
    }
    # Create an object with all firewalls without the canary flag
    $firewalls = Import-CSV $FirewallList | Where-Object Canary -eq false
    # Create another object with all the canary firewalls
    $canaryFirewalls = Import-CSV $FirewallList | Where-Object Canary -eq true   
	# Upgrade the Canary firewalls serially, and end the process if there are any errors. Skip if there are no Canaries specified
    if ($null -ne $canaryFirewalls) {
        foreach ($firewall in $canaryFirewalls){
            $error.Clear()
            try{
                Write-Verbose "Install process starting on canary firewall on $firewall"
                $upgradeOutput = upgradeFirewall -panoramaUrl $PanoramaFQDN -panoramaApiKey $apikey -firewallSerial $firewall.serial -firewallName $firewall.name -SoftwareVersion $SoftwareVersion -firewallIP $firewall.ip -Canary $firewall.canary
            }
            catch{
                throw "Canary Firewall Install Failed, Aborting: $error"
            }
            Write-Output "$upgradeOutput"
        }
        Write-Verbose "Canary upgrade succeeded, starting upgrade of all remaining firewalls"
    }
    else{
        Write-Verbose "No Canaries Specified, Skipping Canary Firewall Check"
    }
    #######################################################
    # Export Functions for use in the powershell jobs
    $exportFunctions = [scriptblock]::Create(@"
        function upgradeFirewall { $function:upgradeFirewall }
        function checkSoftwareUpdate { $function:checkSoftwareUpdate }
        function downloadSoftwareUpdate { $function:downloadSoftwareUpdate }
        function installSoftwareUpdate { $function:installSoftwareUpdate }
        function rebootFirewall { $function:rebootFirewall }
"@)
	# Codeblock for parallel processing of firewall upgrades, arguments are provided at start-job
    Write-Verbose "Starting Upgrade Jobs on all remaining firewalls"
    $firewallUpgradeJobCode = {
        try{
            # This code allows TLS 1.0,1.1,and 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
            # call the upgrade
            $upgradeOutput = upgradeFirewall -panoramaUrl $args[0] -panoramaApiKey $args[1] -firewallSerial $args[2] -firewallName $args[3] -SoftwareVersion $args[4] -firewallIP $args[5] -Canary $args[6]
        }
        catch{
            throw $error
            exit 1
        }
        return $upgradeOutput
    }
    # Firewall parallel job handling
    $firewallJobCount = 0
    $firewallJobName = "FirewallUpgradeProcess"
    # Set max jobs to a number you're comfortable with
    $firewallJobsMax = 100
    # This is how long the back off time will be on checking to make sure firewallJobsCount stays below firewallJobsMax
    $firewallJobsWait = 10
    # Create Jobs
    foreach ($firewall in $firewalls){
        Write-Verbose "Starting upgrade on $firewall"
        Start-Job -Name $firewallJobName -ScriptBlock $firewallUpgradeJobCode -InitializationScript $exportFunctions -ArgumentList $PanoramaFQDN,$apikey,$firewall.serial,$firewall.name,$SoftwareVersion,$firewall.ip,$firewall.canary | out-null
        do {
            $firewallJobCount = Get-Job -Name $firewallJobName | Where-Object {$_.State -ne 'Completed'} | Measure-Object | Select-Object -ExpandProperty Count
            if ($firewallJobCount -ge $firewallJobsMax){
                Write-Verbose "Hit concurrent job limit, waiting $firewallJobsWait until starting more jobs"
                Start-Sleep -Seconds $firewallJobsWait
            }
        }
        until ($firewallJobCount -lt $firewallJobsMax)
    }
	# Track Jobs
    Write-Verbose "All firewall upgrade jobs started"
    $firewallUpgradeJobsInProgress = Get-Job -Name $firewallJobName | Where-Object {($_.State -ne 'Completed') -and ($_.State -ne 'Failed')}
    do {
        $firewallUpgradeJobsInProgress = Get-Job -Name $firewallJobName | Where-Object {($_.State -ne 'Completed') -and ($_.State -ne 'Failed')}
        $firewallJobCount = Get-Job -Name $firewallJobName | Where-Object {$_.State -ne 'Completed'} | Measure-Object | Select-Object -ExpandProperty Count
        Write-Verbose "Waiting for $firewallJobCount Jobs to Complete"
        Start-Sleep -Seconds $firewallJobsWait
    }
    until ($null -eq $firewallUpgradeJobsInProgress)
    # Show Job Output
    Write-Verbose "All Firewall Upgrade Jobs Completed"
    $firewallCompletedJobs = Get-Job -Name $firewallJobName | Where-Object {($_.State -eq 'Completed') -or ($_.State -eq 'Failed')}
    Write-Verbose "Getting Job Ouput"
        foreach ($firewallJob in $firewallCompletedJobs){
        $firewallJobData = Receive-Job -id $firewallJob.id
        Write-Output $firewallJobData
        Remove-Job -id $firewallJob.id
    }
    # On error failureAlert
}

#Call Script Function Main and Start the Process
$timestamp = Get-Date -Format G
Write-Verbose "Script started $timestamp"
main $PanoramaFQDN $FirewallCSV $SoftwareVersion $apikey
$timestamp = Get-Date -Format G
Write-Verbose "Script ended $timestamp"
exit 0