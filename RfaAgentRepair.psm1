# Load external module
(new-object Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | iex;


function Confirm-RequiresAdmin {

    <#
    .SYNOPSIS
    Confirms environment has local admin privilages.
    .DESCRIPTION
    Older versions of PowerShell do not support the #Requires -RunAsAdministrator feature. This function fills the gap.
    .EXAMPLE
    Confirm-RequiresAdmin
    Call this function at the top of your script. AN error will be thrown in the same manner as the modern feature.
    .NOTES
    https://github.com/OfficeDev/Office-IT-Pro-Deployment-Scripts
    #>

    param()


    If (-NOT 
        ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole(`
                [Security.Principal.WindowsBuiltInRole] "Administrator"
            )
        )
    {
        throw "Administrator rights are required to run this script!"
    }

}

function Receive-RfaLtUninstaller {
    
    # previously auto-exteacted installer
    $fileTwoPath = Join-Path $env:TEMP 'Uninstall.exe' 
    Remove-Item $fileTwoPath -Force -ea 0
    
    $fileURL = 'https://automate.rfa.com/Labtech/Deployment.aspx?ID=-2'
    $filePath = Join-Path $env:TEMP 'ltremove.exe'
    (New-Object system.net.WebClient).DownloadFile($fileURL,$filePath)
    Get-Item $filePath
}

function Start-RfaLtUninstaller {
    & cmd /c ((Receive-RfaLtUninstaller).FullName) /s
}

function Receive-RfaLtInstaller {
    $u='http://automate.rfa.com/Labtech/Deployment.aspx?installType=msi'
    $f= Join-Path $env:TEMP 'agent1.msi'
    (new-Object system.net.WebClient).DownloadFile($u,$f)
    Get-Item $f
}

function Receive-RfaLtAgent497 {
    $Url497 = 'https://automate.rfa.com/hidden/install/agent497/agent1-497.msi'
    $Installer = "$($env:TEMP)\agent1-497.msi"
    (new-object Net.WebClient).DownloadFile($Url497,$Installer)
    Get-Item $Installer
}

function Start-RfaLtInstaller {
    param (
        [switch]$OldVersion497,
        [switch]$Quiet
    )

    $FullName = if ($OldVersion497) {
        (Receive-RfaLtAgent497).FullName
    } else {
        (Receive-RfaLtInstaller).FullName
    }
    
    if ($Quiet) {
        & cmd /c msiexec /qn /norestart /i "$FullName"
    } else {
        Invoke-Item "$FullName"
    }
}

function Test-LtFlapping
{
    $read1=gps ltsvc -ea 0;
    sleep 2;
    $read2=gps ltsvc -ea 0;
    
    if ($read2.ID -eq $read1.ID) 
    {$false} else {$true};
    # TRUE = process is flapping
};

function Test-LtErrors
{
    $elog='C:\windows\ltsvc\lterrors.txt';
    $read1=gc $elog -ea 0;
    sleep 25;
    $read2=gc $elog -ea 0;
    
    if (($read2.count - $read1.count) -eq 0)
    {$false} else {$true};
    # TRUE = log is recording errors
};

function Test-JanusExists {
    $LtPath = Join-Path $env:WINDIR 'LtSvc';
    $JanusPath = Join-Path $LtPath 'Janus.dll';
    Test-Path $JanusPath;
};

function Get-LtServerVersion {
    ((New-Object System.Net.WebClient).DownloadString('https://automate.rfa.com/LabTech/Agent.aspx')) -replace '\|'
}

function Get-LtServiceVersion {
    # Get version of LtAgent 
(Get-Item 'C:\Windows\LtSvc\LtSvc.exe').versioninfo |
    ForEach-Object{($_.FileMajorPart -as [string]) + '.' + ($_.FileMinorPart)}

}

# This should be moved out of this module and into the logging/devtools one
function d {(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.f')}; 

function Test-LtRemnants {
    $hasRemnants = $false
    if (gps lt*) {$hasRemnants = $true}
    if (gsv lt*) {$hasRemnants = $true}
    if (gi c:\windows\ltsvc -ea 0) {$hasRemnants = $true}
    if (gi hklm:\software\labtech -ea 0) {$hasRemnants = $true}
    $hasRemnants
}
function Stop-LtFlapping {
    Get-Process ltsvc,ltsvcmon,lttray -ea 0|stop-process -force;    
};

function Stop-LtProcess {
    Get-Process ltsvc,ltsvcmon,lttray -ea 0|stop-process -force;    
};

function Disable-LtService {
    & cmd /c sc config "ltservice" start= disabled | Out-Null;
    & cmd /c sc config "ltsvcmon" start= disabled | Out-Null;
};

function Remove-LtService {
    & cmd /c sc delete "ltservice" | Out-Null;
    & cmd /c sc delete "ltsvcmon" | Out-Null;
};

function Invoke-KillLabTech {
    Stop-LtProcess; sleep 2;
    Get-Item c:\programData\labtech -ea 0 | Remove-Item -Force -Recurse;
}

function Invoke-NukeLabTech {
    Invoke-KillLabTech
    Disable-LtService;sleep 2;
    Stop-LtProcess;sleep 2;
    Remove-LtService;sleep 2;
    Start-RfaLtUninstaller;sleep 2;
    gi c:\windows\ltsvc -ea 0 | Remove-Item -Force -Recurse;
    gi c:\programData\labtech -ea 0 | Remove-Item -Force -Recurse;
    gi hklm:\software\labtech -ea 0 | Remove-Item -Force -Recurse;
}

function Enable-LtService {
    & cmd /c sc config "ltservice" start= Auto | Out-Null;
    & cmd /c sc config "ltsvcmon" start= Auto | Out-Null;
};

function Get-VersionDotNet ()
{
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse |
    Get-ItemProperty -name Version,Release -EA 0 |
    Where { $_.PSChildName -match '^(?!S)\p{L}'} |
    Select PSChildName, Version, Release;
};

function Repair-LtServiceFlap {
    param (
        # Force the reinstall is the service is not flapping. (Recommended to just run Reinstall-LtService function from ltposh).
        [switch]$Force=$false
    )
    
    $TempPath = "$env:WINDIR\Temp\LTInstall";
    if (Test-Path $TempPath) {} else {
        New-Item -ItemType Directory $TempPath -Force | Out-Null;
    };

    $Log = Join-Path $TempPath 'ltinstall.txt'

    ECHO "Running PS1 script on $($env:COMPUTERNAME) at $(d)";

    # Initial QA
    $hasService = [bool](gsv ltservice -ea 0);
    "The ltservice is installed: $($hasService)" | Tee-Object -FilePath $Log | echo;
    if ($hasService) {
        $isFlapping = Test-LtFlapping;
        "Is the service ltserice flapping?: $($isFlapping)" | Tee-Object -FilePath $Log | echo;
        if (!$isFlapping -and !$Force) {
            ECHO "Exiting PS1 script on $($env:COMPUTERNAME) at $(d): No flapping issue detected";
            break
        };
    };

    $TempPath = "$env:WINDIR\Temp\LTInstall";
    if (Test-Path $TempPath) {} else {
        New-Item -ItemType Directory $TempPath -Force | Out-Null;
    };

    # Define the LID
    [int]$lid = Get-LTServiceInfo -ea 0 | Select-Object -ExpandProperty LocationID
    [int]$LocationID = if ($lid -gt 1) {$lid} else {1};
    ECHO "Using Location ID: $($LocationID)";

    # remove the agent
    uninstall-LTService -Server 'https://automate.rfa.com' -force;
    sleep 60;

    # Install the agent
    install-LTService -Server 'https://automate.rfa.com' -ServerPassword '+KuQQJbctLbr7IrXfLCLcg==' -SkipDotNet -Hide -LocationID $LocationID;

    # Final QA
    $hasService = [bool](gsv ltservice -ea 0).Status;
    "The ltservice was installed successfully: $($hasService)" | Tee-Object -FilePath $Log | echo;
    if ($hasService) {
        $isFlapping = Test-LtFlapping;
        "Is the service ltserice flapping?: $($isFlapping)" | Tee-Object -FilePath $Log | echo;
        if ($isFlapping) {
            Disable-LtService;
            Stop-LtFlapping;
            "Service disabled and stopped. Service ltservice status is currently: ($(
                (gsv ltservice -ea 0).Status))" | Tee-Object -FilePath $Log | echo;
        } else {
            $hasErrors = Test-LtErrors;
            "Is the lt error log active?: $($hasErrors)" | Tee-Object -FilePath $Log | echo;
        };
    };
};

function Repair-RfaAgentDuplicateID {
    <#
    .SYNOPSIS
    Removes agent and reinstalls agent with new ComputerID.
    .DESCRIPTION
    Removes agent and reinstalls agent given a location ID. Ensures the new ComputerID is different than the old one.
    .PARAMETER LocationID
    Required ID Number of the location in automate.rfa.com
    .NOTES
    This function is not needed because ltposh has Reset-LTService. 
    #>
    param (
        # ID Number of the location in automate.rfa.com
        [Parameter(Mandatory=$true,Position=0)]
        [int]$LocationID
    )

    # Store the agent ID
    $oldAgentID = Get-LTServiceInfo | Select-Object -ExpandProperty ID

    # remove the agent
    uninstall-LTService -Server 'https://automate.rfa.com' -force;
    Start-Sleep 60

    # Install the agent
    install-LTService -Server 'https://automate.rfa.com' -ServerPassword '+KuQQJbctLbr7IrXfLCLcg==' -SkipDotNet -Hide -LocationID $LocationID;
    Start-Sleep 60

    # Return the Agent ID
    $newAgentID = Get-LTServiceInfo | Select-Object -ExpandProperty ID
    if ($oldAgentID -eq $newAgentID) {
        Write-Warning "The agent ID $($newAgentID) has not been changed after reinstallation. Please review the logs and try again."
    } else {
        Write-Output "New ComputerID confirmed."
    }
}

<# to be tested to see if this throws false pos/neg results. 
$Cert = Get-ChildItem 'Cert:\LocalMachine\' -Recurse |
    Where-Object {$_.FriendlyName -like "GlobalSign Root CA*"}
#>


function Test-LtInstall {
    <#
    .SYNOPSIS
    Determines a healthy state for the Remote Agent.
    .DESCRIPTION
    Looks at the current settings of the Automate agent and returns information based on findings for further processing.
    .PARAMETER LocationShouldBe
    Required for testing all 
    .PARAMETER ServerShouldBeLike
    Value should include wildcards (*) to match against the server the agent shold be connecting to.
    If this check fails the remote agent is checking into a different IT firm's Automate server. 
    .PARAMETER SkipLocationCheck
    The default case, if no parameters are given. This switch bypasses location ID verification.
    .PARAMETER InstalledOnly
    This switch will bypass all health checks and only return a boolean that, if true, means the remote agent service is present.
    .PARAMETER Quiet
    This switch will return a simple boolean which aggregates all health tests. False means at least 1 test failed.
    #>
    [CmdletBinding(DefaultParameterSetName='SkipLocationCheck')]

    param (
        # Required parameter at runtime
        [Parameter(Mandatory=$true,ParameterSetName='Location')]
        [int]$LocationShouldBe,
        
        # Set the "pass" conditions
        [string]$ServerShouldBeLike = '*automate.rfa.com*',
        
        [Parameter(ParameterSetName='SkipLocationCheck')]
        [switch]$SkipLocationCheck,
        
        [Parameter(ParameterSetName='InstalledOnly')]
        [switch]$InstalledOnly,
        
        [Parameter(ParameterSetName='Location')]
        [switch]$Quiet
    )

    # Set the remaining "pass" conditions
    $LastContactShouldBeGreaterThan = (Get-Date).AddMinutes(-5)
    $ServiceVersionShouldBe = Get-LtServerVersion
    Write-Debug "DEBUG: ServiceVersionShouldBe: $($ServiceVersionShouldBe)"
    
    # Check for existing install
    $TestPass = $true
    $LTServiceInfo = Get-LTServiceInfo
    
    # Run all tests
    if ($InstalledOnly) {

        if (-not $LTServiceInfo) {$TestPass = $false}
    
    } else {
    
        [string]$FailReason = ''
        $ServerIs = $LTServiceInfo.'Server Address'
        $LocationIs = $LTServiceInfo.LocationID
        $LastContactIs = $LTServiceInfo.LastSuccessStatus -as [datetime]
        Write-Debug "DEBUG: LastContact: $($LastContactIs)"
        $ServiceVersionIs = (Get-Item 'C:\Windows\LtSvc\LtSvc.exe').versioninfo |
            Foreach-Object {($_.FileMajorPart -as [string]) + '.' + ($_.FileMinorPart)}
        Write-Debug "DEBUG: ServiceVersion: $($ServiceVersionIs)"
        
        # Test the info vs the conditions
        if ($ServerIs -notlike $ServerShouldBeLike) {$TestPass = $false ; $FailReason += 'Wrong Server, '}
        if ($ServiceVersionIs -ne $ServiceVersionShouldBe) {$TestPass = $false ; $FailReason += 'Wrong Version, '}
        if (!$SkipLocationCheck -and $LocationIs -ne $LocationShouldBe) {$TestPass = $false ; $FailReason += 'Wrong Location, '}
        if (-not ($LastContactIs -ge $LastContactShouldBeGreaterThan)) {$TestPass = $false ; $FailReason += 'Old LastContact.'}
    
        Write-Debug "DEBUG: TestPass: $($TestPass)"

    }
    
    if ($Quiet -or $InstalledOnly) {
        Write-Output $TestPass
    } else {
        # Output an object with all results
        [PSCustomObject]@{
            TestPass = $TestPass
            FailReason = $FailReason
            ServerAddress = $ServerIs
            LocationID = $LocationIs
            LastSuccessStatus = $LastContactIs
            ServiceVersion = $ServiceVersionIs
            ComputerId = $LTServiceInfo.Id
            ComputerIdIsNew = $LTServiceInfo.Id -gt $global:RfaLtNewestComputerId
        }
    }

}#END function Test-LtInstall

function Repair-LtAgent496 {
    # This function will reinstall the agent and make sure the location and agent IDs remain the same.
    # If not, a message will be given or thrown, depending on the severity of the result.
    
    param (
        # Do not check for version number, just re/install. You may get weird results.
        [switch]$Force,
    
        # Safer than Force. Should not be enabled in unattended shells or in batches.
        [switch]$MSI
    )


    $ErrorActionPreference='SilentlyContinue';

    $ServiceVersionIs = Try {
        (Get-Item 'C:\Windows\LtSvc\LtSvc.exe' -ea Stop).versioninfo |
            Foreach-Object {($_.FileMajorPart -as [string]) + '.' + ($_.FileMinorPart)}
    } Catch {
        'error'
    };
    
    $targetVersion = '120.496';
    
    if ($MSI -and (Get-Item 'C:\Windows\LtSvc\LtSvc.exe' -ea Stop)) {

        if ((Read-Host "LabTech not installed. Run MSI now? (y/n)") -like 'y*') {
            Invoke-KillLabTech;
            Start-RfaLtInstaller;
        }

    }elseif ($ServiceVersionIs -eq $targetVersion -or $Force) {

        $oldInfo=Get-LTServiceInfo;

        Try {
            Uninstall-LTService -Server 'https://automate.rfa.com' -Force -ea Stop;
        } Catch {
            Invoke-KillLabTech;
        };

        Sleep 5;
        if (Test-LtRemnants) { "Killing LabTech"; Invoke-KillLabTech};

        Try {
            sleep 5;
            Install-LTService -Server 'https://automate.rfa.com' -ServerPassword '+KuQQJbctLbr7IrXfLCLcg==' -Hide -LocationID ($oldInfo.LocationID) -ea Stop;
        } Catch {
            sleep 5;
            Install-LTService -Server 'https://automate.rfa.com' -ServerPassword '+KuQQJbctLbr7IrXfLCLcg==' -Hide -LocationID ($oldInfo.LocationID) -SkipDotNet;
        };
        

        $newInfo=Get-LTServiceInfo -ea 0;
        if ($null -eq $newInfo) {
            $ErrorActionPreference = 'Stop'
            'Install-LTService -Server "https://automate.rfa.com" -ServerPassword "+KuQQJbctLbr7IrXfLCLcg==" -Hide -LocationID 1 -SkipDotNet'
            throw "Reinstall failed. Please connect to $($env:COMPUTERNAME) and manually reinstall the agent. Use the above line"
        };
        

        if ($Force -and $newInfo.ID -gt 0) {
            "Reinstalled $($env:COMPUTERNAME) under ID $($newInfo.ID), Location $($newInfo.locationid)"
        } elseif ($oldInfo.locationid -eq $newInfo.locationid -and $oldInfo.computerid -eq $newInfo.computerid) {
            "Reinstalled OK. $($env:COMPUTERNAME)"
        }elseif ($oldInfo.locationid -eq $newInfo.locationid){
            "Reinstalled $($env:COMPUTERNAME) as a new agentid $($newInfo.id). Please ensure that the old agentID $($oldInfo.id) is migrated to the new one."
        }elseif ($oldInfo.computerid -eq $newInfo.computerid){
            "Reinstalled $($env:COMPUTERNAME) under location ID $($newLID). Please move the device back to Location ID $($oldInfo.locationid)"
        }else{
            "Reinstalled $($env:COMPUTERNAME) under ID $($newInfo.ID). Please move the device back to Location ID $($oldInfo.locationid)"
        };

    } else {
        Write-Warning "Was not able to confirm $targetVersion as the currently installed version of LabTech on $($env:COMPUTERNAME)."
    }#END if ($ServiceVersionIs -eq '120.496')

}


<# to be tested to see if this throws false pos/neg results. 
$Cert = Get-ChildItem 'Cert:\LocalMachine\' -Recurse |
    Where-Object {$_.FriendlyName -like "GlobalSign Root CA*"}
#>

function Repair-RfaLtAgent {

    <# DESCRIPTION
    Checks the local system for the Automate agent and verifies Location, Version, and if the agent belongs to RFA and not some other MSP. 
    (Re-) installs as needed. Also ensures the agent is checking in after install. 

    AUTHOR: Tony Pagliaro (RFA) tpagliaro@rfa.com
    Date: 2020/03/31
    #>

    param ([switch]$ForceRemove)

    # Make sure we're running as admin (psversion 2.0 compatible)
    Confirm-RequiresAdmin # will throw if not admin.

    # If the processes are flapping, make sure the cert auto update is on
    if (Test-LtFlapping) {
        Assert-RootCertificateAutoUpdate
        Write-Host "Certificate option corrected. Please wait..."
        Start-Sleep 45
        if (Test-LtInstall -Quiet -SkipLocationCheck) {
            Write-Host "Agent is checking in."
            break
        } else {
            Write-Warning "Agent is still not checking in..."
        }
    }


    # Attempt to restart the service if it is in a stopped state.
    Write-Host "Assessing service status..."
    $svcStatus = Get-Service ltservice
    if ($svcStatus.Status -ne 'Running') {Restart-LtService ; Start-Sleep 5}
    

    # Get the current location ID, default to 1
    $LocationID = Try {
        Get-LtServiceInfo -ea Stop | Select-Object -exp LocationID
    } Catch {1} #If the device is in the system, MAC signup will put it back where it was
    

    $RfaAutomateServer='https://automate.rfa.com'
    $UninstallRequired = $false
    $InstallRequired = $false
    $InstallSplat = @{

        Server=$RfaAutomateServer
        ServerPassword='+KuQQJbctLbr7IrXfLCLcg=='
        Hide=$true
        LocationID=$LocationID

    }

    # Check for existing install
    if (Test-LtInstall -InstalledOnly -Quiet ) {

        # Test is the agent is checking into correct server/location/version
        $TestData = Test-LtInstall -LocationShouldBe $LocationID
        if ($TestData.TestPass) {
        
            # Already installed, exit no issues
            Get-LtServiceInfo
            Write-Output "PASSED: The Automate Agent is already installed."
            Write-Debug "check Test-LtInstall -Debug result"
            Start-Sleep 15
            break
        
        } else {
        
            # Further work required
            $UninstallRequired = $true
            Write-Host "$($TestData.FailReason): Uninstall will be performed." -f White -b Black

        }

    } else {
        
        $InstallRequired = $true

    }


    # Remove if required
    if ($UninstallRequired) {

        Uninstall-LTService -Server $Server -Force

        if ($ForceRemove) {
            Write-Host "Please wait one minute while the uninstallation is confirmed..." -f White -b Black
            Start-Sleep 45
            Invoke-NukeLabTech
        }

        $InstallRequired = $true

    }

    if ($InstallRequired) {

        Try{

            Install-LTService @InstallSplat -ea stop

        } Catch {

            Install-LTService @InstallSplat -SkipDotNet

        } Finally {
            
            Start-Sleep 60

        }

    }


    # Test is the agent is checking into correct server/location
    if (Test-LtInstall -Quiet -LocationShouldBe $LocationID) {

        Write-Output "SUCCESS: The Automate Agent was successfully reinstalled."
        Get-LtServiceInfo
        Start-Sleep 15
        break

    } else {

        Write-Output ($Error.Exception.Message)
        Write-Output (Test-LtInstall -LocationShouldBe $LocationID | Format-List | Out-String)
        Throw "FAILURE: The Automate Agent could not be verified or is not checking in after a minute."

    }

}


function Assert-RootCertificateAutoUpdate {

    [CmdletBinding()]

    param ([switch]$Disable)

    $CertKey = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot'
    $CertProperty = 'DisableRootAutoUpdate'
    $Value = if ($Disable) {1} else {0}

    $CertUpdatesDisabled = Get-Item $CertKey -ea 0 |
        Get-ItemProperty -Name $CertProperty -ea 0 |
        Select-Object -ExpandProperty $CertProperty

    Write-Debug '$CertUpdatesDisabled variable is populated ($CertUpdatesDisabled -ne $Value)'

    if ($null -ne $CertUpdatesDisabled -and $CertUpdatesDisabled -ne $Value) {
        Set-ItemProperty -Path $CertKey -Name $CertProperty -Value $Value -Force -Confirm:$false
        Write-Verbose "Value changed to $Value."
    } elseif ($null -ne $CertUpdatesDisabled) {
        Write-Verbose "Value already set to $Value."       
    } else {
        # The key doesn't exist. Create it if required or just return a verbose message.
        if ($Value -eq 1) {
            Write-Debug "About to create $CertKey"
            New-Item -Path $CertKey -Force | Out-Null
            Set-ItemProperty -Path $CertKey -Name $CertProperty -Value $Value -Force -Confirm:$false
            Write-Verbose "Key added and Value set to $Value."
        } else {
            Write-Verbose "Key not present. Value of $Value is default case. No action taken."
        }
    }

}


function Get-VirtualNetworkInfo {
    <#
    .SYNOPSIS
    Tool discovers Software VPN adapters for purposes of Labtech agent install MAC Signup case handling.
    .DESCRIPTION
    Finds any ipconfig output lines with 'virtual' in the description and returns pertanent info about that adapter.
    .EXAMPLE
    $BreakOut = $false ; Get-VirtualNetworkInfo | %{if ($_.isActive) {$BreakOut = $true}} ; if ($BreakOut) {break}
    
    Putting this line in your script will break the script if it finds an active software VPN connection.
    
    .NOTES
    Can be used for detecting a vNIC on deployment script and bailing out if one is connected. 
    Another idea, pause deployment at this stage and wait for the tech to advance,
     after purging records of the returned MAC from the DB.
    #>
    
    [CmdletBinding()]
    
    # Record the result of the IP config all command to a variable
    $ipresult = ipconfig /all

    # Define the pattern which will isolate the virtual adapters (this can be customized in the future)
    $ptnVirtual = 'virtual'
    
    # Find any ipconfig output lines with the description that matches the pattern, the next line down is the MAC address 
    #  We would look for the very next line, or add one to this number, and then subtract 1 to get that next line's index.
    #  (or we can say that the line number equals the next one's index number)
    $vMACindex = ($ipresult | Select-String -Pattern $ptnVirtual | select -exp LineNumber)
    
    # For each index we find the MAC and if media is disconnected or not
    foreach ($i in $vMACindex) {
        # Parse the output for each virtual item
        
        # Description
        $thisDesc = [regex]::Match($ipresult[$i-1],'\:\s(.*)$').groups[1].value 
        
        # MAC Address
        $thisMAC =  [regex]::Match($ipresult[$i],'\:\s(.*)$').groups[1].value
        
        # Do we see "Media Disconnected"?
        # If the media is disconected, we see the line 3 above the MAC to say "media disconnected"
        $discIndex = $i - 3
        $isActive = $ipresult[$discIndex] -notmatch 'Media disconnected'
        #Write-Host "$($ipresult[$discIndex])" -f Yellow

        # Output a PS object to allow for conditional OPS in the next pipeline element
        [pscustomobject]@{
            Description = $thisDesc
            MAC = $thisMAC
            isActive = $isActive
        }
    }
} 

function Get-RfaLtNewestComputerId {
    param (
        $URL = "https://automate.rfa.com/RFADL/NewestID.txt"
    )    
    (new-object Net.WebClient).DownloadString($URL).Trim() -as [int]
}
$global:RfaLtNewestComputerId = Get-RfaLtNewestComputerId
