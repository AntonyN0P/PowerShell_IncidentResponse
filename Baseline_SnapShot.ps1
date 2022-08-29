<##############################################################################
.SYNOPSIS
    Creates a folder with files which capture the current OS state.

.DESCRIPTION
    Creates a folder filled with CSV, XML and TXT files which capture
    the current operational state of the computer, such as running
    processes, services, user accounts, audit policies, shared folders,
    networking settings, and more.  These files can be used for threat
    hunting, auditing, compliance, and troubleshooting purposes.  

    The output folder will be named after the local host and the current
    date and time, e.g., .\COMPUTERNAME-Year-Month-Day-Hour-Minute.

    Script requires PowerShell 3.0, Windows 7, Server 2008, or later,
    and must be run with administrative privileges.  

    Most commands are built into PowerShell 3.0 and later, but some
    tools will need to be installed first in order to use them, such
    as AUTORUNSC64.EXE (https://download.sysinternals.com/files/Autoruns.zip) and
    SHA256DEEP.EXE (https://sourceforge.net/projects/md5deep/files/latest/download).

.PARAMETER OutputParentFolder
    Optional path to the parent folder under which a new subfolder will
    be created to hold the baseline files.  This is not the path to
    the output folder itself, which will be automatically created, but
    to its parent folder.  Defaults to $PWD, the present directory.
    Write access permission is required to the output folder.

.PARAMETER TextFileOutput
    Forces all output files to be flat TXT files instead of XML.

.PARAMETER Verbose
    Show progress information as the script is running.

Requires -Version 3.0  
##############################################################################>

[CmdletBinding()]
Param ([String] $OutputParentFolder = ($Pwd.Path), [Switch] $TextFileOutput) 


#Check the module ThreadJob was installed or install if wasn't.
if (!(Get-Module -ListAvailable -Name ThreadJob)){
    Write-Error -Message "Module for multithreads programming hasn't installed, please accept the installation below."
    Install-Module -Name ThreadJob
}


# Verbose start time:
$StartTime = Get-Date 
Write-Verbose -Message ("Started: " + (Get-Date -Format 'F')) 

#.DESCRIPTION
#   Helper function to write output as XML (default) or as TXT (with -TextFileOutput).
#   Almost every command below pipes into this function.
function WriteOut ($FileName) 
{
    if ($TextFileOutput)
    { 
        Write-Verbose -Message ("Writing to " + ($FileName + ".txt")) 
        $Input | Format-List * | Out-File -Encoding UTF8 -FilePath ($FileName + ".txt") 
    } 
    else 
    { 
        Write-Verbose -Message ("Writing to " + ($FileName + ".xml")) 
        $Input | Export-Clixml -Encoding UTF8 -Path ($FileName + ".xml")
    } 
}


function Job-Check($job){
    Do {
        Start-Sleep -Milliseconds 100
    }
    Until ($job.State -match "Completed|Failed")
    
}

# Confirm that the destination PARENT folder exists:
if (-not (Test-Path -Path $OutputParentFolder -PathType Container))
{
    Write-Error -Message "$OutputParentFolder does not exist or is not accessible, exiting."
    Exit
}

# If this script is run with File Explorer, the present working
# directory becomes C:\Windows\System32, which is not good, so
# disallow $env:SystemRoot or anything underneath it:
if ( $OutputParentFolder -like ($env:SystemRoot + '*') )
{
    Write-Error -Message "Output folder cannot be under $Env:SystemRoot, and script must be run from within a command shell, exiting."
    Exit
}

# Get-Volume | foreach {$_.DriveLetter}


# Record present directory in order to switch back to it later,
# and attempt to switch into $OutputParentFolder now:
$PresentDirectory = $Pwd

# Sysinternals AutoRuns; not in the PATH by default even when
# installed; get from microsoft.com/sysinternals
# Check the autoruns installed in the script directory

if (Test-path $PresentDirectory"\autorunsc64.exe"){
    Start-ThreadJob {.\autorunsc64.exe -accepteula -a * -c | Out-File -FilePath AutoRuns.csv}
}

# SHA256 File Hashes
# Takes a long time! Requires lots of space!
# Add more paths as you wish of course, this is just to get started.
# sha256deep.exe is used instead of Get-FileHash because it's faster.
if (Test-path $PresentDirectory"\sha256deep64.exe"){
    $job1 = Start-ThreadJob {.\sha256deep64.exe -s "c:\*" | Out-File -FilePath Hashes-C.txt} | Get-Job
    $job2 = Start-ThreadJob {.\sha256deep64.exe -s "d:\*" | Out-File -FilePath Hashes-D.txt} | Get-Job
    $job3 = Start-ThreadJob {.\sha256deep64.exe -s -r ($env:PROGRAMFILES + "\*") | Out-File -FilePath Hashes-ProgramFiles.txt} | Get-Job
    $job4 = Start-ThreadJob {.\sha256deep64.exe -s -r ($env:SYSTEMROOT + "\*") | Out-File -FilePath Hashes-SystemRoot.txt} | Get-Job
    Job-Check($job1)
    Job-Check($job2)
    Job-Check($job3)
    Job-Check($job4)
    }elseif (Get-Command -Name Get-FileHash -ErrorAction SilentlyContinue) 
    {
        $job1 = Start-ThreadJob {$hashes = dir -File | Get-FileHash -Algorithm SHA256 -ErrorAction SilentlyContinue
        $hashes | Export-Csv -Path Baseline-File-Hashes.csv -Force}  #cannot directly pipe
        Job-Check($job1)
}



cd $OutputParentFolder
if (-not $?){ Write-Error -Message "Could not switch into $OutputParentFolder, exiting." ; Exit } 



# Set FOLDER variable to contain output files. The format will look
$OutputFolder = $env:COMPUTERNAME + "-" + (Get-Date -Format 'yyyy-MM-dd-hh-mm') 
Write-Verbose -Message "Creating $(Join-Path -Path $OutputParentFolder -ChildPath $OutputFolder)" 


# Create the $Folder in the present working directory and switch into it:
mkdir $OutputFolder | out-null
if (-not $?){ Write-Error -Message "Could not create $OutputFolder, exiting." ; Exit } 


cd $OutputFolder

if ($pwd.Path -ne (Join-Path -Path $OutputParentFolder -ChildPath $OutputFolder))
{ Write-Error -Message "Could not switch into $OutputFolder, exiting." ; Exit } 

# Create README.TXT file to identify this computer and baseline record.

$ReadmeText = @"
*SYSTEM CONFIGURATION BASELINE
*Computer: $env:COMPUTERNAME
*HostName: $(hostname.exe)
*Box-Date: $(Get-Date -Format 'F')
*UTC-Date: $(Get-Date -Format 'U') 
*ZuluDate: $(Get-Date -Format 'u')
*PVersion: $($PSVersionTable.PSVersion.ToString())
*UserName: $env:USERNAME 
*User-Dom: $env:USERDOMAIN
"@

$ReadmeText | Out-File -Encoding UTF8 -FilePath .\README.TXT -Force

if (-not $?)
{ Write-Error -Message "Could not write to README.TXT, exiting." ; Exit } 
else
{ Write-Verbose -Message "Created README.TXT" } 


# Computer System 
Get-CimInstance -ClassName Win32_ComputerSystem | WriteOut -FileName ComputerSystem


# BIOS
Get-CimInstance -ClassName Win32_BIOS | WriteOut -FileName BIOS


# Environment Variables
dir env:\ | WriteOut -FileName Environment-Variables


# Users
Get-CimInstance -ClassName Win32_UserAccount | WriteOut -FileName Users


# Groups
Get-CimInstance -ClassName Win32_Group | WriteOut -FileName Groups


# Group Members
Get-CimInstance -ClassName Win32_GroupUser | WriteOut -FileName Group-Members


# Password And Lockout Policies
net.exe accounts | Out-File -FilePath Password-And-Lockout-Policies.txt


# Local Audit Policy
auditpol.exe /get /category:* | Out-File -FilePath Audit-Policy.txt


# SECEDIT Security Policy Export
secedit.exe /export /cfg SecEdit-Security-Policy.txt | out-null 


# Shared Folders
Get-SmbShare | WriteOut -FileName Shared-Folders

# Networking Configuration
Get-NetAdapter -IncludeHidden | WriteOut -FileName Network-Adapters
Get-NetIPAddress | WriteOut -FileName Network-IPaddresses
Get-NetTCPConnection -State Listen | Sort LocalPort | WriteOut -FileName Network-TCP-Listening-Ports
Get-NetUDPEndpoint | Sort LocalPort | WriteOut -FileName Network-UDP-Listening-Ports
Get-NetRoute | WriteOut -FileName Network-Route-Table
nbtstat.exe -n  | Out-File -FilePath Network-NbtStat.txt
netsh.exe winsock show catalog | Out-File -FilePath Network-WinSock.txt
Get-DnsClientNrptPolicy -Effective | WriteOut -FileName Name-Resolution-Policy-Table


# Windows Firewall and IPSec 
Get-NetConnectionProfile | WriteOut -FileName Network-Connection-Profiles
Get-NetFirewallProfile | WriteOut -FileName Network-Firewall-Profiles
Get-NetFirewallRule | WriteOut -FileName Network-Firewall-Rules
Get-NetIPsecRule | WriteOut -FileName Network-IPSec-Rules
netsh.exe advfirewall export Network-Firewall-Export.wfw | out-null 


# Processes
Get-Process -IncludeUserName | WriteOut -FileName Processes


# Drivers
Get-CimInstance -ClassName Win32_SystemDriver | WriteOut -FileName Drivers


# DirectX Diagnostics
dxdiag.exe /whql:off /64bit /t dxdiag.txt


# Services
Start-ThreadJob {Get-Service | WriteOut -FileName Services}


# Registry Exports (add more as you wish)
Write-Verbose -Message "Writing to registry files: *.reg" 
Start-ThreadJob {reg.exe export hklm\system\CurrentControlSet Registry-CurrentControlSet.reg /y | out-null}
Start-ThreadJob {reg.exe export hklm\software\microsoft\windows\currentversion Registry-WindowsCurrentVersion.reg /y | out-null}


# Generate an MSINFO32.EXE report, which includes lots of misc info
Write-Verbose -Message "Writing to MSINFO32-Report.txt" 
Start-ThreadJob {msinfo32.exe /report MSINFO32-Report.txt}


# Hidden Files and Folders 
Start-ThreadJob {dir -Path c:\ -Hidden -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,Mode,CreationTime,LastAccessTime,LastWriteTime | Export-Csv -Path FileSystem-Hidden-Files.csv}


# Non-Hidden Files and Folders
Start-ThreadJob {dir -Path c:\ -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,Mode,CreationTime,LastAccessTime,LastWriteTime | Export-Csv -Path FileSystem-Files.csv}


# NTFS Permissions And Integrity Labels
# This file can reach 100's of MB in size, so
# we'll limit this example to just System32:
Start-ThreadJob {icacls.exe c:\windows\system32 /t /c /q 2>$null | Out-File -FilePath FileSystem-NTFS-Permissions.txt}

# Record baseline metadata to README.TXT and Baseline-File-Hashes.csv:

# Save info about the baseline output files to README.TXT:
'*Finished: ' + $(Get-Date -Format 'u') | Out-File -Encoding UTF8 -Append -FilePath README.TXT

"-" * 50 | Out-File -Encoding UTF8 -Append -FilePath README.TXT

dir | select Name,Length,LastWriteTime | Out-File -Encoding UTF8 -Append -FilePath README.TXT 


Write-Verbose -Message "Saved files to $(Join-Path -Path $OutputParentFolder -ChildPath $OutputFolder)" 
Write-Verbose -Message ("Finished: " + (Get-Date -Format 'F')) 
$seconds = New-TimeSpan -Start $StartTime -End (Get-Date) | Select -ExpandProperty TotalSeconds
Write-Verbose -Message "Total run time = $seconds seconds"


cd $PresentDirectory

if (Test-path $PresentDirectory"\autorunsc64.exe"){
    Move $PresentDirectory"\AutoRuns.csv" $OutputFolder
}

if (Test-path $PresentDirectory"\sha256deep64.exe"){
Move $PresentDirectory"\Hashes-ProgramFiles.txt" $OutputFolder
Move $PresentDirectory"\Hashes-SystemRoot.txt" $OutputFolder
Move $PresentDirectory"\Hashes-C.txt" $OutputFolder
Move $PresentDirectory"\Hashes-D.txt" $OutputFolder
}else{
Move $PresentDirectory"\Baseline-File-Hashes.csv" $OutputFolder    
}