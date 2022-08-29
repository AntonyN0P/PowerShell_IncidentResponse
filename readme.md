Add files via upload
PowerShell script for take a snapshots of hosts (Baseline). Take snapshot or host BaseLine, is good practice in Incident Response cause you have opportunity to compare host before intrusion and after, set differences between policies, services, processes, files hashes etc.
The script created with multithreading programming for some cmdlets (once you start, script'll check ThreadJob powershell module for multithreading programming and suggest to install, if module wasn't found on host), it's more faster.
And for more information you can use autorunsc64.exe and sha256deep64.exe for make hashes.
Script gather:
- Audit-Policy;
- BIOS information;
- ComputerSystem information;
- Info about drivers;
- dxdiag info;
- Environment-Variables info;
- FileSystem existing files and hidden filesystem files;
- FS NTFS permissions;
- Group-Members;
- Groups;
- MSINFO;
- Name-Resolution-Policy-Table;
- Network-Adapters;
- Net. connections profiles;
- Network-Firewall-Export;
- Network-Firewall-Profiles;
- Network-Firewall-Rules;
- Network-IPaddresses;
- Network-IPSec-Rules;
- Network-NbtStat;
- Network-Route-Table;
- Network-TCP-Listening-Ports;
- Network-UDP-Listening-Ports;
- Network-WinSock;
- Password-And-Lockout-Policies;
- Processes;
- Registry-CurrentControlSet;
- Registry-WindowsCurrentVersion;
- SecEdit-Security-Policy;
- Shared-Folders;
- Users;
- Hashes of all SystemRoot's files;
- Hashes of all ProgramFiles;
- Hashes of all files on volumes;
- And big AutoRuns's report (If you use autorunsc64.exe together in script's directory).
