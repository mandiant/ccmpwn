# Ccmexec.py

`ccmexec.py` - lateral movement script that leverages CcmExec to remotely hijack user sessions.

## Explanation

System Center Configuration Manager (SCCM) clients make use of the CcmExec service, which initiates the execution of **C:\Windows\CCM\SCNotification.exe** for **every logged-on user**. Leveraging the fact that SCNotification.exe is a .NET application, red team operators could modify its configuration file (**C:\Windows\CCM\SCNotification.exe.config**) to execute an AppDomainManager payload or coerce authentications as the affected users. This technique provides operators an alternative approach to credential dumping or process injection. Operators must have local administrator privileges on target system.

`ccmexec.py` can perform the following actions:
- **exec** - execute an AppDomainManager payload for every logged-on user. Specify your `-dll` and malicious `-config` to upload to target
- **coerce** - coerce `smb` or `http` authentication for every logged-on user. Specify computer for users to authentication to `-computer`
- **query** - query logged-on users via WMI
- **status** - query CcmExec service status

## Setup
- `pip3 install impacket`

## Examples

### exec
![til](/images/exec.png "Demo")

![til](/images/beacons.png "Demo")

### coerce
![til](/images/coerce.png "Demo")

![til](/images/smb_auths.png "Demo")

### query
![til](/images/query.png "Demo")

### Credits
- Jake Coyne

