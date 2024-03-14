# ccmpwn.py

`ccmpwn.py` - lateral movement script that leverages CcmExec to remotely hijack user sessions.

## Explanation

System Center Configuration Manager (SCCM) clients make use of the CcmExec service, which initiates the execution of **C:\Windows\CCM\SCNotification.exe** for **every logged-on user**. Leveraging the fact that SCNotification.exe is a .NET application, red team operators could modify its configuration file (**C:\Windows\CCM\SCNotification.exe.config**) to execute an AppDomainManager payload or coerce authentications as the affected users. This technique provides operators an alternative approach to credential dumping or process injection. Operators must have local administrator privileges on target system.

`ccmpwn.py` can perform the following actions:
- **exec** - execute an AppDomainManager payload for every logged-on user. Specify your `-dll` and malicious `-config` to upload to target
- **coerce** - coerce `smb` or `http` authentication for every logged-on user (`-method`). Specify computer for users to authentication to `-computer`
- **query** - query logged-on users via WMI
- **status** - query CcmExec service status

## Setup
- `pip3 install impacket`

## Examples

### exec

![image](https://github.com/googlestaging/ccmpwn/assets/32691065/7a40220b-91e3-4670-bc59-1736b83122b6)

![image](https://github.com/googlestaging/ccmpwn/assets/32691065/e0c73bfe-24d1-4695-875d-6facd3085652)

### coerce

![image](https://github.com/googlestaging/ccmpwn/assets/32691065/1fb5b1d4-2b3b-46aa-ae66-a2b2a85067f0)

![image](https://github.com/googlestaging/ccmpwn/assets/32691065/8784f699-8f09-478b-a538-ee02bd94f960)

### query
![image](https://github.com/googlestaging/ccmpwn/assets/32691065/01239203-bded-4264-9b0c-8e9db2832242)



