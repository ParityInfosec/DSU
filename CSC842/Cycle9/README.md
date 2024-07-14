# ShutemDown Version 2.0
### Close Up Shop

Video: http://youtube.com....

Github: https://github.com/ParityInfosec/DSU/tree/main/CSC842/Cycle9

## Intro / The Why
When performing penetration tests, we expect all testers to keep rigorous logs and document all actions, but historically this has been a weak area. One of my past testers wrote a paper on how to tackle this issue when working with multiple testers on a mix of scoped systems.  His conclusion was focused on what pentesters can do on their systems to improve logging, but this still can be flawed with dropped data and suffers in situations with multiple open terminals and test applications running simultaneously. 
(Ref: https://www.sans.org/white-papers/39495/)

SHut Em Down (SHED) was designed with a client-centric focus that checks for typical artifacts and running process/connections that could be unintentionally exposing systems to attacks. The output report provides testers with a consolidated summary that cuts time required to inspect systems so they can spend more time reviewing potential issues before leaving.

## BONUS
This tool is designed to check the window of the engagement, but it also can be used prior to execution to baseline systems. This baseline, along with the final report, can be provided in an annex to customers for added comfort that systems were restored to pre-test configurations. Additionally, this can be the start to a general Incident Response tool against any forms of attacks.

# VERSION 2.0 UPDATES

## Three Main Features/Updates:
- Now features a server application to run checks against systems that conform to requirements (remote terminal, admin, etc.)
- Data is now also formatted to JSON standard!
   - This data is now more ingestible to tools and is easier to work with and compare
- Built a JSON comparison tool to look for differences between a baseline check and a post-engagement check


### Options
| Switch | Arguments |  Description |
| ------- | ------ | ----------- |
|  \-S, --start  | MM/DD/YY | Start of the Engagement Window |
|  \-E, --end  | MM/DD/YY | End of the Engagement Window |
|  \-L, --location | ex: C:\Users, /home | Set Top Folder via cli | 
|  \-F, --folder |  | Enable GUI folder browser |
|  \-C, --cli |  | CLI only; disables GUI popups |

## Future Improvements
- Build in forensic tools (file type mismatch via magic number, time stomp finder)
   - I didn't get to this because of the priority of this, but I still see some purpose in getting there
- Expand to SIEM integration
   - This tool features pulling logging back to server and JSON, so the next logical step is a enterprise SIEM
- Introduce encryption for files at rest
   - This complicates the JSON comparison, but based on the vast amount of data now comllected and stored, this is critical for risk mitigation

### Requirements
- Python
#### Modules
- prettytable
- tkinter
- tkcalendar
- psutil
- platform
- ctypes
- pytz
- babel
- re
- psutil

## Pyinstaller
### *Requires: pip install pyinstaller*

Enables users to bring a single, standalone file over to a client system for checking. This avoids the need to install python itself or more libraries when unnecessary, also eliminates introducing vulnerabilities where there were none.

Users must:
1. From a __*non-scoped*__ system (i.e. pentester computer), run the following command.
   - **NOTE**: This MUST be performed on each OS type you desire to test on. This can be emulated via wine and QEMU, but is easiest if prepped ahead of time on native OS hosts and carried on engagements. Additioanlly, the system running pyinstaller is the only one required to have all imports installed.

> pyinstaller --onefile shutemdown.py

2. Transfer to all scoped systems
3. Execute and follow up on items of concern

## References
- https://www.sans.org/white-papers/39495/
- https://docs.python.org/3/library/tkinter.html
- https://pypi.org/project/prettytable/
- https://community.spiceworks.com/t/list-all-ad-users-created-date-created-by-last-logged-in/704680/2
- https://learning.oreilly.com/library/view/macintosh-terminal-pocket/9781449328962/re98.html
