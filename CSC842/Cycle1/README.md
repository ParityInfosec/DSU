### Credit
** I fully credit Mick Douglas for the original concept and discovery of the debugger to pause and unpause processes. During the initial presentations, Mick showed one application of this concept for combating phishing attempts through pausing child browser processes with a parent process of Outlook [as a result of clicking a link in an email]).  These projects were designed to pause the process so that initial response actions could be taken. If the actions were the result of a good process, it could be safely resumed without the damage of stopping the process. In the event the threat is real, the process could be terminated before significant damage is caused. ** 

### Ransomware 
Building on that idea, this tool is designed to combat ransomware in a similar fashion.  The program leverages windows FileSystemWatcher object through two methods: honeypot filesand rapid file changes. 
I identified 5 different encryption strategies (prioritizations) based on IOCs for common ransomware in the wild. These all begin with files in the user directory, sometimes in varying subfolders (such as Desktop, Documents, Downloads, etc.).  At script initiation, multiple “honeypot” files will be dynamically generated to target these strategies. This should maximize detection chances and help initial triage and variant determinations for incident responders.

### Ransomware File Encryption Strategies

| Strategy             | Ransomware Variant | Description                                                                                          |
|----------------------|--------------------|------------------------------------------------------------------------------------------------------|
| Alphabetical Order   | CryptoLocker       | Encrypts files in alphabetical order by file name.                                                   |
| File Type Priority   | Locky              | Prioritizes certain file types (e.g., documents, spreadsheets) for encryption.                       |
| File Size            | Cerber             | Encrypts smaller files first before proceeding to larger ones.                                       |
| Directory Depth      | WannaCry           | Follows a depth-first approach, encrypting files in the current directory before moving to subdirectories. |
| Random Order         | NotPetya           | Encrypts files in a seemingly random order, making the encryption pattern hard to predict.           |
| Largest File First   | Ryuk               | Prioritizes encrypting the largest files first to maximize impact on critical data.                  |

When the encryption activity is detected, the program will track the process tree and pause the main function and all subprocesses. A pop up notifciation will launch displaying the processes involved and provides the user an option to terminate or to dismiss and continue. For added protection the dismiss option will generate a UAC 
This script could limit User monitoring to “Public”, but if the malware attacks other users first, it may be too late before it hits the watched folder. To counter this, the script builds watcher in the most common default folders in every user directory present in “C:\Users”.

The key behind this tool is that it uses integrated Windows APIs and requires no extra modules or tooling. This is extremely beneficial in environments that require a lot of approvals for modification to software baselines.
