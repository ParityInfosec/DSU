# ShutemDown
### Close Up Shop

Other options (like www.osforensics.com) can test for misnamed files, but it is not a open source/free option. Look to make OS agnostic to reduce over-burden of different types and versions performing similar functions.

## Todo
- Determine OS/arch
    - Need to match up the correct library for the python-magic checks
- os.walk() the system
  > for _ , _ , file in os.walk("/")
    -  Perform timestomp check
    -  Was this in the engagement window
       -  If no, break
    -  Perform file mismatch check
       - If possible misnamed, is a critical file type or magic code?
       - Does it contain things like php code in non-php
- Check /etc/hosts for any 127.0.0.1
- Check for any listeners and the processes attached (with user)?
- Check for +x properties


? Looks like capa
-  reuse their code for the MITRE attack and threat info?

### Arguments
- Engagement Start
- Engagement Stop (defaults to present/now())
- Starting location (if not desired to be root folder)
   - tkinter file select popup


### Requirements
- Python
- python-magic
   - pip install python-magic
- libhash
