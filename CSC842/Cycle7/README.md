# ShutemDown
### Close Up Shop

Other options (like www.osforensics.com) can test for misnamed files, but it is not a open source/free option. Look to make OS agnostic to reduce over-burden of different types and versions performing similar functions.

## Todo
- Determine OS/arch           [done]
    - Need to match up the correct library for the python-magic checks
- os.walk() the system        [DONE]
  > for _ , _ , file in os.walk("/")       [DONE]
    -  Perform timestomp check         [Perform with pytsk3 or create my own?]
    -  Was this in the engagement window [DONE]
       -  If no, break
    -  Perform file mismatch check
       - If possible misnamed, is a critical file type or magic code?
       - Does it contain things like php code in non-php
- Check /etc/hosts for any 127.0.0.1         [DONE]
   - Add checks for other /etc/hosts entries that bypass DNS?  regex [x.x.x.x name\.**]   [done]
- Check for any listeners and the processes attached (with user)? psutil         [done]
- Check for +x properties           [done]

### Arguments
- Engagement Start   [DONE]
- Engagement Stop    [DONE]
- Starting location (if not desired to be root folder)   [DONE]
   - tkinter file select popup       [DONE]


### Requirements
- Python
- python-magic
   - pip install python-magic
- libhash [ Not Yet ]
- prettytable
- tkinter
- tkcalendar
- psutil
- platform
