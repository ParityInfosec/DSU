# Expander-Check
This is a Python script which redirects known url shortners to localhost, resolves full link, determines if domain is a threat (via virustotal API), provides popup to approve or block, and redirects appropriately.

## DESCRIPTION
This script will allow users to gain awareness on URL shortner redirects prior to following in case of malicious redirects.
* Note: This script is only created to handle known sites and immediate redirects. Cannot handle custom vanity URLs without adding to the shortURLs array

This is developed with some Windows specific coding for port redirection and system calls

## REQUIREMENTS
- Script needs to be run as Administrator
  * It is best suited as a scheduled job / run on start task
- VirusTotal API key
  * Free keys are available with a limit: 4 lookups / min; Daily quota	500 lookups / day
- Non-standard Python modules
  * Install using "pip install <module>"
  * requests
  * TKinter 

## Three Main Tool Points
- Prevent obfuscated traffic from automatically redirecting
- Check links for VirusTotal data on the URL/domain
- Provide situational awareness to users

## Why I'm Interested
Primarily this was written for the context of phishing, similar to a pause-process alert function developed by Mick Douglas (SANS Principal Instructor, Incident Responder). This tool allows anytime a website is entered or a link is clicked that belongs to the top URL shortening services (i.e. bit.ly), it stops any uncontrolled traffic from reaching out until information is displayed.

Additionally, this can be extended to environments where you must remain inside of a boundary, such as in some pentesting engagements. In cases where you are trying to use vanity URLs to avoid detection, you may create various links that must be obfuscated but with the smallest observable footprint. By housing this inside a localhost, you can manage the access down and verify links prior to transmitting and "tipping your hand".

## Further Areas of Improvement
- Refactoring for optimization
- Expand to OS-agnostic coding or develop separate scripts for Windows, Linux, etc.
- Cross-reference multiple data sources for a custom malware "score"
- Build in a malware list checker that always denies malicious domains with no user option to continue

## Resources
Virus Total API - https://docs.virustotal.com/reference/overview
