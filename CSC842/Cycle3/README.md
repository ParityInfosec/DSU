# MagentoScan

Video: https://youtu.be/px_GIKOMqGM

## Intro
In the past, I was really interested in webscraping and data collection, but websites have gotten quite complicated. With varying frameworks and languages, it can be deceptively tricky to extract targeted data from sites using a litany of tools: cURL, wget, Puppeteer, Selenium, Mechanize, Postman, etc. The biggest challenge I have routinely encountered has been website’s that go beyond public GET requests and involve more human interaction. 

To access certain points of websites, you need to first login and obtain a session key or some other cookie to identify and provide access to pages. Additionally, you may need to input text or click buttons to perform complex queries. In some cases on Magento, data was not visible because dynamic data can't just be pulled. 

Recently I watched a video demonstrating the tool Playwright and I think it provides a great jumping off point for automating pentest tools. Similar its original intent for testing in a DevSecOps environments, Playwright can be shifted to fit our purposes.

## Magento
Magento is long been on several "Top 5" lists for Commerce sites, indicating a healthy adoption in the market but a smaller marketshare that doesn't draw the full attention of attackers. After Adobe acquired them in 2018, the codebase has been fortified but the support for the Open Source / Community edition has not received the same love as Adobe Commerce. Adobe Commerce is the "easy button" while the Open Source version has a steep technical learning curve which can lead to alot of misconfigured store fronts. In order to enumerate and test target sites for these vulnerabilities, I have put together the tool MagentoScan.

## Three Main Points of the Tool:
- Enumerate services from leaked data
- Perform username enumeration and targeted password spraying to collect credentials
- Use 2Captcha API to solve CAPTCHA checks

### Options
|| Switch | Arguments |  Description |
|- | ------- | ------ | ----------- |
**General** 
||  \-show  |  | Show browser activity |
||  \-key   |  | API key to run normal captcha checks at 2Captcha.com |
**Credentials**
|| \-l | \"user" | Use single user |
|| \-L | \<login.txt> | Use list of users | 
|| \-p | \"passwd" | Use single password (Spray Attack) |
|| \-P | <passwd.txt> | Use list of passwords (Spray Attack) |
**Attack Type**
|| \-lim  || Spray Attack limit \<default=3> | 
|| \-A || Password spray Admin login |
|| \-U || Password spray User login |
|| \-persist || Attempt to establish persistence [Admin creds required] |
|| \-dump || Attempt to dump users [Admin creds required] |

### Examples 
`python3 ./magentoscan.py magento.test -l john.smith -P password123 -A -U -lim 3`

`python3 ./magentoscan.py magento.test -A -L login.txt -P passwd.txt -key <key> -persist -dump -lim 1`
## Playwright 
Courtesy of John Watson Rooney's walkthrough on Playwright, I was able to script out the whole interaction with the `magento.test` website.
* https://www.youtube.com/watch?v=q1GDSHhaH0E

## Areas for Improvement
- Refactoring/Optimization
  - User Login closing and opening browser repeatedly for each username and password could be inefficient.
- Consider adding threading
  - Could expedite password search, but further triggers CAPTCHA checks.

## Python requirements
* Install Playwright (commonly via npm):
  * Install npm via Node.js installer: https://nodejs.org/en/download/prebuilt-installer
  * Install npm via apt: `sudo apt install npm`
  * Install playwright: https://playwright.dev/docs/intro#installing-playwright 
* Install playwright-stealth: `pip install playwright-stealth`
* Install TwoCaptcha: `pip install TwoCaptcha`

## Test Environment
The most amazing reference possible came from a Magento developer and educator, Mark Shust. After countless hours wasted trying to install a test instance of Magento from scratch, I found Mark's *docker-magento* project that installs within "5 minutes". While it may have been closer to 10 or 15 minutes, that's a fraction of time dropped with no product up to this point. His video and GitHub are extremely simple and current to the latest release. Returning to my previous statement, the installation process is full of technical pitfalls and this can cut down on issues for at least test environments.

* https://www.youtube.com/watch?v=qahROPTcBZI
* https://github.com/markshust/docker-magento

###	Webserver VM:
- Ubuntu Desktop 24.04 LTS
- Magento 2.4.7
- Docker-Desktop
- Default setup with credentials as listed on Adobe installer notes:
   - https://experienceleague.adobe.com/en/docs/commerce-operations/installation-guide/composer



## References
* https://playwright.dev/docs
* Captcha evasion:
   * https://netnut.io/playwright-bypass-captcha/?utm_medium=organic&utm_source=google
   * https://www.zenrows.com/blog/playwright-captcha#base-playwright-2captcha
* Magento uses standard CAPTCHA; easy to automate cheaply (~ $1/1000 guesses)
   * https://2captcha.com/
