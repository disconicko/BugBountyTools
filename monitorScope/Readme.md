# Monitor Scope

Monitor scope is a tool to enumerate wide scope targets such as *.example.com. The tool uses tools to find new subdomins, resolve valid HTTP hosts and scan them for vulnerabilities. This tool is a personal project, however if you have any recommendations I would love to add more features.
Before using, please read the Tool Requirements and Before You Start sections. To get the most out of this tool, it should be placed in a cron job to run every hour or two for constant monitoring of wide scope targets. 

When running for the first time:
Make a file called 
./monitor.sh -d {pathToDirectory} -m enumerate 

How to run for continual monitoring:
./monitor.sh -d {pathToDirectory} -m monitor

## Before you start
Monitor scope requirements.
* Install all the Tool Requirements and ensure all the Go tools binaries are referenced in your path variables.
* Install the Tool Requirements and change the notify config to send message directly to your discord. I have three different webhooks setup for different parts of the enumeration process however this is not necessary.
* Ensure that all the tools below are working and that the Go binary path has been added to the PATH environment variable.  

## Tool Requirements
Amass:
https://github.com/owasp-amass

Anew:
https://github.com/tomnomnom/anew

Assetfinder:
https://github.com/tomnomnom/assetfinder

Subfinder:
https://github.com/projectdiscovery/subfinder

Notify:
https://github.com/projectdiscovery/notify

Httprobe:
https://github.com/tomnomnom/httprobe

Nuclei:
https://github.com/projectdiscovery/nuclei
