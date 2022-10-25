# WebHeckScanner
Written by Graham Zemel, using Nikto, Nuclei, Sqlmap, Anew, Gau, and more!

## This is a bash script designed to scan web apps easily, with multiple tools. 
### It uses the following tools (Which must be installed):
[Sqlmap](https://github.com/sqlmapproject/sqlmap), a tool for testing sql injection vulnerabilities which are some of the most dangerous.  
[Nikto](https://github.com/sullo/nikto), a tool for scanning websites written in perl, easy to use, one of my favorites.  
[Nuclei](https://github.com/projectdiscovery/nuclei) is likely the most customizable tool out there for web pentesting,
there's about a million different templates to scan with on Github.   

### Solo Files (Required files that are contained in a single script / file):  
[Anew](https://github.com/tomnomnom/anew): File I/O modification through terminal.    
[Gauplus](https://github.com/bp0lr/gauplus): 'Get All Urls Plus', outdated but still has useful properties.  
[Gau](https://github.com/lc/gau): 'Get All Urls', similar to Subdomainer but I like this tool better.    
[Httpx](https://github.com/projectdiscovery/httpx): Runs a bunch of probes for vulnerabilities, commonly used in combonation with most of these tools.  
[PV](https://github.com/a-j-wood/pv): 'Pipe Viewer', used by some of these tools to print the status of a current scan/process.  
[WayBackUrls](https://github.com/tomnomnom/waybackurls): Neat tool that integrates the waybackmachine as a means of fetching old and possibly useful files that may contain credentials or source code.  

## Installation
### You must install and configure your directory as I have done or change the code if you have tools in your path already
```
$ git clone https://github.com/gzemel/WebHeckScanner
$ cd WebHeckScanner
```
Make sure all tools are installed before continuing
```
$ chmod +x webHeck.sh
$ sudo ./webHeck.sh
```

If there are any permssion errors running the tool files, run ```chmod +x ${toolfile}``` or ```sudo chmod +x ${toolfile}```.  
If there are any errors with the file system or installing, make sure the directory tree matches the one below.  
## Directory Tree Graph  
WebHeckScanner  
-README.md  
-webHeck.sh  
-nikto/  
-nuclei/  
-sqlmap/  
-req_solos/  
--anew  
--gau  
--gauplus  
--httpx  
--pv  
--waybackurls  

## Thanks for using my scripts, feel free to fork this repo and if you could give me credit for the original code I'd appreciate it!
