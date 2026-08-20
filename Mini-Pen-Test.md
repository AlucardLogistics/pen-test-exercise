# Mini Penetration Test
### Black Box Analysis for: http://testasp.vulnweb.com

## PART 1 OSINT 

```
whois vulnweb.com
```
Domain Name: VULNWEB.COM  
Registry Domain ID: 1602006391_DOMAIN_COM-VRSN  
Registrar WHOIS Server: whois.gandi.net  
Registrar URL: http://www.gandi.net  
Updated Date: 2026-06-01T05:28:12Z  
Creation Date: 2010-06-14T07:50:29Z  
Registry Expiry Date: 2027-06-14T07:50:29Z  
Registrar: Gandi SAS  
Registrar IANA ID: 81  
Registrar Abuse Contact Email: abuse@support.gandi.net  
Registrar Abuse Contact Phone: +33.170377661  
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited  
Name Server: NS-136.AWSDNS-17.COM  
Name Server: NS-1450.AWSDNS-53.ORG  
Name Server: NS-1588.AWSDNS-06.CO.UK  
Name Server: NS-557.AWSDNS-05.NET  
DNSSEC: unsigned  


```
dig A testapp.vulnweb.com +noall + answer + stats
``` 
;; Query time: 4 msec  
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)  
;; WHEN: Sun Aug 16 02:36:19 EDT 2026  
;; MSG SIZE  rcvd: 126  

```
dnsrecon -d vulnweb.com -t std
```
```
2026-08-16T02:39:51.709200-0400 INFO Starting enumeration for domain: vulnweb.com
2026-08-16T02:39:51.709616-0400 INFO std: Performing General Enumeration against: vulnweb.com...
2026-08-16T02:39:51.750351-0400 ERROR No answer for DNSSEC query for vulnweb.com
2026-08-16T02:39:51.752484-0400 INFO     SOA ns-136.awsdns-17.com 205.251.192.136
2026-08-16T02:39:51.752643-0400 INFO     SOA ns-136.awsdns-17.com 2600:9000:5300:8800::1
2026-08-16T02:39:51.757437-0400 INFO     NS ns-557.awsdns-05.net 205.251.194.45
2026-08-16T02:39:54.797381-0400 INFO     NS ns-557.awsdns-05.net 2600:9000:5302:2d00::1
2026-08-16T02:39:54.797828-0400 INFO     NS ns-1588.awsdns-06.co.uk 205.251.198.52
2026-08-16T02:39:57.818828-0400 INFO     NS ns-1588.awsdns-06.co.uk 2600:9000:5306:3400::1
2026-08-16T02:39:57.819375-0400 INFO     NS ns-1450.awsdns-53.org 205.251.197.170
2026-08-16T02:40:00.855115-0400 INFO     NS ns-1450.awsdns-53.org 2600:9000:5305:aa00::1
2026-08-16T02:40:00.855905-0400 INFO     NS ns-136.awsdns-17.com 205.251.192.136
2026-08-16T02:40:03.882078-0400 INFO     NS ns-136.awsdns-17.com 2600:9000:5300:8800::1
2026-08-16T02:40:03.907695-0400 INFO     MX alt3.aspmx.l.google.com 192.178.211.26
2026-08-16T02:40:03.907895-0400 INFO     MX alt4.aspmx.l.google.com 192.178.158.26
2026-08-16T02:40:03.908138-0400 INFO     MX alt2.aspmx.l.google.com 172.253.152.26
2026-08-16T02:40:03.908207-0400 INFO     MX aspmx.l.google.com 142.251.127.27
2026-08-16T02:40:03.908354-0400 INFO     MX alt1.aspmx.l.google.com 142.250.147.27
2026-08-16T02:40:03.908467-0400 INFO     MX alt3.aspmx.l.google.com 2404:6800:4000:1025::1b
2026-08-16T02:40:03.908528-0400 INFO     MX alt4.aspmx.l.google.com 2404:6800:4013:813::1a
2026-08-16T02:40:03.908623-0400 INFO     MX alt2.aspmx.l.google.com 2a00:1450:4010:c22::1a
2026-08-16T02:40:03.908761-0400 INFO     MX aspmx.l.google.com 2a00:1450:4001:c21::1a
2026-08-16T02:40:03.908836-0400 INFO     MX alt1.aspmx.l.google.com 2a00:1450:4025:c01::1a
2026-08-16T02:40:03.910776-0400 INFO     A vulnweb.com 44.228.249.3
2026-08-16T02:40:03.914068-0400 INFO     TXT vulnweb.com v=spf1 ~all
2026-08-16T02:40:03.914276-0400 INFO     TXT vulnweb.com google-site-verification=4LQORV-lTi-d4GPxtBEQWmFnwff7UAazQc9gZvHukbw
```
```
whatweb -a 3 http://testasp.vulnweb.com**  
```
```
http://testasp.vulnweb.com [200 OK] ASP_NET, Cookies[ASPSESSIONIDACCTSBTA], Country[UNITED STATES][US], HTTPServer[Microsoft-IIS/8.5], IP[44.238.29.244], Microsoft-IIS[8.5], Title[acuforum forums], X-Powered-By[ASP.NET]
```


Shodan Search: 
```
https://www.shodan.io/host/44.238.29.244
```
```
	GeneralInformation
	Hostnames
	ec2-44-238-29-244.us-west-2.compute.amazonaws.com
	Domains
	Cloud Provider
	Amazon
	Cloud Region
	us-west-2
	Cloud Service
	EC2
	Country
	United States
	City
	Boardman
	Organization
	Amazon.com, Inc.
	ISP
	Amazon.com, Inc.
	ASN
	AS16509
	Operating System
	Windows
```
```
gobuster dir -u http://testasp.vulnweb.com -w /usr/share/wordlists/dirb/common.txt -x asp,aspx,html,txt** 
```
```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://testasp.vulnweb.com
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              asp,aspx,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
_vti_cnf             (Status: 301) [Size: 159] [--> http://testasp.vulnweb.com/_vti_cnf/]
aspnet_client        (Status: 301) [Size: 164] [--> http://testasp.vulnweb.com/aspnet_client/]
avatars              (Status: 301) [Size: 158] [--> http://testasp.vulnweb.com/avatars/]
cgi-bin              (Status: 301) [Size: 158] [--> http://testasp.vulnweb.com/cgi-bin/]
cgi-bin/             (Status: 403) [Size: 1233]
db.asp               (Status: 200) [Size: 0]
DB.asp               (Status: 200) [Size: 0]
default.asp          (Status: 200) [Size: 3497]
Default.asp          (Status: 200) [Size: 3497]
html                 (Status: 301) [Size: 155] [--> http://testasp.vulnweb.com/html/]
HTML                 (Status: 301) [Size: 155] [--> http://testasp.vulnweb.com/HTML/]
images               (Status: 301) [Size: 157] [--> http://testasp.vulnweb.com/images/]
Images               (Status: 301) [Size: 157] [--> http://testasp.vulnweb.com/Images/]
jscripts             (Status: 301) [Size: 159] [--> http://testasp.vulnweb.com/jscripts/]
login.asp            (Status: 200) [Size: 3194]
Login.asp            (Status: 200) [Size: 3194]
logout.asp           (Status: 302) [Size: 132] [--> Default.asp]
register.asp         (Status: 200) [Size: 3617]
robots.txt           (Status: 200) [Size: 13]
robots.txt           (Status: 200) [Size: 13]
search.asp           (Status: 200) [Size: 2809]
Search.asp           (Status: 200) [Size: 2809]
showthread.asp       (Status: 302) [Size: 132] [--> Default.asp]
t                    (Status: 301) [Size: 152] [--> http://testasp.vulnweb.com/t/]
T                    (Status: 301) [Size: 152] [--> http://testasp.vulnweb.com/T/]
templates            (Status: 301) [Size: 160] [--> http://testasp.vulnweb.com/templates/]
Progress: 23065 / 23065 (100.00%)
===============================================================
Finished
===============================================================
```

### FINDINGS/CONCLUZII
**1. Cloud Infrastructure (AWS EC2)**  
	Tools: whois, dnsrecon, Shodan  
	Discovery: IP 44.238.29.244 and the nameservers belong to AWS (us-west-2 / Route 53).Utility: Establishes legal boundaries (no DoS on AWS infrastructure) and guides testing toward specific cloud vectors (e.g., SSRF targeting the AWS Metadata Service 169.254.169.254).  

**2. Technology Stack (Microsoft-IIS/8.5 pe Windows)**  
	Tools: whatweb, Shodan  
	Discovery: Microsoft-IIS/8.5 server, ASP.NET backend, ASPSESSIONID cookie (Windows Server 2012/2012 R2).Utility: Eliminates irrelevant payloads (Linux/PHP) and directs attacks toward vulnerabilities specific to the Microsoft stack (.NET deserialization, IIS Short Name enumeration, paths with ).  

**3. Security DNS & E-mail (No DNSSEC, SPF Softfail)**  
	Tools: dnsrecon  
	Discovery: DNSSEC is unconfigured (unsigned), and the SPF record uses the permissive ~all (Softfail) rule.Utility: Signals spoofing/MITM risks on DNS queries and allows phishing simulations using @vulnweb.com addresses without the messages being directly rejected by email servers.  

**4. Web Attack Surfaces (login.asp, _vti_cnf)**  
	Tools: gobuster  
	Discovery: Active interaction points (login.asp, search.asp) and residual Microsoft FrontPage directories (_vti_cnf).Utility: Maps out primary vectors for SQL Injection and authentication bypass, while _vti_cnf can expose metadata and internal configuration files.  

**5. Outsourced Email Service (Google Workspace)**  
	Tools: dnsrecon  
	Discovery: MX records point to Google servers (aspmx.l.google.com), isolated from the web server.Utility: Clarifies the target architecture; compromising the IIS web server does not provide a direct pivot to an on-premise email server.  
	
## PART 2 NETWORK SCANNING

```
nmap -sS --top-ports 1000 -T3 44.238.29.244
```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 04:14 -0400    
Nmap scan report for ec2-44-238-29-244.us-west-2.compute.amazonaws.com (44.238.29.244)    
Host is up (0.19s latency).  
Not shown: 999 filtered tcp ports (no-response)  
PORT   STATE SERVICE  
80/tcp open  http  

Nmap done: 1 IP address (1 host up) scanned in 14.01 seconds  

**Explanation of the options used:**  
`-sS` (SYN / Half-Open Scan): Sends only a SYN packet and waits for the server's SYN-ACK response. It responds with RST without completing the TCP connection (it does not send the final ACK).  
**Purpose:** It is fast and efficient, and avoids recording complete sessions in application logs.  
`--top-ports 1000` (Common Ports): Scans only the 1,000 most frequently used TCP ports in the Nmap database.  
**Purpose:** Avoids scanning all 65,535 ports, reducing excessive traffic and the risk of being blocked by AWS port-scanning detection mechanisms.  
`-T3` (Normal Timing): Sets the scan speed to the standard level.  
**Purpose:** Provides an ideal balance between speed and stability, preventing rate-limiting rules (limits on the number of requests per second) from being triggered on routers or firewalls.
	
```
nmap -sV -sC -p 80,443 44.238.29.244
```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 04:17 -0400  
Host is up (0.20s latency).  

PORT    STATE    SERVICE VERSION  
80/tcp  open     http    Microsoft IIS httpd 8.5  
| http-methods:   
|_  Potentially risky methods: TRACE  
|_http-title: IIS Windows Server  
|_http-server-header: Microsoft-IIS/8.5  
443/tcp filtered https  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/  
Nmap done: 1 IP address (1 host up) scanned in 15.71 seconds  

**Explanation of the options used:**  
`-sV` (Service / Version Detection): Sends specific probes to open ports and analyzes the response packets to determine the exact software and version (e.g., Microsoft-IIS/8.5).  
**Purpose:** Enables precise identification of the technologies in use so that known vulnerabilities (CVEs) can be researched later.  
`-sC` (Default Scripts): Executes a standard set of Nmap Scripting Engine (NSE) scripts categorized as safe.  
**Purpose:** Automatically extracts basic useful information, such as SSL/TLS certificate details, the web page title, or HTTP response headers.  
`-p 80,443` (Web Port Targeting): Limits the scan to ports confirmed to be of interest.  
**Purpose:** Saves time and prevents unnecessary packets from being sent to closed ports.

```
nmap -p 80,443 --script http-enum,http-headers,http-methods 44.238.29.244
```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 04:19 -0400  
Nmap scan report for ec2-44-238-29-244.us-west-2.compute.amazonaws.com (44.238.29.244)  
Host is up (0.20s latency).  

PORT    STATE    SERVICE  
80/tcp  open     http  
| http-methods:   
|   Supported Methods: OPTIONS TRACE GET HEAD POST  
|_  Potentially risky methods: TRACE  
| http-headers:   
|   Content-Length: 701  
|   Content-Type: text/html  
|   Last-Modified: Mon, 16 Nov 2020 14:34:05 GMT  
|   Accept-Ranges: bytes  
|   ETag: "c6bdf18825bcd61:0"  
|   Server: Microsoft-IIS/8.5  
|   X-Powered-By: ASP.NET  
|   Date: Sun, 16 Aug 2026 08:20:00 GMT  
|   Connection: close  
|     
|_  (Request type: HEAD)  
443/tcp filtered https  
Nmap done: 1 IP address (1 host up) scanned in 522.84 seconds  

**Explanation of the options used:**  
`-p 80,443` (Targeted Web Ports): Focuses execution on the HTTP/HTTPS infrastructure.
--script http-enum (Path/Directory Enumeration): Searches for known files and directories on web servers (e.g., administration pages, temporary directories).  
**Purpose:** Discovers sensitive directories or files overlooked in the application.  
`--script http-headers` (HTTP Header Analysis): Extracts all response headers sent by the web server.  
**Purpose:** Reveals underlying technologies (e.g., X-Powered-By: ASP.NET) or session cookies.  
`--script http-methods` (HTTP Method Detection): Tests which HTTP methods are allowed on the server (GET, POST, PUT, DELETE, OPTIONS).  
**Purpose:** Identifies improperly enabled dangerous methods (such as PUT for unauthorized file uploads).  
	
**Main Findings**  
Minimized Attack Surface at the TCP Level: Only port 80 (HTTP) is directly exposed. Port 443 (HTTPS) is filtered, meaning that the server does not use SSL/TLS encryption or that secure access is blocked at the AWS/system firewall level.  
Technology Stack Confirmation: The server runs Microsoft-IIS/8.5 on a Windows Server operating system (2012 / 2012 R2), with ASP.NET as its backend.  
Dangerous HTTP Method Enabled (TRACE): The server accepts the TRACE method, creating a risk of Cross-Site Tracing (XST) attacks.  
An attacker can use XST to bypass the security flags of cookies (HttpOnly) and steal them from users' sessions.  
Technology Information Disclosure (Info Disclosure): The server explicitly exposes the web server version (Microsoft-IIS/8.5) and framework (ASP.NET) through HTTP response headers (Server and X-Powered-By), simplifying an attacker's search for specific exploits.
	
## 3 WEB RECONNASSANCE

```
subfinder -d vulnweb.com -o subdomains.txt  //ofc the subdomains.txt rests safe on my VM  ;>
```
[INF] Enumerating subdomains for vulnweb.com  
virus.vulnweb.com  
viruswall.vulnweb.com  
antivirus1.vulnweb.com  
testaspnet.vulnweb.com  
testhmtml5.vulnweb.com  
testphp.vulnweb.com  
phptest.vulnweb.com  
testsp.vulnweb.com  
tetphp.vulnweb.com  
www.vulnweb.com  
www.virus.vulnweb.com  
odincovo.vulnweb.com  
testasp.vulnweb.com  
www.test.php.vulnweb.com  
testpphp.vulnweb.com  
php.vulnweb.com  
rest.vulnweb.com  
testhtml5.vulnweb.com  
test.php.vulnweb.com  
u003etestasp.vulnweb.com  
[INF] Found 20 subdomains for vulnweb.com in 1 second 312 milliseconds  

```
paramspider -d testapp.vulnweb.com
```                                                                                     
[INFO] Fetching URLs for testapp.vulnweb.com  
Error fetching URL https://web.archive.org/cdx/search/cdx?url=testapp.vulnweb.com/*&output=txt&collapse=urlkey&fl=original&page=/. Retrying in 5 seconds...  
[INFO] Found 21 URLs for testapp.vulnweb.com  
[INFO] Cleaning URLs for testapp.vulnweb.com  
[INFO] Found 17 URLs after cleaning  
[INFO] Extracting URLs with parameters  
[INFO] Saved cleaned URLs to results/testapp.vulnweb.com.txt  
└─$ cat results/testapp.vulnweb.com.txt   
http://testapp.vulnweb.com/listproducts.php?cat=FUZZ  
http://testapp.vulnweb.com/hpp/?pp=FUZZ  

```
nuclei -l subdomains.txt -tags cve,misconfig,exposure -severity medium,high,critical
```
	[mysql-dump] [http] [medium] http://rest.vulnweb.com/db.sql [paths="/db.sql"]
	[wordpress-db-exposure] [http] [high] http://rest.vulnweb.com/db.sql [paths="/db.sql"]
	[INF] Scan completed in 7m. 2 matches found.
	[INF] HTTP connections: 23724 total, 13270 new, 10454 reused (44.1%)

Scop: Scanează rapid lista de subdomenii găsite de subfinder și aplicația testapp.vulnweb.com pentru vulnerabilități cunoscute (CVE-uri IIS/ASP.NET, fișiere sensibile expuse, configurații greșite de securitate).

```	
ffuf -u http://44.238.29.244/FUZZ -H "Host: testapp.vulnweb.com" -w /usr/share/wordlists/dirb/common.txt -e .asp,.aspx -t 5 -p 0.1  
```

	 :: Method           : GET
	 :: URL              : http://44.238.29.244/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Header           : Host: testapp.vulnweb.com
	 :: Extensions       : .asp .aspx 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 5
	 :: Delay            : 0.10 seconds
	 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
	________________________________________________

							[Status: 200, Size: 701, Words: 27, Lines: 32, Duration: 195ms]
	aspnet_client           [Status: 301, Size: 164, Words: 9, Lines: 2, Duration: 203ms]
	:: Progress: [13842/13842] :: Job [1/1] :: 16 req/sec :: Duration: [0:13:52] :: Errors: 0 ::
	
**ffuf Scan Conclusion**  
Technology Stack Confirmation: The discovery of the /aspnet_client directory (Status 301) confirms the presence of the Microsoft IIS / ASP.NET environment on the target server (44.238.29.244) with 100% certainty.  
Cause of Limited Results: The small number of paths found was due to using the Host header: testapp.vulnweb.com (associated with PHP applications), which caused the IIS server to serve only the default page (701 bytes).  
The scan demonstrates the basic IIS structure, and changing the Host header to testasp.vulnweb.com will map the application's actual .asp routes.
	
## 4 VULNERABILTY RESEARCH

**IIS 8.5 Search / Detection:**  
whatweb http://testasp.vulnweb.com/  
Description: This query returned Server: Microsoft-IIS/8.5 in the response headers, allowing the web server technology and exact version to be identified before beginning the vulnerability research phase.  

**HTTP TRACE Search / Detection:**  
nmap --script http-methods -p 80 testasp.vulnweb.com  
Description: This query tested the HTTP methods supported by the server and confirmed that the TRACE method was enabled, exposing the application to Cross-Site Tracing (XST) risks.  

**Local Database Limitation:**   
Searching the searchsploit utility and the msfconsole framework for the exact string “Microsoft IIS 8.5” returned no active pre-authentication RCE modules, suggesting that the operating system kernel's patch level is up to date.  

**Advisory-Based Research (NVD):** 
Extending the research to the underlying components identified by WhatWeb (IIS 8.5 / HTTP.sys) indicates the historical presence of critical risks 
at the kernel driver level (e.g., MS15-034), demonstrating the need for a configuration audit.

**Specific Configuration and Application Risks:**  
Based on the ASP.NET technology fingerprint and the discovered files (login.asp, search.asp), the research focused on Information Disclosure risks (version exposure in headers and FrontPage directories) and logical Injection risks in accordance with the OWASP methodology.  

### Online findings:
**Conclusions and Potential Vulnerabilities (Microsoft IIS 8.5 & TRACE)**  
1. Technology and Historical Analysis  
	General status: The Microsoft IIS 8.5 server (running on Windows Server 2012 R2) does not present direct critical unauthenticated remote code execution (RCE) vulnerabilities in its basic configuration, but it is exposed to misconfiguration risks and path-processing issues (e.g., CVE-2017-0055 / MS17-016 — an XSS vulnerability through UNC path manipulation).
2. Main Attack Vectors and Risks  
	Malicious Extensions and Modules: The possibility of installing non-standard modules in the IIS pipeline (w3wp.exe) for persistence. 
    WebDAV Misconfigurations: Risk of unauthorized file uploads (.asp/.aspx) through improperly permitted HTTP methods (PUT).  
	Sensitive Information Disclosure: Detailed exposure of application errors or versions in HTTP headers, facilitating targeted attacks (e.g., SQL Injection).  
3. Remediation and Hardening Measures  
	Patching: Applying Windows security updates for system components (HTTP.sys).  
	Disabling Unnecessary Features: Stopping the WebDAV service, directory browsing, and dangerous HTTP methods (TRACE).  
	Header Concealment: Removing version information (Server, X-Powered-By) from HTTP responses.  

1. Description of the TRACE Risk  
	What Is XST: Enabling the HTTP TRACE method allows the server to reflect the received request back in the response body, exposing sensitive data through Cross-Site Tracing.  
	Bypassing HttpOnly Protections: Although cookies marked with the HttpOnly flag are protected from direct theft through XSS scripts, an XST attack can force the server to reflect these cookies as plain text, enabling session compromise.  
	Disclosure of Intermediate Headers: This may expose internal authentication tokens or IP addresses added by security devices behind the infrastructure (proxies, WAFs).
2. Browser-Side Mitigation vs. Active Risk  
	Although modern browsers prevent page scripts from executing TRACE requests, the risk remains active through APIs, command-line utilities (cURL), or third-party extensions, and can be used to map the infrastructure.  
3. Remediation and Hardening for IIS  
	Standard solution: Completely disable the TRACE method on the production web server.
	Implementation on Microsoft IIS: Use the native IIS Request Filtering module to explicitly block the TRACE verb.  
	
## 6 BONUS BINARY CONNECTION
Step 1: WhatWeb (or cURL) → identified the exact web server version (Microsoft-IIS/8.5) from the HTTP headers.  
Step 2: Nmap (using the http-methods script) → tested the identified web server and discovered that the dangerous TRACE method was enabled.  
Step 3: Searchsploit / Metasploit vulnerability search (e.g., MS15-034 / RCE) for the previously identified version (IIS 8.5).