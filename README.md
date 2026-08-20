> A documented, black-box web application security assessment of the intentionally vulnerable `testasp.vulnweb.com` training target. The assessment progresses from passive reconnaissance and technology fingerprinting to network scanning, web-content discovery, vulnerability research, and defensive conclusions.

## Overview

This report demonstrates how common penetration-testing utilities can be combined to build an evidence-based view of a web application's attack surface. It records commands, outputs, observations, and recommended hardening measures for the target's DNS, cloud hosting, IIS/ASP.NET stack, exposed paths, HTTP methods, and application entry points.

**Assessment scope:** `http://testasp.vulnweb.com` and related `vulnweb.com` infrastructure observed during reconnaissance.

**Primary objectives:**

- Identify publicly available domain, DNS, hosting, and email information.
- Fingerprint the web server and application technologies.
- Discover exposed ports, directories, files, parameters, and subdomains.
- Research potential vulnerabilities and configuration weaknesses.
- Document practical remediation steps without attempting destructive exploitation.

## Tools and Binaries Used

| Tool / binary | Purpose in this assessment |
| --- | --- |
| `whois` | Retrieves domain-registration, registrar, status, and nameserver information. |
| `dig` | Performs targeted DNS lookups and displays records and query statistics. |
| `dnsrecon` | Enumerates DNS records, nameservers, MX/TXT records, and DNSSEC status. |
| `WhatWeb` (`whatweb`) | Fingerprints web technologies, server software, cookies, headers, and page titles. |
| `Shodan` | Provides internet-wide host intelligence such as cloud provider, region, ASN, OS, and hostnames. |
| `Gobuster` (`gobuster`) | Brute-forces common directories and files using a wordlist and extensions. |
| `Nmap` (`nmap`) | Scans ports, identifies services and versions, and runs safe NSE scripts for HTTP enumeration, headers, and methods. |
| `Subfinder` (`subfinder`) | Passively discovers subdomains associated with the target domain. |
| `ParamSpider` (`paramspider`) | Finds archived URLs and extracts injectable-looking URL parameters for follow-up review. |
| `Nuclei` (`nuclei`) | Runs template-based checks for known CVEs, exposed files, and security misconfigurations. |
| `Ffuf` (`ffuf`) | Performs fast content discovery while supplying a specific virtual-host `Host` header. |
| `SearchSploit` (`searchsploit`) | Searches the Exploit Database index for relevant public vulnerability references. |
| `Metasploit Framework` (`msfconsole`) | Used for controlled vulnerability and module research; no destructive exploitation is documented here. |
| `cURL` (`curl`, noted as an alternative) | Can manually inspect HTTP responses, headers, and HTTP-method behavior. |

## Report Structure

1. **OSINT** — Domain, DNS, cloud, technology, and web-content reconnaissance.
2. **Network Scanning** — Port, service, version, HTTP-header, and method analysis.
3. **Web Reconnaissance** — Subdomain, parameter, vulnerability-template, and path discovery.
4. **Vulnerability Research** — Research into IIS/ASP.NET exposure, TRACE/XST, and related risks.
5. **Bonus Binary Connection** — Shows how findings from one tool inform the next testing phase.

## Safety and Authorization

This material is intended for authorized security education and testing against the designated vulnerable lab environment. Do not scan or test systems without explicit permission, and avoid denial-of-service activity, credential attacks, data access, or destructive exploitation.
