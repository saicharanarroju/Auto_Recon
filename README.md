Subdomain Enumeration: Combines multiple passive and active techniques using industry-standard tools (Subfinder, Sublist3r, Amass) plus multi-level brute-forcing with Gobuster and customizable wordlists to discover as many subdomains as possible for the target domains.

IP Resolution: Resolves discovered subdomains to their IP addresses to identify live infrastructure.

Port Scanning: Uses Nmap to detect open ports and services on discovered IPs to find potential attack vectors.

Cloud Asset Discovery: Integrates CloudHunter to enumerate cloud assets (AWS, Azure, Google Cloud, Alibaba) tied to subdomains, uncovering exposed buckets, storage, and app engines.

Directory Brute Forcing: Employs Dirsearch with user-provided wordlists on discovered live hosts to find hidden directories, files, and endpoints relevant to further exploitation.

Vulnerability Scanning: Integrates Nuclei with community-maintained templates to scan discovered targets for known vulnerabilities with precision but speed.

Live Host Confirmation: Uses httprobe to filter out dead hosts from discovered subdomains, optimizing further assessment.

Parallel Execution: Runs recon for multiple domains concurrently using GNU Parallel, making best use of system resources to significantly reduce total execution time.
