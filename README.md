# Phishing-Email-Analysis

## Case Summary

I was tasked to investigate a phishing email reported by a finance employee in a corporate environment. The email appeared to come from the CEO, urgently requesting the review of a financial document. Given the sensitive nature of the request, it immediately raised suspicion.

As part of the investigation, I needed to determine whether the email was genuinely malicious, identify any Indicators of Compromise (IOCs), and trace the infrastructure associated with the attack. The goal was not only to contain the immediate threat but also to develop an Incident Response (IR) plan to prevent future attacks. 

The project involved a systematic analysis of the email content, embedded links, and the associated IP addresses, while preserving evidence and maintaining the integrity of the IT systems. Each step was carefully documented to ensure reproducibility and accountability in line with cybersecurity best practices.

---

## 📝 Report Summary
The project involved an in-depth analysis and response to the phishing attempt reported by an employee. The email claimed to be from the CEO and urged him to click a link to review an urgent financial document. Investigation revealed that the link directed to a suspicious IP address, confirming the phishing nature of the email.

# Analysis & Forensic Investigation

### Email Analysis
- Identified phishing indicators such as urgency cues, unusual URL format, and lack of a standard email signature.

### Metadata & IP Analysis
- Checked the IP address using **WHOIS** and **VirusTotal**.
- The IP was linked to known malicious activities.

### Link Analysis
- Investigated the URL using **VirusTotal**, revealing a history of malicious activity associated with the domain.

### Containment & Remediation
Immediate steps were taken to neutralize the threat:
- Isolated affected devices to prevent further interaction.
- Secured and preserved digital evidence.
- Monitored network activity using **Wireshark**.
- Disconnected compromised systems from the network.

### Forensic Investigation (Hypothetical if link clicked)
- Reviewed logs for unusual activities.
- Checked for vulnerabilities using **Nmap** and **Nikto**.
- Strengthened security by closing unnecessary ports and updating software.
  
---

## Tools Used

| Tool | Purpose |
|------|---------|
| **WHOIS Lookup** | Provided domain/IP registration details. |
| **VirusTotal** | Identified threats associated with the IP address and URL.  |
| **Wireshark** | Monitored network traffic for anomalies. |
| **Nmap** | Scanned the system and network for vulnerabilities. |
| **Nikto** | Assessed web servers for potential weaknesses. |

---

## Outcome
- Confirmed phishing attack targeting a finance employee.  
- Identified malicious IP and associated infrastructure.  
- Implemented containment measures and preserved evidence.  
- Mitigated potential damage while maintaining IT system integrity.  
- Recommended security enhancements to prevent future attacks.

## Full Report

For a detailed walkthrough of the investigation, including step-by-step analysis, evidence screenshots, and expanded forensic findings, please refer to the full report:

[View Full Report (report.md)](report.md)
