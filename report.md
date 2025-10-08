## Case Background  
I was tasked to investigate a phishing email reported by a finance employee in a corporate environment. The email appeared to come from the CEO, urgently requesting the review of a financial document.
The email contained a suspicious link:  

<img width="561" height="205" alt="image" src="https://github.com/user-attachments/assets/64895b3d-1e0b-4f5e-ab1f-0048583fa0a4" />

Given the sensitive nature of the request and the urgency implied, the message immediately raised suspicion. The purpose of this investigation was to determine whether the email was malicious, analyze its technical components, and identify the threat actor infrastructure behind it.

## Email Analysis

Upon reviewing the email, several clear indicators of a phishing attempt were identified.

1. **Urgency Cues:**  
The email used a strong, urgent tone, pressuring the recipient (John) to act quickly. This sense of urgency is a common social engineering tactic used to trigger immediate, uncritical actions.

2. **Suspicious URL:**  
The link used the format `hxxp` instead of `http` — a common obfuscation method attackers use to bypass automated detection tools while making the link appear legitimate.

3. **Impersonation:**  
Although the message claimed to be from the CEO, it lacked the official email signature typically used in corporate communications. This inconsistency suggested identity spoofing.

These findings collectively confirmed that the email was a targeted phishing attempt likely designed to steal credentials or deliver malware to a finance system.

---

## Metadata and IP Analysis

To better understand the origin of the email and the infrastructure behind it, I conducted a **WHOIS lookup** on the IP address `23.94.182.50`.

**WHOIS Findings:**  
- The IP is part of a range allocated to **HostPapa**, a hosting provider based in Buffalo, New York.  
- The subnet `23.94.182.0/26` is reassigned to **ColoCrossing**, an organization operating from the same address.  
- Both entities have previously been associated with hosting malicious infrastructure.

<img width="652" height="1170" alt="image" src="https://github.com/user-attachments/assets/013c40e1-8fbc-4cf8-97a7-a00cb19d694c" />

<img width="650" height="594" alt="image" src="https://github.com/user-attachments/assets/04b78580-cc0c-4ef2-82c7-89e8d2393272" />

Cross-referencing this information with internal systems confirmed that the sender was not our CEO and that the IP address was external and unrelated to any legitimate corporate asset.

- **VirusTotal Findings:**  
A scan of the IP address on VirusTotal revealed that **11 out of 92 security vendors** had flagged it as malicious. The IP had a history of association with malware distribution and phishing activity.  
These findings confirmed that the phishing email originated from a known malicious infrastructure.

<img width="808" height="363" alt="image" src="https://github.com/user-attachments/assets/cc69f2f6-91f6-4e59-bb7f-6a620a57feb6" />

---

## Link Analysis

The hyperlink in the email (`hxxp://retajconsultancy.com`) immediately raised red flags due to its unusual formatting and suspicious domain name. Using **VirusTotal**, I found the following:

- The domain was first flagged as malicious on **February 3, 2016**.  
- The most recent detection occurred on **July 25, 2024**.  
- Multiple security vendors consistently categorized it as phishing-related.  

The domain’s long history of malicious activity and continuous detection reinforced the conclusion that this was a deliberate phishing campaign.

<img width="804" height="354" alt="image" src="https://github.com/user-attachments/assets/18c8abe1-9c0c-4ee0-a241-40370ef29fe9" />

This persistent detection across years highlights that the URL is part of a **phishing scheme designed to deceive and harm recipients**.

<img width="808" height="368" alt="image" src="https://github.com/user-attachments/assets/5469ba59-9cff-4968-b63d-4fad6da0b1ad" />

The URL is confirmed to be **dangerous and malicious**, further validating that the email was a **phishing attempt** aimed at:  
- Compromising sensitive information.  
- Distributing malware to corporate systems.  

---

## Incident Response
After confirming that the email was malicious, immediate response actions were taken to contain the threat and preserve evidence.

1. **Isolation:** Affected devices were immediately disconnected from the network to prevent lateral movement or data exfiltration.  
2. **Preservation:** All relevant digital evidence, including email headers, logs, and network data, was preserved to maintain integrity and ensure proper chain of custody.  
3. **Monitoring:** Network traffic was actively monitored using **Wireshark** to detect any anomalies or ongoing connections to malicious domains.  
4. **System Disconnection:** Any system suspected of compromise was fully isolated pending forensic review.

---

## Employee Interview
To assess potential exposure, the affected employee (John) was interviewed to determine:
- Whether he had replied to the email.  
- Whether he had clicked the suspicious link.  

These details were crucial for understanding the potential impact, identifying evidence, and evaluating the need for further forensic investigation.

---

## Communication and Coordination
The findings were immediately escalated to the IT Security and Management teams. A joint meeting was held with key stakeholders to present initial findings and coordinate next steps.  
The response included:
- Informing employees about the phishing attempt.  
- Reinforcing awareness through an internal security bulletin.  
- Reviewing current email filtering and authentication controls.

This collaborative communication ensured transparency, swift decision-making, and consistent messaging across the organization.

---

## Containment and Remediation
The following steps were executed to fully contain the incident and strengthen defenses:

- **Device Isolation:** Disconnected affected systems from the corporate network.  
- **Evidence Preservation:** Archived relevant email headers, logs, and metadata.  
- **Network Monitoring:** Used Wireshark to observe any unusual network behavior.  
- **Vulnerability Scanning:** Performed Nmap and Nikto scans to assess system exposure.  
- **System Hardening:** Closed unnecessary ports, updated vulnerable software, and reviewed firewall rules.

All actions were documented according to standard incident response procedures to maintain traceability and accountability.

---

## Compliance and Evidence Handling
All investigative steps were recorded within a formal chain of custody. This ensured:
- Evidence integrity for any potential legal or regulatory review.  
- Adherence to internal and external compliance requirements.  
- Preservation of transparency and procedural accuracy.

If sensitive data had been exposed, regulatory disclosure procedures would have been initiated per compliance policy.

---

## Forensic Investigation (Hypothetical Scenario)
Had the link been clicked, a deeper forensic investigation would have been initiated to determine system compromise.

This process would have included:
- **Log Analysis:** Reviewing authentication logs, network logs, and system events for suspicious activity.  
- **IOC Extraction:** Identifying attacker IPs, timestamps, and potential malware behavior.  
- **Vulnerability Scans:** Using Nmap and Nikto to identify open ports, outdated services, or misconfigurations.  
- **Remediation:** Applying patches, removing malicious artifacts, and validating system integrity.

These actions would ensure the complete eradication of any threat and restoration of a secure operating environment.

---

## Prevention Measures
To strengthen defenses and reduce future phishing risks, a combination of technical and human-focused strategies was recommended.

**1. Employee Training:**  
Regular awareness sessions and phishing simulations to help staff identify suspicious emails and respond appropriately.  
Focus areas included recognizing urgency cues, verifying sender authenticity, and reporting suspicious messages.

**2. Regular Security Audits:**  
Quarterly vulnerability assessments and penetration tests to evaluate network defenses, review access controls, and ensure compliance with security standards.

**3. Email Filtering and Technical Controls:**  
Deployment of advanced email filtering systems with enforced **SPF**, **DKIM**, and **DMARC** authentication.  
Ongoing patch management to prevent exploitation of known vulnerabilities.

These measures collectively enhance the organization’s resilience against phishing and social engineering attacks.

---

## Conclusion
Based on the investigation, it was confirmed that the reported message was a **phishing attempt leveraging CEO impersonation**. The attack used urgency-based language, a spoofed sender identity, and a malicious hyperlink (`hxxp://retajconsultancy.com`) that resolved to a known malicious IP (`23.94.182.50`).

Key findings included:
- The malicious IP was flagged by 11 out of 92 VirusTotal vendors.  
- The associated domain had a long record of phishing activity.  
- Quick detection and response prevented potential compromise.

The investigation demonstrated the importance of employee vigilance, quick incident reporting, and structured response procedures. By maintaining strong technical controls and fostering continuous awareness, the organization can significantly reduce exposure to future phishing campaigns.

---

## Lessons Learned
- Phishing remains one of the most effective and frequent attack vectors due to its reliance on human error.  
- Employee awareness and immediate reporting are critical to minimizing risk.  
- Combining proactive detection, incident response readiness, and continuous training forms the foundation of effective cybersecurity defense.

---

## Recommendations
To further strengthen the organization’s security posture:
- Conduct regular phishing simulations and employee training.  
- Enhance email authentication and filtering mechanisms.  
- Maintain an updated incident response plan and escalation procedure.  
- Continue routine vulnerability assessments and audits.

These actions will help ensure the organization remains proactive and resilient against social engineering and phishing threats.
