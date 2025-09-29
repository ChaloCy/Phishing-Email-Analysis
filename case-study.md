
---

## 📖 Case Background  
An employee (John, Finance) reported a **suspicious email** that appeared to come from the CEO, requesting him to urgently review a financial document.  
The email contained a suspicious link:  

<img width="561" height="205" alt="image" src="https://github.com/user-attachments/assets/64895b3d-1e0b-4f5e-ab1f-0048583fa0a4" />

This raised suspicion of a **phishing attempt** and triggered a security investigation.  

---

## Report Summary
This report provides an in-depth analysis and response to a phishing attempt
reported by John from our finance department. John received a suspicious email
claiming to be from our CEO, urging him to click a link to review an urgent financial
document. Our investigation revealed that the link led to a suspicious IP address,
suggesting a phishing attack.

---

## Summary of Solutions and Tools Used
Email Analysis: I identified key indicators of phishing within the email body, such as
the sense of urgency, unusual URL format ("hxxp" instead of "http"), and lack of a
standard email signature. These clues indicated the email was a phishing email.

Metadata and IP Analysis: I checked the IP address 23.94.182.50 using WHOIS and
VirusTotal. The IP was linked to known malicious activities, confirming the email was
a phishing attempt.

Link Analysis: The URL in the email was investigated using VirusTotal. The tool's
analysis revealed a long history of malicious activity associated with the domain,
further confirming the phishing attempt.

Containment and Remediation: Immediate steps were taken to isolate and preserve
evidence, including:
- Isolated affected devices to stop further interaction.
- Secured digital evidence from these devices.
- Monitored the network for unusual activity using tools like Wireshark.
- Disconnected compromised systems from the network.

Forensic Investigation: If John had clicked the link, I would have taken the following
steps:
- Reviewed logs for unusual activities.
- Checked for vulnerabilities using Nmap and Nikto.
- Enhanced security by closing unnecessary ports and updating software.

### Tools Used
- WHOIS Lookup: Provided details about the IP address.  
- VirusTotal: Identified threats related to the IP address and URL.  
- Wireshark: Monitored network traffic.  
- Nmap: Scanned for network vulnerabilities.  
- Nikto: Checked web servers for vulnerabilities.  

These tools helped confirm the phishing attempt and guide our response.  
The incident response effectively neutralized the immediate threat, preserved
evidence, and maintained the integrity of our IT systems. By isolating devices,
securing evidence, and monitoring the network, we mitigated potential damage.  
Additionally, a forensic investigation and strengthened security measures helped
prevent future incidents and protect sensitive information.

---

## Email Analysis
[📸 Screenshot placeholder: `./images/email-body.png`]

_Upon reviewing the email, I discovered several indicators of a phishing attempt..._  
(Your full original text continues here without edits)

---

## Metadata and IP Analysis
[📸 Screenshot placeholder: `./images/whois-lookup.png`]  
[📸 Screenshot placeholder: `./images/virustotal.png`]

_(Full original text continues...)_

---

## Link Analysis
[📸 Screenshot placeholder: `./images/url-analysis.png`]  

_(Full original text continues...)_

---

## Incident Response
(Your full original section exactly as written)  

---

## Compliance Implications
(Your full original section exactly as written)  

---

## Forensic Investigation
[📸 Screenshot placeholder: `./images/log-analysis.png`]  
[📸 Screenshot placeholder: `./images/nmap-scan.png`]  
[📸 Screenshot placeholder: `./images/nikto-scan.png`]  

_(Your full original section continues...)_

---

## Prevention Measures
(Your full original text with a, b, c measures)

---

## Conclusion
(Your full original conclusion text exactly as written)

## ✅ Conclusion  
This case confirmed a **phishing attack leveraging CEO impersonation**. Quick user reporting prevented further compromise.  

**Impact (if ignored):** Theft of financial credentials, data breach, and potential malware infection.  

**Recommendations:**  
- Regular phishing awareness training  
- Stronger email filtering policies  
- Routine vulnerability scanning  

---

## 🔑 Lessons Learned  
- Phishing remains one of the most effective attack vectors.  
- **Employee awareness** is critical for early detection.  
- Multi-layered defenses (filtering, IR procedures, awareness) reduce risks significantly.  

---

📸 **Where to add screenshots:**  
- `images/email-body.png` → screenshot of the phishing email  
- `images/whois-lookup.png` → WHOIS results page  
- `images/virustotal-result.png` → VirusTotal scan  
- `images/wireshark-traffic.png` → Wireshark packet capture  

---
