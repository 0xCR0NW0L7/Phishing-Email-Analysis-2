# Phishing Email Analysis 2

### **Instructions:**

- You are a SOC Analyst at Global Logistics. Emily Nguyen, a member of the marketing team, recently had trouble signing into her Dropbox account after trying to access it for the first time in months and reached out to her manager for assistance. The next day, she received an email claiming a password change request was made for her Dropbox account. The email includes a link for resetting her password, but Emily is unsure if the request is legitimate. Concerned about potential phishing, she has forwarded the email to the security team for analysis.
- Using what you've learned within this domain, perform a detailed email analysis on the challenge2.eml file to answer the report questions below.

### **Challenge Questions:**

**Challenge File**

- `01_Phishing_Analysis/Challenges/challenge2.eml`

Q1 Based on the contents of the email header, what is the full date and time of the email delivery?

- `Sun, 12 May 2024 04:10:52 +0000`

Q2 What is the subject of the email?

- `Reset your Dropbox password`

Q3 Who was the email sent to?

- `emily.nguyen@glbllogistics.co`

Q4 Based on the sender's display name, who does the email claim to be from?

- `Dropbox`

Q5 What is the sender's email address?

- `no-reply@dropbox.com`

Q6 What email address is used for receiving bounced emails?

- `0101018f6aff12b2-5bcaa145-861b-45da-a06e-b5c1ee3ca941-000000@email.dropbox.com`

Q7 What is the IP address of the sender's email server? 

- `54.240.60.143`

Q8 What is the resolved hostname of the sender's IP address?

- `a60-143.smtp-out.us-west-2.amazonses.com`

Q9 What is the Autonomous System Number (ASN) that owns this IP address?

- `AS16509`

Q10 What was the result of the SPF check?

- `pass`

Q11 What is the full SPF record of the sender's domain?

- `v=spf1 include:amazonses.com ~all`

Q12 What is email's Message ID?

- `0101018f6aff12b2-5bcaa145-861b-45da-a06e-b5c1ee3ca941-000000@us-west-2.amazonses.com`

Q13 What type of encoding was used to transfer the email body content?

- `quoted-printable`

Q14 Look in the plaintext version of the email. In defanged format, what is the first URL extracted from the email?

- `hxxps[://]www[.]dropbox[.]com/l/ABCIzswwTTJ9--CxR05fYXX35pPA-Y0m3PY/forgot_finish`

Q15 Perform a Cisco Talos lookup on the base domain of the URL in the previous question. What is its web reputation?

- `favorable`

Q16 [Yes or No] - After your analysis, is this email genuine?

- `Yes`

### Challenge URL

- [https://challenges.malwarecube.com/#/c/5e3f6ff6-46f7-4042-a969-34fd16451328](https://challenges.malwarecube.com/#/c/5e3f6ff6-46f7-4042-a969-34fd16451328)

---

## Challenge 2 Report

![Image 1](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-2/main/img/image.png)  

## Headers

|  **Header**  |  **Value**  |
| --- | --- |
| Date | `Sun, 12 May 2024 04:10:52 +0000` |
| Subject | `Reset your Dropbox password` |
|  From  | `no-reply@dropbox.com` |
|  To  | `emily.nguyen@glbllogistics.co` |
|  Reply-To  |   NA |
|  Return-Path  | `0101018f6aff12b2-5bcaa145-861b-45da-a06e-b5c1ee3ca941-000000@email.dropbox.com` |
|  Sender IP  | `54[.]240[.]60[.]143` |
|  Resolved Host  | `a60-143.smtp-out.us-west-2.amazonses.com` |
|  Message-ID  | `0101018f6aff12b2-5bcaa145-861b-45da-a06e-b5c1ee3ca941-000000@us-west-2.amazonses.com` |

## URLs

1. hxxps[://]www[.]dropbox[.]com/l/AADiZXaA7dm2EyafvAILlHJAzwU3D55FQwg/forgot_finish

## Attachments

| **File Name** | NA |
| --- | --- |
| **MD5** | NA |
| **SHA1** | NA |
| **SHA256** | NA |

## Description

This email is a **Dropbox account password reset notification** sent to `emily.nguyen@glbllogistics.co`. The email was triggered by a password reset request, likely initiated by the user.

**The analysis includes:**

- Verification of **email authentication mechanisms** (SPF, DKIM, DMARC).
- Examination of **URLs** embedded in the email for legitimacy.
- Assessment of **attachments** (if any) for potential malicious content.

## Artifact Analysis

- Sender Analysis:
    - spf=pass (domain ...email.dropbox.com designates 54.240.60.143 as permitted sender)
    - dkim=pass [header.i=@dropbox.com](mailto:header.i=@dropbox.com)
    - dkim=pass [header.i=@amazonses.com](mailto:header.i=@amazonses.com)
    - dmarc=pass (p=REJECT sp=REJECT dis=NONE) [header.from=dropbox.com](http://header.from=dropbox.com/)
- URL Analysis:
    - [https://www.dropbox.com/.../forgot_finish](https://www.dropbox.com/.../forgot_finish) → Legitimate Dropbox domain
    - No obfuscated or suspicious redirects detected
    - Reputation Check: Both URLs resolve to legitimate Dropbox infrastructure.
    - Tools Used: VirusTotal / URLScan (checked clean).
    - Findings: No redirection to malicious/phishing pages. Matches legitimate Dropbox reset workflow.
- Attachment Analysis:
    - No attachments present in the email

## Verdict

- All email authentication checks (SPF, DKIM, DMARC) passed
- URLs resolve to trusted Dropbox infrastructure
- No malicious indicators found

## Defense Actions

- No action required – email is safe and verified
- Marked as **legitimate business communication**
- Educate the user to reset the password only if the request was intentional

## Screenshots

1. Reverse IP Lookup on Outgoing mail server (MTA)

![Image 2](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-2/main/img/image%201.png)  

2. CISCO Talos IP Checks

![Image 3](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-2/main/img/image%202.png)  

3. VirusTotal Check

![Image 4](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-2/main/img/image%203.png)  

4. URLscan.io check

![Image 5](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-2/main/img/image%204.png)
