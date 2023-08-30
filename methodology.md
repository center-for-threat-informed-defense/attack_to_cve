# Using MITRE ATT&CK® to Describe Vulnerabilities

[ATT&CK](https://attack.mitre.org/) tactics and techniques can be used as a set of standard terms to describe the exploitation process of a vulnerability.  For example, to exploit a vulnerability where credentials are sent in clear text, the following steps could be used:
1. Sniff the network ([T1040](https://attack.mitre.org/techniques/T1040/))
2. Which gets you the unsecured credentials ([T1552](https://attack.mitre.org/techniques/T1552/))
3. Which you can use to access a valid account ([T1078](https://attack.mitre.org/techniques/T1078/))

Once the attacker has access to the valid account, there are too many paths they can take to list them all.  

When developing this methodology, we found that three steps in the attack is usually as far in the process as can be reasonably described.  We categorize these steps in the following way:
1. **Exploitation Technique** - the method used to exploit the vulnerability (T1040 in the example).
2. **Primary Impact** - the initial benefit gained through exploitation of a vulnerability (T1552 in the example).
3. **Secondary Impact** - what the adversary can do by gaining the benefit of the primary impact (T1078 in the example).

Using these three categories, you can create a vulnerability impact description template such as:

> The vulnerability allows the attacker to use **[EXPLOITATION TECHNIQUE]** to gain **[Primary Impact]**, which leads to **[Secondary Impact]**.

![/cve-to-attack-sentence.png](/cve-to-attack-sentence.png)

ATT&CK will not always contain a technique for each of the categories. ATT&CK is written at a higher level of abstraction than is often used to describe a vulnerability and ATT&CK requires examples where the technique has been used in real-world attacks.  For example, the primary impact of a vulnerability may be too low-level to include an ATT&CK technique.  In which case, you can use the secondary impact in place of the primary or use one of the [tactic-level techniques](methodology.md#tactic-level-techniques).

##	Using the Methodology
We defined three methods to map ATT&CK techniques to vulnerabilities:

-	[**Vulnerability Type**](methodology.md#vulnerability-type-mappings) – This method groups vulnerabilities with common vulnerability types (e.g., cross-site scripting and SQL injection) that have common technique mappings.
-	[**Functionality**](methodology.md#functionality) - This method groups common mappings based on the type of functionality the attacker gains access to by exploiting the vulnerability.
-	[**Exploit Technique**](methodology.md#exploitation-techniques) – This method groups common mappings depending on the method used to exploit the vulnerability.

Only the vulnerability type method has mappings for all three categories.  The functionality method has mappings for primary and secondary impacts. The exploit techniques method only has mappings for the exploitation technique categories.

#### Vulnerability Type Method

Vulnerabilities that have the same type often also have the same attack steps.  This method maps ATT&CK techniques to some of the more common vulnerability types.  [CWE-699 (Software Development)](https://cwe.mitre.org/data/definitions/699.html) and [CWE-1000 (Research Concepts)](https://cwe.mitre.org/data/definitions/1000.html) were used to select the vulnerability types, though the method sometimes creates its own high-level categories for the sake of brevity.

The vulnerability type mappings can include the following technique categories:
1. Exploitation Technique
2. Primary Impact
3. Secondary Impact

If one of these categories is not included in the mapping for a particular vulnerability type, use one of the other methods to find the appropriate techniques.

#### Functionality Method

For a vulnerability to be useful, it needs to provide the attacker with a capability they did not have before.  Attackers are often trying to gain access to the same functionality and thus, many vulnerabilities can be grouped by functionality.

This method includes the following technique categories:
1. Primary Impact
2. Secondary Impact

To find the exploitation technique for a vulnerability, use one of the other two mapping methods in this document.

#### Exploit Technique Method

This method groups techniques by the common steps taken to exploit a vulnerability.  Use this method when a vulnerability type has too many possible exploitation scenarios to list in the Vulnerability Type method.

This method includes the following technique categories:
1. Exploitation Technique

To find the exploit technique for a vulnerability, use one of the other two mapping methods in this document.

### Mapping & Methodology Scope

In each method there are cases where we have not included a mapping for all available categories (Exploitation Technique, Primary Impact, Secondary Impact). Technique mappings are only included for a category when it is likely that different vulnerabilities in the group share that technique.  For example, vulnerabilities that modify memory (e.g., buffer overflows) share a common primary impact, but the secondary impacts and exploitation techniques are so varied that the methodology does not include a mapping for those categories.  

![/cve-to-attack-no-secondary-impact.png](/cve-to-attack-no-secondary-impact.png)

Some groupings will have more than one technique listed for a mapping category because there are common variations within that grouping.  In these cases, select only the techniques that apply to the vulnerability.  For example, the cross-site scripting (XSS) vulnerability type includes an option of [T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise) or [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link) depending on whether the attacked is stored or not.

This methodology establishes a starting point for vulnerability reporters and researchers to standardize the way they describe some vulnerability data. The methodology does not cover all the ways that systems are exploited.

### Example

[**CVE-2018-17900**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17900)

> Yokogawa STARDOM Controllers FCJ, FCN-100, FCN-RTU, FCN-500, All versions R4.10 and prior, The web application improperly protects credentials which could allow an attacker to obtain credentials for remote access to controllers.

To find the appropriate ATT&CK techniques, start by identifying the vulnerability type.  For CVE-2018-17900, the vulnerability is a credential management issue.  Looking through the list of vulnerability types in the methodology, the "General Credential Management Errors" vulnerability type appears to be the most appropriate.  Using one of the lower-level credential management vulnerability types is preferable but the CVE record does not provide the level of detail need to do so.  

The ”General Credential Management Errors” vulnerability type maps to [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials) for the primary impact and [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts) for the secondary impact.  These mappings follow the description in the CVE record.  “improperly protects credentials which could allow an attacker to obtain credentials” matches T1552 and “for remote access to controllers” matches T1078.

The ”General Credential Management Errors” vulnerability type does not have a mapping for the exploitation technique because there are too many ways general credential management vulnerabilities can be exploited.  To find the exploitation technique for CVE-2018-17900, use the Exploit Technique section.  The Exploit Technique section documents a set of scenarios to help the user determine which exploitation technique(s) are appropriate for the vulnerability.  For CVE-2018-17900, the entry point is the web application so the “Attacker exploits remote system application” scenario applies, which makes [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application) the exploitation technique for the vulnerability.

The description for CVE-2018-17900 can now be re-written using the ATT&CK standard.

![/cve-2018-17900-mapping-example.png](/cve-2018-17900-mapping-example.png)

> Yokogawa STARDOM Controllers FCJ, FCN-100, FCN-RTU, FCN-500, All versions R4.10 and prior, have Unsecured Credentials which could allow an attacker to gain access to Valid Accounts by Exploiting the Public-Facing Application.

# Vulnerability type mappings

The vulnerability type section contains mappings for many of the common vulnerability types.  Mappings for vulnerability types are only included if that type has a common set of techniques used to exploit the vulnerability or that can be executed when the vulnerability is exploited. Each vulnerability type will include a one or more of the following where applicable, a primary and secondary impact and one or more exploitation techniques.

| Vulnerability Type | Primary Impact | Secondary Impact | Exploitation Technique | Notes |
| ---- | ---- | ---- | ---- | ---------- |
| General Improper Access Control | [See the Functionality Section](methodology.md#functionality)  | [See the Functionality Section](methodology.md#functionality) | N/A | The impacts of authentication, authorization, and permissions errors generally depend on the functionality missing the authentication, authorization or permission. |
| Authentication Bypass by Capture-replay | [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application) | N/A | [T1040](https://attack.mitre.org/techniques/T1040) (Network Sniffing) |  |
| Improper Restriction of Excessive Authentication Attempts | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts) | N/A | [T1110.001](https://attack.mitre.org/techniques/T1110/001) (Brute Force: Password Guessing) |  |
| Overly Restrictive Account Lockout Mechanism | <ul><li>Mobile - [T1446](https://attack.mitre.org/techniques/T1446) (Device Lockout)</li><li>Others – [T1531](https://attack.mitre.org/techniques/T1531) (Account Access Removal)</li></ul> | N/A | [T1110](https://attack.mitre.org/techniques/T1110) (Brute Force) |  |
| Use of Password Hash Instead of Password for Authentication | [T1550.002](https://attack.mitre.org/techniques/T1550/002) (Use Alternate Authentication Material: Pass the Hash) | N/A | N/A |  |
| General Credential Management Errors | [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials) | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts) | N/A | A sub-technique can be chosen where applicable. |
| Cleartext Transmission of Sensitive Information | [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials) | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts) | [T1040](https://attack.mitre.org/techniques/T1040) (Network Sniffing) | A sub-technique can be chosen where applicable. |
| Hard-coded Credentials | [T1078.001](https://attack.mitre.org/techniques/T1078/001) (Default Accounts) | N/A | N/A |  |
| Weak Password/Hashing | N/A | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts) | [T1110](https://attack.mitre.org/techniques/T1110) (Brute Force) |  |
| General Cryptographic Issues | <ul><li>Credential storage or transmission – [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts)</li><li>Transmitting over network – [T1557](https://attack.mitre.org/techniques/T1557) (Adversary-in-the-Middle), [T1040](https://attack.mitre.org/techniques/T1040) (Network Sniffing)</li><li>Sensitive information storage – various techniques from the Collection tactic</li></ul> | N/A | [T1110](https://attack.mitre.org/techniques/T1110) (Brute Force) |  |
| XML External Entity (XXE) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter). | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System), [T1046](https://attack.mitre.org/techniques/T1046) (Network Service Discovery) | N/A |  |
| XML Entity Expansion (XEE) | [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) | N/A | N/A |  |
| URL Redirection to Untrusted Site ('Open Redirect') | N/A | [T1036](https://attack.mitre.org/techniques/T1036) (Masquerading) | [T1566.002](https://attack.mitre.org/techniques/T1566/002) (Phishing: Spearphishing Link) |  |
| Cross-site Scripting (XSS) | [T1059.007](https://attack.mitre.org/techniques/T1059/007) (Command and Scripting Interpreter: JavaScript) | [T1557](https://attack.mitre.org/techniques/T1557) (Adversary-in-the-Browser) | <ul><li>Stored – [T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise)</li><li>Others – [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link)</li></ul> | There are lots of possible secondary impacts but most of them can be summed up by Adversary-in-the-Browser. |
| OS Command Injection | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | N/A | [T1133](https://attack.mitre.org/techniques/T1133) (External Remote Service) | Primary depends on the OS being attacked but is often T1059.004. |
| SQL Injection | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System), [T1505.003](https://attack.mitre.org/techniques/T1505/003) (Server Software Component: Web Shell), [T1136](https://attack.mitre.org/techniques/T1136) (Create Account), [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application), [T1565.001](https://attack.mitre.org/techniques/T1565/001) (Data Manipulation: Stored Data Manipulation) | N/A | There currently is not a sub-technique for SQL commands.  Not all possible secondary impacts are listed and not all secondary impacts will always apply. |
| Code Injection | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | N/A | N/A | A sub-technique can be used depending on the type of injection. |
| Directory Traversal (Relative and Absolute) | [See the Functionality Section](methodology.md#functionality) (File Processing) | [See the Functionality Section](methodology.md#functionality) (File Processing) | [T1202](https://attack.mitre.org/techniques/T1202) (Indirect Command Execution) | Indirect command execution is used here because the vulnerable application is being used to as a proxy to execute the file handling commands.  |
| Symlink Attacks | [See the Functionality Section](methodology.md#functionality) (File Processing) | [See the Functionality Section](methodology.md#functionality) (File Processing) | [T1202](https://attack.mitre.org/techniques/T1202) (Indirect Command Execution) | Indirect command execution is used here because the vulnerable application is being used to as a proxy to execute the file handling commands.  |
| Untrusted/Uncontrolled/Unquoted Search Path | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) | N/A | N/A | A sub-technique can be chosen where appropriate. |
| Unrestricted File Upload | [T1505.003](https://attack.mitre.org/techniques/T1505/003) (Server Software Component: Web Shell) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | N/A |  |
| Deserialization of Untrusted Data | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | N/A | N/A |  |
| Infinite Loop | [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) | N/A | N/A |  |
| Cross-site Request Forgery (CSRF) | [T1068](https://attack.mitre.org/techniques/T1068) (Exploitation for Privilege Escalation) | Depends on the functionality the vulnerability gives access to.  See the [Functionality Section](methodology.md#functionality) for guidance on which techniques are appropriate. | [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link) |  |
| Session Fixation | [T1563](https://attack.mitre.org/techniques/T1563) (Remote Service Session Hijacking) | N/A | N/A | Often can be used for Initial Access. |
| Uncontrolled Resource Consumption | [T1499](https://attack.mitre.org/techniques/T1499) (Endpoint Denial of Service) | N/A | N/A | A sub-technique may be chosen depending on the type of resource being consumed |
| Server-Side Request Forgery (SSRF) | [T1090](https://attack.mitre.org/techniques/T1090) (Proxy) | [T1135](https://attack.mitre.org/techniques/T1135) (Network Share Discovery), [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) | [T1133](https://attack.mitre.org/techniques/T1133) (External Remote Service) | Tactic/Technique mismatch for the primary impact. |

# Functionality

This section provides ATT&CK technique mappings based on common functions an attacker may be trying to gain access to.

| Functionality | Primary Impact | Secondary Impact | Notes |
| --- | --- | --- | --- |
| Modify Configuration | [T1632](https://attack.mitre.org/techniques/T1632) (Subvert Trust Controls) | N/A |  |
| Create Account | [T1136](https://attack.mitre.org/techniques/T1136) (Create Account) | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts) |  |
| Disable protections | [T1562](https://attack.mitre.org/techniques/T1562) (Impair Defenses) | N/A |  |
| Restart/Reboot | [T1529](https://attack.mitre.org/techniques/T1529) (System Shutdown/Reboot) | N/A |  |
| Read from Memory | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) | N/A |  |
| Obtain sensitive information: Credentials | [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials) | N/A |  |
| Obtain sensitive information: Other data | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) | N/A |  |
| Password Reset | [T1098](https://attack.mitre.org/techniques/T1098) (Account Manipulation) | N/A |  |
| Read files | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) | [T1003.008](https://attack.mitre.org/techniques/T1003/008) (OS Credential Dumping: /etc/passwd and /etc/shadow), [T1552.001](https://attack.mitre.org/techniques/T1552/001) (Unsecured Credentials: Credentials in Files) | The list of secondary impacts covers common techniques included in proof-of-concepts but is not exhaustive.  |
| Delete files | [T1485](https://attack.mitre.org/techniques/T1485) (Data Destruction) | [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) |  |
| Create/Upload file | [T1505.003](https://attack.mitre.org/techniques/T1505/003) (Server Software Component: Web Shell) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | The techniques mapped here are the ones most used when reporting vulnerabilities that create or upload files.  There are likely other techniques that could apply. |
| Write to existing file | [T1565.001](https://attack.mitre.org/techniques/T1565/001) (Data Manipulation: Stored Data Manipulation) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter), [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow), [T1554](https://attack.mitre.org/techniques/T1554) (Compromise Client Software Binary) | The list of secondary impacts covers common techniques included in proof-of-concepts but is not exhaustive. |
| Change ownership or permissions | [T1222](https://attack.mitre.org/techniques/T1222) (File and Directory Permissions Modification) | N/A |  |
| Memory Modification (Memory Buffer Errors, Pointer Issues, Type Errors, etc.) | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow), [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) | N/A | T1574 is not in the right tactic for this vulnerability.  Propose adding it to Execution.  "Hijack Execution Flow" is used here because exploitation for memory modification usually involves changing the execution flow of a process to execute the attacker’s code. |
| Memory Read (Memory Buffer Errors, Pointer Issues, Type Errors, etc.) | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System), [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) | [T1211](https://attack.mitre.org/techniques/T1211) (Exploitation for Defense Evasion), [T1212](https://attack.mitre.org/techniques/T1212) (Exploitation for Credential Access) | May need a sub-technique. |

# Exploitation Techniques

This section provides common mappings for exploit techniques to ATT&CK techniques. Use this list together with the vulnerability type mappings section to determine the appropriate exploitation technique when not specified in the vulnerability type mappings.  This list can also be used independently to determine the appropriate exploitation technique. 

## Tips for mapping exploitation techniques:
Start by asking, "what steps are necessary to exploit this vulnerability?" 

- If the user executes a malicious file: [T1204.002](https://attack.mitre.org/techniques/T1204/002) (User Execution: Malicious File)
  - Where did this file come from?
    - A malicious link: [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link)
    - An email: [T1566.001](https://attack.mitre.org/techniques/T1566/001) (Phishing: Spearphishing Attachment)
    - A third-party service: [T1566.003](https://attack.mitre.org/techniques/T1566/003) (Phishing: Spearphishing via Service)
    - Removable media:  [T1091](https://attack.mitre.org/techniques/T1091) (Replication Through Removable Media)
- If the user clicks a malicious link: [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link)
  - Where did this link come from?
    - An email: [T1566.002](https://attack.mitre.org/techniques/T1566/002) (Phishing: Spearphishing Link)
    - A third-party service: [T1566.003](https://attack.mitre.org/techniques/T1566/003) (Phishing: Spearphishing via Service)
- If the user visits a malicious website: [T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise)
- If the attacker exploits remote system application: [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application)
- If the attacker exploits an external service: [T1133](https://attack.mitre.org/techniques/T1133) (External Remote Services), [T1210](https://attack.mitre.org/techniques/T1210) (Exploitation of Remote Services)
- If the attacker uses valid/default credentials: [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts)
- If the target uses hardcoded credentials: [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts)
- If the attacker "sniffs" unencrypted network traffic: [T1040](https://attack.mitre.org/techniques/T1040) (Network Sniffing)

# Tactic-level Techniques

When the three methods above (Vulnerability Type, Functionality, and Exploit Technique) don't support mapping the exploit type or impacts of a vulnerability, consider focusing at a higher level in ATT&CK. For many tactics within ATT&CK, there is a generic exploitation technique.  When mapping techniques to vulnerabilities, exploitation can be assumed so these techniques are not as useful in this context than for other uses of ATT&CK.  In this document, where possible, a more specific technique is used over the generic exploitation techniques. 

| Tactic | Generic Exploitation Technique |
| ---- | ---- |
| Initial Access | T1190 (Exploit Public-Facing Application) |
| Execution | T1203 (Exploitation of Client Execution) |
| Privilege Escalation | T1068 (Exploitation for Privilege Escalation) |
| Defense Evasion | T1211 (Exploitation for Defense Evasion) |
| Credential Access | T1212 (Exploitation for Credential Access) |
| Lateral Movement | T1210 (Exploitation of Remote Services) |

# Examples

## CVE-2020-6960

[CVE-2020-6960](https://nvd.nist.gov/vuln/detail/CVE-2020-6960) is a SQL injection vulnerability.  The SQL injection listing the Vulnerability Type section contains mappings for the Primary Impact and Secondary Impact.  For the Primary Impact, the mapping is [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter).  For the Secondary Impact, there are several options to choose from.  Unfortunately, the CVE record does not provide enough information to choose a Secondary Impact.

## CVE-2018-17900

[CVE-2018-17900](https://nvd.nist.gov/vuln/detail/CVE-2018-17900) is about insecure credential handling.  The in "General Credential Management Errors" vulnerability type applies for this vulnerability.  In this case, both mappings in the methodology apply.  The Primary Impact is [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials), when then leads to the Secondary Impact allowing the adversary to use [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts).

## CVE-2020-11036

[CVE-2020-11036](https://nvd.nist.gov/vuln/detail/CVE-2020-11036) is a cross-site scripting (XSS) vulnerability.  For XSS vulnerabilities, there are standard Primary Impact and Secondary Impact mappings (T1059.007 and T1185 respectively).  However, the Exploitation Technique depends on what type of XSS vulnerability it is.  Since CVE-2020-11036 is a stored XSS vulnerability, the mapping should be [T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise), as the attack is stored in the web page and the victims are attacked by visiting the infected web page.

## CVE-2020-5210

[CVE-2020-5210](https://nvd.nist.gov/vuln/detail/CVE-2020-5210) is a buffer overflow.  Since buffer overflows modify the memory, the "Memory Modification (Memory Buffer Errors, Pointer Issues, Type Errors, etc.)" vulnerability type is used, making the Primary Impacts [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) and [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation).  The vulnerability also has an exploitation technique mapping of [T1548.001](https://attack.mitre.org/techniques/T1548/001) (Abuse Elevation Control Mechanism: Setuid and Setgid).  The methodology does not list T1548.001 as an exploitation technique because it is relatively rare.
