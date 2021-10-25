# Integrating ATT&CK into Vulnerability Management
ATT&CK is a powerful tool in threat intelligence and risk management but its utility is not limited to them.  This paper explains how to leverage ATT&CK to improve vulnerability management and provides guidance on how to minimize the cost of integrating ATT&CK into vulnerability information.

Main Benefits

- Improve risk assessments by linking vulnerabilities to real-world adversary behaviors
- Leverage the detection and mitigation capabilities built on top of ATT&CK
- Speak to your customers at their level
- Help automate vulnerability description writing and translation

Costs
- ATT&CK is a freely available knowledge base of adversary behaviors 
- The 3 levels of adoption let you choose the amount of resources you want to dedicate to the process
- Based on an 80% accuracy rate, less than 1 minute per CVE spent by our analysts 

# What is ATT&CK?

ATT&CK is a knowledge base of adversary tactics and techniques based on real-world observations. The knowledge base represents adversary goals as tactics and the specific behaviors to achieve those goals as techniques and sub-techniques. Through its global adoption, ATT&CK has become a common taxonomy for both offense and defense to understand and communicate about adversary behaviors. ATT&CK is widely used as a foundation for threat models and a critical input into many cybersecurity disciplines to convey threat intelligence.

ATT&CK is broken down into tactics (the "why") and techniques (the "how").  The tactic is the objective of an attackers and the technique is how the attacker achieves that objective.  In the vulnerability context, tactics and techniques can be used to describe how a vulnerability is exploited and the impacts of the vulnerability.  For example, to exploit a cross-site scripting vulnerability, an attacker might send out emails containing a malicious link ([T1566.002](https://attack.mitre.org/techniques/T1566/002/)).  When a victim clicks on the link, the impact is JavaScript executing in the browser ([T1059.007](https://attack.mitre.org/techniques/T1059/007/)).  From there, the JavaScript can be used for any number of attacks, such as stealing web session cookies ([T1539](https://attack.mitre.org/techniques/T1539/)) or cryptomining ([T1496](https://attack.mitre.org/techniques/T1496/)).

# Why use ATT&CK

## Vulnerability Report Authors

For those who create vulnerability reports, including vulnerability researchers and product vendors, ATT&CK presents a clear, consistent method for describing the impacts and exploitation methods of vulnerabilities.  ATT&CK allows vulnerability reports to tell the story of what the attacker is trying to achieve by exploiting a given vulnerability.  Many vulnerability reports focus on the technical details of exploitation and impact but ignore the higher-level goal the malicious actor is trying to achieve.  ATT&CK bridges that gap and allows readers to understand where the vulnerability fits within an attack scenario and their environment.

ATT&CK facilitates making descriptions of impacts and exploitation methods consistent across reports.  While many reporters use the same language within their reports, different reporters often describe the same impact differently.  For example, one reporter might describe [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) as a blue screen of death (BSOD), while another might describe it as a kernel panic.  Either way, if they both reference [T1499.004](https://attack.mitre.org/techniques/T1499/004), the reader knows what they are talking about.  This consistency makes it easier for readers to process the reports and act on the information.

For those looking to automate the publication of their vulnerability reports, ATT&CK techniques provide a standard reference that a computer can understand.  Computers struggle with natural language descriptions, but they can easily tell what to do with a standard identifier like T1189.  This is doubly true for reporters who want to provide translations of their reports in many languages.  Rather than translating the natural language of every report, do it once for an ATT&CK technique and replicate it every time you use the technique in a report.

## Defenders
ATT&CK allows defenders to rapidly assess the risk of and create a mitigation plan for a new vulnerability.  Techniques in ATT&CK include detection and mitigation information.  For example, ATT&CK recommends a defender do the following for for vulnerabilities related to [T1574.009](https://attack.mitre.org/techniques/T1574/009) (Hijack Execution Flow: Path Interception by Unquoted Path):

>Monitor file creation for files named after partial directories and in locations that may be searched for common processes through the environment variable, or otherwise should not be user writable. Monitor the executing process for process executable paths that are named for partial directories. Monitor file creation for programs that are named after Windows system programs or programs commonly executed without a path (such as "findstr," "net," and "python"). If this activity occurs outside of known administration activity, upgrades, installations, or patches, then it may be suspicious.

Defenders can then investigate whether the mitigations they have in place are adequate for addressing the vulnerability or if additional mitigations are needed.  For example, if the exploitation technique is [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application), the defender should monitor incoming traffic and block malicious requests.  If the defender decides additional mitigations are needed, they can use the mappings from ATT&CK to other resources like [NIST 800-53](https://ctid.mitre-engenuity.org/our-work/nist-800-53-control-mappings/) or the [MITRE Cyber Analytics Repository](https://car.mitre.org/) to  decide which actions to take.   For the [T1574.009](https://attack.mitre.org/techniques/T1574/009) (Hijack Execution Flow: Path Interception by Unquoted Path) example, CAR suggests using [CAR-2013-01-002: Autorun Differences](https://car.mitre.org/analytics/CAR-2013-01-002/) and [CAR-2014-07-001: Service Search Path Interception](https://car.mitre.org/analytics/CAR-2014-07-001/).
ATT&CK also allows defenders to understand how a new vulnerability fits into the overall risk picture. A plaintext passwords in a log file vulnerability ([T1552.001](https://attack.mitre.org/techniques/T1552/001)) might not be a high priority if the proper access restrictions are in place for the log file.  However, if there is also a vulnerability that allows arbitrary file reads ([T1005](https://attack.mitre.org/techniques/T1005)), then the defenders might want to prioritize addressing the vulnerabilities since the risk of the two combined is greater than individually.

# Getting Started
Using ATT&CK in vulnerability records shifts the thinking in how vulnerabilities have traditionally been described.  Rather than focusing on the technical aspects of a vulnerability, ATT&CK focuses the vulnerability record on what the adversary is trying to achieve and how they go about reaching their goal.

If you are not familiar with ATT&CK, incorporating it into your vulnerability records is a daunting task.  To help, this document breaks the task down in to three steps.  Adding ATT&CK to a vulnerability record should not take long (5 minutes or less for most cases). If you find that this process is taking too long, consider moving back to an earlier level.

## Level 1
A good place to start is at the tactic level.  Tactics are ATT&CK’s method for representing the goal for taking an action.  For example, an adversary may take one action to achieve credential access and take another action to achieve the goal of privilege escalation.  In ATT&CK, each tactic has a set of techniques an adversary might use to achieve their tactical goal.  However, there are fewer tactics than techniques and they will apply to a larger range of vulnerabilities than an individual technique, so the tactic level is the best place to start.

What is more, not all tactics are relevant to vulnerabilities.  For example, the Command and Control tactic is for techniques that adversaries use to communicate with systems under their control.  The adversary may have exploited a vulnerability to gain control of the system but is not likely to need to exploit a vulnerability to send it commands once under its control.  In fact, there are only six tactics that have techniques targeted at exploitation of vulnerabilities. 

| TACTIC | GENERIC |
| ---- | ---- |
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application) |
| Execution | [T1203](https://attack.mitre.org/techniques/T1203) (Exploitation of Client Execution) |
| Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068) (Exploitation for Privilege Escalation) |
| Defense Evasion | [T1211](https://attack.mitre.org/techniques/T1211) (Exploitation for Defense Evasion) |
| Credential Access | [T1212](https://attack.mitre.org/techniques/T1212) (Exploitation for Credential Access) |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210) (Exploitation of Remote Services) |

These tactics map closely with common methods for describing the impact of a vulnerability.  Vulnerability records often use Privilege Escalation or a variation, like gains administrator privileges.  For remote code execution, use the Execution tactic in combination with either Initial Access or Lateral Movement tactic, depending on whether the affected service was public facing.  And most other vulnerability impacts fall within one of these tactics. 

Using ATT&CK does not require you to provide any more or less information than you normally provide in a vulnerability record.  The advantage of ATT&CK is to standardize how records describe vulnerability information so that readers can leverage the resources built on top of ATT&CK.

## Level 2
So, you have been using the ATT&CK tactics in your vulnerability records, but they don’t provide the level of detail you need.  How do you go about using the lower-level techniques?

Taking on the full ATT&CK matrix of techniques is still too much at this point.  Instead, focus on integrating techniques from one tactic group at a time, starting with the tactic you care about the most.  For example, a vendor of an office suite may want to focus on the Execution tactic.  Searching through the techniques for the Execution tactic, they find that the [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link), [T1204.002](https://attack.mitre.org/techniques/T1204/002) (User Execution: Malicious File), and [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) techniques apply to most of the vulnerabilities in their product.  

By distinguishing between the three techniques, the vendor’s advisories now provide more details on how to monitor for exploitation of and mitigate the vulnerabilities.  For example, the tactic-level exploitation technique for the Exploit tactic ([T1203](https://attack.mitre.org/techniques/T1203)) says that the effective mitigations for the technique are application isolation and sandboxing and exploit protection.  However, using [T1204.002](https://attack.mitre.org/techniques/T1204/002) says that user training on common phishing and spearphishing techniques can also help mitigate the vulnerability.

## Level 3

Now that you are familiar with ATT&CK techniques and how to use them in your records, the next step is to show how an adversary chains techniques together.  An adversary’s ultimate goal is rarely achieved by one technique.  The adversary usually needs to string multiple techniques together to achieve its ends.  For example, an adversary may send phishing ([T1566](https://attack.mitre.org/techniques/T1566)) emails to a victim.  The victim opens the attachment ([T1204.002](https://attack.mitre.org/techniques/T1204/002)) and the vulnerability is exploited to achieve execution ([T1203](https://attack.mitre.org/techniques/T1203)).  From there, you can’t be certain which technique the adversary will use because they have too many techniques to choose from.  Providing the possible chains of techniques used by an adversary gives more options to choose from when detecting and mitigating the vulnerability.

While some vulnerabilities contain unique technique chains, vulnerabilities often share chains with other vulnerabilities of the same type.  For example, all reflected cross-site scripting vulnerabilities (XSS) required a victim to click on a malicious link ([T1204.001](https://attack.mitre.org/techniques/T1204/001)) and then the malicious script is executed ([T1059](https://attack.mitre.org/techniques/T1059); usually [T1059.007](https://attack.mitre.org/techniques/T1059/007)).  For stored cross-site scripting vulnerabilities, drive-by compromise ([T1189](https://attack.mitre.org/techniques/T1189)) replaces the malicious link.  The [vulnerability type mapping methodology](/methodology.md#vulnerability-type-mappings) contains more examples of the common technique chains for different vulnerability types. 

When including technique chains into your records, start by including chains for the vulnerability type you are most concerned about.  As you gain confidence you are conveying the correct set of techniques, expanding to include chains for the other vulnerability types. 

