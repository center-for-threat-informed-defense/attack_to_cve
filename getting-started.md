# Getting Started

Using ATT&CK in vulnerability records shifts the thinking in how vulnerabilities have traditionally been described.  Rather than focusing on the technical aspects of a vulnerability, ATT&CK focuses the vulnerability record on what the adversary is trying to achieve and how they go about reaching their goal.

If you are not familiar with ATT&CK, incorporating it into your vulnerability records is a daunting task.  To help, this document breaks the task down in to three levels.  Adding ATT&CK to a vulnerability record should not take long (5 minutes or less for most cases). If you find that this process is taking too long, consider moving back to an earlier level.

## Level 1 - Focus on ATT&CK's tactics

A good place to start is at the tactic level.  Tactics are ATT&CK’s method for representing the goal for taking an action.  For example, an adversary may take one action to achieve credential access and take another action to achieve the goal of privilege escalation.  In ATT&CK, each tactic has a set of techniques an adversary might use to achieve their tactical goal.  However, there are fewer tactics than techniques and they will apply to a larger range of vulnerabilities than an individual technique, so the tactic level is the best place to start.

What is more, not all tactics are relevant to vulnerabilities.  For example, the Command and Control tactic is for techniques that adversaries use to communicate with systems under their control.  The adversary may have exploited a vulnerability to gain control of the system but is not likely to need to exploit a vulnerability to send it commands once under its control.  In fact, there are only six tactics that have techniques targeted at exploitation of vulnerabilities. 

These tactics map closely with common methods for describing the impact of a vulnerability.  Vulnerability records often use Privilege Escalation or a variation, like gains administrator privileges.  For remote code execution, use the Execution tactic in combination with either Initial Access or Lateral Movement tactic, depending on whether the affected service was public facing.  And most other vulnerability impacts fall within one of these tactics. 

The [Tactic-level Techniques](methodology.md#tactic-level-techniques) section in the methodology lists the generic exploitation techniques for each tactic in ATT&CK tactic. 

Using ATT&CK does not require you to provide any more or less information than you normally provide in a vulnerability record.  The advantage of ATT&CK is to standardize how records describe vulnerability information so that readers can leverage the resources built on top of ATT&CK.

## Level 2 - Expand, one tactic at a time

If focusing on ATT&CK tactics in your vulnerability records doesn’t provide the level of detail you need. Consider using the [vulnerability type mappings](methodology.md#vulnerability-type-mappings), but limiting your focus to just one or two tactics at a time. 

Focus on integrating techniques from one tactic at a time, starting with the tactic you care about the most.  For example, a vendor of an office suite may want to focus on the Execution tactic.  Searching through the techniques for the Execution tactic, they find that the [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link), [T1204.002](https://attack.mitre.org/techniques/T1204/002) (User Execution: Malicious File), and [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) techniques apply to most of the vulnerabilities in their product.  

By distinguishing between the three techniques, the vendor’s advisories now provide more details on how to monitor for exploitation of and mitigate the vulnerabilities.  For example, the tactic-level exploitation technique for the Exploit tactic ([T1203](https://attack.mitre.org/techniques/T1203)) says that the effective mitigations for the technique are application isolation and sandboxing and exploit protection.  However, using [T1204.002](https://attack.mitre.org/techniques/T1204/002) says that user training on common phishing and spearphishing techniques can also help mitigate the vulnerability.

## Level 3 - Aim for technique chains

Now that you are familiar with ATT&CK techniques and how to use them in your records, the next step is to show how an adversary chains techniques together.  An adversary’s ultimate goal is rarely achieved by one technique.  The adversary usually needs to string multiple techniques together to achieve its ends.  For example, an adversary may send phishing ([T1566](https://attack.mitre.org/techniques/T1566)) emails to a victim.  The victim opens the attachment ([T1204.002](https://attack.mitre.org/techniques/T1204/002)) and the vulnerability is exploited to achieve execution ([T1203](https://attack.mitre.org/techniques/T1203)).  From there, you can’t be certain which technique the adversary will use because they have too many techniques to choose from.  Providing the possible chains of techniques used by an adversary provides more context for defenders when detecting and mitigating the vulnerability.

While some vulnerabilities contain unique technique chains, vulnerabilities often share chains with other vulnerabilities of the same type.  For example, all reflected cross-site scripting vulnerabilities (XSS) required a victim to click on a malicious link ([T1204.001](https://attack.mitre.org/techniques/T1204/001)) and then the malicious script is executed ([T1059](https://attack.mitre.org/techniques/T1059); usually [T1059.007](https://attack.mitre.org/techniques/T1059/007)).  For stored cross-site scripting vulnerabilities, drive-by compromise ([T1189](https://attack.mitre.org/techniques/T1189)) replaces the malicious link.  The [vulnerability type mapping methodology](/methodology.md#vulnerability-type-mappings) contains more examples of the common technique chains for different vulnerability types. 

When including technique chains into your records, start by including chains for the vulnerability type you are most concerned about.  As you gain confidence you are conveying the correct set of techniques, expanding to include chains for the other vulnerability types. 

