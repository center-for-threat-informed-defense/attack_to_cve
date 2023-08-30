# Mapping MITRE ATT&CK® to CVEs for Impact

This project defines a methodology for using MITRE ATT&CK to characterize the impact of a vulnerability as described in the CVE list. ATT&CK techniques provide a standard way of describing the methods adversaries use to exploit a vulnerability and what adversaries may achieve by exploiting the vulnerability. Using ATT&CK techniques to describe a vulnerability makes it easier for defenders to integrate vulnerabilities into their threat modeling. 


![/cve-2018-17900-mapping-example.png](/cve-2018-17900-mapping-example-full.png)

Our goal is to enable vendors, researchers, vulnerability databases, and other producers of vulnerability information to standardize the way they describe the impacts of vulnerabilities. Defenders will be able to use this ATT&CK-based impact information to better inform their risk models. When used with security control frameworks that are mapped to ATT&CK, CVE’s with ATT&CK Technique references should enable defenders to better understand their compensating controls for a given CVE. Ultimately, this methodology aims to establish a critical connection between vulnerability management and threat modeling.

| Resource | Description |
| ---- | ---- |
| [Mapping Methodology](/methodology.md) | The methodology for mapping MITRE ATT&CK techniques to vulnerability records to describe the impact of a vulnerability.  |
| [Getting Started Guide](/getting-started.md) | After you review the methodology, this guide suggests an approach to starting small and increasing your use of ATT&CK as you get comfortable with the methdology. |
| [CVE Mappings](/Att&ckToCveMappings.csv) | Set of CVEs with ATT&CK mappings created in the process of developing the methodology.  The results of the Phase 1 mappings were used to generate the methodology.  The Phase 2 mappings were created using the methodology.  The mappings categories are defined in the mapping methodology document.  The Phase 1 mappings are uncategorized because they were created before the categories in the methodology was created. |
| [CVE JSON Schema Extension](https://github.com/CVEProject/cve-schema/pull/6) | An extension to the CVE JSON schema that introduces a taxonomy mapping object that can be used to include ATT&CK for describing impact.  The schema change has been approved by the CVE Program and is waiting for the final release of the new version of the schema. |


_This methodology was originally based on [ATT&CK v9](https://attack.mitre.org/resources/updates/updates-april-2021/index.html) and has been updated for [ATT&CK v13.1](https://attack.mitre.org/resources/updates/updates-april-2023/index.html)._

## How does this help vulnerability report authors?

For those who create vulnerability reports, including vulnerability researchers and product vendors, this methodology creates a clear, consistent approach to describing the impacts and exploitation methods of vulnerabilities. Using ATT&CK allows vulnerability reports to tell the story of what the attacker is trying to achieve by exploiting a given vulnerability. Many vulnerability reports focus on the technical details of exploitation and impact but ignore the higher-level goal the malicious actor is trying to achieve. ATT&CK bridges that gap and allows users to understand where the vulnerability fits within an attack scenario and their environment.

Using ATT&CK facilitates making descriptions of impacts and exploitation methods consistent across reports. While many reporters use the same language within their reports, different reporters often describe the same impact differently. For example, one reporter might describe [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) as a blue screen of death (BSOD), while another might describe it as a kernel panic. Either way, if they both reference [T1499.004](https://attack.mitre.org/techniques/T1499/004), the reader knows what they are talking about. This consistency makes it easier for readers to process the reports and act on the information.

## How does this help defenders? 

Vulnerability reports that include ATT&CK technique references allow defenders to rapidly assess the risk of and create a mitigation plan for a new vulnerability. Techniques in ATT&CK include detection and mitigation information, which can be used to investigate whether the mitigations they have in place are adequate for addressing the vulnerability or if additional mitigations are needed. For example, if the exploitation technique is [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application), the defender should monitor incoming traffic and block malicious requests. If the defender decides additional mitigations are needed, they can use the mappings from ATT&CK to other resources like [NIST 800-53](https://ctid.mitre-engenuity.org/our-work/nist-800-53-control-mappings/) or the [MITRE Cyber Analytics Repository](https://car.mitre.org/) to decide which actions to take. 

## Future Work

Creating a methodology for mapping ATT&CK techniques to CVE is the first step. To realize our goal of establishing a connection between vulnerability management and threat modeling, the methodology needs widespread adoption. Users need consistent access to vulnerability information including ATT&CK technique references.

To support widespread adoption of this methodology, the following next steps are underway:
* CVE JSON Schema Enhancement: Our proposed CVE JSON schema extension should be integrated into the official CVE JSON Schema in November 2021.
* Integrate CVE Mappings: With adoption of our proposed JSON schema changes, we aim to add our initial mappings to the official CVE List.

With an established foundation in place for the community to build upon, broad community engagement is our next focus. We need ongoing engagement with the CVE CNA community, threat intel teams, and end users to make the case for adoption and to collect feedback.

Defenders can help by reviewing the methodology and the set of CVEs that we mapped and let us know what you think.  Be an advocate and ask your vendors to include ATT&CK references in their vulnerability reports. 

Vulnerability reporters are critical to realizing our goal of connecting threat and vulnerability management. You can help by reviewing the methodology and applying it in your vulnerability reports. Help build the corpus of vulnerability reports with ATT&CK references. 

You can help make the case for change and we welcome your feedback. You can contact us at ctid@mitre-engenuity.org or simply file issues on our GitHub repository.

## Questions and Feedback

Please submit issues for any technical questions/concerns or contact ctid@mitre-engenuity.org directly for more general inquiries.

Also see the guidance for contributors if you are interested in [contributing.](/CONTRIBUTING.md)

## Notice

Copyright 2021 MITRE Engenuity. Approved for public release. Document number CT0018

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
