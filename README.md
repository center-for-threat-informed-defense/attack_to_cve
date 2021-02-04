# Mapping ATT&CK Techniques to CVEs for Impact

This project defines a methodology and guidance for using MITRE ATT&CK to characterize the impact of a vulnerability as described in the CVE list. ATT&CK techniques provide a standard way of describing the methods adversaries use to exploit a vulnerability and what adversaries hope to achieve by exploiting the vulnerability. Using ATT&CK techniques to describe a vulnerability makes it easier for defenders to integrate vulnerabilities into their threat modeling. 

Our goal is to enable vendors, researchers, vulnerability databases, and other producers of vulnerability information to standardize the way they describe the impacts of vulnerabilities. Defenders will be able to use this ATT&CK-based impact information to better inform their risk models. When used with security control frameworks that are mapped to ATT&CK, CVE’s with ATT&CK Technique references should enable defenders to better understand their compensating controls for a given CVE. Ultimately, this methodology aims to establish a critical connection between vulnerability management and threat modeling.

## Repository Contents

| Resource | Description |
| ---- | ---- |
| [Mapping Methodology](/Attack_to_Vulnerability_Mapping_Model.md) | A methodology for mapping MITRE ATT&CK techniques to vulnerability records to describe the impact of a vulnerability.  |
| [Getting Started Guidance](/Getting_Started_with_ATT&CK_with_Vulnerabilties.md) | Guidance for applying the mapping methodology. |
| [CVE Mappings](/Att&ckToCveMappings.csv) | An initial set of CVEs with ATT&CK mappings. |
| [CVE JSON Schema](/CVE_JSON_5.0.schema) | An extension to the CVE JSON schema that introduces ATT&CK for describing impact.  |

## Future Work

Establishing a methodolgy for mapping ATT&CK techniques to CVE is the first step. To realize our goal of establising a connection between vulnerability management and threat modeling, the methodology needs widespread adoption. Users need consistant access to vulnerability information including ATT&CK technique references. The methodology needs widespread adoption by the CVE community. 

- CVE JSON Schema
- CVE Mappings
- CNA Engagenment


## Questions and Feedback

Please submit issues for any technical questions/concerns or contact ctid@mitre-engenuity.org directly for more general inquiries.

Also see the guidance for contributors if are interested in [contributing.](/CONTRIBUTING.md)

## Notice

Copyright 2021 MITRE Engenuity. Approved for public release. Document number CT0018

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
