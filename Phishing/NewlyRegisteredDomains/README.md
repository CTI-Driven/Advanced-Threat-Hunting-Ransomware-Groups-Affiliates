# 🛡️ KQL-Based Hunting for Newly Registered Potential Phishing & Typosquatting Domains

## 📌 Description

 Threat actors frequently **register lookalike domains** to support malicious activities such as phishing attacks, drive-by compromises, and command-and-control (C2) operations. This **KQL hunting query** is designed to help **identify potential phishing and typosquatting domains that may be targeting your organization or its third-party vendors**.

---

## 🔍 Threat Intelligence Feed

The hunting query utilizes data from the **SANS Internet Storm Center (ISC) API**, which provides access to **newly registered domains**.

- **API Endpoint**:  
  [`https://isc.sans.edu/api/recentdomains/today?json`](https://isc.sans.edu/api/recentdomains/today?json)

- **Use Cases**:
  - Threat intelligence enrichment  
  - Detection of suspicious or malicious domains  
  - Security log correlation  

- **Returned Data Fields**:
  - Domain name  
  - Registration date  
  - IP address  
  - Type  
  - Additional metadata (if available)  

- **Query by Date (Optional)**:  
  Example: [`https://isc.sans.edu/api/recentdomains/2025-07-08?json`](https://isc.sans.edu/api/recentdomains/2025-07-08?json)

---

## 🎯 ATT&CK Framework Mapping

- **Technique**: Acquire Infrastructure: Domains  
- **ID**: T1583.001  
- **Reference**: [MITRE ATT&CK](https://attack.mitre.org/techniques/T1583/001/)  

---
## 🔍 KQL Advanced Threat Hunting Querie

```kql
let newlyRegisteredDomains = externaldata (
    domainname: string,
    ip: string,
    type: string,
    firstseen: string) ['https://isc.sans.edu/api/recentdomains/today?json'] with(format='multijson');
// Replace this list with your organization's name and common typosquatting variants.
let possibleTyposquattingOrgDomains = dynamic([
    "myorganisation", "0rganisattion", "myorgaanisation"]); 
// Replace with relevant third-party vendors and their common typosquatting variants.
let possibleTyposquattingThirdPartyDomains = dynamic([
    "microsoft", "mlcrosofft", "m1crosoft", "microsfot",
    "amazon", "amaz0n", "amzon", "amazn", "amaz0n",
    "okta", "oktaa", "0kta",
    "salesforce", "salesforcce", "saleforce", "safesforce"]); 
newlyRegisteredDomains
| where domainname has_any (possibleTyposquattingOrgDomains)
     or domainname has_any (possibleTyposquattingThirdPartyDomains)
| extend PhishingTyposquattingCategory = case(
         domainname has_any (possibleTyposquattingOrgDomains), "Possible Phishing/Typosquatting Domains Targeting My Org",
         domainname has_any (possibleTyposquattingThirdPartyDomains), "Possible Phishing/Typosquatting Targeting Third Party Domains",
         "Unknown")
| project firstseen, domainname, ip, type, PhishingTyposquattingCategory

```

---
## 📚Resources
- **SANS ISC API Documentation:**  
  [https://isc.sans.edu/api/](https://isc.sans.edu/api/)

