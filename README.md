# Test_malicious-packages-ossf
# Objective

The connector will ingest malicious package JSONs from the repo, create hash-based STIX Indicators and related File Observables in OpenCTI.  

**Connector type:** External Import connector  
**Source:** GitHub repo `ossf/malicious-packages`  
**Target:** OpenCTI, then Sentinel via Sentinel stream connector  
**Schedule:** Daily  

# Scope

- Ingest malicious package JSONs from the repo, create hash-based STIX Indicators and related Observables/Reports in OpenCTI  
- Map all relevant fields into OpenCTI entities (hash-based Indicators and related File Observables)
