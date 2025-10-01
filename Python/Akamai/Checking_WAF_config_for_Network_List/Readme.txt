# Readme.txt

## Overview

This script audits an Akamai WAF (Web Application Firewall) configuration with the specific goal of 
identifying any mention or usage of Network Lists within the specified WAF version. It systematically scans 
the WAF configuration to extract all references to Network Lists wherever they are used—in rate control policies, 
custom bots, conditional actions, policy match targets, IP/Geo firewall rules, and custom rules. This enables users 
to precisely identify how and where Network Lists are applied in their WAF setup, supporting compliance, validation,
and review efforts.
---

## Features

- Authenticates using Akamai `.edgerc` credentials.
- Inspects and reports:
  - Rate control policies
  - Custom bot configurations
  - Conditional (response) actions
  - Policy targets (website & API)
  - IP/GEO firewall rule details
  - Custom rules tied to network lists
  - WAF rules and advanced exception conditions
- Outputs all findings to a specified file in a human-readable format.
- Parallel processing (via ThreadPoolExecutor) for custom rule evaluation to improve performance on large configs.
- Tracks and displays progress using `tqdm`.

---

## Prerequisites

- Python 3.7 or greater
- Access to an Akamai account and WAF APIs
- Akamai `.edgerc` credentials file with valid API secrets

---

## Required Packages

Install with pip:

```
pip install requests tqdm akamai
```

---

## Setup

1. **.edgerc File**  
   Place your `.edgerc` file in your home directory (`~/.edgerc`) or provide the full path when prompted.
   - Ensure that a section `[default]` is set for the WAF APIs in the `.edgerc`.

2. **API Permissions**  
   Required access includes Akamai AppSec and Network Lists APIs.

---

## Usage

Run the script as follows:

```
python script_name.py -wafpolID <WAF_POLICY_ID> -verNum <VERSION_NUMBER> -filepath <OUTPUT_FILE_PATH>
```

- `-wafpolID` or `--waf_policy_id`: ID of the WAF configuration to audit  
- `-verNum` or `--ver_Num`: Version number of the WAF configuration  
- `-filepath` or `--file_path`: Path to the output file for the report  

If arguments are missing, the script will prompt for them (especially the `.edgerc` location, if not found at default).

---

## Output

The script writes a multi-section report to the file specified as `--file_path`, including:

- Rate control and match details tied to network lists
- Custom bot details with network list associations
- Conditional action rules
- Website and API match targets
- IP/GEO related firewall values
- Custom and firewall rules referencing specific network lists or advanced conditions

Progress for some operations (rule processing) is displayed interactively in the terminal.

---

## Notes

- The script is tailored for defensive/offensive security engineering, WAF auditing, and compliance review.
- To use non-default `.edgerc` credentials location, provide the path when prompted at startup.
- API rate limits may be hit if run repeatedly or on very large configurations; use responsibly.
- Minor modifications may be needed for use with other Akamai environments or custom endpoints.

---

## Troubleshooting

- **Missing Packages:**  
  If you encounter `ModuleNotFoundError`, double-check that all required packages are installed.

- **Akamai Authentication Errors:**  
  Ensure the `.edgerc` is correct and has requisite API permissions for AppSec endpoints.

- **API call failures:**  
  The script depends on Akamai's API contract staying stable. Endpoint changes or permission restrictions may cause failures.

---

## License

For internal documentation or demonstration use only—review your organization's policy on third-party integration scripts before wider use. This script does **not** come with any warranty or official support.

---

## Maintainer

Script creator: Will Crews
Adapted for security operations, engineering, and compliance use cases.

---

For further customization or troubleshooting, consult the comments in the source code.
