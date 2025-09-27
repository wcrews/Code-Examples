Terragrunt Module: Akamai Client List Management

This Terragrunt module manages a list of Akamai clients by configuring client details through Terragrunt inputs and leveraging a Terraform module for Akamai client list management.

Module Source

terraform {
  source = "../../modules/akamai_client_list"
}

Inputs

Name                  Description                                                                                      Type                      Required Default
client_lists          Map of client list configurations.                                                             map(object)               yes      
ans_block_list        Configuration block for each client list entry describing client-specific data and settings.    object                    yes      
edgerc                Local path to the Edgerc authentication file.                                                  string                    yes      "TODO#_file_path_on_local_system_to_edgerc_file"
edgerc_section        If multiple Akamai API keys are configured, specify which section to use.                       string                    yes      "TODO#_If_you_have_multiple_Akamai_API_Keys_you_will_use_this"

ans_block_list Fields Description

Field                     Description                                                  Type           Required Default
cl_name                   Name of the client list                                       string         yes      " "
cl_type                   Type of client list                                          string         yes      " "
notes                     Additional notes about the client list                       string         no       " "
tags                      List of tags related to the client list                      list(string)   no       []
contract_id               Contract identifier associated with the client               string         no       " "
group_id                  Group identifier associated with the client                  string         no       " "
csv_file_header           CSV file header used for the client list                      string         no       " "
enable_activation         Whether activation is enabled for this client                 bool           no       false
cl_environment            Environment of the client list                                string         no       " "
cl_activation_comments    Comments related to activation                                string         no       " "
activation_email_recipient Email to receive activation notifications                   string         no       " "

Usage Example

terraform {
  source = "../../modules/akamai_client_list"
}

inputs = {
  client_lists = {
    ans_block_list = {
      cl_name                  = "example client"
      cl_type                  = "example type"
      notes                    = "notes about the client"
      tags                     = ["tag1", "tag2"]
      contract_id              = "12345"
      group_id                 = "67890"
      csv_file_header          = "header"
      enable_activation        = true
      cl_environment           = "production"
      cl_activation_comments   = "activation notes"
      activation_email_recipient = "user@example.com"
    }
  }

  edgerc          = "TODO#_file_path_on_local_system_to_edgerc_file"
  edgerc_section  = "TODO#_If_you_have_multiple_Akamai_API_Keys_you_will_use_this"
}

Notes

- The "TODO#" marker indicates where users need to provide input values.
- Make sure the edgerc file path and edgerc_section are correctly set to authenticate with Akamai APIs.

License:

