variable "client_list_ips_file_path" {

  description = "value"

  type        = string

  default     = null

}



variable "ips" {

  description = "value"

  type        = list(string)

  default     = []

}

variable "edgerc" {

  description = "Path to the Akamai credentials file."

  type        = string

}



variable "edgerc_section" {

  description = "Section of the credentials file to use."

  type        = string

  default     = "default"

}



variable "cl_description" {

  description = "Description for the client list."

  type        = string

  default     = ""

}



variable "enable_activation" {

  description = "Whether to activate the client list"

  type        = bool

  default     = true

}



variable "client_lists" {

  description = "Map of client list configurations"

  type = map(object({

    cl_name                   = string

    cl_type                   = string

    notes                     = string

    tags                      = list(string)

    contract_id               = string

    group_id                  = string

    client_list_ips_file_path = string

    csv_file_header           = string

    enable_activation         = bool

    cl_environment            = string

    cl_activation_comments    = string

    activation_email_recipient = string

  }))

}
