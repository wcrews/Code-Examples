variable "waf_config_id" {
    description = "Akamai WAF Configuration number."
    type        = string
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

variable "custom_defined_categories" {
    description = "Map of Custom Bot Categories"
    type = map(object({
    waf_config_id               = string
    bot_json                    = string
    }))
}
