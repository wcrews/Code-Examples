terraform {
  required_providers {
    akamai = {
      source  = "akamai/akamai"
      version = "6.5.0"
    }
    
  }

  required_version = "= 1.8.7" # OpenTofu
}

provider "akamai" {
    edgerc = var.edgerc
    config_section = var.edgerc_section
  
}