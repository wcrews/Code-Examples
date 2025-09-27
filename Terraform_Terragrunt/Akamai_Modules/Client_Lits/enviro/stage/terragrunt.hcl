terraform {

  source = "../../modules/akamai_client_list"

}



remote_state {

  backend = "s3"

  config = {

    bucket         = "TODO#_your-bucket-name"

    dynamodb_table = "TODO#_terraform-state"

    key            = "TODO#_aws_dynamodb_key_value"

    region         = "us-east-1"

  }

  generate = {

    path      = "terraform.tf"

    if_exists = "overwrite_terragrunt"

  }

}



generate "provider" {

  path      = "provider.tf"

  if_exists = "overwrite_terragrunt"

  contents  = <<EOF

provider "aws" {

  region   = "us-east-1"

  assume_role {

    role_arn = "TODO#_Needs_Vale"

  }



  default_tags {

    tags = {

      Terraform_Managed = true

      Repo              = "TODO#_Needs_Vale"

    }

  }

}

EOF

}



inputs = {

  client_lists = {

    

  ans_block_list = {

    cl_name                    = " "

    cl_type                    = " "

    notes                      = " "

    tags                       = []

    contract_id                = " "

    group_id                   = " "

    csv_file_header            = " "

    enable_activation          = false

    cl_environment             = " "

    cl_activation_comments     = " "

    activation_email_recipient = " "

  }

  }



  # Auth Cred

  edgerc         = "TODO#_Needs_Vale_file_path_location"

  edgerc_section = "TODO#_Needs_Vale_if_you_have_muliple_akamai_keys_in_your_edgerc_file"

}

