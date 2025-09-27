terraform {
  source = "../../modules/custom_bot_category"

}

inputs = {
  custom_bot_categories = {

    bad_privileged_bot = {
      waf_config_id               = "TODO#_Add_WAF_congig_number"
      filepath_to_json            = "${path_relative_from_include()}/custom_bot_category_files/Bad_Privileged_Bot.json"
    }
  }
  
  #Auth Cred
  edgerc           = "TODO#_Needs_Vale_file_path_location"
  edgerc_section   = "TODO#_Needs_Vale_if_you_have_muliple_akamai_keys_in_your_edgerc_file"

}





