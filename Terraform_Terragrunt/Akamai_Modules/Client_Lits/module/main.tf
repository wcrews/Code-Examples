terraform {

  locals {

  decoded_csv_map = {

    for key, cfg in var.client_lists :

    key => cfg.client_list_ips_file_path != null ? csvdecode(file(cfg.client_list_ips_file_path)) : []

  }

}



resource "akamai_clientlist_list" "client_lists" {

  for_each    = var.client_lists



  name        = each.value.cl_name

  type        = each.value.cl_type

  notes       = each.value.notes

  tags        = each.value.tags

  contract_id = each.value.contract_id

  group_id    = each.value.group_id



dynamic "items" {

  for_each = {

    for item in local.decoded_csv_map[each.key] :

    item[each.value.csv_file_header] => item

  }



  content {

  value           = items.value[each.value.csv_file_header]

  description     = items.value["Description"]

  tags            = items.value["Tags"] != "" ? [for tag in split(",", items.value["Tags"]) : trimspace(tag)] : []

  expiration_date = items.value["Expiration Date (UTC)"]

  }

}

}



resource "akamai_clientlist_activation" "client_list_activations" {

  for_each = {

    for key, cfg in var.client_lists :

    key => cfg if cfg.enable_activation

  }



  list_id                 = akamai_clientlist_list.client_lists[each.key].id

  version                 = akamai_clientlist_list.client_lists[each.key].version

  network                 = each.value.cl_environment

  comments                = each.value.cl_activation_comments

  notification_recipients = [each.value.activation_email_recipient]

}

