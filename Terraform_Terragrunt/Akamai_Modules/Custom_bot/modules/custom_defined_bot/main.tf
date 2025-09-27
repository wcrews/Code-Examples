resource "akamai_botman_custom_defined_bot" "custom_defined_bot" {
    config_id          = var.waf_config_id
    custom_defined_bot = jsondecode(file("${path.module}/custom_bot.json"))
}
