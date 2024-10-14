resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = var.resource_group_name
  location                 = var.resource_group_location
  account_tier             = var.settings["account_tier"]
  account_replication_type = var.settings["account_replication_type"]
  min_tls_version          = var.settings["min_tls_version"]
}
