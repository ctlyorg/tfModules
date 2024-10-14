provider "azurerm" {
  alias           = "keyvault"
  subscription_id = local.subscription_id
  features {}
}

data "azurerm_client_config" "current" {}

data "azurerm_subscription" "current" {}

data "azurerm_key_vault_key" "instance" {
  count = local.enable_storage_byok == "true" ? 1 : 0

  name         = local.byok_key_name
  key_vault_id = var.keyvault_id
  provider     = azurerm.keyvault
}

resource "azurerm_key_vault_key" "cmek_key" {
  count = local.enable_storage_cmek == "true" && local.enable_storage_byok == "false" ? 1 : 0

  name         = local.byok_key_name
  key_vault_id = var.keyvault_id
  key_type     = "RSA-HSM"
  key_size     = var.key_size
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]

  provider = azurerm.keyvault
}

data "azurerm_key_vault" "instance" {
  count = local.enable_storage_byok == "true" ? 1 : 0

  name                = element(split("/", var.keyvault_id), 8)
  resource_group_name = element(split("/", var.keyvault_id), 4)
  provider            = azurerm.keyvault
}

data "azurerm_key_vault" "cmek_instance" {
  count = local.enable_storage_cmek == "true" && local.enable_storage_byok == "false" ? 1 : 0

  name                = element(split("/", var.keyvault_id), 8)
  resource_group_name = element(split("/", var.keyvault_id), 4)
  provider            = azurerm.keyvault
}

data "azurerm_subnet" "instance" {
  count = length(compact(split(",", lookup(var.settings, "subnet_ref", ""))))

  name                 = "sbt-${local.app_lbu}-${local.app_sub}-${local.app_loc}-${element(split(",", var.settings["subnet_ref"]), count.index)}"
  virtual_network_name = "vnw-${local.app_lbu}-${local.app_sub}-${local.app_loc}-${local.vnet_ref}"
  resource_group_name  = "rsg-${local.app_lbu}-${local.app_sub}-${local.app_loc}-${local.vnet_ref}"
}

resource "azurerm_storage_account" "instance" {
  # use count loop to allow storage decommission
  # valid input `true` or `false`. Default is `true`
  count = local.enable_storage_account == "true" ? 1 : 0

  name                            = local.storage_account_name
  resource_group_name             = var.resource_group_name
  location                        = local.location
  account_tier                    = var.settings["account_tier"]
  account_replication_type        = var.settings["account_replication_type"]
  account_kind                    = var.settings["account_kind"]
  access_tier                     = var.settings["access_tier"]
  is_hns_enabled                  = lookup(var.settings, "is_hns_enabled", "false")
  https_traffic_only_enabled      = lookup(var.settings, "https_traffic_only_enabled", "true")
  min_tls_version                 = local.min_tls_version
  large_file_share_enabled        = local.enable_large_file_share
  sftp_enabled                    = lookup(var.settings, "sftp_enabled", "false")
  nfsv3_enabled                   = lookup(var.settings, "nfsv3_enabled", "false")
  allow_nested_items_to_be_public = lookup(var.settings,"allow_nested_items_to_be_public", "false")
  public_network_access_enabled   = lookup(var.settings,"public_network_access_enabled", "false")

  identity {
    type = "SystemAssigned"
  }

  network_rules {
    default_action = var.default_action
    ip_rules       = compact(split(",", local.firewall_ip_rules))
    virtual_network_subnet_ids = compact(
      concat(data.azurerm_subnet.instance.*.id, local.subnet_endpoint),
    )
    bypass = split(
      ",",
      lookup(var.settings, "network_rules_bypass", "AzureServices"),
    )
  }

  dynamic "static_website" {
    for_each = try(var.settings["static_website"], "false") == "true" ? ["create"] : []
    content {
      index_document     = lookup(var.settings, "index_html", "index.html")
      error_404_document = lookup(var.settings, "error_html", "error.html")
    }
  }

  tags = {
    Environment              = var.resource_tags["tag_env"]
    Location                 = "azure ${lower(local.location)}"
    BusinessUnit             = var.resource_tags["tag_business_unit"]
    ApplicationName          = var.resource_tags["tag_app_name"]
    ApplicationOwner         = var.resource_tags["tag_app_owner"]
    AzDefenderPlanAutoEnable = local.auto_enable_defender_plan
  }

    dynamic "blob_properties" {
      for_each = var.settings["account_kind"] != "FileStorage" ? [1] : []
      content {
        dynamic "cors_rule" {
          for_each = { for k, v in var.cors_rule : k => v }
          content {
            allowed_headers    = split(",", trimspace(cors_rule.value.allowed_headers))
            allowed_methods    = split(",", trimspace(cors_rule.value.allowed_methods))
            allowed_origins    = split(",", trimspace(cors_rule.value.allowed_origins))
            exposed_headers    = split(",", trimspace(cors_rule.value.exposed_headers))
            max_age_in_seconds = cors_rule.value.max_age_in_seconds
          }
        }

        dynamic "delete_retention_policy" {
          for_each = try(var.settings["enable_blob_delete_retention"], "false") == "true" ? ["blob_properties"] : []
          content {
            days = try(var.settings["blob_delete_retention_policy"], 7)
          }
        }

        dynamic "container_delete_retention_policy" {
          for_each = try(var.settings["enable_container_delete_retention"], "false") == "true" ? ["blob_properties"] : []
          content {
            days = try(var.settings["container_delete_retention_policy"], 7)
          }
        }

        last_access_time_enabled = lookup(var.settings,"last_access_time_enabled", "false")
      } 
    } 

  lifecycle {
    ignore_changes = [
      azure_files_authentication,
      tags,
      customer_managed_key,
    ]
  }

}

resource "azurerm_key_vault_access_policy" "instance" {
  count = local.enable_storage_account == "true" && local.enable_storage_byok == "true" ? 1 : 0

  key_vault_id = data.azurerm_key_vault.instance[0].id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_storage_account.instance[0].identity[0].principal_id

  key_permissions    = ["Get", "Create", "List", "Restore", "Recover", "UnwrapKey", "WrapKey", "Purge", "Encrypt", "Decrypt", "Sign", "Verify", "GetRotationPolicy", "SetRotationPolicy"]
  secret_permissions = ["Get"]

  provider = azurerm.keyvault
}

resource "azurerm_key_vault_access_policy" "cmek_instance" {
  count = local.enable_storage_account == "true" && local.enable_storage_cmek == "true" && local.enable_storage_byok == "false" ? 1 : 0

  key_vault_id = data.azurerm_key_vault.cmek_instance[0].id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_storage_account.instance[0].identity[0].principal_id

  key_permissions    = ["Get", "Create", "List", "Restore", "Recover", "UnwrapKey", "WrapKey", "Purge", "Encrypt", "Decrypt", "Sign", "Verify", "GetRotationPolicy", "SetRotationPolicy"]
  secret_permissions = ["Get"]

  provider = azurerm.keyvault
}

resource "azurerm_storage_account_customer_managed_key" "instance" {
  count = local.enable_storage_account == "true" && local.enable_storage_byok == "true" ? 1 : 0

  storage_account_id = azurerm_storage_account.instance[0].id
  key_vault_id       = data.azurerm_key_vault.instance[0].id
  key_name           = data.azurerm_key_vault_key.instance[0].name
  key_version        = data.azurerm_key_vault_key.instance[0].version

  depends_on = [azurerm_key_vault_access_policy.instance]
}

resource "azurerm_storage_account_customer_managed_key" "enablecmekencryption" {
  count = local.enable_storage_account == "true" && local.enable_storage_cmek == "true" && local.enable_storage_byok == "false" ? 1 : 0

  storage_account_id = azurerm_storage_account.instance[0].id
  key_vault_id       = data.azurerm_key_vault.cmek_instance[0].id
  key_name           = azurerm_key_vault_key.cmek_key[0].name
  key_version        = azurerm_key_vault_key.cmek_key[0].version

  depends_on = [azurerm_key_vault_access_policy.cmek_instance, azurerm_key_vault_key.cmek_key]
}

resource "vault_generic_secret" "sakey_kv2" {
  # if the storage account is disabled, it will be removed and we will delete the secret endpoint
  count = local.enable_storage_account == "true" ? 1 : 0

  path = "kv2/${local.app_lbu}/${local.slacode_map[local.app_sub]}/${local.app_sub}/${local.app_ref}/${local.storage_account_name}"

  data_json = <<EOT
  {
    "storage_account_name":   "${azurerm_storage_account.instance[0].id}",
    "primary_key": "${azurerm_storage_account.instance[0].primary_access_key}",
    "secondary_key": "${azurerm_storage_account.instance[0].secondary_access_key}"
  }
  
EOT
}

resource "azurerm_storage_sync" "instance" {
  count = local.enable_storage_account == "true" && local.enable_storage_sync_service == "true" ? 1 : 0

  name                = local.storagesyncservicename
  resource_group_name = var.resource_group_name
  location            = local.location
}

resource "azurerm_monitor_diagnostic_setting" "blob_diagnostics" {
  count = local.enable_storage_account == "true" ? 1 : 0

  name                       = "diag-${local.storage_name}-blob"
  target_resource_id         = "${azurerm_storage_account.instance[0].id}/blobServices/default/"
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
    enabled  = true    
  }
  metric {
    category = "Capacity"
    enabled  = false
  }

  timeouts {}
}

resource "azurerm_monitor_diagnostic_setting" "table_diagnostics" {
  count = local.enable_storage_account == "true" ? 1 : 0

  name                       = "diag-${local.storage_name}-table"
  target_resource_id         = "${azurerm_storage_account.instance[0].id}/tableServices/default/"
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
    enabled  = true
  }
  metric {
    category = "Capacity"
    enabled  = false
  }

  timeouts {}
}

resource "azurerm_monitor_diagnostic_setting" "queue_diagnostics" {
  count = local.enable_storage_account == "true" ? 1 : 0

  name                       = "diag-${local.storage_name}-queue"
  target_resource_id         = "${azurerm_storage_account.instance[0].id}/queueServices/default/"
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
    enabled  = true    
  }
  metric {
    category = "Capacity"
    enabled  = false
  }

  timeouts {}
}

resource "azurerm_monitor_diagnostic_setting" "file_diagnostics" {
  count = local.enable_storage_account == "true" ? 1 : 0

  name                       = "diag-${local.storage_name}-file"
  target_resource_id         = "${azurerm_storage_account.instance[0].id}/fileServices/default/"
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
    enabled  = true
  }
  metric {
    category = "Capacity"
    enabled  = false
  }

  timeouts {}
}

resource "azurerm_storage_container" "reports_container" {
  for_each = var.enable_inventory_report ? var.inventory_policy_rules : {}
  name                  = each.value.inventory_reports_container_name
  storage_account_name  = azurerm_storage_account.instance[0].name  
  container_access_type = "private"
  depends_on = [
    azurerm_storage_account.instance[0]
  ]
  
}
 
resource "azurerm_storage_management_policy" "inventory_report_container_retention_policy" {
  # Rules will install if enable_inventory_report = true
  # Default for report_retention_days is set in varaibles of requested 30 days
  count = length(azurerm_storage_container.reports_container) > 0 ? 1 : 0 
  storage_account_id = azurerm_storage_account.instance[0].id  
  dynamic "rule" {
    for_each = var.inventory_policy_rules 
    content {
      name = "rp${rule.value.inventory_reports_container_name}"
      enabled = true 
      filters {
        prefix_match = ["${rule.value.inventory_reports_container_name}/"]
        blob_types = [ "blockBlob", "appendBlob"]
      }
      actions {
        base_blob {        
          delete_after_days_since_modification_greater_than = var.report_retention_days
        }
        snapshot {
          delete_after_days_since_creation_greater_than = var.report_retention_days
        }
        version {
          delete_after_days_since_creation = var.report_retention_days
        }
      }
    }
  }
}

resource "azurerm_storage_blob_inventory_policy" "inventory_report_policy" {
  # We install the policies if the container exists, see null resource update_rules_enablement if they will be enabled
  count = length(azurerm_storage_container.reports_container) > 0 ? 1 : 0 
  storage_account_id  = azurerm_storage_account.instance[0].id
  
  dynamic "rules" {
    for_each = var.inventory_policy_rules
    # Note enable is not handled here as the terraform provider does not support it
    content {
      name                   = rules.value.inventory_reports_rule_name
      storage_container_name = rules.value.inventory_reports_container_name
      format                 = rules.value.inventory_export_format
      schedule               = rules.value.inventory_frequency
      scope                  = rules.value.object_type_to_inventory
      schema_fields          = rules.value.blob_inventory_fields      
      filter       {
        blob_types             = rules.value.filter.blob_types
        include_blob_versions  = rules.value.filter.include_blob_versions
        include_snapshots      = rules.value.filter.include_snapshots
        include_deleted        = rules.value.filter.include_deleted
        prefix_match           = rules.value.filter.prefix_match
        exclude_prefixes       = rules.value.filter.exclude_prefixes
      }
    }  
  }

  timeouts {
    create = var.inventory_policy_timeouts.create
    read   = var.inventory_policy_timeouts.read
    update = var.inventory_policy_timeouts.update
    delete = var.inventory_policy_timeouts.delete
  }
  depends_on = [
    azurerm_storage_account.instance[0],
    azurerm_storage_container.reports_container
  ]

  lifecycle {
    create_before_destroy = true
    ignore_changes        = []
  
  }
}


resource "null_resource" "update_rules_enablement" {
  for_each = length(azurerm_storage_container.reports_container) > 0 ? var.inventory_policy_rules : {}
  
  triggers = {
    always_run = timestamp()
  }
  # Note this will set enabledment for each rule one by one - setting all rules not currently supporte by provider
  # See retries = 100 , if there are like many mnay storage accounts check if this expires
  provisioner "local-exec" {
    command = <<EOT
      policy_file=policy_${azurerm_storage_account.instance[0].name}.json
      az storage account blob-inventory-policy show --resource-group ${var.resource_group_name} --account-name ${azurerm_storage_account.instance[0].name} > $policy_file
      INDEX=$(jq 'def findIndex(name): [.policy.rules[].name] | index(name) ; findIndex("${each.value.inventory_reports_rule_name}")' $policy_file )
      echo "For rule ${each.value.inventory_reports_rule_name} ,  Index is $INDEX , and setting to ${each.value.enabled }" 
      echo "INDEX is $INDEX finding ${each.value.inventory_reports_rule_name}"
      cat $policy_file    
      retries=100
      flag_update_passed=0
      sempaphore_file=semaphore_${azurerm_storage_account.instance[0].name}
      # sleep $(( RANDOM % 10 ))
      while [ $flag_update_passed == 0 ] && [ $retries -gt 0  ]
      do        
        if [ $retries -gt 0 ]
        then 
          if [ -f $sempaphore_file ]
          then 
            random_sleep_interval=$(( RANDOM % 10 ))
            current_processing=$( cat "$sempaphore_file" )
            echo "Found another update_rules_enablement in progress : $current_processing , sleeping $random_sleep_interval. Retries : $retries"           
            sleep $random_sleep_interval          
          else
            echo "Processing Starting for  ${each.value.inventory_reports_rule_name} for enabled attribute."
            echo  "${each.value.inventory_reports_rule_name}" > $sempaphore_file
            if [ "${var.disable_inventory_rules}" == "true" ]
            then 
              az storage account blob-inventory-policy update --resource-group ${var.resource_group_name} --account-name ${azurerm_storage_account.instance[0].name} --set "policy.rules[$INDEX].enabled=false"
            else
              az storage account blob-inventory-policy update --resource-group ${var.resource_group_name} --account-name ${azurerm_storage_account.instance[0].name} --set "policy.rules[$INDEX].enabled=${each.value.enabled}"
            fi

            if [ $? -eq 0 ]    
            then
              flag_update_passed=1
              rm $sempaphore_file
            fi
          fi 
        else 
          echo "Out of retries for ${each.value.inventory_reports_rule_name} "
        fi
        retries=$(( retries - 1 ))
      done
      echo "Processing for ${each.value.inventory_reports_rule_name} done"
      if [ $flag_update_passed -eq 0 ]
      then 
        exit 1
      fi
      
    EOT
  }
  
  depends_on = [
    azurerm_storage_blob_inventory_policy.inventory_report_policy
  ]
}


resource "null_resource" "enable_access_time_tracking" {
  count = length(azurerm_storage_container.reports_container) > 0 ? 1 : 0 
  # Ref https://learn.microsoft.com/en-us/azure/storage/blobs/blob-inventory-how-to?tabs=azure-cli#optionally-enable-access-time-tracking
  provisioner "local-exec" {
    command = <<EOT
      az storage account blob-service-properties update --resource-group ${var.resource_group_name} --account-name ${azurerm_storage_account.instance[0].name} --enable-last-access-tracking true
    EOT
  }
  depends_on = [
    azurerm_storage_blob_inventory_policy.inventory_report_policy
  ]
}
