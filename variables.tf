variable "app_ref" {
  description = "(Required) App reference (from CMDB)"
  type        = string
}

variable "resource_group_name" {
  description = "(Required) Resource group name"
  type        = string
}

variable "resource_tags" {
  description = "(Required) Map of resource tags"
  type        = map(string)
}

variable "settings" {
  description = "(Required) Map of storage account settings"
  type        = any
}

variable "keyvault_id" {
  description = "Keyvault ID"
  type        = string
  default     = ""
}

variable "default_action" {
  description = "required value"
  type        = string
  default     = "Deny"
}

variable "key_size" {
  description = "Key size"
  type        = string
  default     = "2048"
}

variable "firewall_public_ip" {
  description = "Firewall public IP"
  type        = string
  default     = ""
}

variable "log_analytics_workspace_id" {
  description = "(Required) Log analytics workspace ID"
  type        = string
}

variable "cors_rule" {
  type        = any
  description = "optional storage cors"
  default     = {}
}

variable "location_map" {
  description = "the mapping of locations in azure"
  type        = map(string)
  default = {
    az1 = "southeast asia"
    az2 = "east asia"
  }
}

locals {
  resources    = split("-", var.resource_group_name)
  app_lbu      = local.resources[1]
  app_sub      = local.resources[2]
  app_loc      = local.resources[3]
  app_ref      = local.resources[4]
  storage_name = "sta${local.app_lbu}${local.app_sub}${local.app_loc}${var.app_ref}"

  # If keyvault id provided use its subscription_id. If not,use current subscription_id. For non-BYOK storage case.
  subscription_id = var.keyvault_id == "" ? data.azurerm_subscription.current.subscription_id : element(split("/", var.keyvault_id), 2)

  jenkins_subnet = [
    "/subscriptions/ab80cd14-4408-40cb-876c-8c32328bbcc2/resourceGroups/rsg-sgrtss-prd-az1-aks/providers/Microsoft.Network/virtualNetworks/vnw-sgrtss-prd-az1-aks/subnets/sbt-sgrtss-prd-az1-1-aks",
    "/subscriptions/ab80cd14-4408-40cb-876c-8c32328bbcc2/resourceGroups/rsg-sgrtss-prd-az2-aks/providers/Microsoft.Network/virtualNetworks/vnw-sgrtss-prd-az2-aks/subnets/sbt-sgrtss-prd-az2-1-aks",
    "/subscriptions/ab80cd14-4408-40cb-876c-8c32328bbcc2/resourceGroups/rsg-sgrtss-prd-az1-aks/providers/Microsoft.Network/virtualNetworks/vnw-sgrtss-prd-az1-aks/subnets/sbt-sgrtss-prd-az1-2-aks",
    "/subscriptions/ab80cd14-4408-40cb-876c-8c32328bbcc2/resourceGroups/rsg-sgrtss-prd-az2-aks/providers/Microsoft.Network/virtualNetworks/vnw-sgrtss-prd-az2-aks/subnets/sbt-sgrtss-prd-az2-2-aks",
  ]
  suffix                 = lookup(var.settings, "suffix", "")
  storage_account_name   = "sta${local.app_lbu}${local.app_sub}${local.app_loc}${local.app_ref}${local.suffix}"
  storagesyncservicename = "sss${local.app_lbu}${local.app_sub}${local.app_loc}${local.app_ref}${local.suffix}"
  vnet_ref = contains(
    split("-", lookup(var.settings, "subnet_ref", "vnet")),
    "aks",
  ) ? "aks" : "vnet"
  firewall_ip_rules = "${var.firewall_public_ip},${lookup(var.settings, "firewall_ip_rules", "")},202.40.228.118,118.143.162.216,202.176.218.64/27"
  _region           = substr(lower(var.location_map[local.app_loc]), -4, -1)
  subnet_endpoint   = compact(concat(split(",", lookup(var.settings, "subnet_endpoint", "")), local._region == "asia" ? local.jenkins_subnet : []))

  # interpolate default value for storage account resource build and BYOK enabled
enable_storage_account   = lookup(var.settings, "enable_storage_account", "true")

  enable_storage_byok         = lookup(var.settings, "storage_byok", "false")
  enable_storage_cmek         = lookup(var.settings, "enable_storage_cmek", "false")
  enable_storage_sync_service = lookup(var.settings, "enable_storage_sync_service", "false")
  enable_large_file_share     = lookup(var.settings, "enable_large_file_share", "false")
  auto_enable_defender_plan   = lookup(var.settings, "auto_enable_defender_plan", "on")

  location = var.location_map[local.app_loc]

  slacode_map = {
    nhb = "nprd"
    dev = "nprd"
    sit = "nprd"
    uat = "nprd"
    phb = "prod"
    prd = "prod"
    vdi = "prod"
  }

  min_tls_version = lookup(var.settings, "min_tls_version", "TLS1_2")
  byok_key_name   = lookup(var.settings, "byok_key_name", "CMK-${local.app_ref}-sakey")

}

variable "enable_inventory_report" {
  description = "Installs the Inventory Report Configuration"
  type        = bool
  default     = false
}

variable "disable_inventory_rules" {
  description = "Disable all the inventory Rules"
  type        = bool
  default     = false
}


variable "inventory_policy_rules" {
    description = "Map of rules"
    type        = map(object({        
        inventory_reports_rule_name         = string
        inventory_reports_container_name    = string        
        enabled                             = bool
        object_type_to_inventory            = string        
        blob_inventory_fields               = list(string)
        inventory_frequency                 = string
        inventory_export_format             = string
        filter                              = object({
            blob_types                          = list(string)
            include_blob_versions               = bool
            include_snapshots                   = bool
            include_deleted                     = bool
            prefix_match                        = list(string)
            exclude_prefixes                    = list(string)
        })


    }))

    default = {
        "finops-default" = {
            inventory_reports_rule_name         = "finops-invrpt-default"
            inventory_reports_container_name    = "inventoryreports"
            enabled                             = true
            object_type_to_inventory            = "Blob"
            blob_inventory_fields               =  [ 
                                                    "Name", 
                                                    "Creation-Time", 
                                                    "Last-Modified", 
                                                    "LastAccessTime", 
                                                    "BlobType", 
                                                    "AccessTier", 
                                                    "AccessTierChangeTime",
                                                    "AccessTierInferred"
                                                ]
            filter                              = {
                blob_types                          = [ "blockBlob", "pageBlob", "appendBlob" ]  # is_hns_enabled will not support blob
                include_blob_versions               = false
                include_snapshots                   = false
                include_deleted                     = false
                prefix_match                        = null 
                exclude_prefixes                    = null                
            }
            inventory_frequency                 = "Weekly"
            inventory_export_format             = "Csv"

        }
    }

    # Validation : object_type_to_inventory
    validation {
        condition = alltrue([
            for k,v in var.inventory_policy_rules : (
                v.object_type_to_inventory == null || contains(["Blob"], v.object_type_to_inventory)
            )
        ])
        error_message = "ERROR in object_type_to_inventory. Supported object_type_to_inventory values : [\"Blob\"]."
    }

    # Validation : blob_inventory_fields
    validation {
        condition = alltrue([
            for k,v in var.inventory_policy_rules : 
                v.blob_inventory_fields == null || alltrue([for field in v.blob_inventory_fields : contains([
                "Name",
                "Creation-Time", 
                "Last-Modified",
                "LastAccessTime",
                "ETag",
                "Content-Length",
                "Content-Type",
                "Content-Encoding",
                "Content-Language",
                "Content-CRC64",
                "Content-MD5",
                "Cache-Control",
                "Cache-Disposition",
                "BlobType",
                "AccessTier",
                "AccessTierChangeTime",
                "AccessTierInferred",
                "LeaseStatus",
                "LeaseState",
                "ServerEncrypted",
                "CustomerProvidedKeySHA256",
                "Metadata",
                "Snapshot",
                "Deleted",
                "RemainingRetentionDays",
                "VersionId",
                "IsCurrentVersion",
                "TagCount",
                "Tags",
                "CopyId",
                "CopySource",
                "CopyStatus",
                "CopyProgress",
                "CopyCompletionTime",
                "CopyStatusDescription",
                "ImmutabilityPolicyUntilDate",
                "ImmutabilityPolicyMode",
                "LegalHold",                                                        	
                "RehydratePriority",
                "ArchiveStatus",
                "EncryptionScope",
                "IncrementalCopy", 
                "x-ms-blob-sequence-number"
            ] , field)
        
        ])])
        error_message = "ERROR in passed blob_inventory_fields. Supported blob_inventory_fields values : [ \"Name\", \"Creation-Time\", \"Last-Modified\", \"LastAccessTime\", \"ETag\", \"Content-Length\", \"Content-Type\", \"Content-Encoding\", \"Content-Language\", \"Content-CRC64\", \"Content-MD5\", \"Cache-Control\", \"Cache-Disposition\", \"BlobType\", \"AccessTier\",\"AccessTierChangeTime\", \"AccessTierInferred\", \"LeaseStatus\", \"LeaseState\", \"ServerEncrypted\", \"CustomerProvidedKeySHA256\", \"Metadata\", \"Snapshot\", \"Deleted\", \"RemainingRetentionDays\", \"VersionId\", \"IsCurrentVersion\", \"TagCount\", \"Tags\", \"CopyId\", \"CopySource\", \"CopyStatus\", \"CopyProgress\", \"CopyCompletionTime\", \"CopyStatusDescription\", \"ImmutabilityPolicyUntilDate\", \"ImmutabilityPolicyMode\", \"LegalHold\", \"RehydratePriority\",\"ArchiveStatus\", \"EncryptionScope\", \"IncrementalCopy\", \"x-ms-blob-sequence-number\"]."
    }

    # Validation : inventory_frequency
    validation {
        condition = alltrue([
            for k,v in var.inventory_policy_rules : (
                v.inventory_frequency == null || contains([ "Daily", "Weekly" ], v.inventory_frequency)
            )
        ])
        error_message = "ERROR in passed inventory_frequency. Supported inventory_frequency values : [ \"Daily\", \"Weekly\" ]."
    }

    # Validation : inventory_export_format
    validation {
        condition = alltrue([
            for k,v in var.inventory_policy_rules : (
                v.inventory_export_format == null || contains([ "Csv", "Parquet" ], v.inventory_export_format)
            )
        ])
        error_message = "ERROR in passed inventory_export_format. Supported inventory_export_format values : [ \"Csv\", \"Parquet\" ]."
    }

    # Validation : filter.blob_types
    validation {
        condition = alltrue([
            for k,v in var.inventory_policy_rules : 
                v.filter.blob_types == null || alltrue([for bt in v.filter.blob_types: contains([ "blockBlob", "pageBlob", "appendBlob" ], bt)])                 
        ])
        error_message = "ERROR in passed filter.blob_types. Supported filter.blob_types values : [ \"blockBlob\", \"pageBlob\", \"appendBlob\" ]."
    }


}

variable "inventory_policy_timeouts" {
    description = "Set the timeouts for the policy"
    type = object({
        create = string
        read = string
        update = string
        delete = string
    })
    default = {
        create = "30m"
        read = "5m"
        update = "30m"
        delete = "30m"
    }
}

variable "report_retention_days" {
    description = " Number of days to keep the inventory reports"
    default     = 30
    type        = number
}
