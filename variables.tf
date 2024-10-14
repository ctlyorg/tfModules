variable "resource_group_name" {
  description = "(Required) Resource group name"
  type        = string
}

variable "resource_group_location" {
  description = "(Required) Resource group location"
  type        = string
}

variable "settings" {
  description = "(Required) Map of storage account settings"
  type        = any
}
