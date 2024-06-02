variable "velociraptor" {
type = map
default = {
    "domain"            = "evilcorp.io"
    "prefix"            = "vr"
    "rg_location"       = "Australia East"
}
}

variable "vr_allowlist_ip" {
type = string
default = "1.2.3.4"
description = "Allowed IP for Velociraptor SSH on the NSG"
}

variable "velociraptor_auth" {
type = map
default = {
    "azure_application_owner" = "00000000-0000-0000-0000-000000000000"
    "default_admin"           = "badmin@evilcorp.io"
}
}

variable "velociraptor_vm" {
type = map
default = {
    "admin_username"    = "vr-admin"
    "hostname"          = "velociraptor"
    "managed_disk_type" = "Premium_LRS"
    "os_disk_size"      = 1024
    "os_offer"          = "0001-com-ubuntu-server-jammy"
    "os_publisher"      = "Canonical"
    "os_sku"            = "22_04-lts"
    "os_version"        = "latest"
    "vm_size"           = "Standard_D4as_v5"

}   
}