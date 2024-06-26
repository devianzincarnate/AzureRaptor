velociraptor = {
    "domain"            = "evilcorp.io"
    "prefix"            = "vr"
    "rg_location"       = "Australia East"
}

vr_allowlist_ip = "1.2.3.4"

velociraptor_auth = {
    "azure_application_owner" = "00000000-0000-0000-0000-000000000000"
    "default_admin"           = "badmin@evilcorp.io"
}

velociraptor_vm = {
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