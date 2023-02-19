terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
       version = "3.41.0"
    }
  }
}

provider "azurerm" {
  features {}
}

provider "azuread" {
}


data "azurerm_client_config" "vr_azurerm_config" {
}

data "azuread_client_config" "vr_azuread_config" {
}

variable "prefix" {
default = "VR-op-name"
description = "Prefix appended to resource names - format 'VR-op-name'"
}

variable "vr_allowlist_ip" {
type = string
default = "1.2.3.4"
description = "Allowed IP for Velociraptor SSH on the NSG"
}

variable "vr_azure_application_owner" {
default = "00000000-0000-0000-0000-000000000000"
description = "Owner of Azure App Registration for SSO"
}

variable "vr_managed_disk_type" {
type = string
default = "StandardSSD_LRS"
description = "Disk SKU for Velociraptor Server"
}

variable "vr_os_disk_size" {
type = number
default = 1024
description = "Velociraptor Server OS Disk Size (in GB)"
}

variable "vr_os_offer" {
type = string
default = "0001-com-ubuntu-server-jammy"
description = "Operating system offer in Azure Marketplace"
}

variable "vr_os_publisher" {
type = string
default = "Canonical"
description = "OS Publisher in Azure Marketplace"
}

variable "vr_os_sku" {
type = string
default = "22_04-lts"
description = "Operating system SKU in Azure Marketplace"
}

variable "vr_os_version" {
type = string
default = "latest"
description = "Operating system version in Azure Marketplace"
}

variable "vr_rg_location" {
type = string
default = "Australia East"
description = "Location of the resource group in Azure"
}

variable "vr_vm_sku" {
type = string
default = "Standard_D2as_v5"
description = "Velociraptor Server VM SKU"
}

variable "vr_domain" {
default = "velociraptor.evilcorp.io"
description = "Domain name"
}

variable "vr_user" {
default = "badmin@evilcorp.io"
description = "Default administrator user"
}

resource "random_id" "rid" {
  byte_length = 5
}



locals {
  custom_data = <<CUSTOM_DATA
#!/bin/bash

# Run OS and package updates
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y

# Download Velociraptor Linux binary to /usr/local/bin and make it executable
sudo wget -O /usr/local/bin/velociraptor "https://github.com/Velocidex/velociraptor/releases/download/v0.6.7-5/velociraptor-v0.6.7-5-linux-amd64"
sudo chmod +x /usr/local/bin/velociraptor

# Generate new Velociraptor server configuration with some preset variables and change permissions
sudo velociraptor config generate --merge '{"Client":{"server_urls":["https://${var.vr_domain}/"]},"GUI":{"bind_address":"127.0.0.1","bind_port":443,"public_url":"https://${var.vr_domain}/","initial_users":[{"name":"${var.vr_user}"}],"authenticator":{"type":"Azure","oauth_client_id":"${azuread_application.velociraptor.application_id}","oauth_client_secret":"${azuread_application_password.velociraptor_app_password.value}","tenant":"${data.azurerm_client_config.vr_azurerm_config.tenant_id}"}}, "Frontend":{"hostname":"${var.vr_domain}","bind_address":"0.0.0.0","bind_port":443},"autocert_domain":"${var.vr_domain}","autocert_cert_cache":"/etc/velociraptor/"}' > /etc/velociraptor.config.yaml


# Create Velociraptor as a service to be started when the server starts.
sudo echo "[Unit]
Description=Velociraptor linux amd64
After=syslog.target network.target

[Service]
Type=simple
Restart=always
RestartSec=120
LimitNOFILE=20000
Environment=LANG=en_US.UTF-8
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor.config.yaml frontend -v

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/velociraptor.service

# Disable IPv6
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Reload Daemon and enable Velociraptor as a service
sudo systemctl daemon-reload
sudo systemctl enable --now velociraptor


wget https://aka.ms/downloadazcopy-v10-linux
tar -xvf downloadazcopy-v10-linux

sudo rm -f /usr/bin/azcopy
sudo cp ./azcopy_linux_amd64_*/azcopy /usr/bin/
sudo chmod 755 /usr/bin/azcopy

rm -f downloadazcopy-v10-linux
rm -rf ./azcopy_linux_amd64_*/

export AZCOPY_AUTO_LOGIN_TYPE=MSI

# Create folder for client files
sudo mkdir -p /etc/velociraptor/clientrepo/export

# Generate new Velociraptor client config based on the preset variables in the server config
sudo velociraptor config client -c /etc/velociraptor.config.yaml > /etc/velociraptor/clientrepo/client.config.yaml

# Download Velociraptor MSI source installer
sudo wget -O /etc/velociraptor/clientrepo/velociraptor-v0.6.7-4-windows-amd64.msi "https://github.com/Velocidex/velociraptor/releases/download/v0.6.7-5/velociraptor-v0.6.7-4-windows-amd64.msi"

# Generate MSI installer with today's date
sudo velociraptor config repack --msi /etc/velociraptor/clientrepo/velociraptor-v0.6.7-4-windows-amd64.msi /etc/velociraptor/clientrepo/client.config.yaml /etc/velociraptor/clientrepo/VRInstaller.msi
sudo mv /etc/velociraptor/clientrepo/VRInstaller.msi "/etc/velociraptor/clientrepo/export/VRInstaller_$(date +"%d-%m-%y").msi"

# Generate Debian installer
sudo velociraptor --config /etc/velociraptor/clientrepo/client.config.yaml debian client --output "/etc/velociraptor/clientrepo/export/VRInstaller_$(date +"%d-%m-%y").deb"

# Generate CentOS/RHEL installer
sudo velociraptor --config /etc/velociraptor/clientrepo/client.config.yaml rpm client --output "/etc/velociraptor/clientrepo/export/VRInstaller_$(date +"%d-%m-%y").rpm"

# Note - all installers are located in /etc/velociraptor/clientrepo
azcopy copy "/etc/velociraptor/clientrepo/export/*" ${azurerm_storage_container.velociraptor.id}

sleep 1m

# Reboot machine
sudo reboot
  CUSTOM_DATA
  }

resource "azurerm_resource_group" "velociraptor" {
  name     = "${var.prefix}-RG"
  location = var.vr_rg_location
}

resource "azurerm_virtual_network" "main" {
  name                = "${var.prefix}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.velociraptor.location
  resource_group_name = azurerm_resource_group.velociraptor.name
}

resource "azurerm_subnet" "internal" {
  name                 = "${var.prefix}-subnet"
  resource_group_name  = azurerm_resource_group.velociraptor.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_security_group" "nsg" {
  name                = "${var.prefix}-nsg"
  location            = azurerm_resource_group.velociraptor.location
  resource_group_name = azurerm_resource_group.velociraptor.name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.vr_allowlist_ip
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_HTTPS"
    priority                   = 900
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Temp_Allow_HTTP"
    priority                   = 901
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

}

resource "azurerm_public_ip" "pip" {
  name                = "${var.prefix}-pip"
  location            = azurerm_resource_group.velociraptor.location
  resource_group_name = azurerm_resource_group.velociraptor.name
  allocation_method   = "Static"
}



resource "azurerm_network_interface" "main" {
  name                = "${var.prefix}-nic"
  location            = azurerm_resource_group.velociraptor.location
  resource_group_name = azurerm_resource_group.velociraptor.name

  ip_configuration {
    name                = "${var.prefix}-ip"
    subnet_id                     = azurerm_subnet.internal.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

resource "azurerm_network_interface_security_group_association" "assoc" {
  network_interface_id      = azurerm_network_interface.main.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}


resource "azurerm_virtual_machine" "main" {
  name                  = "${var.prefix}-vm"
  location              = azurerm_resource_group.velociraptor.location
  resource_group_name   = azurerm_resource_group.velociraptor.name
  network_interface_ids = [azurerm_network_interface.main.id]
  vm_size               = var.vr_vm_sku

  delete_os_disk_on_termination = false
  delete_data_disks_on_termination = false

  identity {
    type    = "SystemAssigned"    
  }


  storage_image_reference {
    publisher = var.vr_os_publisher
    offer     = var.vr_os_offer
    sku       = var.vr_os_sku
    version   = var.vr_os_version
  }
  storage_os_disk {
    name              = "${var.prefix}-osdisk"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "StandardSSD_LRS"
    disk_size_gb      = var.vr_os_disk_size
  }
  os_profile {
    computer_name  = "velociraptor"
    admin_username = "vm-admin"
    admin_password = random_password.vr_vmpassword.result
    custom_data = base64encode(local.custom_data)
  }

  os_profile_linux_config {
    disable_password_authentication = false
  }
  tags = {
    environment = "staging"
  }
}

resource "azuread_application" "velociraptor" {

    device_only_auth_enabled       = false
    display_name                   = "Velociraptor"
    fallback_public_client_enabled = false
    group_membership_claims        = []
    identifier_uris                = []
    oauth2_post_response_required  = false
    owners                         = [
        var.vr_azure_application_owner,
    ]
    prevent_duplicate_names        = false
    sign_in_audience               = "AzureADMyOrg"

    api {
        known_client_applications      = []
        mapped_claims_enabled          = false
        requested_access_token_version = 1
    }


    public_client {
        redirect_uris = []
    }

    required_resource_access {
        resource_app_id = "00000003-0000-0000-c000-000000000000"

        resource_access {
            id   = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
            type = "Scope"
        }
        resource_access {
            id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
            type = "Scope"
        }
    }

    single_page_application {
        redirect_uris = []
    }

    timeouts {}

    web {
        redirect_uris = [
            "https://${var.vr_domain}/auth/azure/callback",
        ]

        implicit_grant {
            access_token_issuance_enabled = false
            id_token_issuance_enabled     = false
        }
    }
}

resource "azuread_application_password" "velociraptor_app_password" {
  application_object_id = "${azuread_application.velociraptor.id}"
  end_date              = timeadd(timestamp(), "8760h")

}

resource "azurerm_key_vault" "vr_kv" {
  name                        = "${var.prefix}-kv-${random_id.rid.hex}"
  location                    = azurerm_resource_group.velociraptor.location
  resource_group_name         = azurerm_resource_group.velociraptor.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.vr_azurerm_config.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.vr_azurerm_config.tenant_id
    object_id = var.vr_azure_application_owner

    key_permissions = [
      "Get",
    ]

    secret_permissions = [
      "Get", "Backup", "Delete", "List", "Purge", "Recover", "Restore", "Set",
    ]

    storage_permissions = [
      "Get",
    ]
  }

}
#Create KeyVault VM password
resource "random_password" "vr_vmpassword" {
  length  = 20
  special = true
}
#Create Key Vault Secret
resource "azurerm_key_vault_secret" "vr_vmpassword" {
  name         = "vmpassword"
  value        = random_password.vr_vmpassword.result
  key_vault_id = azurerm_key_vault.vr_kv.id
  depends_on   = [azurerm_key_vault.vr_kv]
}

resource "azurerm_storage_account" "velociraptor" {
  name                            = "${var.prefix}${random_id.rid.hex}sa"
  resource_group_name             = azurerm_resource_group.velociraptor.name
  location                        = azurerm_resource_group.velociraptor.location
  account_replication_type        = "LRS"
  account_tier                    = "Standard"
  min_tls_version = "TLS1_2"
}

resource "azurerm_storage_container" "velociraptor" {
  name                  = "${var.prefix}-container"
  storage_account_name  = azurerm_storage_account.velociraptor.name
  container_access_type = "private"
}

resource "azurerm_role_assignment" "velociraptor" {
  scope                = azurerm_storage_account.velociraptor.id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = "${azurerm_virtual_machine.main.identity.0.principal_id}"
}