terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
       version = "3.61.0"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "vr_azurerm_config" {
}

variable "prefix" {
default = "vr"
description = "Prefix appended to resource names"
}

variable "vr_allowlist_ip" {
type = string
default = "1.2.3.4"
description = "Allowed IP for Velociraptor SSH on the NSG"
}

variable "vr_security_group" {
default = "00000000-0000-0000-0000-000000000000"
description = "Assigns the defined group or user with privileges to access Velociraptor RG, key vault and storage"
}

variable "vr_managed_disk_type" {
type = string
default = "Premium_LRS"
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

variable "dns_zone_name" {
default = "evilcorp.io"
description = "Domain name for the Azure DNS Zone"
}

variable "dns_zone_rgname" {
default = "RG-Evilcorp"
description = "Name of the resource group for the Azure DNS Zone"
}

variable "dns_zone_servername" {
default = "velociraptor"
description = "Server name to use for the Azure DNS Zone A record"
}

resource "random_id" "rid" {
  byte_length = 3
}

# Define Velociraptor configuration script to be run as part of cloud-init

locals {
  custom_data = <<CUSTOM_DATA
#!/bin/bash

# Run OS and package updates
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y

# Download latest Velociraptor Linux binary to /usr/local/bin and make it executable
curl -s https://api.github.com/repos/Velocidex/velociraptor/releases/latest \
| grep "browser_download_url.*linux-amd64*" \
| grep -v "sig" \
| head -1 \
| cut -d : -f 2,3 \
| tr -d \", \
| wget -O /usr/local/bin/velociraptor -qi -
sudo chmod +x /usr/local/bin/velociraptor

# Generate new Velociraptor server configuration with some preset variables and change permissions
sudo velociraptor config generate --merge '{"Client":{"server_urls":["https://${var.vr_domain}/"],"writeback_linux":"/etc/velociraptor.writeback.yaml","writeback_windows":"/Program Files/Velociraptor/velociraptor.writeback.yaml"},"API":{"hostname":"${var.vr_domain}","bind_address":"127.0.0.1","bind_port":8001,"bind_scheme":"tcp"},"GUI":{"bind_address":"0.0.0.0","bind_port":8889,"public_url":"https://${var.vr_domain}/","authenticator":{"type":"Basic"}},"Frontend":{"hostname":"${var.vr_domain}","bind_address":"0.0.0.0","bind_port":443},"autocert_domain":"${var.vr_domain}","autocert_cert_cache":"/etc/velociraptor"}' > /etc/velociraptor.config.yaml
# Grant user access to Velociraptor and modify role to administrator.
velociraptor user add --role=administrator ${var.vr_user} ${random_password.vr_adminpassword.result} --config /etc/velociraptor.config.yaml

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

# Download and install AzCopy
wget https://aka.ms/downloadazcopy-v10-linux
tar -xvf downloadazcopy-v10-linux
sudo rm -f /usr/bin/azcopy
sudo cp ./azcopy_linux_amd64_*/azcopy /usr/bin/
sudo chmod 755 /usr/bin/azcopy
rm -f downloadazcopy-v10-linux
rm -rf ./azcopy_linux_amd64_*/

# Set variable to allow AzCopy to log in using Managed Service Identity
export AZCOPY_AUTO_LOGIN_TYPE=MSI

# Create folder for client files
sudo mkdir -p /etc/velociraptor/clientrepo/export

# Generate new Velociraptor client config based on the preset variables in the server config
sudo velociraptor config client -c /etc/velociraptor.config.yaml > /etc/velociraptor/clientrepo/client.config.yaml

# Get latest Velociraptor MSI installer name
export VR_WIN_CURRENT_AGENT_VERSION=/etc/velociraptor/clientrepo/$(curl -s https://api.github.com/repos/Velocidex/velociraptor/releases/latest \
| grep "name.*msi*" \
| grep -v "sig" \
| head -1 \
| cut -d : -f 2,3 \
| tr -d \", \
| xargs )

# Download Velociraptor MSI source installer
curl -s https://api.github.com/repos/Velocidex/velociraptor/releases/latest \
| grep "browser_download_url.*msi*" \
| grep -v "sig" \
| head -1 \
| cut -d : -f 2,3 \
| tr -d \" \
| sudo wget -O $VR_WIN_CURRENT_AGENT_VERSION -qi -


# Generate MSI installer with today's date
sudo velociraptor config repack --msi $VR_WIN_CURRENT_AGENT_VERSION /etc/velociraptor/clientrepo/client.config.yaml /etc/velociraptor/clientrepo/VRInstaller.msi
sudo mv /etc/velociraptor/clientrepo/VRInstaller.msi "/etc/velociraptor/clientrepo/export/VRInstaller_$(date +"%d-%m-%y").msi"

# Generate Debian installer
sudo velociraptor --config /etc/velociraptor/clientrepo/client.config.yaml debian client --output "/etc/velociraptor/clientrepo/export/VRInstaller_$(date +"%d-%m-%y").deb"

# Generate CentOS/RHEL installer
sudo velociraptor --config /etc/velociraptor/clientrepo/client.config.yaml rpm client --output "/etc/velociraptor/clientrepo/export/VRInstaller_$(date +"%d-%m-%y").rpm"

# Copy Velociraptor agents to Azure Blob Storage Container
azcopy copy "/etc/velociraptor/clientrepo/export/*" ${azurerm_storage_container.velociraptor.id}

# Delay reboot by 1 minute to allow for AzCopy to finish
sleep 1m

# Reboot machine
sudo reboot
  CUSTOM_DATA
  }

# Create resource group for Velociraptor
resource "azurerm_resource_group" "velociraptor" {
  name     = "${var.prefix}-RG"
  location = var.vr_rg_location
}

# Create virtual network to be used by Velociraptor
resource "azurerm_virtual_network" "main" {
  name                = "${var.prefix}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.velociraptor.location
  resource_group_name = azurerm_resource_group.velociraptor.name
}

# Create associated subnet
resource "azurerm_subnet" "internal" {
  name                 = "${var.prefix}-subnet"
  resource_group_name  = azurerm_resource_group.velociraptor.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

# Create NSG and lock down SSH and management ports to approved IPs.
# 443 and 80 are required for Let's Encrypt certificate issuing - 80 can be removed after resource creation and first logon to Velociraptor.

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
    priority                   = 899
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

    security_rule {
    name                       = "Allow_GUI"
    priority                   = 900
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8889"
    source_address_prefix      = var.vr_allowlist_ip
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

# Create public IP associated with the VM, NSG and DNS
resource "azurerm_public_ip" "pip" {
  name                = "${var.prefix}-pip"
  location            = azurerm_resource_group.velociraptor.location
  resource_group_name = azurerm_resource_group.velociraptor.name
  allocation_method   = "Static"
}

# Create NIC associated with the VM and NSG
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

# Create association between NIC and NSG
resource "azurerm_network_interface_security_group_association" "assoc" {
  network_interface_id      = azurerm_network_interface.main.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# Create Linux VM for Velociraptor application to be installed with Managed Service Identity
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
    managed_disk_type = var.vr_managed_disk_type
    disk_size_gb      = var.vr_os_disk_size
  }
  os_profile {
    computer_name  = "velociraptor"
    admin_username = "vr-admin"
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

# Create key vault for storing VM and Velociraptor administrator credentials
resource "azurerm_key_vault" "vr_kv" {
  name                        = "${replace(substr(var.prefix, 0, 19), "-", "")}kv${random_id.rid.hex}"
  location                    = azurerm_resource_group.velociraptor.location
  resource_group_name         = azurerm_resource_group.velociraptor.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.vr_azurerm_config.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.vr_azurerm_config.tenant_id
    object_id = var.vr_security_group

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

# Create KeyVault VM password
resource "random_password" "vr_vmpassword" {
  length  = 32
  special = true
}
# Create Key Vault Secret for VM password
resource "azurerm_key_vault_secret" "vr_vmpassword" {
  name         = "VRVMPassword"
  value        = random_password.vr_vmpassword.result
  key_vault_id = azurerm_key_vault.vr_kv.id
  depends_on   = [azurerm_key_vault.vr_kv]
}

# Create storage account for agent uploads
resource "azurerm_storage_account" "velociraptor" {
  name                            = "sa${replace(substr(var.prefix, 0, 19), "-", "")}${random_id.rid.hex}"
  resource_group_name             = azurerm_resource_group.velociraptor.name
  location                        = azurerm_resource_group.velociraptor.location
  account_replication_type        = "LRS"
  account_tier                    = "Standard"
  min_tls_version = "TLS1_2"
}

# Create storage container in storage account for uploads
resource "azurerm_storage_container" "velociraptor" {
  name                  = "${var.prefix}-container"
  storage_account_name  = azurerm_storage_account.velociraptor.name
  container_access_type = "private"
}

# Assign user/group privileges for key vault
resource "azurerm_role_assignment" "velociraptor" {
  scope                = azurerm_storage_account.velociraptor.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = "${azurerm_virtual_machine.main.identity.0.principal_id}"
}

# Create Velociraptor application password to be stored in key vault
resource "random_password" "vr_adminpassword" {
  length  = 32
  special = false
}

# Create Key Vault Secret for Velociraptor application password
resource "azurerm_key_vault_secret" "vr_adminpassword" {
  name         = "VRAdminPassword"
  value        = random_password.vr_adminpassword.result
  key_vault_id = azurerm_key_vault.vr_kv.id
  depends_on   = [azurerm_key_vault.vr_kv]
}

# Create DNS entry mapping for the Velociraptor server in an existing Azure DNS Zone
resource "azurerm_dns_a_record" "vr_record" {
  name                = var.dns_zone_servername
  zone_name           = var.dns_zone_name
  resource_group_name = var.dns_zone_rgname
  ttl                 = 300
  records             = ["${azurerm_public_ip.pip.ip_address}"]
}

# Assign contributor resource group permissions to the group
resource "azurerm_role_assignment" "vr_contributor" {
  scope = "/subscriptions/${data.azurerm_client_config.vr_azurerm_config.tenant_id}/resourceGroups/${azurerm_resource_group.velociraptor.name}"
  role_definition_name = "Contributor"
  principal_id         = var.vr_security_group
}
