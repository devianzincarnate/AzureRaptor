# AzureRaptor

AzureRaptor is designed to assist incident responders with rapidly deploying an instance of Velociraptor via Azure within a matter of minutes using Terraform.

Please note that this uses the Let's Encrypt configuration and therefore requires a valid domain name and associated DNS service.

Prerequisites:
- Domain Name
- DNS Service (e.g. Cloudflare)
- An Azure subscription and an appropriate level of access (e.g. Contributor)

AzureRaptor deploys the following:
- An Azure resource group
- A Ubuntu 22.04 LTS VM with Velociraptor installed
- A Network Security Group
- A storage account and container for storing the generated Velociraptor agents
- An Azure enterprise application (to enable SSO with Velociraptor)
- A key vault which stores the default VM credentials

## Instructions
1. Open an instance of Azure Cloud Shell.

2. Create a new folder and copy main.tf and terraform.tfvars.

3. Edit terraform.tfvars using a text editor and change the values to suit your environment.

4. Initialise the terraform environment with the following command:
   terraform init

4. Deploy the instance using the following command:
   terraform apply

5. Make the required domain name to IP address mappings via your DNS service provider.

6. Access the Velociraptor agents via the deployed storage account container.

7. The console should be accessible after the DNS update (please ensure you have waited out your DNS TTL before trying to access it) at
   at https://<domainname.tld>

8. For SSH access to the VM, check the key vault inside the deployed resource group.



NOTES: For added security, remove the Port 80 allow rule on the Network Security Group and restrict HTTPS access to the external IP address of sites
where agents are connecting in from. You may not be able to do the latter if there are a large proportion of home users and VPN split tunnelling is allowed.
