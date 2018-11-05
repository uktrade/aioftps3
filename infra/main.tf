data "aws_region" "aws_region" {}

variable "name" {}

variable "availability_zone" {}
variable "vpc_id" {}

variable "route_53_zone" {}
variable "app_external_host" {}
variable "app_internal_host" {}

variable "ip_whitelist" {
  type = "list"
}

variable "public_nlb_eip_allocation_id" {}
variable "nat_gateway_id" {}
variable "internet_gateway_id" {}

variable "public_subnet_cidr" {}
variable "private_subnet_cidr" {}
variable "private_subnet_vpc_peering_connection_id" {}

# We must know all the available IPs for the subnet to pre-register them
# with the target groups. Terraform doesn't have enough functions to work
# these out, so we must tell it the first host index + num hosts
#
# Note that subnet_first_host_index would typically be 4 and
# subnet_count_hosts would be size of subnet - 5 due to AWS internal use
variable "app_subnet_cidr" {}
variable "app_subnet_hosts_first" {}
variable "app_subnet_hosts_count" {}

variable "app_container_image" {}
variable "app_bucket" {}

variable "ftp_user_login" {}
variable "ftp_user_password" {}
variable "ftp_command_port" {}
variable "ftp_data_ports_first" {}
variable "ftp_data_ports_count" {}

locals {
  app_container_name    = "ftps3-app"
  app_container_memory  = 2048
  app_container_cpu     = 1024
}

data "null_data_source" "app_ips" {
  count = "${var.app_subnet_hosts_count}"
  inputs = {
    ip = "${cidrhost(var.app_subnet_cidr, var.app_subnet_hosts_first + count.index)}"
  }
}

data "null_data_source" "ftp_data_ports" {
  count = "${var.ftp_data_ports_count}"
  inputs = {
    port = "${var.ftp_data_ports_first + count.index}"
  }
}
