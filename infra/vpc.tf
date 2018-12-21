# The network load balancers don't have security groups, and
# to allow healthchecks from them to the application, from
# them, we have to open up security groups to the entire subnet
# that they're in. Hence we have a subnet per network load
# balancer.

data "aws_vpc" "main" {
  id = "${var.vpc_id}"
}

data "aws_internet_gateway" "main" {
  internet_gateway_id = "${var.internet_gateway_id}"
}

data "aws_nat_gateway" "main" {
  id = "${var.nat_gateway_id}"
}

data "aws_vpc_peering_connection" "private_subnet" {
  id = "${var.private_subnet_vpc_peering_connection_id}"
}

data "aws_eip" "healthcheck_nat" {
  id = "${var.healthcheck_nat_eip_allocation_id}"
}

resource "aws_subnet" "public" {
  vpc_id     = "${data.aws_vpc.main.id}"
  cidr_block = "${var.public_subnet_cidr}"

  availability_zone = "${var.availability_zone}"

  tags {
    Name = "${var.name}-public-${var.availability_zone}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = "${data.aws_vpc.main.id}"
  tags {
    Name = "${var.name}-public"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = "${aws_subnet.public.id}"
  route_table_id = "${aws_route_table.public.id}"
}

resource "aws_route" "public_internet_gateway_ipv4" {
  route_table_id         = "${aws_route_table.public.id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "${data.aws_internet_gateway.main.id}"
}

resource "aws_subnet" "app" {
  vpc_id     = "${data.aws_vpc.main.id}"
  cidr_block = "${var.app_subnet_cidr}"

  availability_zone = "${var.availability_zone}"

  tags {
    Name = "${var.name}-app-${var.availability_zone}"
  }
}

resource "aws_route_table" "app" {
  vpc_id = "${data.aws_vpc.main.id}"
  tags {
    Name = "${var.name}-app"
  }
}

resource "aws_route" "vpc_peering_connection_app_subnet" {
  route_table_id            = "${aws_route_table.app.id}"
  vpc_peering_connection_id = "${data.aws_vpc_peering_connection.private_subnet.id}"
  destination_cidr_block    = "${data.aws_vpc_peering_connection.private_subnet.cidr_block}"
}

resource "aws_route" "app_nat_gateway_ipv4" {
  route_table_id         = "${aws_route_table.app.id}"
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = "${data.aws_nat_gateway.main.id}"
}

resource "aws_route_table_association" "app" {
  subnet_id      = "${aws_subnet.app.id}"
  route_table_id = "${aws_route_table.app.id}"
}

resource "aws_subnet" "healthcheck_private" {
  vpc_id     = "${data.aws_vpc.main.id}"
  cidr_block = "${var.healthcheck_private_subnet_cidr}"

  availability_zone = "${var.availability_zone}"

  tags {
    Name = "${var.name}-healthcheck-private-${var.availability_zone}"
  }
}

resource "aws_nat_gateway" "healthcheck" {
  allocation_id = "${data.aws_eip.healthcheck_nat.id}"
  subnet_id     = "${aws_subnet.healthcheck_public_a.id}"

  tags {
    Name = "${var.name}-healthcheck"
  }
}

resource "aws_route_table" "healthcheck_private" {
  vpc_id = "${data.aws_vpc.main.id}"
  tags {
    Name = "${var.name}-healthcheck-private"
  }
}

resource "aws_route_table_association" "healthcheck_private" {
  subnet_id      = "${aws_subnet.healthcheck_private.id}"
  route_table_id = "${aws_route_table.healthcheck_private.id}"
}

resource "aws_route" "healthcheck_nat_gateway_ipv4" {
  route_table_id         = "${aws_route_table.healthcheck_private.id}"
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = "${aws_nat_gateway.healthcheck.id}"
}

resource "aws_subnet" "healthcheck_public_a" {
  vpc_id     = "${data.aws_vpc.main.id}"
  cidr_block = "${var.healthcheck_public_subnet_a_cidr}"

  availability_zone = "${var.availability_zone}"

  tags {
    Name = "${var.name}-healthcheck-public-${var.availability_zone}"
  }
}

resource "aws_subnet" "healthcheck_public_b" {
  vpc_id     = "${data.aws_vpc.main.id}"
  cidr_block = "${var.healthcheck_public_subnet_b_cidr}"

  availability_zone = "${var.availability_zone_secondary}"

  tags {
    Name = "${var.name}-healthcheck-public-${var.availability_zone_secondary}"
  }
}

resource "aws_route_table" "healthcheck_public" {
  vpc_id = "${data.aws_vpc.main.id}"
  tags {
    Name = "${var.name}-healthcheck-public"
  }
}

resource "aws_route_table_association" "healthcheck_public_a" {
  subnet_id      = "${aws_subnet.healthcheck_public_a.id}"
  route_table_id = "${aws_route_table.healthcheck_public.id}"
}

resource "aws_route_table_association" "healthcheck_public_b" {
  subnet_id      = "${aws_subnet.healthcheck_public_b.id}"
  route_table_id = "${aws_route_table.healthcheck_public.id}"
}

resource "aws_route" "healthcheck_internet_gateway_ipv4" {
  route_table_id         = "${aws_route_table.healthcheck_public.id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "${data.aws_internet_gateway.main.id}"
}
