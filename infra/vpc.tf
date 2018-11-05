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

# Ideally, this would be private. However, for some reason
# the data FTP connections don't work if we do (while the
# command connections work in both cases)
resource "aws_route" "app_internet_gateway_ipv4" {
  route_table_id         = "${aws_route_table.app.id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "${data.aws_internet_gateway.main.id}"
}

resource "aws_route_table_association" "app" {
  subnet_id      = "${aws_subnet.app.id}"
  route_table_id = "${aws_route_table.app.id}"
}

resource "aws_subnet" "private" {
  vpc_id     = "${data.aws_vpc.main.id}"
  cidr_block = "${var.private_subnet_cidr}"

  availability_zone = "${var.availability_zone}"

  tags {
    Name = "${var.name}-private-${var.availability_zone}"
  }
}

resource "aws_route_table" "private" {
  vpc_id = "${data.aws_vpc.main.id}"
  tags {
    Name = "${var.name}-private"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = "${aws_subnet.private.id}"
  route_table_id = "${aws_route_table.private.id}"
}

resource "aws_route" "private_nat_gateway_ipv4" {
  route_table_id         = "${aws_route_table.private.id}"
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = "${data.aws_nat_gateway.main.id}"
}

resource "aws_route" "vpc_peering_connection_private_subnet" {
  route_table_id            = "${aws_route_table.private.id}"
  vpc_peering_connection_id = "${data.aws_vpc_peering_connection.private_subnet.id}"
  destination_cidr_block    = "${data.aws_vpc_peering_connection.private_subnet.cidr_block}"
}
