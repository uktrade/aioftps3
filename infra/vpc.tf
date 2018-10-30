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
    Name = "ftps3-public-${var.availability_zone}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = "${data.aws_vpc.main.id}"
  tags {
    Name = "ftps3-public"
  }
}

resource "aws_route" "public_internet_gateway_ipv4" {
  route_table_id         = "${aws_route_table.public.id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "${data.aws_internet_gateway.main.id}"
}

resource "aws_route_table_association" "public" {
  subnet_id      = "${aws_subnet.public.id}"
  route_table_id = "${aws_route_table.public.id}"
}

resource "aws_route_table" "private" {
  vpc_id = "${data.aws_vpc.main.id}"
  tags {
    Name = "ftps3-private"
  }
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

resource "aws_subnet" "private" {
  vpc_id     = "${data.aws_vpc.main.id}"
  cidr_block = "${var.private_subnet_cidr}"

  availability_zone = "${var.availability_zone}"

  tags {
    Name = "ftps3-private-${var.availability_zone}"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = "${aws_subnet.private.id}"
  route_table_id = "${aws_route_table.private.id}"
}
