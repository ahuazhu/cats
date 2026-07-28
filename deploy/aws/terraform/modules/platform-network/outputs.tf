output "vpc_id" {
  value = aws_vpc.this.id
}

output "vpc_cidr" {
  value = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnets, tagged for the EKS Auto Mode ALB."
  value       = [for s in aws_subnet.public : s.id]
}

output "private_subnet_ids" {
  description = "Private subnets for EKS nodes, bare-metal workers and RDS."
  value       = [for s in aws_subnet.private : s.id]
}

output "availability_zones" {
  value = local.azs
}

output "nat_public_ips" {
  description = "Stable egress addresses for the fleet."
  value       = [for e in aws_eip.nat : e.public_ip]
}
