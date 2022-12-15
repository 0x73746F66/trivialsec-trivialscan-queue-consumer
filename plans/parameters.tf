resource "aws_ssm_parameter" "sendgrid_api_key" {
  name        = "/${var.app_env}/${var.app_name}/Sendgrid/api-key"
  type        = "SecureString"
  value       = var.sendgrid_api_key
  tags        = local.tags
  overwrite   = true
}
