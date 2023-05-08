resource "aws_ssm_parameter" "sendgrid_api_key" {
  name      = "/${var.app_env}/${var.app_name}/Sendgrid/api-key"
  type      = "SecureString"
  value     = var.sendgrid_api_key
  tags      = local.tags
  overwrite = true
}
resource "aws_ssm_parameter" "pusher_secret" {
  name      = "/${var.app_env}/${var.app_name}/Pusher/secret"
  type      = "SecureString"
  value     = var.pusher_secret
  tags      = local.tags
  overwrite = true
}
resource "aws_ssm_parameter" "pusher_key" {
  name      = "/${var.app_env}/${var.app_name}/Pusher/key"
  type      = "String"
  value     = var.pusher_key
  tags      = local.tags
  overwrite = true
}
resource "aws_ssm_parameter" "pusher_app_id" {
  name      = "/${var.app_env}/${var.app_name}/Pusher/app-id"
  type      = "String"
  value     = var.pusher_app_id
  tags      = local.tags
  overwrite = true
}
resource "aws_ssm_parameter" "lumigo_token" {
  name      = "/${var.app_env}/${var.app_name}/Lumigo/token"
  type      = "SecureString"
  value     = var.lumigo_token
  tags      = local.tags
  overwrite = true
}
