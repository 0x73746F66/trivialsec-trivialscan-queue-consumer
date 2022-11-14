output "trivialscan_ondemand_arn" {
    value = aws_lambda_function.trivialscan_ondemand.arn
}
output "trivialscan_ondemand_role" {
  value = aws_iam_role.trivialscan_ondemand_role.name
}
output "trivialscan_ondemand_role_arn" {
  value = aws_iam_role.trivialscan_ondemand_role.arn
}
output "trivialscan_ondemand_policy_arn" {
  value = aws_iam_policy.trivialscan_ondemand_policy.arn
}
