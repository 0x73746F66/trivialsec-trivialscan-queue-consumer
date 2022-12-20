output "trivialscan_queue_consumer_arn" {
    value = aws_lambda_function.trivialscan_queue_consumer.arn
}
output "trivialscan_queue_consumer_role" {
  value = aws_iam_role.trivialscan_queue_consumer_role.name
}
output "trivialscan_queue_consumer_role_arn" {
  value = aws_iam_role.trivialscan_queue_consumer_role.arn
}
output "trivialscan_queue_consumer_policy_arn" {
  value = aws_iam_policy.trivialscan_queue_consumer_policy.arn
}
