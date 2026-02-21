terraform {
  required_version = ">= 1.5"
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.name}-monitoring"

  dashboard_body = jsonencode({
    widgets = [
      # Usage Metrics Section
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/MWAA", "TaskInstanceSuccess", { stat = "Sum", label = "Successful Tasks" }],
            [".", "TaskInstanceFailure", { stat = "Sum", label = "Failed Tasks" }],
            [".", "DAGRunSuccess", { stat = "Sum", label = "Successful DAG Runs" }],
            [".", "DAGRunFailure", { stat = "Sum", label = "Failed DAG Runs" }]
          ]
          period = 300
          stat   = "Sum"
          region = var.region
          title  = "MWAA Task & DAG Execution"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
        width  = 12
        height = 6
        x      = 0
        y      = 0
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/ECS", "CPUUtilization", { stat = "Average", label = "CPU %" }],
            [".", "MemoryUtilization", { stat = "Average", label = "Memory %" }]
          ]
          period = 300
          stat   = "Average"
          region = var.region
          title  = "ECS Job Resource Usage"
          yAxis = {
            left = {
              min = 0
              max = 100
            }
          }
        }
        width  = 12
        height = 6
        x      = 12
        y      = 0
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Firehose", "IncomingRecords", { stat = "Sum", label = "Incoming Records" }],
            [".", "IncomingBytes", { stat = "Sum", label = "Incoming Bytes" }],
            [".", "DeliveryToS3.Success", { stat = "Sum", label = "Successful Deliveries" }]
          ]
          period = 300
          stat   = "Sum"
          region = var.region
          title  = "Kinesis Firehose Throughput"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
        width  = 12
        height = 6
        x      = 0
        y      = 6
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/S3", "BucketSizeBytes", { stat = "Average", label = "Bucket Size (Bytes)" }],
            [".", "NumberOfObjects", { stat = "Average", label = "Object Count" }]
          ]
          period = 86400
          stat   = "Average"
          region = var.region
          title  = "S3 Data Lake Storage"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
        width  = 12
        height = 6
        x      = 12
        y      = 6
      },
      # Billing and Cost Section
      {
        type = "metric"
        properties = {
          metrics = [
            [
              "AWS/Billing",
              "EstimatedCharges",
              {
                stat = "Maximum",
                label = "Estimated Monthly Charges"
              }
            ]
          ]
          period = 21600
          stat   = "Maximum"
          region = "us-east-1"
          title  = "Estimated AWS Charges (USD)"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
        width  = 12
        height = 6
        x      = 0
        y      = 12
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Billing", "EstimatedCharges", { stat = "Maximum", label = "MWAA" }, { dimensions = { ServiceName = "AmazonMWAA" } }],
            ["...", { dimensions = { ServiceName = "AmazonS3" } }, { label = "S3" }],
            ["...", { dimensions = { ServiceName = "AmazonECS" } }, { label = "ECS" }],
            ["...", { dimensions = { ServiceName = "AmazonKinesisFirehose" } }, { label = "Kinesis Firehose" }],
            ["...", { dimensions = { ServiceName = "AWSCloudWatch" } }, { label = "CloudWatch" }]
          ]
          period = 21600
          stat   = "Maximum"
          region = "us-east-1"
          title  = "Estimated Charges by Service (USD)"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
        width  = 12
        height = 6
        x      = 12
        y      = 12
      },
      # Error and Performance Metrics
      {
        type = "log"
        properties = {
          query   = <<-EOT
            SOURCE '${var.log_group_name}'
            | fields @timestamp, @message
            | filter @message like /ERROR/
            | stats count() by bin(5m)
          EOT
          region  = var.region
          title   = "Error Rate (5 min intervals)"
          stacked = false
        }
        width  = 12
        height = 6
        x      = 0
        y      = 18
      },
      {
        type = "log"
        properties = {
          query   = <<-EOT
            SOURCE '${var.log_group_name}'
            | fields @timestamp, @message
            | filter @message like /TaskInstanceFailure/
            | parse @message "task_id=* " as task_id
            | stats count() by task_id
            | sort count desc
            | limit 10
          EOT
          region  = var.region
          title   = "Top 10 Failed Tasks"
          stacked = false
        }
        width  = 12
        height = 6
        x      = 12
        y      = 18
      }
    ]
  })
}

output "dashboard_name" {
  value       = aws_cloudwatch_dashboard.main.dashboard_name
  description = "CloudWatch Dashboard name for monitoring"
}

output "dashboard_url" {
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
  description = "URL to access the CloudWatch Dashboard"
}
