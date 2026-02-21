# Monitoring Dashboard

The Data Platform Genie includes a comprehensive CloudWatch monitoring dashboard that provides visibility into both **usage metrics** and **billing/cost information** for your data platform infrastructure.

## Features

The monitoring dashboard includes the following widgets:

### Usage Metrics

1. **MWAA Task & DAG Execution**
   - Successful task instances
   - Failed task instances
   - Successful DAG runs
   - Failed DAG runs
   - Updated every 5 minutes

2. **ECS Job Resource Usage**
   - CPU utilization percentage
   - Memory utilization percentage
   - Helps identify resource constraints in batch jobs

3. **Kinesis Firehose Throughput**
   - Incoming records per second
   - Incoming bytes
   - Successful deliveries to S3
   - Monitor streaming data ingestion

4. **S3 Data Lake Storage**
   - Total bucket size in bytes
   - Number of objects stored
   - Daily aggregation for storage trends

### Billing and Cost Metrics

5. **Estimated AWS Charges**
   - Total estimated monthly charges across all services
   - Updated every 6 hours
   - Note: Billing metrics are only available in `us-east-1` region

6. **Estimated Charges by Service**
   - Breakdown by individual AWS services:
     - Amazon MWAA (Managed Airflow)
     - Amazon S3 (Data Lake storage)
     - Amazon ECS (Batch job execution)
     - Amazon Kinesis Firehose (Streaming ingestion)
     - AWS CloudWatch (Monitoring and logs)
   - Helps identify cost optimization opportunities

### Error Analysis

7. **Error Rate**
   - 5-minute intervals showing error count trends
   - Uses CloudWatch Logs Insights to parse log messages

8. **Top 10 Failed Tasks**
   - Identifies the most frequently failing Airflow tasks
   - Helps prioritize debugging efforts

## Accessing the Dashboard

After deploying your environment, the dashboard URL is available as a Terraform output:

```bash
# For dev environment
terraform -chdir=terraform/envs/dev output dashboard_url

# For prod environment
terraform -chdir=terraform/envs/prod output dashboard_url
```

Or use the `genie` CLI (if you add a command to display outputs):

```bash
genie show-dashboard dev
```

The dashboard is also accessible through the AWS Console:
1. Navigate to CloudWatch → Dashboards
2. Look for `<project>-dev-monitoring` or `<project>-prod-monitoring`

## Enabling Billing Metrics

For billing metrics to appear in the dashboard, you must enable cost and usage data in your AWS account:

1. Sign in to the AWS Management Console with your root account or IAM administrator
2. Navigate to **Billing and Cost Management** → **Billing Preferences**
3. Enable **Receive Billing Alerts**
4. Wait 24 hours for billing data to populate

**Important**: Billing metrics are only available in the `us-east-1` (N. Virginia) region, regardless of where your resources are deployed.

## Customizing the Dashboard

The dashboard is defined in Terraform at `terraform/modules/dashboard/main.tf`. You can customize it by:

### Adding New Metrics

Edit the `dashboard_body` JSON to add additional metric widgets:

```hcl
{
  type = "metric"
  properties = {
    metrics = [
      ["AWS/Lambda", "Invocations", { stat = "Sum", label = "Lambda Invocations" }]
    ]
    period = 300
    stat   = "Sum"
    region = var.region
    title  = "Lambda Usage"
  }
  width  = 12
  height = 6
  x      = 0
  y      = 24
}
```

### Adding Log Insights Queries

Add custom log analysis widgets:

```hcl
{
  type = "log"
  properties = {
    query   = <<-EOT
      SOURCE '${var.log_group_name}'
      | fields @timestamp, @message
      | filter @message like /WARNING/
      | stats count() by bin(5m)
    EOT
    region  = var.region
    title   = "Warning Rate"
  }
  width  = 12
  height = 6
  x      = 12
  y      = 24
}
```

### Adjusting Time Ranges

The dashboard shows the last 3 hours by default. Users can adjust the time range using the CloudWatch console dropdown.

## Monitoring Best Practices

1. **Set up CloudWatch Alarms** - Create alarms for critical metrics like task failure rate or high costs
2. **Review daily** - Check the dashboard daily during development
3. **Weekly cost reviews** - Monitor the billing section weekly to avoid surprise charges
4. **Investigate anomalies** - Use the "Top 10 Failed Tasks" widget to prioritize fixes
5. **Optimize resources** - Use ECS resource utilization to right-size task definitions

## Integration with Alerting

While the dashboard provides visibility, consider setting up CloudWatch Alarms for proactive monitoring:

```hcl
resource "aws_cloudwatch_metric_alarm" "task_failure_rate" {
  alarm_name          = "${var.name}-high-task-failure-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TaskInstanceFailure"
  namespace           = "AWS/MWAA"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Alert when task failure rate is high"
  
  alarm_actions = [aws_sns_topic.alerts.arn]
}
```

## Troubleshooting

### Dashboard not showing data

- **Billing metrics**: Wait 24 hours after enabling billing alerts
- **MWAA metrics**: Ensure at least one DAG has run
- **Log insights**: Verify the log group name matches the MWAA log group

### Metrics showing zero

- Check that resources are actually running (DAGs scheduled, jobs executed)
- Verify IAM permissions allow CloudWatch metric publishing
- Ensure the correct AWS region is selected

### Dashboard not found

- Run `terraform apply` to create the dashboard
- Verify the dashboard module is included in your environment's `main.tf`

## Further Reading

- [AWS CloudWatch Dashboards Documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html)
- [CloudWatch Logs Insights Query Syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html)
- [AWS Cost Management](https://aws.amazon.com/aws-cost-management/)
