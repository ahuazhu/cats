# Production alarm recipient runbook

This runbook closes the delivery path for the three usage-pipeline alarms. A
CloudWatch alarm changing state is not evidence of paging unless the exact SNS
topic has a confirmed recipient and the live alarm still names that topic.

The repository preflight is read-only. The controlled test in the final
section changes one CloudWatch alarm's state and therefore requires the normal
production change approval. Neither check is run by Terraform or CI.

## 1. Wire the two Terraform states

Keep actual email addresses, account-specific ARNs, state, saved plans and
evidence outside source control. `*.auto.tfvars` is ignored, and the tracked
examples contain placeholders only.

1. In the private `stacks/platform/platform.auto.tfvars`, set at least one
   operator-owned address in `alert_email_addresses`. Review and apply the
   platform saved plan. It must retain the existing alert topic and create or
   repair only the intended email subscription; stop on an unexpected topic
   replacement.
2. The recipient opens the AWS confirmation email and confirms the
   subscription out of band. A Terraform apply cannot prove this step.
3. Read the exact output from the reviewed platform state:

   ```sh
   topic_arn="$(terraform -chdir=deploy/aws/terraform/stacks/platform output -raw alert_sns_topic_arn)"
   ```

4. Copy that value into the private
   `stacks/production-infrastructure/production.auto.tfvars` as
   `platform_alert_sns_topic_arn`. Do not substitute a similarly named topic
   discovered from the account.
5. Review the production-infrastructure saved plan. Each of these exact metric
   alarms must keep `actions_enabled = true`, and both `alarm_actions` and
   `ok_actions` must contain the one platform topic ARN:

   - `cats-production-usage-write-throttled`
   - `cats-production-usage-read-throttled`
   - `cats-production-usage-consumer-lag`

   Apply only that reviewed saved plan. The usage module and stack reject an
   empty or malformed destination before planning.

If the name prefix or environment differs from production defaults, derive the
three names from the Terraform usage resource name and pass that exact name to
the preflight below.

## 2. Prove the live subscription and alarm actions

Use credentials for the exact topic account. Obtain the confirmed subscription
ARN from a protected terminal after the recipient confirms it. A confirmed
subscription has a canonical ARN; `Deleted`, `PendingConfirmation`, and
`pending confirmation` are statuses, not acceptable ARNs.

The verifier uses one absolute deadline and only these read operations:

- `sts:GetCallerIdentity`;
- `sns:GetTopicAttributes`, `sns:ListSubscriptionsByTopic`, and
  `sns:GetSubscriptionAttributes`;
- `cloudwatch:DescribeAlarms`.

It binds the caller account and region to the topic ARN, finds the exact email
subscription on that exact topic, reads the canonical subscription ARN, and
then requires exactly the three expected Kinesis alarms with actions enabled
and the topic in both ALARM and OK actions. It never emits the recipient email
address.

```sh
subscription_arn="REPLACE_WITH_CONFIRMED_SUBSCRIPTION_ARN"
evidence_dir="/approved/private/cats-cutover-evidence"
install -d -m 0700 "$evidence_dir"
umask 077
python3 deploy/aws/preflight-alarm-recipients.py \
  --topic-arn "$topic_arn" \
  --subscription-arn "$subscription_arn" \
  --usage-resource-name cats-production-usage \
  >"$evidence_dir/e5-alarm-recipients-preflight.json"
```

Keep the one-line JSON with the reviewed plans and exact release evidence. A
nonzero exit is a cutover blocker. Repair the subscription or Terraform state,
then rerun the whole preflight; do not edit a failed evidence file into a
passing one.

The parser and every negative condition can be exercised without AWS:

```sh
python3 deploy/aws/preflight-alarm-recipients-fixture.py
```

## 3. Send one controlled test alarm

Do this only after the preflight passes and the production change owner
approves an alarm-state mutation. Choose a quiet interval, name an incident or
change identifier, and tell the recipient to expect one test page. Do not put
customer data, credentials, or email addresses in the state reason.

First record the alarm's current state and recent history in the protected
evidence directory. Its live state must be `OK`; if it is already `ALARM` or
`INSUFFICIENT_DATA`, stop and investigate the real signal instead of hiding it
with a test. Then temporarily move the write-throttled metric alarm to
`ALARM`:

```sh
test_alarm="cats-production-usage-write-throttled"
test_run_id="REPLACE_WITH_APPROVED_CHANGE_OR_RUN_ID"
aws_region="REPLACE_WITH_TOPIC_REGION"
aws --region "$aws_region" --no-cli-pager --output json cloudwatch describe-alarms \
  --alarm-names "$test_alarm" \
  >"$evidence_dir/e5-test-alarm-before.json"
aws --region "$aws_region" --no-cli-pager cloudwatch set-alarm-state \
  --alarm-name "$test_alarm" \
  --state-value ALARM \
  --state-reason "Cats controlled recipient test $test_run_id"
aws --region "$aws_region" --no-cli-pager --output json cloudwatch describe-alarm-history \
  --alarm-name "$test_alarm" \
  --history-item-type StateUpdate \
  >"$evidence_dir/e5-test-alarm-history.json"
```

AWS documents `SetAlarmState` as a temporary alarm test: when the state really
changes, it invokes the action for the new state. Metric evaluation can restore
the actual state within seconds, so retain `DescribeAlarmHistory` evidence
rather than relying on a console screenshot alone. The operator verifies that
the intended recipient received the SNS message for the exact alarm/topic and
records a bounded acknowledgement tied to `test_run_id` outside the repository.

If the alarm did not automatically return to its metric-derived state, set it
back to the state proven by the current metric and retain that history. Rerun
the read-only preflight after the test. A missing notification, wrong recipient,
wrong topic, disabled action, or unverifiable history keeps the cutover closed.

AWS references:

- [SNS subscription attributes](https://docs.aws.amazon.com/sns/latest/api/API_GetSubscriptionAttributes.html)
- [CloudWatch alarm reads](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/describe-alarms.html)
- [Controlled alarm state test](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/set-alarm-state.html)
