# Production alarm recipient runbook

This runbook closes the delivery path for the three usage-pipeline alarms. A
CloudWatch alarm changing state is not evidence of paging unless the exact SNS
topic has a confirmed recipient and the live alarm still names that topic.

The repository preflight is read-only. The separate controlled-test command in
the final section changes one CloudWatch alarm's state and therefore requires
the normal production change approval, `--execute`, and an exact alarm-ARN
confirmation. CI runs only offline fakes; it never invokes either live command.

## 1. Wire the two Terraform states

Keep actual email addresses, account-specific ARNs, state, saved plans and
evidence outside source control. `*.auto.tfvars` is ignored, and the tracked
examples contain placeholders only.

1. In the private `stacks/platform/platform.auto.tfvars`, set the exact
   production `expected_account_id`, keep `expected_aws_partition` and
   `aws_region` exact, and map at least one opaque stable operator ID to an
   address in sensitive `alert_email_recipients`. For example,
   `primary_oncall = "..."`; never use an address as the key. Production
   rejects an empty map and duplicate address values. Non-production may use
   an empty map.
2. If an earlier revision already put an email-keyed subscription in this
   state, do not apply the key change as a destroy/create. In a protected
   terminal, review the one-to-one old-address to opaque-ID mapping and move
   each exact state address before planning:

   ```sh
   terraform state mv \
     'aws_sns_topic_subscription.alert_email["REPLACE_WITH_OLD_EMAIL_KEY"]' \
     'aws_sns_topic_subscription.alert_email["primary_oncall"]'
   ```

   This command necessarily handles the old email-bearing address, so keep it
   out of shared logs and shell history. If the confirmed subscription exists
   but is not in state, import its protected subscription ARN directly at the
   opaque address instead:

   ```sh
   terraform import \
     'aws_sns_topic_subscription.alert_email["primary_oncall"]' \
     "$subscription_arn"
   ```

   There is intentionally no checked-in `moved` block: the old email key and
   its opaque replacement are private, operator-specific data. Terraform state
   still contains the endpoint value and must remain protected.
3. Review the platform saved plan. It must retain the exact
   `cats-production-alerts` topic and each confirmed subscription at its opaque
   resource address; stop on any replacement. The provider and plan-time
   preconditions independently resolve and check the expected AWS partition,
   account and region.
4. The recipient opens the AWS confirmation email and confirms the
   subscription out of band. A Terraform apply cannot prove this step.
5. Read the exact output from the reviewed platform state:

   ```sh
   topic_arn="$(terraform -chdir=deploy/aws/terraform/stacks/platform output -raw alert_sns_topic_arn)"
   ```

6. Copy that value into the private
   `stacks/production-infrastructure/production.auto.tfvars` as
   `platform_alert_sns_topic_arn`, alongside the same exact
   `expected_account_id`, `expected_aws_partition`, and `aws_region`. The input
   must equal the deterministic `cats-<environment>-alerts` ARN in that exact
   identity; null, malformed, similarly named, cross-account, cross-partition,
   and cross-region topics are rejected. Do not substitute a discovered topic.
7. Review the production-infrastructure saved plan. Each of these exact metric
   alarms must keep `actions_enabled = true`, `alarm_actions` and `ok_actions`
   must each equal the one-element platform topic list, and
   `insufficient_data_actions` must be empty:

   - `cats-production-usage-write-throttled`
   - `cats-production-usage-read-throttled`
   - `cats-production-usage-consumer-lag`

   Apply only that reviewed saved plan. The usage module rejects empty,
   duplicate, or additional destinations.

If the environment differs from the production default, derive the three names
from the Terraform usage resource name and pass that exact name to the
preflight below.

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

It binds the caller ARN partition and account plus the command region to the
topic ARN, finds the exact email subscription on that exact topic, reads the
canonical subscription ARN, and
then requires exactly the three expected Kinesis alarms with actions enabled
and closed action sets: ALARM and OK each equal only the topic, while
INSUFFICIENT_DATA is empty. It strips every `AWS_ENDPOINT_URL*` variable and
disables configured service endpoints before invoking AWS, so compatible API
overrides cannot become live evidence. It never emits the recipient email.

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
python3 deploy/aws/run-controlled-alarm-recipient-test-fixture.py
python3 deploy/aws/terraform/test-alert-recipient-privacy.py
```

## 3. Send one controlled test alarm

Do this only after the preflight passes and the production change owner
approves an alarm-state mutation. Choose a quiet interval, name an incident or
change identifier, and tell the recipient to expect one test page. Do not put
customer data, credentials, or email addresses in the state reason.

Use the separate bounded executor. It first binds the STS caller ARN and exact
alarm ARN to the topic partition/account/region, requires the full live alarm
contract and current state exactly `OK`, and writes the canonical private
before record. It then changes only that alarm to `ALARM`, restores it to `OK`
even after an ambiguous CLI response, and accepts success only when exact
history proves both approval-specific transitions and the final exact read is
`OK`. It writes three new, non-overwriting, canonical evidence files named
`e5-controlled-alarm-{before,history,after}.json`.

The evidence directory must already exist and must not already contain those
files. Use a unique approved change ID. The explicit ARN confirmation must be
byte-for-byte identical to `--alarm-arn`:

```sh
test_run_id="REPLACE_WITH_APPROVED_CHANGE_OR_RUN_ID"
test_alarm_arn="arn:REPLACE_WITH_PARTITION:cloudwatch:REPLACE_WITH_REGION:REPLACE_WITH_ACCOUNT_ID:alarm:cats-production-usage-write-throttled"
python3 deploy/aws/run-controlled-alarm-recipient-test.py \
  --topic-arn "$topic_arn" \
  --alarm-arn "$test_alarm_arn" \
  --confirm-alarm-arn "$test_alarm_arn" \
  --usage-resource-name cats-production-usage \
  --approval-id "$test_run_id" \
  --evidence-directory "$evidence_dir" \
  --deadline-seconds 60 \
  --execute
```

AWS documents `SetAlarmState` as a temporary alarm test: when the state changes,
it invokes the action for the new state. The operator verifies that
the intended recipient received the SNS message for the exact alarm/topic and
records a bounded acknowledgement tied to `test_run_id` outside the repository.

Any nonzero exit after the ALARM attempt is a live incident until the exact
alarm is independently observed `OK`; do not infer restoration from a CLI exit
code. Rerun the read-only preflight after the test. A missing notification,
wrong recipient, wrong topic, disabled action, incomplete evidence, or
unverifiable history keeps the cutover closed.

AWS references:

- [SNS subscription attributes](https://docs.aws.amazon.com/sns/latest/api/API_GetSubscriptionAttributes.html)
- [CloudWatch alarm reads](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/describe-alarms.html)
- [Controlled alarm state test](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/set-alarm-state.html)
