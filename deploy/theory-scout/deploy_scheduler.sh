#!/bin/bash
# Idempotent deploy of the PrismTheoryScout monthly schedule:
#   CodeBuild project (source = repo main) + EventBridge Scheduler rule.
# Prereqs: driver role + scheduler role exist (created with user approval),
#          deploy/theory-scout/{driver.py,buildspec.yml} merged to main.
set -euo pipefail

REGION=us-east-1
ACCT=$(aws sts get-caller-identity --query Account --output text)
HARNESS_ARN="arn:aws:bedrock-agentcore:${REGION}:${ACCT}:harness/PrismTheoryScout-eWHXxBqu5C"
PROJECT=prism-theory-scout
REPO_URL=https://github.com/timwukp/agentic-ai-industry-use-cases
DRIVER_ROLE="arn:aws:iam::${ACCT}:role/PrismTheoryScoutDriverRole"
SCHED_ROLE="arn:aws:iam::${ACCT}:role/PrismTheoryScoutSchedulerRole"

# CodeBuild project — small container, 90 min timeout headroom over the
# harness's 60 min invocation timeout
if aws codebuild batch-get-projects --names "$PROJECT" --region "$REGION" \
     --query 'projects[0].name' --output text 2>/dev/null | grep -q "^$PROJECT$"; then
  ACTION=update-project
else
  ACTION=create-project
fi
aws codebuild $ACTION --region "$REGION" \
  --name "$PROJECT" \
  --source "type=GITHUB,location=${REPO_URL},buildspec=deploy/theory-scout/buildspec.yml" \
  --source-version main \
  --artifacts type=NO_ARTIFACTS \
  --environment "type=LINUX_CONTAINER,image=aws/codebuild/amazonlinux-x86_64-standard:5.0,computeType=BUILD_GENERAL1_SMALL,environmentVariables=[{name=HARNESS_ARN,value=${HARNESS_ARN}}]" \
  --service-role "$DRIVER_ROLE" \
  --timeout-in-minutes 90 \
  --tags key=project,value=prism key=agent-type,value=research-scout >/dev/null
echo "OK codebuild project $PROJECT ($ACTION)"

# Monthly: 1st of each month 02:00 UTC (= 09:00 WIB)
cat > /tmp/theory-scout/sched-target.json <<EOF
{
  "Arn": "arn:aws:scheduler:::aws-sdk:codebuild:startBuild",
  "RoleArn": "${SCHED_ROLE}",
  "Input": "{\"ProjectName\": \"${PROJECT}\"}"
}
EOF
if aws scheduler get-schedule --name prism-theory-scout-monthly --region "$REGION" >/dev/null 2>&1; then
  SCHED_ACTION=update-schedule
else
  SCHED_ACTION=create-schedule
fi
aws scheduler $SCHED_ACTION --region "$REGION" \
  --name prism-theory-scout-monthly \
  --schedule-expression "cron(0 2 1 * ? *)" \
  --flexible-time-window Mode=OFF \
  --target file:///tmp/theory-scout/sched-target.json >/dev/null
echo "OK schedule prism-theory-scout-monthly ($SCHED_ACTION): cron(0 2 1 * ? *) UTC"
