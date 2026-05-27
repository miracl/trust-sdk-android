#!/bin/sh

./gradlew connectedAndroidTest \
  -Pmiracltrust.cuvProjectId="$TEST_CUV_PROJECT_ID" \
  -Pmiracltrust.cuvProjectUrl="$TEST_CUV_PROJECT_URL" \
  -Pmiracltrust.cuvServiceAccountToken="$TEST_CUV_SERVICE_ACCOUNT_TOKEN" \
  -Pmiracltrust.dvProjectId="$TEST_DV_PROJECT_ID" \
  -Pmiracltrust.dvProjectUrl="$TEST_DV_PROJECT_URL" \
  -Pmiracltrust.ecvProjectId="$TEST_ECV_PROJECT_ID" \
  -Pmiracltrust.ecvProjectUrl="$TEST_ECV_PROJECT_URL" \
  -Pmailpit.url=$TEST_MAILPIT_URL \
  -Pmailpit.user=$TEST_MAILPIT_USER \
  -Pmailpit.pass=$TEST_MAILPIT_PASS \
  -Pmailpit.emailAddress=$TEST_MAILPIT_EMAIL_ADDRESS
