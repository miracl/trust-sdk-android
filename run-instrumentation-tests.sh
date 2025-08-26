#!/bin/sh

TEST_CREDENTIALS_DIR="./utilities/src/main/res/raw"
mkdir -p $TEST_CREDENTIALS_DIR
echo $GMAIL_CREDENTIALS > "${TEST_CREDENTIALS_DIR}/credentials.json"
echo $GMAIL_TOKEN > "${TEST_CREDENTIALS_DIR}/token.json"

#Instrumentation tests
./gradlew connectedAndroidTest \
  -Pmiracltrust.baseUrl="$TEST_BASE_URL" \
  -Pmiracltrust.cuvClientId="$TEST_CUV_CLIENT_ID" \
  -Pmiracltrust.cuvClientSecret="$TEST_CUV_CLIENT_SECRET" \
  -Pmiracltrust.cuvProjectId="$TEST_CUV_PROJECT_ID" \
  -Pmiracltrust.cuvProjectUrl="$TEST_CUV_PROJECT_URL" \
  -Pmiracltrust.dvProjectId="$TEST_DV_PROJECT_ID" \
  -Pmiracltrust.dvProjectUrl="$TEST_DV_PROJECT_URL" \
  -Pmiracltrust.ecvProjectId="$TEST_ECV_PROJECT_ID" \
  -Pmiracltrust.ecvProjectUrl="$TEST_ECV_PROJECT_URL"

GRADLE_EXIT_CODE=$?

rm "${TEST_CREDENTIALS_DIR}/credentials.json"
rm "${TEST_CREDENTIALS_DIR}/token.json"

exit $GRADLE_EXIT_CODE
