# MIRACL Trust Android SDK Sample

A sample application demonstrating user registration via
[Email Link verification](https://miracl.com/docs/guides/built-in-user-verification/email-link/)
and [user authentication](https://miracl.com/docs/guides/authentication/mobile-sdk/#authenticate-on-your-mobile-application)
within the app.

## Set up and run

### Clone the repository and get the signing fingerprint

1. Start by cloning the repository:

   ```sh
   git clone https://github.com/miracl/trust-sdk-android.git
   cd trust-sdk-android
   ```

2. Get your debug signing key's SHA-256 fingerprint:

   ```sh
   ./gradlew :sample:signingReport
   ```

3. Find the `Variant: debug` section in the output and copy the `SHA-256` value.

### Configure a project in the MIRACL Trust Portal

To run the sample, you need a project in the MIRACL Trust Portal to connect
the app to the platform. The project domain also hosts the `assetlinks.json`
file required for email link verification via Android App Links. Adding your
app details in the portal updates this file automatically.

1. Go to the [MIRACL Trust Portal](https://trust.miracl.cloud) and create a
   project.
2. In the sidebar under **Configuration**, select **Mobile Applications**.
3. In the **Android App Association** section, click **Add Android app**
   and enter your application details:
   - **Package Name:** `com.miracl.trust.sample`
   - **SHA-256 Fingerprint:** The SHA-256 fingerprint copied in the previous section.
4. Under **Configuration > General**, copy your **Project ID** and
   **Project Domain** to configure the sample in the next step.

### Configure and run the app

1. In the project root, open `config.properties` and enter your project
   credentials:

   ```properties
   miracl.projectId=<YOUR_PROJECT_ID>
   # Raw host without protocol scheme (e.g., example.miracl.io)
   miracl.projectDomain=<YOUR_PROJECT_DOMAIN>
   ```

   > **How Android App Links are configured:**  
   > The sample pre-configures an `<intent-filter>` with
   > `android:autoVerify="true"` in `AndroidManifest.xml` and injects
   > `miracl.projectDomain` into the `<data>` tag at build time. When
   > integrating into your own app, you must add this intent filter
   > manually.

2. Build and run the sample in Android Studio, or install it from the
   terminal:

   ```sh
   ./gradlew :sample:installDebug
   ```
