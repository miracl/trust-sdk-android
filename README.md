# MIRACL Trust Android SDK

<!-- markdownlint-configure-file
{
  "line_length": {
    "code_block_line_length": 100
  }
}
-->

The MIRACL Trust Android SDK provides the following functionalities:

- [User ID Verification](#user-id-verification)
- [Registration](#registration)
- [Authentication](#authentication)
- [Signing](#signing)
- [QuickCode](#quickcode)

## System Requirements

- Android API 21 or newer

## Installation

1. Add the following line to the dependencies section in your module
   `build.gradle`

   Kotlin:

   ```kotlin
   dependencies {
       implementation("com.miracl:trust-sdk-android:1.9.0")
   }
   ```

   Groovy:

   ```groovy
   dependencies{
       implementation "com.miracl:trust-sdk-android:1.9.0"
   }
   ```

## Usage

### SDK Configuration

To configure the SDK:

1. Create an account in the MIRACL Trust platform. For information about how
   to do it, see the
   [Getting Started](https://miracl.com/resources/docs/guides/get-started/)
   guide.
1. Call the
   [configure](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/-companion/configure.html)
   method with a configuration created by the [Configuration.Builder](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.configuration/-configuration/-builder/index.html)
   class using [your project properties](https://miracl.com/resources/docs/get-started/create-project/#project-properties):

Kotlin:

```kotlin
class YourApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val configuration = Configuration.Builder(PROJECT_ID, PROJECT_URL).build()
        MIRACLTrust.configure(applicationContext, configuration)
    }
}
```

Java:

```java
public class YourApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        Configuration configuration = new Configuration.Builder(PROJECT_ID, PROJECT_URL).build();
        MIRACLTrust.configure(getApplicationContext(), configuration);
    }
}
```

Call the
[configure](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/-companion/configure.html)
method as early as possible in the application lifecycle and avoid using the
[getInstance](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/-companion/get-instance.html)
method before that; otherwise assertion will be triggered.

### Obtain instance of the SDK

To obtain an instance of the SDK, call the [getInstance](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/-companion/get-instance.html)
method:

Kotlin:

```kotlin
val miraclTrust = MIRACLTrust.getInstance()
```

Java:

```java
MIRACLTrust miraclTrust = MIRACLTrust.getInstance();
```

### User ID Verification

To register a new User ID, you need to verify it. MIRACL Trust offers two
options for that:

- [Custom User Verification](https://miracl.com/resources/docs/guides/custom-user-verification/)
- Built-in Email Verification

  With this type of verification, the end user's email address serves as the
  User ID. Currently, MIRACL Trust provides two kinds of built-in email
  verification methods:

  - [Email Link](https://miracl.com/resources/docs/guides/built-in-user-verification/email-link/)
    (default)
  - [Email Code](https://miracl.com/resources/docs/guides/built-in-user-verification/email-code/)

  Start the verification by calling of the
  [sendVerificationEmail](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/send-verification-email.html)
  method:

  Kotlin:

  ```kotlin
  miraclTrust.sendVerificationEmail(
      userId = USER_ID,
      resultHandler = ResultHandler { result ->
          when (result) {
              is MIRACLSuccess -> {
                  // Verification email is sent.
              }
              is MIRACLError -> {
                  val error = result.value
                  // Verification email is not sent due to an error.
              }
          }
      }
  )
  ```

  Java:

  ```java
  miraclTrust.sendVerificationEmail(
      USER_ID,
      result -> {
          if (result instanceof MIRACLSuccess) {
              // Verification email is sent.
          } else {
              MIRACLError<VerificationResponse, VerificationException> error =
                      (MIRACLError<VerificationResponse, VerificationException>)
                              result;
              // Verification email is not sent due to an error.
          }
      }
  );
  ```
  
  Then, a verification email is sent, and a
  [VerificationResponse](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.registration/-verification-response/index.html)
  with backoff and email verification method is returned.

  If the verification method you have chosen for your project is:

  - **Email Code:**
  
    You must check the email verification method in the response.
  
    - If the end user is registering for the first time or resetting their PIN,
      an email with a verification code will be sent, and the email
      verification method in the response will be
      [EmailVerificationMethod.Code](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.registration/-email-verification-method/-code/index.html).
      Then, ask the user to enter the code in the application.

    - If the end user has already registered another device with the same
      User ID, a Verification URL will be sent, and the verification method in
      the response will be
      [EmailVerificationMethod.Link](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.registration/-email-verification-method/-link/index.html).
      In this case, proceed as described for the **Email Link** verification
      method below.

  - **Email Link:** Your application must open when the end user follows the
    Verification URL in the email. To ensure proper deep linking behaviour on
    mobile applications, use
    [Android's App Links](https://developer.android.com/training/app-links).
    To associate your application with the email Verification URL, use the
    **Android association** field in **Mobile Applications** under
    **Configuration** in the [MIRACL Trust Portal](https://trust.miracl.cloud).

### Registration

1. To register the mobile device, get an activation token. This happens in
   two different ways depending on type of verification.

   - [Custom User Verification](https://miracl.com/resources/docs/guides/custom-user-verification/)
   or [Email Link](https://miracl.com/resources/docs/guides/built-in-user-verification/email-link/):

      After the application recieves the Verification URL, it must confirm the
      verification by passing it to the
      [getActivationToken](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/get-activation-token.html)
      method:

      Kotlin:

      ```kotlin
      intent?.data?.let { verificationUri ->
          miraclTrust.getActivationToken(
              verificationUri,
              resultHandler = { result ->
                  when (result) {
                      is MIRACLSuccess -> {
                          val userId = result.value.userId
                          val activationToken = result.value.activationToken

                          // Use the activation token and the User ID to register the user.
                      }

                      is MIRACLError -> {
                          val error = result.value
                          // Cannot obtain activation token due to an error.
                      }
                  }
              }
          )
      }
      ```

      Java:

      ```java
      Uri verificationUri = intent.getData();
      if (verificationUri != null) {
          miraclTrust.getActivationToken(verificationUri, result -> {
              if (result instanceof MIRACLSuccess) {
                  ActivationTokenResponse response =
                          ((MIRACLSuccess<ActivationTokenResponse, ActivationTokenException>)
                                  result).getValue();

                  String userId = response.getUserId();
                  String activationToken = response.getActivationToken();

                  // Use the activation token and the User ID to register the user.
              } else {
                  MIRACLError<ActivationTokenResponse,
                          ActivationTokenException> error =
                          (MIRACLError<ActivationTokenResponse, ActivationTokenException>)
                                  result;
                  // Cannot obtain activation token due to an error.
              }
          });
      }
      ```

   - [Email Code](https://miracl.com/resources/docs/guides/built-in-user-verification/email-code/):

      When the end user enters the verification code, the application must
      confirm the verification by passing it to the
      [getActivationToken](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/get-activation-token.html)
      method:

       Kotlin:

      ```kotlin
      miraclTrust.getActivationToken(userId, code) { result ->
          when (result) {
              is MIRACLSuccess -> {
                  val userId = result.value.userId
                  val activationToken = result.value.activationToken

                  // Use the activation token and the User ID to register the user.
              }

              is MIRACLError -> {
                  val error = result.value
                  // Cannot obtain activation token due to an error.
              }
          }
      }
      ```

      Java:

      ```java
      miraclTrust.getActivationToken(userId, code, result -> {
          if (result instanceof MIRACLSuccess) {
              ActivationTokenResponse response =
                      ((MIRACLSuccess<ActivationTokenResponse, ActivationTokenException>)
                              result).getValue();

              String userId = response.getUserId();
              String activationToken = response.getActivationToken();

              // Use the activation token and the User ID to register the user.
          } else {
              MIRACLError<ActivationTokenResponse,
                      ActivationTokenException> error =
                      (MIRACLError<ActivationTokenResponse, ActivationTokenException>)
                              result;
              // Cannot obtain activation token due to an error.
          }
      });
      ```

1. Pass the User ID (email or any string you use for identification), activation
   token (received from verification), [PinProvider](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.delegate/-pin-provider/index.html)
   and [ResultHandler](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.delegate/-result-handler/index.html)
   implementations to the [register](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/register.html)
   function. When the registration is successful, a [ResultHandler](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.delegate/-result-handler/index.html)
   callback is returned, passing a [MIRACLSuccess](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-success/index.html)
   together with the registered user as its value. Otherwise, [MIRACLError](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-error/index.html)
   with a [RegistrationException](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.registration/-registration-exception/index.html)
   is passed in the callback.

   Kotlin:

   ```kotlin
   miraclTrust.register(
       userId = USER_ID,
       activationToken = activationToken,
       pinProvider = { pinConsumer ->
           // Ask the user to create a PIN code for their new User ID.
           // Then pass the PIN code to the PinConsumer.
           pinConsumer.consume(userPin)
       },
       resultHandler = { result ->
           when (result) {
               is MIRACLSuccess -> {
                   val user = result.value
               }

               is MIRACLError -> {
                   val error = result.value
                   // Cannot register user due to an error.
               }
           }
       }
   )
   ```

   Java:

   ```java
   miraclTrust.register(
       USER_ID,
       activationToken,
       pinConsumer -> {
           // Ask the user to create a PIN code for their new User ID.
           // Then pass the PIN code to the PinConsumer.
           pinConsumer.consume(userPin);
       },
       result -> {
           if (result instanceof MIRACLSuccess) {
               User user = ((MIRACLSuccess<User, RegistrationException>) result).getValue();
           } else {
               MIRACLError<User, RegistrationException> error =
                       (MIRACLError<User, RegistrationException>) result;
               // Cannot register user due to an error.
           }
       }
   );
   ```

   If you call the
   [register](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/register.html)
   method with the same User ID more than once, the User ID will be overridden.
   Therefore, you can use it when you want to reset your authentication PIN
   code.

### Authentication

MIRACL Trust SDK offers two options:

- [Authenticate users on the mobile application](#authenticate-users-on-the-mobile-application)
- [Authenticate users on another application](#authenticate-users-on-another-application)

#### Authenticate users on the mobile application

The
[authenticate](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/authenticate.html)
method generates a [JWT](https://datatracker.ietf.org/doc/html/rfc7519)
authentication token for а registered user.

Use [PinProvider](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.delegate/-pin-provider/index.html)
the same way it is used during registration.

Kotlin:

```kotlin
miraclTrust.authenticate(
    user = user,
    pinProvider = pinProvider,
    resultHandler = ResultHandler { result ->
        when (result) {
            is MIRACLSuccess -> {
                // user is authenticated
                val jwt = result.value
            }
            is MIRACLError -> {
                // user is not authenticated
            }
        }
    }
)
```

Java:

```java
miraclTrust.authenticate(
    user,
    pinProvider,
    result -> {
        if (result instanceof MIRACLSuccess) {
            // user is authenticated
            String jwt = ((MIRACLSuccess<String, AuthenticationException>) result).getValue();
        } else {
            // user is not authenticated
        }
    }
);
```

After the JWT authentication token is generated, it needs to be sent to the
application server for [verification](https://miracl.com/resources/docs/guides/authentication/jwt-verification/).

#### Authenticate users on another application

To authenticate a user on another application, there are three options:

- Authenticate with [AppLink](https://developer.android.com/training/app-links)

  Use the [authenticateWithAppLink](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/authenticate-with-app-link.html)
  method:

  Kotlin:

  ```kotlin
  intent.data?.let { appLink ->
      miraclTrust.authenticateWithAppLink(
          user = user,
          appLink = appLink,
          pinProvider = pinProvider,
          resultHandler = ResultHandler { result ->
              when (result) {
                  is MIRACLSuccess -> {
                      // user is authenticated
                  }

                  is MIRACLError -> {
                      // user is not authenticated
                  }
              }
          }
      )
  }
  ```

  Java:

  ```java
  Uri appLink = getIntent().getData();
  if (appLink != null) {
      miraclTrust.authenticateWithAppLink(
          user,
          appLink,
          pinProvider,
          result -> {
              if (result instanceof MIRACLSuccess) {
                  // user is authenticated
              } else {
                  // user is not authenticated
              }
          }
      );
  }
  ```

- Authenticate with QR code

  Use the [authenticateWithQRCode](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/authenticate-with-q-r-code.html)
  method:

  Kotlin:

  ```kotlin
  miraclTrust.authenticateWithQRCode(
      user = user,
      qrCode = qrCode,
      pinProvider = pinProvider,
      resultHandler = ResultHandler { result ->
          when (result) {
              is MIRACLSuccess -> {
                  // user is authenticated
              }
              is MIRACLError -> {
                  // user is not authenticated
              }
          }
      }
  )
  ```

  Java:

  ```java
  miraclTrust.authenticateWithQRCode(
      user,
      qrCode,
      pinProvider,
      result -> {
          if (result instanceof MIRACLSuccess) {
              // user is authenticated
          } else {
              // user is not authenticated
          }
      }
  );
  ```

- Authenticate with
  [notification](https://developer.android.com/guide/topics/ui/notifiers/notifications)

  Use the [authenticateWithNotificationPayload](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/authenticate-with-notification-payload.html)
  method:

  Kotlin:

  ```kotlin
  val payload = remoteMessage.data
  miraclTrust.authenticateWithNotificationPayload(
      payload = payload,
      pinProvider = pinProvider,
      resultHandler = ResultHandler { result ->
          when (result) {
              is MIRACLSuccess -> {
                  // user is authenticated
              }
              is MIRACLError -> {
                  // user is not authenticated
              }
          }
      }
  )
  ```

  Java:

  ```java
  Map<String, String> payload = remoteMessage.getData();
  miraclTrust.authenticateWithNotificationPayload(
      payload,
      pinProvider,
      result -> {
          if (result instanceof MIRACLSuccess) {
              // user is authenticated
          } else {
              // user is not authenticated
          }
      }
  );
  ```

For more information about authenticating users on custom applications, see
[Cross-Device Authentication](https://miracl.com/resources/docs/guides/how-to/custom-mobile-authentication/).

### Signing

DVS stands for Designated Verifier Signature, which is a protocol for
cryptographic signing of documents. For more information, see
[Designated Verifier Signature](https://miracl.com/resources/docs/concepts/dvs/).
In the context of this SDK, we refer to it as 'Signing'.

To sign a document, use the
[sign](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/sign.html)
method as follows:

Kotlin:

```kotlin
miraclTrust.sign(
    hashedMessage,
    user,
    pinProvider
) { result ->
    when (result) {
        is MIRACLSuccess -> {
            val signingResult = result.value
        }
        is MIRACLError -> {
            val error = result.value
            // Cannot sign the message/document due to an error.
        }
    }
}
```

Java:

```java
miraclTrust.sign(
        hashedMessage,
        user,
        pinProvider,
        result -> {
            if (result instanceof MIRACLSuccess) {
               SigningResult signingResult =
                       ((MIRACLSuccess<SigningResult, SigningException>) result).getValue();
            } else {
                MIRACLError<SigningResult, SigningException> error =
                        (MIRACLError<SigningResult, SigningException>) result;
                // Cannot sign the message/document due to an error.
            }
        }
);
```

The signature needs to be verified. This is done when the signature and the
timestamp are sent to the application server, which then makes an HTTP call to the
[POST /dvs/verify](https://miracl.com/resources/docs/guides/dvs/dvs-web-plugin/#api-reference)
endpoint. If the MIRACL Trust platform returns a status code `200`, the
`certificate` entry in the response body indicates that the signing is successful.

### QuickCode

[QuickCode](https://miracl.com/resources/docs/guides/built-in-user-verification/quickcode/)
is a way to register another device without going through the verification
process.

To generate a QuickCode, call the [generateQuickCode](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust/-m-i-r-a-c-l-trust/generate-quick-code.html)
method with an already registered [User](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.model/-user/index.html)
object:

Kotlin:

```kotlin
miraclTrust.generateQuickCode(
    user,
    pinProvider
) { result ->
    when (result) {
        is MIRACLSuccess -> {
            val quickCode = result.value
        }
        is MIRACLError -> {
            val error = result.value
            // handle error
        }
    }
}
```

Java:

```java
miraclTrust.generateQuickCode(
    user,
    pinProvider,
    result -> {
        if (result instanceof MIRACLSuccess) {
            QuickCode quickCode =
                    ((MIRACLSuccess<QuickCode, AuthenticationException>) result).getValue();
        } else {
            MIRACLError<QuickCode, AuthenticationException> error =
                    (MIRACLError<QuickCode, AuthenticationException>) result;
            // handle error
        }
    }
);
```

## Dependencies

MIRACL Trust SDK Android depends on:

1. [Kotlin Coroutines](https://github.com/Kotlin/kotlinx.coroutines/tree/master/ui/kotlinx-coroutines-android)
1. [Kotlin Serialization](https://github.com/Kotlin/kotlinx.serialization)
1. [Room Persistence Library](https://developer.android.com/topic/libraries/architecture/room)
1. [SQLCipher](https://github.com/sqlcipher/sqlcipher-android)

## FAQ

1. How to provide PIN code?

   For security reasons, the PIN code is sent to the SDK at the last possible
   moment. A [PinProvider](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.delegate/-pin-provider/index.html)
   is responsible for that and when the SDK calls it, the currently executed
   operation is blocked until a PIN code is provided. Therefore, this is a good
   place to display some user interface for entering the PIN code. Implement [PinProvider](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.delegate/-pin-provider/index.html)
   and use it to obtain a PIN. Then pass the PIN to the [PinConsumer](https://miracl.github.io/trust-sdk-android/miracl-sdk/com.miracl.trust.delegate/-pin-consumer/index.html).

   Kotlin:

   ```kotlin
   val pinProvider =
       PinProvider { pinConsumer ->
           val pin = /* user pin */
           pinConsumer.consume(pin)
       }
   ```

   Java:

   ```java
   PinProvider pinProvider =
       pinConsumer -> {
           String pin = /* user pin */
           pinConsumer.consume(pin);
       };
   ```

1. What is Project ID?

   Project ID is a common identifier of applications in the MIRACL Trust
   platform that share a single owner.

   You can find the Project ID value in the MIRACL Trust Portal:

   1. Go to [trust.miracl.cloud](https://trust.miracl.cloud).
   1. Log in or create a new User ID.
   1. Select your project.
   1. In the CONFIGURATION section, go to **General**.
   1. Copy the **Project ID** value.

## Documentation

- [Developer Documentation](https://miracl.com/resources/docs/get-started/overview/)
- [API reference](https://miracl.github.io/trust-sdk-android/)
