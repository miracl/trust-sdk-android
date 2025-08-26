package com.miracl.trust;


import static com.miracl.trust.utilities.UtilitiesKt.USER_ID;
import static com.miracl.trust.utilities.UtilitiesKt.USER_PIN_LENGTH;
import static com.miracl.trust.utilities.UtilitiesKt.getUnixTime;
import static com.miracl.trust.utilities.UtilitiesKt.randomNumericPin;
import static com.miracl.trust.utilities.UtilitiesKt.randomUuidString;

import android.content.Context;
import android.net.Uri;

import androidx.test.platform.app.InstrumentationRegistry;

import com.miracl.trust.authentication.AuthenticationException;
import com.miracl.trust.configuration.Configuration;
import com.miracl.trust.configuration.ConfigurationException;
import com.miracl.trust.delegate.PinProvider;
import com.miracl.trust.model.QuickCode;
import com.miracl.trust.model.User;
import com.miracl.trust.registration.ActivationTokenException;
import com.miracl.trust.registration.ActivationTokenResponse;
import com.miracl.trust.registration.QuickCodeException;
import com.miracl.trust.registration.RegistrationException;
import com.miracl.trust.session.AuthenticationSessionDetails;
import com.miracl.trust.session.AuthenticationSessionException;
import com.miracl.trust.session.CrossDeviceSession;
import com.miracl.trust.session.CrossDeviceSessionException;
import com.miracl.trust.session.SessionDetails;
import com.miracl.trust.session.SigningSessionDetails;
import com.miracl.trust.session.SigningSessionException;
import com.miracl.trust.signing.Signature;
import com.miracl.trust.signing.SigningException;
import com.miracl.trust.signing.SigningResult;
import com.miracl.trust.storage.UserStorageException;
import com.miracl.trust.utilities.GmailService;
import com.miracl.trust.utilities.JwtHelper;
import com.miracl.trust.utilities.MIRACLService;
import com.miracl.trust.utilities.SigningSessionCreateResponse;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import kotlinx.coroutines.test.TestCoroutineDispatchersKt;
import kotlinx.coroutines.test.TestDispatcher;

public class MIRACLTrustJavaTest {
    private final String projectId = BuildConfig.CUV_PROJECT_ID;
    private final String projectUrl = BuildConfig.CUV_PROJECT_URL;
    private final String clientId = BuildConfig.CUV_CLIENT_ID;
    private final String clientSecret = BuildConfig.CUV_CLIENT_SECRET;

    private final TestDispatcher testCoroutineDispatcher = TestCoroutineDispatchersKt.StandardTestDispatcher(null, null);

    private MIRACLTrust miraclTrust;
    private PinProvider pinProvider;

    @Before
    public void setUp() throws ConfigurationException {
        Configuration configuration = new Configuration.Builder(projectId, projectUrl)
                .coroutineContext$miracl_sdk_debug(testCoroutineDispatcher)
                .build();
        MIRACLTrust.configure(InstrumentationRegistry.getInstrumentation().getContext(), configuration);
        miraclTrust = MIRACLTrust.getInstance();
        miraclTrust.setResultHandlerDispatcher$miracl_sdk_debug(testCoroutineDispatcher);
        String pin = randomNumericPin(USER_PIN_LENGTH);
        pinProvider = pinConsumer -> pinConsumer.consume(pin);
    }

    @Test
    public void testDefaultVerification() throws ConfigurationException {
        miraclTrust.updateProjectSettings(BuildConfig.DV_PROJECT_ID, BuildConfig.DV_PROJECT_URL);

        long timestamp = getUnixTime();
        miraclTrust.sendVerificationEmail(USER_ID, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            Context context = InstrumentationRegistry.getInstrumentation().getContext();
            String verificationUrl = GmailService.INSTANCE.getVerificationUrl(context, USER_ID, USER_ID, timestamp);
            Assert.assertNotNull(verificationUrl);

            miraclTrust.getActivationToken(
                    Uri.parse(verificationUrl),
                    activationTokenResult -> {
                        Assert.assertTrue(activationTokenResult instanceof MIRACLSuccess);

                        String userId = ((MIRACLSuccess<ActivationTokenResponse, ActivationTokenException>)
                                activationTokenResult).getValue().getUserId();
                        Assert.assertEquals(USER_ID, userId);
                    }
            );
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testCustomVerification() {
        String verificationUrl = MIRACLService.INSTANCE.getVerificationUrl(
                BuildConfig.CUV_PROJECT_URL,
                BuildConfig.CUV_CLIENT_ID,
                BuildConfig.CUV_CLIENT_SECRET,
                USER_ID,
                null,
                null
        );

        miraclTrust.getActivationToken(
                Uri.parse(verificationUrl),
                activationTokenResult -> {
                    Assert.assertTrue(activationTokenResult instanceof MIRACLSuccess);

                    ActivationTokenResponse activationTokenResponse =
                            ((MIRACLSuccess<ActivationTokenResponse, ActivationTokenException>)
                                    activationTokenResult).getValue();

                    Assert.assertEquals(USER_ID, activationTokenResponse.getUserId());
                    Assert.assertEquals(projectId, activationTokenResponse.getProjectId());
                }
        );
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testQuickCode() {
        createUser(user -> miraclTrust.generateQuickCode(user, pinProvider, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);
            QuickCode quickCode = ((MIRACLSuccess<QuickCode, QuickCodeException>) result).getValue();

            miraclTrust.getActivationToken(USER_ID, quickCode.getCode(), activationTokenResult -> {
                Assert.assertTrue(activationTokenResult instanceof MIRACLSuccess);

                ActivationTokenResponse activationTokenResponse =
                        ((MIRACLSuccess<ActivationTokenResponse, ActivationTokenException>)
                                activationTokenResult).getValue();

                Assert.assertEquals(USER_ID, activationTokenResponse.getUserId());
                Assert.assertEquals(projectId, activationTokenResponse.getProjectId());
            });
        }));
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testRegistration() {
        String activationToken = MIRACLService.INSTANCE.obtainActivationToken(
                BuildConfig.CUV_PROJECT_URL,
                BuildConfig.CUV_CLIENT_ID,
                BuildConfig.CUV_CLIENT_SECRET,
                USER_ID
        );

        miraclTrust.register(USER_ID, activationToken, pinProvider, null, registerResult -> {
            Assert.assertTrue(registerResult instanceof MIRACLSuccess);

            User user = ((MIRACLSuccess<User, RegistrationException>)
                    registerResult).getValue();
            Assert.assertEquals(USER_ID, user.getUserId());
            Assert.assertEquals(projectId, user.getProjectId());
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testAuthentication() {
        createUser(user -> miraclTrust.authenticate(user, pinProvider, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            String token = ((MIRACLSuccess<String, AuthenticationException>) result).getValue();
            Jws<Claims> claims = JwtHelper.INSTANCE.parseSignedClaims(token, projectUrl);
            Assert.assertTrue(claims.getPayload().getAudience().contains(projectId));
        }));
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testAuthenticationWithCrossDeviceSession() {
        String qrCode = MIRACLService.INSTANCE.obtainAccessId().getQrURL();
        miraclTrust.getCrossDeviceSessionFromQRCode(qrCode, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            CrossDeviceSession crossDeviceSession =
                    ((MIRACLSuccess<CrossDeviceSession, CrossDeviceSessionException>) result).getValue();
            createUser(user -> miraclTrust.authenticate(user, crossDeviceSession, pinProvider, authenticationResult -> {
                Assert.assertTrue(authenticationResult instanceof MIRACLSuccess);
            }));
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testAppLinkAuthentication() {
        Uri appLink = Uri.parse(MIRACLService.INSTANCE.obtainAccessId().getQrURL());
        createUser(user -> miraclTrust.authenticateWithAppLink(user, appLink, pinProvider, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);
        }));
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testQRCodeAuthentication() {
        String qrCode = MIRACLService.INSTANCE.obtainAccessId().getQrURL();
        createUser(user -> miraclTrust.authenticateWithQRCode(user, qrCode, pinProvider, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);
        }));
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testNotificationAuthentication() {
        String qrUrl = MIRACLService.INSTANCE.obtainAccessId().getQrURL();
        Map<String, String> payload = new HashMap<String, String>() {
            {
                put("projectID", projectId);
                put("userID", USER_ID);
                put("qrURL", qrUrl);
            }
        };

        createUser(user -> miraclTrust.authenticateWithNotificationPayload(payload, pinProvider, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);
        }));
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testSigning() {
        createUser(user -> miraclTrust.sign("message".getBytes(), user, pinProvider, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            SigningResult signingResult = ((MIRACLSuccess<SigningResult, SigningException>) result).getValue();
            Signature signature = signingResult.getSignature();
            int timestamp = (int) (signingResult.getTimestamp().getTime() / 1000);
            boolean signatureVerified = MIRACLService.INSTANCE.verifySignature(projectId, projectUrl, clientId, clientSecret, signature, timestamp);
            Assert.assertTrue(signatureVerified);
        }));
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testGetUsers() {
        createUser(createdUser -> miraclTrust.getUsers(result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            List<User> users = ((MIRACLSuccess<List<User>, UserStorageException>) result).getValue();
            Assert.assertEquals(1, users.size());
            Assert.assertEquals(createdUser.getUserId(), users.getFirst().getUserId());
        }));
    }

    @Test
    public void testGetUser() {
        createUser(createdUser -> miraclTrust.getUser(USER_ID, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            User user = ((MIRACLSuccess<User, UserStorageException>) result).getValue();
            Assert.assertEquals(createdUser.getUserId(), user.getUserId());
        }));
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testDeleteUser() {
        createUser(createdUser -> miraclTrust.delete(createdUser, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);
            getUser(Assert::assertNull);
        }));
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testGetAuthenticationSessionDetailsFromAppLink() {
        Uri appLink = Uri.parse(MIRACLService.INSTANCE.obtainAccessId().getQrURL());
        miraclTrust.getAuthenticationSessionDetailsFromAppLink(appLink, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            SessionDetails sessionDetails =
                    ((MIRACLSuccess<AuthenticationSessionDetails, AuthenticationSessionException>) result).getValue();
            Assert.assertEquals(projectId, sessionDetails.getProjectId());
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testGetAuthenticationSessionDetailsFromQRCode() {
        String qrCode = MIRACLService.INSTANCE.obtainAccessId().getQrURL();
        miraclTrust.getAuthenticationSessionDetailsFromQRCode(qrCode, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            SessionDetails sessionDetails =
                    ((MIRACLSuccess<AuthenticationSessionDetails, AuthenticationSessionException>) result).getValue();
            Assert.assertEquals(projectId, sessionDetails.getProjectId());
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testGetAuthenticationSessionDetailsFromNotificationPayload() {
        String qrUrl = MIRACLService.INSTANCE.obtainAccessId().getQrURL();
        Map<String, String> payload = new HashMap<String, String>() {
            {
                put("projectID", projectId);
                put("userID", USER_ID);
                put("qrURL", qrUrl);
            }
        };

        miraclTrust.getAuthenticationSessionDetailsFromNotificationPayload(payload, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            SessionDetails sessionDetails =
                    ((MIRACLSuccess<AuthenticationSessionDetails, AuthenticationSessionException>) result).getValue();
            Assert.assertEquals(projectId, sessionDetails.getProjectId());
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testAbortAuthenticationSession() {
        String qrCode = MIRACLService.INSTANCE.obtainAccessId().getQrURL();
        miraclTrust.getAuthenticationSessionDetailsFromQRCode(qrCode, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            AuthenticationSessionDetails sessionDetails =
                    ((MIRACLSuccess<AuthenticationSessionDetails, AuthenticationSessionException>) result).getValue();
            miraclTrust.abortAuthenticationSession(sessionDetails, abortSessionResult -> {
                Assert.assertTrue(abortSessionResult instanceof MIRACLSuccess);
            });
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testGetSigningSessionDetailsFromAppLink() {
        String hash = randomUuidString();
        String description = randomUuidString();
        SigningSessionCreateResponse signingSessionCreateResponse =
                MIRACLService.INSTANCE.createSigningSession(projectId, projectUrl, USER_ID, hash, description);
        Uri appLink = Uri.parse(signingSessionCreateResponse.getQrURL());
        miraclTrust.getSigningSessionDetailsFromAppLink(appLink, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            SigningSessionDetails sessionDetails =
                    ((MIRACLSuccess<SigningSessionDetails, SigningSessionException>) result).getValue();
            Assert.assertEquals(signingSessionCreateResponse.getId(), sessionDetails.getSessionId());
            Assert.assertEquals(projectId, sessionDetails.getProjectId());
            Assert.assertEquals(hash, sessionDetails.getSigningHash());
            Assert.assertEquals(description, sessionDetails.getSigningDescription());
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testGetSigningSessionDetailsFromQRCode() {
        String hash = randomUuidString();
        String description = randomUuidString();
        SigningSessionCreateResponse signingSessionCreateResponse =
                MIRACLService.INSTANCE.createSigningSession(projectId, projectUrl, USER_ID, hash, description);
        String qrCode = signingSessionCreateResponse.getQrURL();
        miraclTrust.getSigningSessionDetailsFromQRCode(qrCode, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            SigningSessionDetails sessionDetails =
                    ((MIRACLSuccess<SigningSessionDetails, SigningSessionException>) result).getValue();
            Assert.assertEquals(signingSessionCreateResponse.getId(), sessionDetails.getSessionId());
            Assert.assertEquals(projectId, sessionDetails.getProjectId());
            Assert.assertEquals(hash, sessionDetails.getSigningHash());
            Assert.assertEquals(description, sessionDetails.getSigningDescription());
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testAbortSigningSession() {
        String hash = randomUuidString();
        String description = randomUuidString();
        Uri appLink = Uri.parse(MIRACLService.INSTANCE.createSigningSession(projectId, projectUrl, USER_ID, hash, description).getQrURL());
        miraclTrust.getSigningSessionDetailsFromAppLink(appLink, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            SigningSessionDetails sessionDetails =
                    ((MIRACLSuccess<SigningSessionDetails, SigningSessionException>) result).getValue();
            miraclTrust.abortSigningSession(sessionDetails, abortSigningSessionResult -> {
                Assert.assertTrue(abortSigningSessionResult instanceof MIRACLSuccess);
            });
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testGetCrossDeviceSessionFromAppLink() {
        Uri appLink = Uri.parse(MIRACLService.INSTANCE.obtainAccessId().getQrURL());
        miraclTrust.getCrossDeviceSessionFromAppLink(appLink, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            CrossDeviceSession crossDeviceSession =
                    ((MIRACLSuccess<CrossDeviceSession, CrossDeviceSessionException>) result).getValue();
            Assert.assertEquals(projectId, crossDeviceSession.getProjectId());
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testGetCrossDeviceSessionFromQRCode() {
        String qrCode = MIRACLService.INSTANCE.obtainAccessId().getQrURL();
        miraclTrust.getCrossDeviceSessionFromQRCode(qrCode, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            CrossDeviceSession crossDeviceSession =
                    ((MIRACLSuccess<CrossDeviceSession, CrossDeviceSessionException>) result).getValue();
            Assert.assertEquals(projectId, crossDeviceSession.getProjectId());
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testGetCrossDeviceSessionFromNotificationPayload() {
        String qrUrl = MIRACLService.INSTANCE.obtainAccessId().getQrURL();
        Map<String, String> payload = new HashMap<String, String>() {
            {
                put("projectID", projectId);
                put("userID", USER_ID);
                put("qrURL", qrUrl);
            }
        };

        miraclTrust.getCrossDeviceSessionFromNotificationPayload(payload, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            CrossDeviceSession crossDeviceSession =
                    ((MIRACLSuccess<CrossDeviceSession, CrossDeviceSessionException>) result).getValue();
            Assert.assertEquals(projectId, crossDeviceSession.getProjectId());
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    @Test
    public void testAbortCrossDeviceSession() {
        String qrCode = MIRACLService.INSTANCE.obtainAccessId().getQrURL();
        miraclTrust.getCrossDeviceSessionFromQRCode(qrCode, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);

            CrossDeviceSession crossDeviceSession =
                    ((MIRACLSuccess<CrossDeviceSession, CrossDeviceSessionException>) result).getValue();
            miraclTrust.abortCrossDeviceSession(crossDeviceSession, abortSessionResult -> {
                Assert.assertTrue(abortSessionResult instanceof MIRACLSuccess);
            });
        });
        testCoroutineDispatcher.getScheduler().advanceUntilIdle();
    }

    private void createUser(Consumer<User> callback) {
        String activationToken = MIRACLService.INSTANCE.obtainActivationToken(
                BuildConfig.CUV_PROJECT_URL,
                BuildConfig.CUV_CLIENT_ID,
                BuildConfig.CUV_CLIENT_SECRET,
                USER_ID
        );

        miraclTrust.register(USER_ID, activationToken, pinProvider, null, registerResult -> {
            Assert.assertTrue(registerResult instanceof MIRACLSuccess);
            callback.accept(((MIRACLSuccess<User, RegistrationException>) registerResult).getValue());
        });
    }

    private void getUser(Consumer<User> callback) {
        miraclTrust.getUser(USER_ID, result -> {
            Assert.assertTrue(result instanceof MIRACLSuccess);
            callback.accept(((MIRACLSuccess<User, UserStorageException>) result).getValue());
        });
    }
}
