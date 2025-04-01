#ifdef __cplusplus
extern "C" {
#endif

#include "crypto.h"
#include <mpin_BN254CX.h>
#include <string.h>

const int HASH_ALG = 32;
const char *ERROR_CLIENT_SECRET_MESSAGE = "Could not get client secret";
const char *ERROR_INCORRECT_PIN_MESSAGE = "Incorrect pin";
const char *ERROR_CLIENT_TOKEN_MESSAGE = "Getting client token fail";
const char *ERROR_PASS_1_MESSAGE = "Could not get pass1 proof";
const char *ERROR_PASS_2_MESSAGE = "Could not get pass2 proof";
const char *ERROR_GENERATE_SIGNING_KEY_MESSAGE = "Could not generate signing keys";
const char *ERROR_DVS_CLIENT_TOKEN = "Getting dvs client token fail";
const char *ERROR_DVS_SIGNING = "Signing fail";
const char *ERROR_MESSAGE_DELIMITER = ": ";
const int ERROR_CODE_CHAR_LENGTH = 5;
const int CLIENT_SECRET_ERROR_CODE = -14;
const int WRONG_PIN_ERROR_CODE = -19;
const int EMPTY_OCTET_LENGTH = 65;
const int PUBLIC_SIGNING_KEY_OCTET_SIZE = 128;
const int X_EMPTY_OCTET_LENGTH = 32;
const int RANDOM_ARRAY_LENGTH = 256;

char *generateExceptionMessage(const char *errorMessage, int errorCode) {
    char *message = malloc(
            strlen(errorMessage)
            + strlen(ERROR_MESSAGE_DELIMITER)
            + ERROR_CODE_CHAR_LENGTH
    );

    sprintf(message, "%s%s%d", errorMessage, ERROR_MESSAGE_DELIMITER, errorCode);

    return message;
}

octet createEmptyOctet(int length) {
    char *buffer = malloc((size_t) (length + 1));
    octet csOctet = {.len = length, .max = length, .val = buffer};
    buffer[length + 1] = 0;

    return csOctet;
}

JNIEXPORT jbyteArray JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_combineClientSecret(JNIEnv *env, jobject jobj,
                                                                jbyteArray css1,
                                                                jbyteArray css2) {
    jsize num_bytes_css1 = (*env)->GetArrayLength(env, css1);
    jbyte *elements_css1 = (*env)->GetByteArrayElements(env, css1, 0);
    octet css1Octet = {.len= num_bytes_css1, .max= num_bytes_css1, .val= (char *) elements_css1};

    jsize num_bytes_css2 = (*env)->GetArrayLength(env, css2);
    jbyte *elements_css2 = (*env)->GetByteArrayElements(env, css2, 0);
    octet css2Octet = {.len= num_bytes_css2, .max= num_bytes_css2, .val= (char *) elements_css2};

    octet csOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);

    int recombineResponse = MPIN_BN254CX_RECOMBINE_G1(&css1Octet, &css2Octet, &csOctet);
    if (recombineResponse != 0) {
        jclass Exception = (*env)->FindClass(env, "java/lang/Exception");
        (*env)->ThrowNew(env, Exception,
                         generateExceptionMessage(ERROR_CLIENT_SECRET_MESSAGE, recombineResponse));
    }

    jbyteArray clientSecret = (*env)->NewByteArray(env, csOctet.len);
    (*env)->SetByteArrayRegion(env, clientSecret, 0, csOctet.len, (const jbyte *) csOctet.val);

    (*env)->ReleaseByteArrayElements(env, css1, elements_css1, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, css2, elements_css2, JNI_ABORT);

    return clientSecret;
}

char *generateRandomArray(size_t length) {
    char *buffer = malloc(length + 1);

    int i;
    for (i = 0; i < length; i++) {
        buffer[i] = (char) ((rand() % RANDOM_ARRAY_LENGTH) + '0');
    }

    buffer[length + 1] = 0;

    return buffer;
}

JNIEXPORT jobject JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_getClientPass1(JNIEnv *env, jobject jobj,
                                                           jbyteArray mpinId,
                                                           jbyteArray token, jint pin) {
    jsize num_bytes_mpinId = (*env)->GetArrayLength(env, mpinId);
    jbyte *elements_mpinId = (*env)->GetByteArrayElements(env, mpinId, 0);
    octet mpinIdOctet = {.len= num_bytes_mpinId, .max= num_bytes_mpinId, .val= (char *) elements_mpinId};

    jsize num_bytes_token = (*env)->GetArrayLength(env, token);
    jbyte *elements_token = (*env)->GetByteArrayElements(env, token, 0);
    octet tokenOctet = {.len= num_bytes_token, .max= num_bytes_token, .val= (char *) elements_token};

    char *randomArray = generateRandomArray(RANDOM_ARRAY_LENGTH);
    csprng *R = malloc(sizeof(csprng) * 1);

    RAND_seed(R, RANDOM_ARRAY_LENGTH, randomArray);

    octet xOctet = createEmptyOctet(X_EMPTY_OCTET_LENGTH);
    octet sOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);
    octet uOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);
    octet utOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);
    octet tpOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);

    int pass1Result = MPIN_BN254CX_CLIENT_1(HASH_ALG, 0, &mpinIdOctet, R, &xOctet, pin, &tokenOctet,
                                            &sOctet, &uOctet, &utOctet, &tpOctet);
    if (pass1Result != 0) {
        jclass Exception = (*env)->FindClass(env, "java/lang/Exception");
        (*env)->ThrowNew(env, Exception,
                         generateExceptionMessage(ERROR_PASS_1_MESSAGE, pass1Result));
    }

    jbyteArray x = (*env)->NewByteArray(env, xOctet.len);
    (*env)->SetByteArrayRegion(env, x, 0, xOctet.len, (const jbyte *) xOctet.val);

    jbyteArray s = (*env)->NewByteArray(env, sOctet.len);
    (*env)->SetByteArrayRegion(env, s, 0, sOctet.len, (const jbyte *) sOctet.val);

    jbyteArray u = (*env)->NewByteArray(env, uOctet.len);
    (*env)->SetByteArrayRegion(env, u, 0, uOctet.len, (const jbyte *) uOctet.val);

    jclass clazz = (*env)->FindClass(env, "com/miracl/trust/crypto/Pass1Proof");
    jmethodID constructor = (*env)->GetMethodID(env, clazz, "<init>", "()V");

    jobject obj = (*env)->NewObject(env, clazz, constructor);

    jfieldID xField = (*env)->GetFieldID(env, clazz, "X", "[B");
    jfieldID secField = (*env)->GetFieldID(env, clazz, "SEC", "[B");
    jfieldID uField = (*env)->GetFieldID(env, clazz, "U", "[B");

    (*env)->SetObjectField(env, obj, xField, x);
    (*env)->SetObjectField(env, obj, secField, s);
    (*env)->SetObjectField(env, obj, uField, u);

    (*env)->ReleaseByteArrayElements(env, mpinId, elements_mpinId, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, token, elements_token, JNI_ABORT);
    free(randomArray);
    free(xOctet.val);
    free(sOctet.val);
    free(uOctet.val);
    free(utOctet.val);
    free(tpOctet.val);

    return obj;
}

JNIEXPORT jobject JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_getClientPass2(JNIEnv *env, jobject jobj,
                                                           jbyteArray x,
                                                           jbyteArray y,
                                                           jbyteArray s) {
    jsize num_bytes_x = (*env)->GetArrayLength(env, x);
    jbyte *elements_x = (*env)->GetByteArrayElements(env, x, 0);
    octet xOctet = {.len= num_bytes_x, .max= num_bytes_x, .val= (char *) elements_x};

    jsize num_bytes_y = (*env)->GetArrayLength(env, y);
    jbyte *elements_y = (*env)->GetByteArrayElements(env, y, 0);
    octet yOctet = {.len= num_bytes_y, .max= num_bytes_y, .val= (char *) elements_y};

    jsize num_bytes_s = (*env)->GetArrayLength(env, s);
    jbyte *elements_s = (*env)->GetByteArrayElements(env, s, 0);
    octet vOctet = {.len= num_bytes_s, .max= num_bytes_s, .val= (char *) elements_s};

    int pass2Result = MPIN_BN254CX_CLIENT_2(&xOctet, &yOctet, &vOctet);
    if (pass2Result != 0) {
        jclass Exception = (*env)->FindClass(env, "java/lang/Exception");
        (*env)->ThrowNew(env, Exception,
                         generateExceptionMessage(ERROR_PASS_2_MESSAGE, pass2Result));
    }

    jbyteArray v = (*env)->NewByteArray(env, vOctet.len);
    (*env)->SetByteArrayRegion(env, v, 0, vOctet.len, (const jbyte *) vOctet.val);

    jclass clazz = (*env)->FindClass(env, "com/miracl/trust/crypto/Pass2Proof");
    jmethodID constructor = (*env)->GetMethodID(env, clazz, "<init>", "()V");

    jobject obj = (*env)->NewObject(env, clazz, constructor);

    jfieldID vField = (*env)->GetFieldID(env, clazz, "V", "[B");

    (*env)->SetObjectField(env, obj, vField, v);

    (*env)->ReleaseByteArrayElements(env, x, elements_x, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, y, elements_y, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, s, elements_s, JNI_ABORT);

    return obj;
}

JNIEXPORT jobject JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_generateSigningKeyPair(JNIEnv *env,
                                                                   jobject jobj) {
    octet privateKeyOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);
    octet publicKeyOctet = createEmptyOctet(PUBLIC_SIGNING_KEY_OCTET_SIZE);

    char *randomArray = generateRandomArray(RANDOM_ARRAY_LENGTH);
    csprng *R = malloc(sizeof(csprng) * 1);

    RAND_seed(R, RANDOM_ARRAY_LENGTH, randomArray);

    int result = MPIN_BN254CX_GET_DVS_KEYPAIR(R, &privateKeyOctet, &publicKeyOctet);

    if (result != 0) {
        jclass Exception = (*env)->FindClass(env, "java/lang/Exception");
        (*env)->ThrowNew(env, Exception,
                         generateExceptionMessage(ERROR_GENERATE_SIGNING_KEY_MESSAGE, result));
    }

    jbyteArray publicKey = (*env)->NewByteArray(env, publicKeyOctet.len);
    (*env)->SetByteArrayRegion(env, publicKey, 0, publicKeyOctet.len,
                               (const jbyte *) publicKeyOctet.val);
    jbyteArray privateKey = (*env)->NewByteArray(env, privateKeyOctet.len);
    (*env)->SetByteArrayRegion(env, privateKey, 0, privateKeyOctet.len,
                               (const jbyte *) privateKeyOctet.val);

    jclass clazz = (*env)->FindClass(env, "com/miracl/trust/crypto/SigningKeyPair");
    jmethodID constructor = (*env)->GetMethodID(env, clazz, "<init>", "()V");

    jobject obj = (*env)->NewObject(env, clazz, constructor);

    jfieldID publicKeyField = (*env)->GetFieldID(env, clazz, "publicKey", "[B");
    jfieldID privateKeyField = (*env)->GetFieldID(env, clazz, "privateKey", "[B");

    (*env)->SetObjectField(env, obj, publicKeyField, publicKey);
    (*env)->SetObjectField(env, obj, privateKeyField, privateKey);

    free(randomArray);
    free(publicKeyOctet.val);
    free(privateKeyOctet.val);

    return obj;
}

JNIEXPORT jbyteArray JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_getDVSClientToken(JNIEnv *env,
                                                              jobject jobj,
                                                              jbyteArray clientSecret,
                                                              jbyteArray privateKey,
                                                              jbyteArray mpinId,
                                                              jint pin) {
    jsize num_bytes_cs = (*env)->GetArrayLength(env, clientSecret);
    jbyte *elements_cs = (*env)->GetByteArrayElements(env, clientSecret, 0);
    octet csOctet = {.len= num_bytes_cs, .max= num_bytes_cs, .val= (char *) elements_cs};

    jsize num_bytes_privateKey = (*env)->GetArrayLength(env, privateKey);
    jbyte *elements_privateKey = (*env)->GetByteArrayElements(env, privateKey, 0);
    octet privateKeyOctet = {.len= num_bytes_privateKey,
            .max= num_bytes_privateKey,
            .val= (char *) elements_privateKey};

    int result = MPIN_BN254CX_GET_G1_MULTIPLE(
            NULL,
            0,
            &privateKeyOctet,
            &csOctet,
            &csOctet
    );

    if (result != 0) {
        jclass Exception = (*env)->FindClass(env, "java/lang/Exception");
        (*env)->ThrowNew(env, Exception, generateExceptionMessage(ERROR_DVS_CLIENT_TOKEN, result));
    }

    jsize num_bytes_mpinId = (*env)->GetArrayLength(env, mpinId);
    jbyte *elements_mpinId = (*env)->GetByteArrayElements(env, mpinId, 0);
    octet mpinIdOctet = {.len= num_bytes_mpinId, .max= num_bytes_mpinId, .val= (char *) elements_mpinId};

    result = MPIN_BN254CX_EXTRACT_PIN(
            HASH_ALG,
            &mpinIdOctet,
            pin,
            &csOctet
    );
    jclass Exception = (*env)->FindClass(env, "java/lang/Exception");
    if (result == CLIENT_SECRET_ERROR_CODE) {
        (*env)->ThrowNew(env, Exception,
                         generateExceptionMessage(ERROR_CLIENT_SECRET_MESSAGE, result));
    } else if (result == WRONG_PIN_ERROR_CODE) {
        (*env)->ThrowNew(env, Exception,
                         generateExceptionMessage(ERROR_INCORRECT_PIN_MESSAGE, result));
    } else if (result != 0) {
        (*env)->ThrowNew(env, Exception, generateExceptionMessage(ERROR_DVS_CLIENT_TOKEN, result));
    }

    jbyteArray token = (*env)->NewByteArray(env, csOctet.len);
    (*env)->SetByteArrayRegion(env, token, 0, csOctet.len, (const jbyte *) csOctet.val);

    (*env)->ReleaseByteArrayElements(env, clientSecret, elements_cs, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, privateKey, elements_privateKey, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, mpinId, elements_mpinId, JNI_ABORT);

    return token;
}

JNIEXPORT jobject JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_sign(JNIEnv *env,
                                                 jobject thiz,
                                                 jbyteArray message,
                                                 jbyteArray signing_mpin_id,
                                                 jbyteArray signing_token,
                                                 jint pin,
                                                 jint timestamp) {
    jsize num_bytes_message = (*env)->GetArrayLength(env, message);
    jbyte *elements_message = (*env)->GetByteArrayElements(env, message, 0);
    octet messageOctet = {.len= num_bytes_message, .max= num_bytes_message, .val= (char *) elements_message};

    jsize num_bytes_mpin = (*env)->GetArrayLength(env, signing_mpin_id);
    jbyte *elements_mpin = (*env)->GetByteArrayElements(env, signing_mpin_id, 0);
    octet mpinOctet = {.len= num_bytes_mpin, .max= num_bytes_mpin, .val= (char *) elements_mpin};

    jsize num_bytes_token = (*env)->GetArrayLength(env, signing_token);
    jbyte *elements_token = (*env)->GetByteArrayElements(env, signing_token, 0);
    octet tokenOctet = {.len= num_bytes_token, .max= num_bytes_token, .val= (char *) elements_token};

    octet xOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);
    octet vOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);
    octet uOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);
    octet utOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);
    octet tpOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);
    octet yOctet = createEmptyOctet(EMPTY_OCTET_LENGTH);

    char *randomArray = generateRandomArray(RANDOM_ARRAY_LENGTH);
    csprng *R = malloc(sizeof(csprng) * 1);

    RAND_seed(R, RANDOM_ARRAY_LENGTH, randomArray);

    int result = MPIN_BN254CX_CLIENT(
            SHA256,
            0,
            &mpinOctet,
            R,
            &xOctet,
            pin,
            &tokenOctet,
            &vOctet,
            &uOctet,
            &utOctet,
            &tpOctet,
            &messageOctet,
            timestamp,
            &yOctet
    );

    if (result != 0) {
        jclass Exception = (*env)->FindClass(env, "java/lang/Exception");
        (*env)->ThrowNew(env, Exception, generateExceptionMessage(ERROR_DVS_SIGNING, result));
    }

    jbyteArray uValue = (*env)->NewByteArray(env, uOctet.len);
    (*env)->SetByteArrayRegion(env, uValue, 0, uOctet.len,
                               (const jbyte *) uOctet.val);
    jbyteArray vValue = (*env)->NewByteArray(env, vOctet.len);
    (*env)->SetByteArrayRegion(env, vValue, 0, vOctet.len,
                               (const jbyte *) vOctet.val);

    jclass clazz = (*env)->FindClass(env, "com/miracl/trust/crypto/SigningResult");
    jmethodID constructor = (*env)->GetMethodID(env, clazz, "<init>", "()V");

    jobject obj = (*env)->NewObject(env, clazz, constructor);

    jfieldID uField = (*env)->GetFieldID(env, clazz, "u", "[B");
    jfieldID vyField = (*env)->GetFieldID(env, clazz, "v", "[B");

    (*env)->SetObjectField(env, obj, uField, uValue);
    (*env)->SetObjectField(env, obj, vyField, vValue);

    free(randomArray);
    free(xOctet.val);
    free(vOctet.val);
    free(uOctet.val);
    free(utOctet.val);
    free(tpOctet.val);
    free(yOctet.val);

    return obj;
}

#ifdef __cplusplus
}
#endif
