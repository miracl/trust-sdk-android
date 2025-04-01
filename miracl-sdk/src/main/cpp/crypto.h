#include <jni.h>
#include <android/log.h>

#ifndef MIRACLTRUST_CRYPTO_H
#define MIRACLTRUST_CRYPTO_H


#ifdef __cplusplus
#define CEXTERN extern "C"
#else
#define CEXTERN

JNIEXPORT jbyteArray JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_combineClientSecret(JNIEnv *, jobject, jbyteArray,
                                                                jbyteArray);

JNIEXPORT jbyteArray JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_getClientToken(JNIEnv *, jobject, jbyteArray,
                                                           jbyteArray, jint);

JNIEXPORT jobject JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_getClientPass1(JNIEnv *, jobject, jbyteArray,
                                                           jbyteArray, jint);

JNIEXPORT jobject JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_getClientPass2(JNIEnv *, jobject, jbyteArray,
                                                           jbyteArray, jbyteArray);

JNIEXPORT jobject JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_generateSigningKeyPair(JNIEnv *, jobject);

JNIEXPORT jbyteArray JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_getDVSClientToken(JNIEnv *, jobject,
                                                              jbyteArray,
                                                              jbyteArray,
                                                              jbyteArray,
                                                              jint);

JNIEXPORT jobject JNICALL
Java_com_miracl_trust_crypto_CryptoExternal_sign(JNIEnv *, jobject,
                                                 jbyteArray,
                                                 jbyteArray,
                                                 jbyteArray,
                                                 jint,
                                                 jint);

#endif
#endif //MIRACLTRUST_CRYPTO_H