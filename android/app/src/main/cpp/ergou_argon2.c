/*
 * ErgouTreeCrypt Argon2id JNI 桥接。
 *
 * 把 Java 侧 hbnu.project.ergoutreecrypt.crypto.NativeArgon2 的派生请求
 * 转发给 vendored 的 libargon2（phc-winner-argon2）argon2id_hash_raw。
 *
 * 许可：随 libargon2 采用 CC0 1.0 / Apache 2.0 双许可（见 argon2/LICENSE）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>

#include "argon2.h"

/*
 * Class:     hbnu_project_ergoutreecrypt_crypto_NativeArgon2
 * Method:    argon2idHashRaw
 * Signature: ([B[BIIII)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_hbnu_project_ergoutreecrypt_crypto_NativeArgon2_argon2idHashRaw(
        JNIEnv *env, jclass clazz, jbyteArray password, jbyteArray salt,
        jint tCost, jint mCost, jint parallelism, jint outputLen) {
    uint8_t out[64];
    jbyteArray result;

    if (password == NULL || salt == NULL || outputLen <= 0 ||
        outputLen > (jint)sizeof(out)) {
        jclass ex = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        (*env)->ThrowNew(env, ex, "invalid argon2 arguments");
        return NULL;
    }

    jsize pwdLen = (*env)->GetArrayLength(env, password);
    jsize saltLen = (*env)->GetArrayLength(env, salt);
    jbyte *pwd = (*env)->GetByteArrayElements(env, password, NULL);
    jbyte *slt = (*env)->GetByteArrayElements(env, salt, NULL);
    if (pwd == NULL || slt == NULL) {
        if (pwd != NULL) {
            (*env)->ReleaseByteArrayElements(env, password, pwd, JNI_ABORT);
        }
        if (slt != NULL) {
            (*env)->ReleaseByteArrayElements(env, salt, slt, JNI_ABORT);
        }
        return NULL;
    }

    int rc = argon2id_hash_raw((uint32_t)tCost, (uint32_t)mCost,
                               (uint32_t)parallelism, pwd, (size_t)pwdLen,
                               slt, (size_t)saltLen, out, (size_t)outputLen);

    (*env)->ReleaseByteArrayElements(env, password, pwd, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, salt, slt, JNI_ABORT);

    if (rc != ARGON2_OK) {
        jclass ex = (*env)->FindClass(env, "java/lang/IllegalStateException");
        (*env)->ThrowNew(env, ex, argon2_error_message(rc));
        return NULL;
    }

    result = (*env)->NewByteArray(env, outputLen);
    if (result == NULL) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, outputLen, (const jbyte *)out);
    return result;
}
