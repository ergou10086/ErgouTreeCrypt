/* FAST 私有文件的原子且不覆盖提交；不支持的内核或文件系统直接报错。 */
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <linux/fs.h>
#include <sys/syscall.h>
#include <unistd.h>

/* 路径来自共享核心的零结尾标准 UTF-8，不能使用 JNI 修改版 UTF-8。 */
JNIEXPORT jint JNICALL
Java_hbnu_project_ergoutreecrypt_volume_FastNativeCommit_renameNoReplace(
        JNIEnv *env, jclass clazz, jbyteArray source, jbyteArray target) {
    jbyte *from = (*env)->GetByteArrayElements(env, source, NULL);
    if (from == NULL) return ENOMEM;
    jbyte *to = (*env)->GetByteArrayElements(env, target, NULL);
    if (to == NULL) {
        (*env)->ReleaseByteArrayElements(env, source, from, JNI_ABORT);
        return ENOMEM;
    }
    int status = syscall(SYS_renameat2, AT_FDCWD, (const char *)from,
                         AT_FDCWD, (const char *)to, RENAME_NOREPLACE);
    int result = status == 0 ? 0 : (errno == EEXIST ? -1 : errno);
    (*env)->ReleaseByteArrayElements(env, source, from, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, target, to, JNI_ABORT);
    return result;
}
