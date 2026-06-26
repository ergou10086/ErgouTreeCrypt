package hbnu.project.ergoutreecrypt.crypto;

import java.util.Arrays;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id 密钥派生函数（KDF）。
 *
 * <p>根据安全模式选择迭代次数与并行度，从密码与 salt 派生 32 字节加密密钥。
 * 内存量固定为 1 GiB。派生结果为全零时视为 Argon2 故障并抛出异常。
 *
 * <p>参数对照：
 * <ul>
 *   <li>普通模式：4 passes / 1 GiB / 4 threads</li>
 *   <li>偏执模式：8 passes / 1 GiB / 8 threads</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class Argon2Kdf {

    private Argon2Kdf() {
    }

    /**
     * 从密码与 salt 派生 32 字节加密密钥。
     *
     * @param password 已归一化（NFC）的密码 UTF-8 字节
     * @param salt     16 字节 Argon2 salt
     * @param paranoid 是否使用偏执模式参数（更多迭代与线程）
     * @return 32 字节派生密钥
     * @throws IllegalStateException 若派生结果为全零，视为 Argon2 故障
     */
    public static byte[] deriveKey(byte[] password, byte[] salt, boolean paranoid) {
        int passes = paranoid
                ? CryptoConstants.ARGON2_PARANOID_PASSES
                : CryptoConstants.ARGON2_NORMAL_PASSES;
        int memoryKiB = paranoid
                ? CryptoConstants.ARGON2_PARANOID_MEMORY_KIB
                : CryptoConstants.ARGON2_NORMAL_MEMORY_KIB;
        int threads = paranoid
                ? CryptoConstants.ARGON2_PARANOID_THREADS
                : CryptoConstants.ARGON2_NORMAL_THREADS;

        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(passes)
                .withMemoryAsKB(memoryKiB)
                .withParallelism(threads)
                .withSalt(salt)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] key = new byte[CryptoConstants.ARGON2_KEY_SIZE];
        generator.generateBytes(password, key);

        // 全零结果视为 Argon2 致命故障
        if (Arrays.equals(key, new byte[CryptoConstants.ARGON2_KEY_SIZE])) {
            throw new IllegalStateException("fatal Argon2 error: produced zero key");
        }
        return key;
    }
}
