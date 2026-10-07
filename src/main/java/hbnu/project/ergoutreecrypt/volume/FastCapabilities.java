package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.fast.FastKdfPolicy;
import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;

/** 共享能力检查，前端禁用选项之外仍在核心拒绝冲突请求。 */
public final class FastCapabilities {
    /** 禁止实例化工具类。 */
    private FastCapabilities() {}

    /**
     * FAST 只允许基础字段与独立归档，禁止内部压缩和裸多文件合并。
     *
     * @param request 加密请求
     * @throws CryptoException 选项冲突或输入非法
     */
    public static void validateEncryption(EncryptRequest request) throws CryptoException {
        if (request.isParanoid()
                || request.isReedSolomon()
                || request.isSplit()
                || request.isCompress()
                || request.isDeniability()
                || request.isDualDeniability()
                || request.isKeyfileOrdered()
                || request.getKeyfiles() != null && !request.getKeyfiles().isEmpty()
                || request.getComments() != null && !request.getComments().isEmpty()
                || different(request.getArgon2MemoryKib(), FastKdfPolicy.MEMORY_KIB)
                || different(request.getArgon2Passes(), FastKdfPolicy.PASSES)
                || different(request.getArgon2Threads(), FastKdfPolicy.LANES)) {
            throw unsupported();
        }
        if (request.getInputFiles() != null
                && request.getInputFiles().size() > 1
                && !enabled(request.getPreArchiveFormat())) {
            throw new CryptoException(ErrorKind.UNSUPPORTED_FORMAT, "FAST 多文件输入必须先归档");
        }
    }

    /**
     * 自动识别 FAST 后不接受跳过认证、密钥文件或其他容器选项。
     *
     * @param request 解密请求
     * @throws CryptoException 选项冲突
     */
    public static void validateDecryption(DecryptRequest request) throws CryptoException {
        if (request.isForceDecrypt()
                || request.isDeniability()
                || request.isDualDeniability()
                || request.isRecombine()
                || request.getKeyfiles() != null && !request.getKeyfiles().isEmpty())
            throw unsupported();
    }

    /**
     * 独立认证同样禁止绕过和密钥文件。
     *
     * @param request 认证请求
     * @throws CryptoException 选项冲突
     */
    public static void validateVerification(VerifyRequest request) throws CryptoException {
        if (request.isForceDecrypt()
                || request.isDeniability()
                || request.isRecombine()
                || request.getKeyfiles() != null && !request.getKeyfiles().isEmpty())
            throw unsupported();
    }

    /**
     * 判断显式覆写是否不同于冻结参数。
     *
     * @param requested 可选覆写
     * @param fixed 固定值
     * @return 是否冲突
     */
    private static boolean different(Integer requested, int fixed) {
        return requested != null && requested != fixed;
    }

    /**
     * 与原归档请求保持相同的启用判断。
     *
     * @param format 格式字符串
     * @return 是否启用
     */
    static boolean enabled(String format) {
        return format != null && !format.isEmpty();
    }

    /** @return 统一的选项冲突错误 */
    private static CryptoException unsupported() {
        return new CryptoException(ErrorKind.UNSUPPORTED_FORMAT, "FAST 不支持所选高级选项或 KDF 覆写");
    }
}
