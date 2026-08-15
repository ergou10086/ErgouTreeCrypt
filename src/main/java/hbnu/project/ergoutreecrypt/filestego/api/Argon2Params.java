package hbnu.project.ergoutreecrypt.filestego.api;

/**
 * Argon2id 参数覆写（移动端低内存档位）。
 *
 * <p>STEG-V2 格式的 Argon2 参数默认取 {@code CryptoConstants} 常量（1 GiB），
 * 移动端通过 {@code CarrierMetadata} 的 RESERVED 字段持久化更低的参数；
 * 字段全零（旧文件）对应 null 覆写（使用默认常量）。
 *
 * <p>该参数是密钥派生的组成部分，编码侧与解码侧必须严格一致：
 * 编码时由调用方构建一次，同时传入 {@code PayloadCodec} 与
 * {@code CarrierMetadata}，解码时从 {@code CarrierMetadata} 读取。
 *
 * @param memoryKiB 内存参数（KiB），须 &gt;= 8
 * @param passes    迭代次数，须 &gt;= 1
 * @param threads   并行线程数，须 &gt;= 1
 * @author ErgouTree
 * @since 2026/8/14
 */
public record Argon2Params(int memoryKiB, int passes, int threads) {

    /**
     * 校验参数组合的合法性。
     *
     * <p>Argon2 规范要求：memory &gt;= 8 KiB、passes &gt;= 1、threads &gt;= 1。
     *
     * @return true 表示参数合法
     */
    public boolean isValid() {
        return memoryKiB >= 8 && passes >= 1 && threads >= 1;
    }
}
