package hbnu.project.ergoutreecrypt.encoding;

/**
 * 预初始化的 Reed-Solomon 编解码器集合。
 *
 * <p>命名 RSn 表示 n 个数据字节编码为相应总字节数。除 RS128 为 n→n+8（约 6% 开销）外，
 * 其余规格为 n→n×3（200% 开销）。所有编解码器在启动时创建一次并全程复用。
 *
 * @author ErgouTree
 */
public final class RsCodecs {

    /**
     * 1→3：用于注释单字符编码。
     */
    public final Fec rs1;

    /**
     * 5→15：用于 version / 注释长度 / flags 等短字段。
     */
    public final Fec rs5;

    /**
     * 16→48：用于 Argon2 salt / Serpent IV 等 16 字节字段。
     */
    public final Fec rs16;

    /**
     * 24→72：用于 XChaCha20 nonce（24 字节）。
     */
    public final Fec rs24;

    /**
     * 32→96：用于 HKDF salt / keyfile hash 等 32 字节字段。
     */
    public final Fec rs32;

    /**
     * 64→192：用于 key hash / auth tag 等 64 字节字段。
     */
    public final Fec rs64;

    /**
     * 128→136：用于载荷分块编码（约 6% 开销）。
     */
    public final Fec rs128;

    /**
     * 创建并初始化全部 RS 编解码器。
     */
    public RsCodecs() {
        rs1 = Fec.newFec(1, 3);
        rs5 = Fec.newFec(5, 15);
        rs16 = Fec.newFec(16, 48);
        rs24 = Fec.newFec(24, 72);
        rs32 = Fec.newFec(32, 96);
        rs64 = Fec.newFec(64, 192);
        rs128 = Fec.newFec(128, 136);
    }
}
