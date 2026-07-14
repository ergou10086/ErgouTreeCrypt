package hbnu.project.ergoutreecrypt.volume;

/**
 * 进度阶段类型，用于区分加解密与压缩/解压进度的独立展示。
 *
 * <p>{@link #CRYPTO} 覆盖密钥派生、加解密载荷、MAC 校验等密码学流水线；
 * {@link #ARCHIVE} 覆盖压缩前准备、加密后归档打包、解密前解压等归档操作。
 * UI 层据此使用独立进度条与不同配色，避免压缩/解压进度与加解密进度混在同一条轨道上。
 *
 * @author ErgouTree
 */
public enum ProgressPhase {

    /**
     * 加解密 / 校验等密码学阶段。
     */
    CRYPTO,

    /**
     * 压缩 / 解压 / 归档打包阶段。
     */
    ARCHIVE
}
