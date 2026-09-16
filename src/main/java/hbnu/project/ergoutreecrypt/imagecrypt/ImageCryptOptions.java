package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;

/**
 * 图片加密的调用选项。
 *
 * <h3>为什么保护模式必须显式给出</h3>
 * <p>公开恢复与密码保护的安全语义完全不同：前者只阻止直接查看，任何拿到文件的人都能还原；后者才提供机密性。
 * 若用"密码是否为空"隐式推断模式，UI 上一次忘记填密码就会把用户以为受保护的内容写成任何人可还原的公开文件。
 * 因此模式只能由调用方显式选择，加密失败也不会静默降级。
 *
 * <p>选项同样承载"输出已存在时是否覆盖"，把覆盖决策留在 UI 的确认流程里，核心不静默替换。
 *
 * @param mode             保护模式，不可为 {@code null}
 * @param overwriteExisting true 表示允许覆盖已存在的输出文件
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public record ImageCryptOptions(ImageCryptMode mode, boolean overwriteExisting) {

    /**
     * 默认的公开恢复选项：不覆盖已有输出。
     *
     * <p>默认值刻意选择"最保守的覆盖策略 + 明确无保密性的模式"，而不是选择密码模式，
     * 避免调用方忘记传参时误以为产物受到密码保护。
     */
    public static final ImageCryptOptions DEFAULT =
            new ImageCryptOptions(ImageCryptMode.PUBLIC_RECOVERY, false);

    /**
     * 紧凑构造器：拒绝缺失的保护模式。
     *
     * @throws IllegalArgumentException 模式为 {@code null}
     */
    public ImageCryptOptions {
        if (mode == null) {
            throw new IllegalArgumentException("图片加密必须显式指定保护模式");
        }
    }

    /**
     * 构造指定模式的选项，保留默认的不覆盖策略。
     *
     * @param mode 保护模式
     * @return 选项实例
     */
    public static ImageCryptOptions of(final ImageCryptMode mode) {
        return new ImageCryptOptions(mode, false);
    }

    /**
     * 构造指定模式的选项，并允许覆盖已存在的输出。
     *
     * @param mode 保护模式
     * @return 选项实例
     */
    public static ImageCryptOptions overwriting(final ImageCryptMode mode) {
        return new ImageCryptOptions(mode, true);
    }

    /**
     * 判断当前选项是否依赖密码。
     *
     * @return true 表示密码保护模式
     */
    public boolean requiresPassword() {
        return mode == ImageCryptMode.PASSWORD;
    }

    /**
     * 校验调用方给出的密码字节与当前模式是否匹配。
     *
     * <p>两个方向都属于调用错误，必须在进入 KDF 或写出任何字节之前发现：密码模式缺少密码会
     * 派生出一把无意义的密钥；公开模式却给了密码则说明调用方混淆了模式，若被忽略就会写出
     * 一份没有保密性的产物。
     *
     * @param password 调用方提供的密码 UTF-8 字节，可为 {@code null}
     * @throws ImageCryptException 模式与密码的存在性不匹配
     */
    public void validatePassword(final byte[] password) throws ImageCryptException {
        boolean provided = password != null && password.length > 0;
        if (requiresPassword() && !provided) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "密码保护模式必须提供密码；公开恢复请使用 PUBLIC_RECOVERY 模式");
        }
        if (!requiresPassword() && provided) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "公开恢复模式不得提供密码，请改用 PASSWORD 模式");
        }
    }
}
