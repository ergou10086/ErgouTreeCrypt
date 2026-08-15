package hbnu.project.ergoutreecrypt.classical.modern;

import hbnu.project.ergoutreecrypt.classical.CipherInfo;
import hbnu.project.ergoutreecrypt.classical.ClassicalCipher;
import hbnu.project.ergoutreecrypt.crypto.RandomBytes;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * 现代字符串密码的抽象基类。
 *
 * <p>统一处理现代分组/流密码共有的流程：口令校验、PBKDF2 密钥派生、随机盐与 IV 生成、
 * 帧格式封装（魔数 + 算法 id + 盐 + IV + 密文）与 Base64 编码、解密时的帧解析与错误映射。
 * 子类只需通过模板方法声明密钥/IV/标签/分块尺寸并实现核心加密解密过程。
 *
 * <p>帧格式（Base64 编码前的字节布局）：
 * <pre>
 * 偏移 0      : 魔数 0xE7（标识"现代字符串密码 v1"）
 * 偏移 1      : 算法 id（防止跨算法粘贴密文造成误导性报错）
 * 偏移 2..17  : PBKDF2 盐（16 字节）
 * 偏移 18..   : IV/nonce（长度由子类决定）
 * 剩余        : 密文（GCM 模式末尾附带认证标签）
 * </pre>
 *
 * <p>参数：{@code password} — 用户口令，由 PBKDF2-HMAC-SHA256 派生为固定长度的算法密钥。
 *
 * @author ErgouTree
 */
public abstract class AbstractModernCipher implements ClassicalCipher {

    /**
     * 帧头魔数，标识"现代字符串密码 v1"。
     */
    private static final byte MAGIC = (byte) 0xE7;

    /**
     * PBKDF2 盐的固定字节数。
     */
    private static final int SALT_SIZE = 16;

    /**
     * PBKDF2 迭代次数（移动端主线程同步调用，10k 约为几十毫秒）。
     */
    private static final int PBKDF2_ITERATIONS = 10_000;

    /**
     * 算法元数据，由构造时传入的 id 与 i18n 键组装。
     */
    private final CipherInfo info;

    /**
     * 构造现代密码实例，统一附加 {@code password} 参数定义。
     *
     * @param id      算法唯一标识
     * @param nameKey 算法名称的 i18n 键
     * @param descKey 算法描述的 i18n 键
     */
    protected AbstractModernCipher(final String id, final String nameKey, final String descKey) {
        this.info = new CipherInfo(id, nameKey, descKey,
                List.of(new CipherInfo.ParamDef("password", "cc.param.password", "password", "")));
    }

    /**
     * 返回密钥字节数。
     *
     * @return 密钥字节数
     */
    protected abstract int keySize();

    /**
     * 返回 IV/nonce 字节数。
     *
     * @return IV/nonce 字节数
     */
    protected abstract int ivSize();

    /**
     * 返回认证标签字节数（无认证的模式返回 0）。
     *
     * @return 认证标签字节数
     */
    protected abstract int tagSize();

    /**
     * 返回分组字节数（流式/GCM 模式返回 0 以跳过密文长度取模校验）。
     *
     * @return 分组字节数
     */
    protected abstract int blockSize();

    /**
     * 返回帧头中的算法标识字节（0x01~0x07）。
     *
     * @return 算法标识字节
     */
    protected abstract byte algorithmId();

    /**
     * 执行核心加密过程。
     *
     * @param plain 明文字节
     * @param key   派生后的算法密钥
     * @param iv    随机 IV/nonce
     * @return 密文字节（GCM 模式包含末尾认证标签）
     */
    protected abstract byte[] encryptBytes(byte[] plain, byte[] key, byte[] iv);

    /**
     * 执行核心解密过程。
     *
     * @param cipher 密文字节（GCM 模式包含末尾认证标签）
     * @param key    派生后的算法密钥
     * @param iv     IV/nonce
     * @return 明文字节
     * @throws InvalidCipherTextException 认证/填充校验失败
     */
    protected abstract byte[] decryptBytes(byte[] cipher, byte[] key, byte[] iv)
            throws InvalidCipherTextException;

    /**
     * 密钥派生后的调整钩子，默认原样返回。
     *
     * @param key 派生后的密钥
     * @return 调整后的密钥
     */
    protected byte[] adjustKey(final byte[] key) {
        return key;
    }

    @Override
    public final CipherInfo getInfo() {
        return info;
    }

    @Override
    public final String encrypt(final String plaintext, final Map<String, String> params) {
        if (plaintext == null || plaintext.isEmpty()) {
            return "";
        }
        String password = requirePassword(params);
        return encryptWith(plaintext, password, RandomBytes.generate(SALT_SIZE),
                RandomBytes.generate(ivSize()));
    }

    /**
     * 测试接缝：使用固定盐与 IV 加密，结果可复现。
     *
     * @param plaintext 明文
     * @param password  口令
     * @param salt      盐字节
     * @param iv        IV/nonce 字节
     * @return Base64 密文
     */
    final String encryptWith(final String plaintext, final String password,
                             final byte[] salt, final byte[] iv) {
        byte[] key = null;
        try {
            key = deriveKey(password, salt, keySize());
            byte[] adjusted = adjustKey(key);
            byte[] cipher = encryptBytes(plaintext.getBytes(StandardCharsets.UTF_8), adjusted, iv);
            return Base64.getEncoder().encodeToString(buildFrame(salt, iv, cipher));
        } finally {
            SecureZero.zero(key);
        }
    }

    /**
     * 组装帧字节：魔数 + 算法 id + 盐 + IV + 密文。
     *
     * @param salt   盐字节
     * @param iv     IV/nonce 字节
     * @param cipher 密文字节
     * @return 帧字节数组
     */
    private byte[] buildFrame(final byte[] salt, final byte[] iv, final byte[] cipher) {
        byte[] frame = new byte[2 + SALT_SIZE + iv.length + cipher.length];
        frame[0] = MAGIC;
        frame[1] = algorithmId();
        System.arraycopy(salt, 0, frame, 2, salt.length);
        System.arraycopy(iv, 0, frame, 2 + SALT_SIZE, iv.length);
        System.arraycopy(cipher, 0, frame, 2 + SALT_SIZE + iv.length, cipher.length);
        return frame;
    }

    @Override
    public final String decrypt(final String ciphertext, final Map<String, String> params) {
        if (ciphertext == null || ciphertext.isEmpty()) {
            return "";
        }
        String password = requirePassword(params);
        byte[] frame;
        try {
            frame = Base64.getDecoder().decode(ciphertext);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(Messages.get("cc.error.invalid.base64"), e);
        }
        byte[] key = null;
        try {
            ParsedFrame parsed = parseFrame(frame);
            key = deriveKey(password, parsed.salt, keySize());
            byte[] adjusted = adjustKey(key);
            byte[] plain = decryptBytes(parsed.cipher, adjusted, parsed.iv);
            return decodeUtf8Strict(plain);
        } catch (InvalidCipherTextException e) {
            throw new IllegalArgumentException(Messages.get("cc.error.wrong.password"), e);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException(Messages.get("cc.error.wrong.password"), e);
        } finally {
            SecureZero.zero(key);
        }
    }

    /**
     * 从参数中读取口令，为空时抛出带本地化文案的异常。
     *
     * @param params 算法参数
     * @return 非空口令
     */
    private static String requirePassword(final Map<String, String> params) {
        String password = params != null ? params.get("password") : null;
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException(Messages.get("cc.error.password.empty"));
        }
        return password;
    }

    /**
     * 使用 PBKDF2-HMAC-SHA256 从口令与盐派生指定长度的密钥。
     *
     * @param password 用户口令
     * @param salt     盐字节
     * @param keySize  目标密钥字节数
     * @return 派生密钥字节
     */
    static byte[] deriveKey(final String password, final byte[] salt, final int keySize) {
        PKCS5S2ParametersGenerator generator =
                new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password.getBytes(StandardCharsets.UTF_8), salt, PBKDF2_ITERATIONS);
        return ((KeyParameter) generator.generateDerivedParameters(keySize * 8)).getKey();
    }

    /**
     * 以 CBC 模式 + PKCS7 填充处理数据，供分组密码子类复用。
     *
     * @param forEncryption 是否为加密方向
     * @param data          输入数据
     * @param engine        底层分组密码引擎
     * @param key           算法密钥
     * @param iv            IV
     * @return 处理结果
     */
    protected final byte[] cbcProcess(final boolean forEncryption, final byte[] data,
                                      final BlockCipher engine, final byte[] key, final byte[] iv) {
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(new CBCBlockCipher(engine), new PKCS7Padding());
        cipher.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, out, 0);
        try {
            len += cipher.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            throw new IllegalArgumentException(Messages.get("cc.error.wrong.password"), e);
        }
        return java.util.Arrays.copyOf(out, len);
    }

    /**
     * 解析并校验帧格式。
     *
     * @param frame Base64 解码后的帧字节
     * @return 解析结果（盐、IV、密文）
     */
    private ParsedFrame parseFrame(final byte[] frame) {
        if (frame.length < 2 + SALT_SIZE + ivSize() + tagSize()) {
            throw new IllegalArgumentException(Messages.get("cc.error.invalid.format"));
        }
        if (frame[0] != MAGIC || frame[1] != algorithmId()) {
            throw new IllegalArgumentException(Messages.get("cc.error.invalid.format"));
        }
        int cipherLen = frame.length - 2 - SALT_SIZE - ivSize();
        if (blockSize() > 0 && cipherLen % blockSize() != 0) {
            throw new IllegalArgumentException(Messages.get("cc.error.invalid.format"));
        }
        byte[] salt = new byte[SALT_SIZE];
        System.arraycopy(frame, 2, salt, 0, SALT_SIZE);
        byte[] iv = new byte[ivSize()];
        System.arraycopy(frame, 2 + SALT_SIZE, iv, 0, ivSize());
        byte[] cipher = new byte[cipherLen];
        System.arraycopy(frame, 2 + SALT_SIZE + ivSize(), cipher, 0, cipherLen);
        return new ParsedFrame(salt, iv, cipher);
    }

    /**
     * 以严格模式将解密结果解码为 UTF-8 字符串。
     *
     * @param bytes 解密后的字节
     * @return 明文
     * @throws CharacterCodingException 字节序列不是合法 UTF-8
     */
    private static String decodeUtf8Strict(final byte[] bytes) throws CharacterCodingException {
        CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes));
        return decoded.toString();
    }

    /**
     * 帧解析结果。
     */
    private record ParsedFrame(byte[] salt, byte[] iv, byte[] cipher) {
    }
}
