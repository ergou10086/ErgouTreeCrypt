package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.KdfProgress;
import hbnu.project.ergoutreecrypt.crypto.RandomBytes;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.fast.FastKeyMaterial;
import hbnu.project.ergoutreecrypt.crypto.fast.FastStreamingAeadFactory;
import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.header.FastHeader;
import hbnu.project.ergoutreecrypt.header.FastHeaderReaderWriter;
import hbnu.project.ergoutreecrypt.i18n.Messages;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;

/** FAST-v1 共享完整流编解码器；认证入口不落盘明文，解密成功前不发布最终文件。 */
public final class FastVolumeCodec {
    private static final int BUFFER_SIZE = 256 << 10;

    /** 禁止实例化工具类。 */
    private FastVolumeCodec() {}

    /**
     * 加密一个稳定的普通文件，目标必须不存在且父目录已经存在。
     *
     * @param input 明文文件
     * @param output 新密文路径
     * @param password 非空密码
     * @param reporter 进度与取消回调
     * @param kdfProgress KDF 回调
     * @throws Exception 取消、参数、密码库或 I/O 错误
     */
    public static void encrypt(
            Path input,
            Path output,
            String password,
            ProgressReporter reporter,
            KdfProgress kdfProgress)
            throws Exception {
        var progress = new FastProgress(reporter, kdfProgress);
        progress.checkCancelled();
        Path source = regularFile(input);
        try (var stage = FastOutput.create(output)) {
            writeEncrypted(source, stage.path(), password, progress);
            progress.finish();
            stage.commit();
        }
    }

    /**
     * 写入核心内部已创建且限制权限的中间文件，不向用户发布名称。
     *
     * @param input 明文文件
     * @param ownedOutput 本任务私有文件
     * @param password 非空密码
     * @param progress 本次取消及进度
     * @throws Exception 加密或 I/O 失败
     */
    static void writeEncrypted(Path input, Path ownedOutput, String password, FastProgress progress)
            throws Exception {
        try (var source = FileChannel.open(input, StandardOpenOption.READ)) {
            long length = source.size();
            FileTime modified = Files.getLastModifiedTime(input);
            byte[] unsigned =
                    FastHeaderReaderWriter.unsignedHeader(
                            length, RandomBytes.generate(16), RandomBytes.generate(32));
            FastHeader draft = FastHeaderReaderWriter.withMac(unsigned, new byte[32]);
            progress.status(Messages.get("status.deriving"));
            try (var keys =
                    FastKeyMaterial.derive(
                            password, draft.argonSalt(), draft.hkdfSalt(), progress)) {
                FastHeader header =
                        FastHeaderReaderWriter.withMac(unsigned, keys.headerMac(unsigned));
                progress.status(Messages.get("status.encrypting"));
                try (var output =
                        Files.newOutputStream(
                                ownedOutput,
                                StandardOpenOption.WRITE,
                                StandardOpenOption.TRUNCATE_EXISTING)) {
                    output.write(header.bytes());
                    try (var encrypted =
                            keys.streamingAead()
                                    .newEncryptingStream(
                                            output,
                                            FastStreamingAeadFactory.associatedData(header))) {
                        copy(Channels.newInputStream(source), encrypted, length, progress, false);
                    }
                }
                if (source.size() != length || !modified.equals(Files.getLastModifiedTime(input))) {
                    throw new IOException("加密期间输入文件发生变化");
                }
                if (Files.size(ownedOutput) != FastHeaderReaderWriter.containerLength(length)) {
                    throw new IOException("FAST 完整流长度与冻结格式不一致");
                }
            }
        }
    }

    /**
     * 完整认证后提交新明文，错误或取消仅删除本任务临时文件。
     *
     * @param input FAST 密文
     * @param output 尚不存在的明文路径
     * @param password 原始密码
     * @param reporter 进度和取消回调
     * @param kdfProgress KDF 回调
     * @throws Exception 认证、取消或 I/O 失败
     */
    public static void decrypt(
            Path input,
            Path output,
            String password,
            ProgressReporter reporter,
            KdfProgress kdfProgress)
            throws Exception {
        var progress = new FastProgress(reporter, kdfProgress);
        progress.checkCancelled();
        try (var source = FileChannel.open(regularFile(input), StandardOpenOption.READ)) {
            InputStream ciphertext = Channels.newInputStream(source);
            FastHeader header = readHeader(ciphertext, source.size());
            progress.status(Messages.get("status.deriving"));
            try (var keys = authenticatedKeys(header, password, progress);
                    var stage = FastOutput.create(output)) {
                progress.status(Messages.get("status.decrypting"));
                try (var outputStream =
                        Files.newOutputStream(
                                stage.path(),
                                StandardOpenOption.WRITE,
                                StandardOpenOption.TRUNCATE_EXISTING)) {
                    readPayload(ciphertext, outputStream, header, keys, progress);
                }
                if (source.size()
                        != FastHeaderReaderWriter.containerLength(header.plaintextLength())) {
                    throw new CryptoException(ErrorKind.TAMPERED_DATA, "FAST 密文长度在读取期间发生变化");
                }
                progress.finish();
                stage.commit();
            }
        }
    }

    /**
     * 验证头、所有段、末段、实际明文长度和真实 EOF；不创建明文文件。
     *
     * @param input FAST 密文
     * @param password 原始密码
     * @param reporter 进度和取消回调
     * @param kdfProgress KDF 回调
     * @return 只有完整认证通过才返回 true
     * @throws Exception 认证、取消或 I/O 失败
     */
    public static boolean verify(
            Path input, String password, ProgressReporter reporter, KdfProgress kdfProgress)
            throws Exception {
        var progress = new FastProgress(reporter, kdfProgress);
        progress.checkCancelled();
        try (var source = FileChannel.open(regularFile(input), StandardOpenOption.READ)) {
            InputStream ciphertext = Channels.newInputStream(source);
            FastHeader header = readHeader(ciphertext, source.size());
            progress.status(Messages.get("status.deriving"));
            try (var keys = authenticatedKeys(header, password, progress)) {
                progress.status(Messages.get("status.scanning"));
                readPayload(ciphertext, OutputStream.nullOutputStream(), header, keys, progress);
                if (source.size()
                        != FastHeaderReaderWriter.containerLength(header.plaintextLength())) {
                    throw new CryptoException(ErrorKind.TAMPERED_DATA, "FAST 密文长度在读取期间发生变化");
                }
                progress.finish();
                return true;
            }
        }
    }

    /**
     * 读取及预检结构和精确密文长度，不把此检查当作认证。
     *
     * @param input 密文流
     * @param size 打开文件的当前长度
     * @return 结构有效的头
     * @throws Exception 头或长度非法
     */
    private static FastHeader readHeader(InputStream input, long size) throws Exception {
        FastHeader header = FastHeaderReaderWriter.read(input);
        if (size != FastHeaderReaderWriter.containerLength(header.plaintextLength())) {
            throw new CryptoException(ErrorKind.TAMPERED_DATA, "FAST 密文截断、追加或长度不一致");
        }
        return header;
    }

    /**
     * 派生并认证头，异常时立即释放材料。
     *
     * @param header 已结构校验的头
     * @param password 原始密码
     * @param progress 进度及取消
     * @return 已通过头认证的密钥材料，仍需验证载荷
     * @throws Exception 密码错误或头被篡改
     */
    private static FastKeyMaterial authenticatedKeys(
            FastHeader header, String password, FastProgress progress) throws Exception {
        FastKeyMaterial keys =
                FastKeyMaterial.derive(password, header.argonSalt(), header.hkdfSalt(), progress);
        try {
            if (!keys.authenticate(header))
                throw new CryptoException(ErrorKind.WRONG_PASSWORD, "FAST 密码错误或头认证失败");
            progress.checkCancelled();
            return keys;
        } catch (Exception e) {
            keys.close();
            throw e;
        }
    }

    /**
     * 消费完整认证流和真实 EOF，不能以关闭流代替读取末段。
     *
     * @param ciphertext 外头之后的流
     * @param output 私有明文文件或内存丢弃流
     * @param header 已认证头
     * @param keys 密钥材料
     * @param progress 进度及取消
     * @throws Exception 载荷、长度、尾随数据或 I/O 错误
     */
    private static void readPayload(
            InputStream ciphertext,
            OutputStream output,
            FastHeader header,
            FastKeyMaterial keys,
            FastProgress progress)
            throws Exception {
        // 不关闭 Tink 输入流所持有的源通道，外层仍需复核文件长度；外层统一关闭文件。
        InputStream nonClosing =
                new java.io.FilterInputStream(ciphertext) {
                    /** 由拥有源通道的外层作用域负责关闭。 */
                    @Override
                    public void close() {}
                };
        try (var plaintext =
                keys.streamingAead()
                        .newDecryptingStream(
                                nonClosing, FastStreamingAeadFactory.associatedData(header))) {
            copy(plaintext, output, header.plaintextLength(), progress, true);
            if (ciphertext.read() != -1)
                throw new CryptoException(ErrorKind.TAMPERED_DATA, "FAST 存在未消费的尾随数据");
        }
    }

    /**
     * 用有界可复用缓冲处理完整流；输出 I/O 错误不会被误包装成认证失败。
     *
     * @param input 输入流
     * @param output 输出流
     * @param expected 精确明文长度
     * @param progress 进度及取消
     * @param authenticatedRead 是否正在读取 Tink 认证流
     * @throws Exception 输入、输出、认证或取消错误
     */
    private static void copy(
            InputStream input,
            OutputStream output,
            long expected,
            FastProgress progress,
            boolean authenticatedRead)
            throws Exception {
        byte[] buffer = new byte[BUFFER_SIZE];
        long done = 0;
        try {
            for (; ; ) {
                progress.checkCancelled();
                int count;
                try {
                    count = input.read(buffer);
                } catch (IOException e) {
                    if (authenticatedRead)
                        throw new CryptoException(ErrorKind.TAMPERED_DATA, "FAST 认证流读取失败", e);
                    throw e;
                }
                if (count == -1) break;
                if (count == 0) continue;
                if (count > expected - done)
                    throw new CryptoException(ErrorKind.TAMPERED_DATA, "FAST 实际明文超出头长度");
                output.write(buffer, 0, count);
                done += count;
                progress.update(done, expected);
            }
            if (done != expected)
                throw new CryptoException(ErrorKind.TAMPERED_DATA, "FAST 实际明文长度不足");
            progress.checkCancelled();
        } finally {
            SecureZero.zero(buffer);
        }
    }

    /**
     * 仅允许稳定普通文件，排除设备和目录输入。
     *
     * @param path 输入路径
     * @return 真实文件路径
     * @throws IOException 输入不可用
     */
    private static Path regularFile(Path path) throws IOException {
        Path real = path.toRealPath();
        if (!Files.isRegularFile(real)) throw new IOException("FAST 输入必须为普通文件");
        return real;
    }
}
