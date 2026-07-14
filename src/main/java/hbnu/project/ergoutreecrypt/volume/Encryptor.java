package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.CipherSuite;
import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.crypto.HkdfStream;
import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.crypto.MacFactory;
import hbnu.project.ergoutreecrypt.crypto.RandomBytes;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.SubkeyReader;
import hbnu.project.ergoutreecrypt.encoding.Padding;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.header.Flags;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.header.HeaderAuth;
import hbnu.project.ergoutreecrypt.header.HeaderLayout;
import hbnu.project.ergoutreecrypt.header.HeaderWriter;
import hbnu.project.ergoutreecrypt.header.VolumeHeader;
import hbnu.project.ergoutreecrypt.keyfile.KeyfileProcessor;
import hbnu.project.ergoutreecrypt.password.PasswordNormalizer;
import hbnu.project.ergoutreecrypt.password.Passwordless;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.List;

/**
 * 加密编排器（8 阶段流水线）。
 *
 * <p>流水线：
 * <ol>
 *   <li>preprocess — 多文件预处理</li>
 *   <li>generateValues — 随机 salt/nonce/IV + header</li>
 *   <li>writeHeader — RS 编码写 header（auth 值占位）</li>
 *   <li>deriveKeys — Argon2id 密码派生</li>
 *   <li>processKeyfiles — keyfile 哈希 + XOR</li>
 *   <li>computeAuth — v2 header HMAC</li>
 *   <li>encryptPayload — XChaCha20(+Serpent) + MAC + 可选 RS</li>
 *   <li>finalize — 回填 auth → 原子重命名 → 可选 deniability/分卷/压缩</li>
 * </ol>
 *
 * @author ErgouTree
 */
public final class Encryptor {

    private Encryptor() {
    }

    /**
     * 主入口：执行完整加密流程。
     *
     * @param req 加密请求参数
     * @throws Exception 密码学或 I/O 错误
     */
    public static void encrypt(EncryptRequest req) throws Exception {
        // 双卷可否认加密：完全独立的路径
        if (req.isDualDeniability()) {
            DualDeniability.encrypt(req);
            return;
        }

        OperationContext ctx = new OperationContext();
        ctx.outputFile = req.getOutputFile();
        ctx.reporter = req.getReporter();
        try {
            encryptPreprocess(ctx, req);
            encryptGenerateValues(ctx, req);
            encryptWriteHeader(ctx, req);
            encryptDeriveKeys(ctx, req);
            encryptProcessKeyfiles(ctx, req);
            encryptComputeAuth(ctx, req);
            encryptPayload(ctx, req);
            encryptFinalize(ctx, req);
        } catch (Exception e) {
            cleanupEncrypt(ctx, req);
            throw e;
        } finally {
            ctx.close();
        }
    }

    // ==================== Phase 1: Preprocess ====================

    /**
     * 加密预处理：多文件合并为临时文件。
     */
    private static void encryptPreprocess(OperationContext ctx, EncryptRequest req) throws Exception {
        List<String> files = req.getInputFiles();
        if (files != null && !files.isEmpty()) {
            if (files.size() > 1 || req.isCompress()) {
                ctx.setStatus(Messages.get("status.compressing"), ProgressPhase.ARCHIVE);
                Path tmp = Files.createTempFile("ergou", ".tmp");
                ctx.tempFile = tmp.toString();
                try (OutputStream out = Files.newOutputStream(tmp)) {
                    for (String f : files) {
                        Files.copy(Path.of(f), out);
                    }
                }
                ctx.updateProgress(1f, "", ProgressPhase.ARCHIVE);
                ctx.inputFile = ctx.tempFile;
                return;
            }
            ctx.inputFile = files.get(0);
        } else {
            ctx.inputFile = req.getInputFile();
        }
    }

    // ==================== Phase 2: Generate values ====================

    /**
     * 生成随机密码学材料并构建 VolumeHeader。
     */
    private static void encryptGenerateValues(OperationContext ctx, EncryptRequest req) throws IOException {
        ctx.setStatus(Messages.get("status.generating"));

        byte[] salt = RandomBytes.generate(VolumeHeader.SALT_SIZE);
        byte[] hkdfSalt = RandomBytes.generate(VolumeHeader.HKDF_SALT_SIZE);
        byte[] serpentIV = RandomBytes.generate(VolumeHeader.SERPENT_IV_SIZE);
        byte[] nonce = RandomBytes.generate(VolumeHeader.NONCE_SIZE);

        Path inPath = Path.of(ctx.inputFile);
        ctx.total = Files.size(inPath);

        // 末块不足 1 MiB - 128 字节时标记为需要填充
        ctx.padded = (ctx.total % CryptoConstants.MIB) >= (CryptoConstants.MIB - Padding.BLOCK_SIZE);

        ctx.header = new VolumeHeader(salt, hkdfSalt, serpentIV, nonce);
        ctx.header.setComments(req.getComments() == null ? "" : req.getComments());
        Flags flags = new Flags(
                req.isParanoid(),
                req.getKeyfiles() != null && !req.getKeyfiles().isEmpty(),
                req.isKeyfileOrdered(),
                req.isReedSolomon(),
                ctx.padded
        );
        ctx.header.setFlags(flags);
    }

    // ==================== Phase 3: Write header ====================

    /**
     * RS 编码并写入 header（auth 值位置写入零占位符）。
     */
    private static void encryptWriteHeader(OperationContext ctx, EncryptRequest req) throws IOException {
        String incomplete = req.getOutputFile() + ".incomplete";
        try (OutputStream out = Files.newOutputStream(Path.of(incomplete))) {
            HeaderWriter writer = new HeaderWriter(out, req.getRsCodecs());
            writer.writeHeader(ctx.header);
        }
    }

    // ==================== Phase 4: Derive keys ====================

    /**
     * Argon2id 密码派生。无密码时使用公开默认密码。
     */
    private static void encryptDeriveKeys(OperationContext ctx, EncryptRequest req) {
        ctx.setStatus(Messages.get("status.deriving"));
        String effectivePw = Passwordless.effectivePassword(req.getPassword());
        byte[] pwBytes = PasswordNormalizer.encodeForKdf(effectivePw);
        byte[] key = Argon2Kdf.deriveKey(pwBytes, ctx.header.getSalt(), req.isParanoid());
        SecureZero.zero(pwBytes);
        ctx.setKey(key);
    }

    // ==================== Phase 5: Process keyfiles ====================

    /**
     * Keyfile 处理：计算各 keyfile 的 SHA3-256 哈希并合并。
     */
    private static void encryptProcessKeyfiles(OperationContext ctx, EncryptRequest req) throws IOException {
        List<String> kfPaths = req.getKeyfiles();
        if (kfPaths == null || kfPaths.isEmpty()) {
            ctx.keyfileHash = new byte[32];
            ctx.useKeyfiles = false;
            return;
        }
        ctx.setStatus(Messages.get("status.keyfiles"));
        ctx.useKeyfiles = true;

        List<Path> paths = kfPaths.stream().map(Path::of).toList();
        KeyfileProcessor kf = KeyfileProcessor.process(paths, req.isKeyfileOrdered(), null);
        ctx.setKeyfileKey(kf.key());
        ctx.keyfileHash = kf.hash();

        // 纯 keyfile 模式（无密码）：keyfile 密钥即为主密钥
        String password = req.getPassword();
        if ((password == null || password.isEmpty()) && ctx.keyfileKey != null) {
            if (KeyfileProcessor.isDuplicateKeyfileKey(ctx.keyfileKey)) {
                throw new IOException("duplicate keyfiles detected (keys cancel out)");
            }
            ctx.setKey(ctx.keyfileKey.clone());
        }
    }

    // ==================== Phase 6: Compute auth ====================

    /**
     * 计算 v2 header HMAC-SHA3-512 认证码。
     */
    private static void encryptComputeAuth(OperationContext ctx, EncryptRequest req) {
        ctx.setStatus(Messages.get("status.computingAuth"));
        HkdfStream hkdf = new HkdfStream(ctx.key, ctx.header.getHkdfSalt());
        ctx.subkeyReader = new SubkeyReader(hkdf);

        byte[] subkeyHeader = ctx.subkeyReader.headerSubkey();
        ctx.header.setKeyHash(HeaderAuth.computeV2HeaderMac(subkeyHeader, ctx.header, ctx.keyfileHash));
        ctx.header.setKeyfileHash(ctx.keyfileHash);
    }

    // ==================== Phase 7: Encrypt payload ====================

    /**
     * 加密载荷：XChaCha20(+Serpent) 加密 + MAC 累积 + 可选 RS 编码。
     */
    private static void encryptPayload(OperationContext ctx, EncryptRequest req) throws Exception {
        // v2: keyfile XOR 在 HKDF 初始化之后（仅当有密码时）
        boolean keyfileOnly = (req.getPassword() == null || req.getPassword().isEmpty())
                && ctx.useKeyfiles;
        if (ctx.useKeyfiles && ctx.keyfileKey != null && !keyfileOnly) {
            if (KeyfileProcessor.isDuplicateKeyfileKey(ctx.keyfileKey)) {
                throw new IllegalStateException("duplicate keyfiles detected (keys cancel out)");
            }
            ctx.setKey(KeyfileProcessor.xorWithKey(ctx.key, ctx.keyfileKey));
        }

        byte[] macSubkey = ctx.subkeyReader.macSubkey();
        byte[] serpentKey = ctx.subkeyReader.serpentKey();

        Mac mac = MacFactory.create(macSubkey, req.isParanoid());
        CipherSuite cs = new CipherSuite(ctx.key, ctx.header.getNonce(), serpentKey,
                ctx.header.getSerpentIV(), mac, ctx.subkeyReader.stream(), req.isParanoid());
        ctx.cipherSuite = cs;

        String incomplete = req.getOutputFile() + ".incomplete";
        try (InputStream fin = Files.newInputStream(Path.of(ctx.inputFile));
             OutputStream fout = Files.newOutputStream(Path.of(incomplete), StandardOpenOption.APPEND)) {

            byte[] src = new byte[CryptoConstants.MIB];
            byte[] dst = new byte[CryptoConstants.MIB];
            long done = 0;
            long counter = 0;
            long startMs = System.currentTimeMillis();

            while (true) {
                if (ctx.isCancelled()) {
                    throw new InterruptedException("cancelled");
                }

                int n = readFull(fin, src);
                if (n <= 0) {
                    break;
                }

                // XChaCha20(+Serpent) 加密
                cs.encrypt(dst, src, n);

                // 可选 RS 编码
                if (req.isReedSolomon()) {
                    byte[] writeData = encodeWithRS(dst, n, req.getRsCodecs());
                    fout.write(writeData);
                } else {
                    fout.write(dst, 0, n);
                }
                done += n;
                counter += CryptoConstants.MIB;

                if (ctx.total > 0) {
                    float progress = (float) done / ctx.total;
                    long elapsed = System.currentTimeMillis() - startMs;
                    String speed = elapsed > 0
                            ? Messages.format("status.speed", done / 1048576.0 / (elapsed / 1000.0))
                            : "";
                    ctx.updateProgress(progress, speed);
                }

                // 每 60 GiB rekey 一次
                if (counter >= CryptoConstants.REKEY_THRESHOLD) {
                    cs.rekey();
                    counter = 0;
                }
            }
        }

        SecureZero.zero(macSubkey);
        SecureZero.zero(serpentKey);
    }

    // ==================== Phase 8: Finalize ====================

    /**
     * 最终化：回填 auth 值、原子重命名，按序执行分卷→压缩→可否认加密。
     */
    private static void encryptFinalize(OperationContext ctx, EncryptRequest req) throws Exception {
        ctx.setStatus(Messages.get("status.finalizing"));

        // 回填 auth 值（keyHash / keyfileHash / authTag）
        byte[] authTag = ctx.cipherSuite.sum();
        String incomplete = req.getOutputFile() + ".incomplete";
        try (FileChannel ch = FileChannel.open(Path.of(incomplete), StandardOpenOption.WRITE)) {
            HeaderWriter.writeAuthValues(ch,
                    HeaderLayout.authValuesOffset(
                            ctx.header.getComments().getBytes(StandardCharsets.UTF_8).length),
                    ctx.header.getKeyHash(), ctx.header.getKeyfileHash(), authTag,
                    req.getRsCodecs());
        }

        // 原子重命名
        Files.move(Path.of(incomplete), Path.of(req.getOutputFile()),
                StandardCopyOption.REPLACE_EXISTING);

        // 可选：可否认加密外层
        if (req.isDeniability()) {
            Deniability.addDeniability(req.getOutputFile(),
                    Passwordless.effectivePassword(req.getPassword()), ctx.reporter);
        }

        boolean archive = req.getArchiveFormat() != null && !req.getArchiveFormat().isEmpty();
        boolean split = req.isSplit() && req.getChunkSize() > 0;

        // 顺序约定：先分卷，再（若启用）压缩。压缩永远是最后一步
        Path chunkDir = null;
        if (split) {
            ctx.setStatus(Messages.get("status.splitting"));
            long chunkBytes = (long) req.getChunkSize() * CryptoConstants.MIB;
            Path outPath = Path.of(req.getOutputFile());
            String outName = outPath.getFileName().toString();

            // 检测是否已在分卷碎片文件夹内
            String folderName = outName;
            if (folderName.toLowerCase().endsWith(".ergou")) {
                folderName = folderName.substring(0, folderName.length() - ".ergou".length());
            } else if (folderName.toLowerCase().endsWith(".pcv")) {
                folderName = folderName.substring(0, folderName.length() - ".pcv".length());
            }
            Path parent = outPath.getParent() != null ? outPath.getParent() : Path.of(".");
            boolean alreadyInChunkFolder = parent.getFileName() != null
                    && parent.getFileName().toString().equals(folderName);

            Path fileToSplit;
            if (!alreadyInChunkFolder) {
                chunkDir = parent.resolve(folderName);
                if (Files.exists(chunkDir) && !Files.isDirectory(chunkDir)) {
                    folderName = folderName + "_ergou_split";
                    chunkDir = parent.resolve(folderName);
                }
                Files.createDirectories(chunkDir);
                Path movedFile = chunkDir.resolve(outName);
                Files.move(outPath, movedFile, StandardCopyOption.REPLACE_EXISTING);
                req.setOutputFile(movedFile.toString());
                fileToSplit = movedFile;
            } else {
                chunkDir = parent;
                fileToSplit = outPath;
            }

            Splitter.split(fileToSplit, chunkBytes);
            Files.deleteIfExists(fileToSplit);
        }

        if (archive) {
            ctx.setStatus(Messages.get("status.archiving"), ProgressPhase.ARCHIVE);
            ctx.updateProgress(0f, "", ProgressPhase.ARCHIVE);
            ArchivePacker.Format fmt = ArchivePacker.parseFormat(req.getArchiveFormat());
            Path outPath = Path.of(req.getOutputFile());
            Path parent = outPath.getParent() != null ? outPath.getParent() : Path.of(".");

            if (split) {
                // GZ 多条目时 packEntries 会自动提升为 TAR.GZ，扩展名也需同步调整
                ArchivePacker.Format extFmt = (fmt == ArchivePacker.Format.GZ)
                        ? ArchivePacker.Format.TAR_GZ : fmt;
                List<Path> chunks = Splitter.listChunks(outPath);
                Path archiveParent = parent.getParent() != null ? parent.getParent() : Path.of(".");
                String archiveName = parent.getFileName().toString() + ArchivePacker.extOf(extFmt);
                Path archivePath = archiveParent.resolve(archiveName);
                ArchivePacker.packEntries(archivePath, parent, chunks, fmt,
                        ArchivePacker.resolveArchivePassword(
                                req.getArchivePassword(), req.getPassword(), fmt), ctx.reporter);
                for (Path c : chunks) {
                    Files.deleteIfExists(c);
                }
                try {
                    Files.deleteIfExists(parent);
                } catch (IOException ignored) {
                }
                req.setOutputFile(archivePath.toString());
            } else {
                Path archivePath = Path.of(req.getOutputFile() + ArchivePacker.extOf(fmt));
                ArchivePacker.pack(archivePath, outPath, fmt,
                        ArchivePacker.resolveArchivePassword(
                                req.getArchivePassword(), req.getPassword(), fmt), ctx.reporter);
                Files.deleteIfExists(outPath);
                req.setOutputFile(archivePath.toString());
            }
            ctx.updateProgress(1f, "", ProgressPhase.ARCHIVE);
        }

        // 清理临时文件
        if (ctx.tempFile != null) {
            Files.deleteIfExists(Path.of(ctx.tempFile));
        }
    }

    /**
     * 加密失败时清理临时文件与不完整输出。
     */
    private static void cleanupEncrypt(OperationContext ctx, EncryptRequest req) {
        if (ctx.tempFile != null) {
            try {
                Files.deleteIfExists(Path.of(ctx.tempFile));
            } catch (IOException ignored) {
            }
        }
        try {
            Files.deleteIfExists(Path.of(req.getOutputFile() + ".incomplete"));
        } catch (IOException ignored) {
        }
    }

    // ==================== RS 编码辅助 ====================

    /**
     * RS128 编码：将明文数据按 128 字节块分割，逐块 RS 编码为 136 字节。
     * 末块不满 128 字节时先 PKCS#7 填充再编码。
     */
    /**
     * RS128 编码：将明文数据按 128 字节块分割，逐块 RS 编码为 136 字节。
     * 末块不满 128 字节时先 PKCS#7 填充再编码。
     *
     * <p>复用临时缓冲区避免每次迭代分配，减少 GC 压力。
     */
    static byte[] encodeWithRS(byte[] data, int len, RsCodecs rs) {
        boolean isFullBlock = len == CryptoConstants.MIB;

        if (isFullBlock) {
            // 整 1 MiB 块：8192 个 128B 块，无填充
            int fullChunks = len / Padding.BLOCK_SIZE;
            byte[] result = new byte[fullChunks * 136];
            // 复用缓冲区，避免每次迭代分配 new byte[128] 和 new byte[136]
            byte[] chunk = new byte[Padding.BLOCK_SIZE];
            byte[] enc = new byte[136];
            int pos = 0;
            for (int i = 0; i < fullChunks; i++) {
                System.arraycopy(data, i * Padding.BLOCK_SIZE, chunk, 0, Padding.BLOCK_SIZE);
                ReedSolomon.encodeInto(enc, rs.rs128, chunk);
                System.arraycopy(enc, 0, result, pos, 136);
                pos += 136;
            }
            return result;
        }

        // 部分块：编码全部 128B 块 + 恰好一个填充块（即使整除 128）
        int fullChunks = len / Padding.BLOCK_SIZE;
        int remaining = len - fullChunks * Padding.BLOCK_SIZE;
        int chunkCount = fullChunks + 1;

        byte[] result = new byte[chunkCount * 136];
        byte[] chunk = new byte[Padding.BLOCK_SIZE];
        byte[] enc = new byte[136];
        int pos = 0;
        for (int i = 0; i < fullChunks; i++) {
            System.arraycopy(data, i * Padding.BLOCK_SIZE, chunk, 0, Padding.BLOCK_SIZE);
            ReedSolomon.encodeInto(enc, rs.rs128, chunk);
            System.arraycopy(enc, 0, result, pos, 136);
            pos += 136;
        }

        byte[] last = new byte[remaining];
        System.arraycopy(data, fullChunks * Padding.BLOCK_SIZE, last, 0, remaining);
        byte[] padded = Padding.pad(last);
        ReedSolomon.encodeInto(enc, rs.rs128, padded);
        System.arraycopy(enc, 0, result, pos, 136);

        return result;
    }

    /**
     * 从输入流中尽量读满缓冲区，返回实际读取的字节数。
     */
    private static int readFull(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) {
                break;
            }
            total += n;
        }
        return total;
    }
}
