package hbnu.project.ergoutreecrypt.volume;

import com.github.luben.zstd.ZstdOutputStream;
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
import hbnu.project.ergoutreecrypt.filetypes.OutputNaming;
import hbnu.project.ergoutreecrypt.exception.CancelledException;
import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.header.Flags;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.header.HeaderAuth;
import hbnu.project.ergoutreecrypt.header.HeaderLayout;
import hbnu.project.ergoutreecrypt.header.HeaderWriter;
import hbnu.project.ergoutreecrypt.header.VolumeHeader;
import hbnu.project.ergoutreecrypt.keyfile.KeyfileProcessor;
import hbnu.project.ergoutreecrypt.log.LogPhases;
import hbnu.project.ergoutreecrypt.log.LogService;
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
        long t0 = System.nanoTime();
        String label = inputLabel(req);
        LogService.info("Encryptor", "开始加密 " + label);
        if (LogService.isTraceEnabled()) {
            LogService.trace("Encryptor", "paranoid=" + req.isParanoid()
                    + ", rs=" + req.isReedSolomon()
                    + ", split=" + req.isSplit()
                    + ", dual=" + req.isDualDeniability()
                    + ", compress=" + req.isCompress());
        }
        try {
            // 双卷可否认加密：完全独立的路径
            if (req.isDualDeniability()) {
                DualDeniability.encrypt(req);
            } else {
                OperationContext ctx = new OperationContext();
                ctx.outputFile = req.getOutputFile();
                ctx.reporter = req.getReporter();
                try {
                    LogPhases.run("Encryptor", "preprocess", () -> encryptPreprocess(ctx, req));
                    LogPhases.run("Encryptor", "generateValues", () -> encryptGenerateValues(ctx, req));
                    LogPhases.run("Encryptor", "writeHeader", () -> encryptWriteHeader(ctx, req));
                    LogPhases.run("Encryptor", "deriveKeys", () -> encryptDeriveKeys(ctx, req));
                    LogPhases.run("Encryptor", "processKeyfiles", () -> encryptProcessKeyfiles(ctx, req));
                    LogPhases.run("Encryptor", "computeAuth", () -> encryptComputeAuth(ctx, req));
                    LogPhases.run("Encryptor", "encryptPayload", () -> encryptPayload(ctx, req));
                    LogPhases.run("Encryptor", "finalize", () -> encryptFinalize(ctx, req));
                } catch (Exception e) {
                    cleanupEncrypt(ctx, req);
                    throw e;
                } finally {
                    ctx.close();
                }
            }
            LogService.info("Encryptor", "加密完成", (System.nanoTime() - t0) / 1_000_000L);
        } catch (Exception e) {
            LogService.error("Encryptor", "加密失败", e);
            throw e;
        }
    }

    /**
     * 解析「压缩后加密」实际使用的归档格式。
     *
     * <p>GZ 是纯单文件流格式、不保存条目名：条目多于一个时若仍用 GZ，解压只能得到一个
     * 以压缩包基名命名的无后缀文件，本工具后续无法再识别。故多条目时提升为 TAR.GZ。
     * 单条目（单文件）时保持 GZ——此时压缩包基名本身就是 {@code <原输出名>}，
     * 解压后正好还原成带 {@code .ergou} 后缀的名字，不会丢信息。
     *
     * @param raw        用户选择的归档格式字符串
     * @param entryCount 归档内条目数
     * @return 实际使用的归档格式
     */
    private static ArchivePacker.Format preArchiveFormat(String raw, int entryCount) {
        ArchivePacker.Format fmt = ArchivePacker.parseFormat(raw);
        if (fmt == ArchivePacker.Format.GZ && entryCount > 1) {
            return ArchivePacker.Format.TAR_GZ;
        }
        return fmt;
    }

    /**
     * 拼装「压缩后加密」的产物名：{@code <基名>.<归档扩展名>.ergou}。
     *
     * <p>与「加密后压缩」的 {@code <名>.ergou.<归档扩展名>} 顺序相反——压缩后加密是
     * 先有归档再整体加密，因此卷后缀必须在最外层。调用方传入的若是常规的
     * {@code <基名>.ergou}（桌面/移动端默认），这里先剥掉卷后缀再插入归档扩展名；
     * 若传入的本来就没有卷后缀，则直接拼接。
     *
     * @param output 调用方给出的输出路径
     * @param fmt    实际使用的归档格式
     * @return 最终产物路径
     */
    private static String preArchiveOutputName(String output, ArchivePacker.Format fmt) {
        return OutputNaming.preArchiveEncryptOutputName(output, fmt.name());
    }

    /**
     * 从请求中提取适合日志的输入标签（仅文件名，不含路径与密钥）。
     *
     * @param req 加密请求
     * @return 文件名或文件数量描述
     */
    private static String inputLabel(EncryptRequest req) {
        if (req.getInputFile() != null && !req.getInputFile().isBlank()) {
            return Path.of(req.getInputFile()).getFileName().toString();
        }
        List<String> files = req.getInputFiles();
        if (files != null && !files.isEmpty()) {
            return files.size() + " files";
        }
        return "?";
    }

    // ==================== Phase 1: Preprocess ====================

    /**
     * 加密预处理：多文件合并、压缩后加密（先打包）、加密前压缩（Zstandard）。
     *
     * <p>三级处理的先后顺序固定为「先打包成归档 → 再做 Zstandard 压缩 → 最后加密」：
     * 归档本身就是一种压缩，先打包再对归档做 Zstandard 不会破坏归档结构，
     * 解密端按 header 中的压缩标志先解 Zstandard 再解归档即可还原。
     *
     * @param ctx 操作上下文
     * @param req 加密请求
     * @throws Exception 打包或压缩失败
     */
    private static void encryptPreprocess(OperationContext ctx, EncryptRequest req) throws Exception {
        List<String> files = req.getInputFiles();
        boolean hasMultipleFiles = files != null && files.size() > 1;
        String singleFile = (files != null && files.size() == 1) ? files.get(0) : req.getInputFile();

        String preArchive = req.getPreArchiveFormat();
        boolean packFirst = preArchive != null && !preArchive.isEmpty();
        String working = singleFile;

        // 第一级：压缩后加密 —— 先按所选格式把输入打成一个归档
        if (packFirst) {
            List<Path> inputs = files != null && !files.isEmpty()
                    ? files.stream().map(Path::of).toList()
                    : List.of(Path.of(singleFile));
            ctx.setStatus(Messages.get("status.compressing"), ProgressPhase.ARCHIVE);
            ArchivePacker.Format fmt = preArchiveFormat(preArchive, inputs.size());
            // 产物名由核心统一拼装为 <基名>.<归档扩展名>.ergou：
            // 调用方只给常规的 <基名>.ergou，两端的命名规则因此不会彼此漂移。
            req.setOutputFile(preArchiveOutputName(req.getOutputFile(), fmt));
            Path archive = Files.createTempFile("ergou-pre-", ArchivePacker.extOf(fmt));
            ctx.preArchiveTempFile = archive.toString();
            try {
                ArchivePacker.packEntries(archive, null, inputs,
                        ArchivePacker.uniqueEntryNames(null, inputs), fmt,
                        ArchivePacker.resolveArchivePassword(
                                req.getPreArchivePassword(), null, ArchivePacker.Format.ZIP),
                        req.getReporter());
            } catch (Exception e) {
                Files.deleteIfExists(archive);
                ctx.preArchiveTempFile = null;
                throw e;
            }
            working = archive.toString();
            LogService.info("Encryptor", "压缩后加密：已打包 " + inputs.size()
                    + " 个输入为 " + archive.getFileName());
        }

        // 第二级：加密前压缩（Zstandard），或多文件合并
        if (hasMultipleFiles || req.isCompress()) {
            ctx.setStatus(Messages.get("status.compressing"), ProgressPhase.ARCHIVE);
            Path tmp = Files.createTempFile("ergou", ".tmp");
            ctx.tempFile = tmp.toString();
            try (OutputStream out = Files.newOutputStream(tmp)) {
                if (req.isCompress()) {
                    // 加密前压缩：用 ZstdOutputStream 包裹临时输出流
                    try (ZstdOutputStream zos = new ZstdOutputStream(out, req.getCompressionLevel())) {
                        if (packFirst) {
                            Files.copy(Path.of(working), zos);
                        } else if (hasMultipleFiles) {
                            for (String f : files) {
                                Files.copy(Path.of(f), zos);
                            }
                        } else {
                            Files.copy(Path.of(singleFile), zos);
                        }
                    }
                } else {
                    for (String f : files) {
                        Files.copy(Path.of(f), out);
                    }
                }
            }
            ctx.inputFile = ctx.tempFile;
            ctx.updateProgress(1f, "", ProgressPhase.ARCHIVE);
            return;
        }
        ctx.inputFile = working;
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

        // B1：始终把实际生效的 Argon2 参数写进卷头（升级到 v2.15），使解密端无需
        // 猜测默认档位。有效参数与 Argon2Kdf.deriveKey 的决策链保持一致：覆写值
        // 优先，否则按 paranoid 标志取 CryptoConstants 的默认档位。
        int effMem = req.getArgon2MemoryKib() != null ? req.getArgon2MemoryKib()
                : (req.isParanoid() ? CryptoConstants.ARGON2_PARANOID_MEMORY_KIB
                : CryptoConstants.ARGON2_NORMAL_MEMORY_KIB);
        int effPasses = req.getArgon2Passes() != null ? req.getArgon2Passes()
                : (req.isParanoid() ? CryptoConstants.ARGON2_PARANOID_PASSES
                : CryptoConstants.ARGON2_NORMAL_PASSES);
        int effThreads = req.getArgon2Threads() != null ? req.getArgon2Threads()
                : (req.isParanoid() ? CryptoConstants.ARGON2_PARANOID_THREADS
                : CryptoConstants.ARGON2_NORMAL_THREADS);

        // 压缩时版本为 v2.16（额外携带压缩标志），否则 v2.15
        ctx.header.setVersion(req.isCompress()
                ? VolumeHeader.VERSION_V216 : VolumeHeader.VERSION_V215);
        ctx.header.setArgon2MemoryKib(effMem);
        ctx.header.setArgon2Passes(effPasses);
        ctx.header.setArgon2Threads(effThreads);
        if (req.isCompress()) {
            ctx.header.setCompressed(true);
        }
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
    private static void encryptWriteHeader(OperationContext ctx, EncryptRequest req)
            throws IOException, CryptoException {
        String incomplete = req.getOutputFile() + ".incomplete";
        try (OutputStream out = Files.newOutputStream(Path.of(incomplete))) {
            HeaderWriter writer = new HeaderWriter(out, req.getRsCodecs());
            writer.writeHeader(ctx.header);
        }
    }

    // ==================== Phase 4: Derive keys ====================

    /**
     * Argon2id 密码派生。无密码时使用公开默认密码。
     *
     * <p>若 EncryptRequest 中指定了 Argon2 参数覆写（如 Android 移动端），则优先使用覆写值。
     */
    private static void encryptDeriveKeys(OperationContext ctx, EncryptRequest req) {
        ctx.setStatus(Messages.get("status.deriving"));
        String effectivePw = Passwordless.effectivePassword(req.getPassword());
        byte[] pwBytes = PasswordNormalizer.encodeForKdf(effectivePw);
        byte[] key = Argon2Kdf.deriveKey(pwBytes, ctx.header.getSalt(), req.isParanoid(),
                req.getArgon2MemoryKib(), req.getArgon2Passes(), req.getArgon2Threads(),
                req.getKdfProgress());
        SecureZero.zero(pwBytes);
        ctx.setKey(key);
    }

    // ==================== Phase 5: Process keyfiles ====================

    /**
     * Keyfile 处理：计算各 keyfile 的 SHA3-256 哈希并合并。
     */
    private static void encryptProcessKeyfiles(OperationContext ctx, EncryptRequest req)
            throws IOException, CryptoException {
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
                throw new CryptoException(ErrorKind.KEYFILE_MISMATCH,
                        "duplicate keyfiles detected (keys cancel out)");
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
                throw new CryptoException(ErrorKind.KEYFILE_MISMATCH,
                        "duplicate keyfiles detected (keys cancel out)");
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
                    throw new CancelledException();
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
                            ctx.header.getComments().getBytes(StandardCharsets.UTF_8).length,
                            ctx.header.getVersion()),
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
        deleteTempFiles(ctx);
    }

    /**
     * 删除本次加密产生的全部中间临时文件（Zstandard 压缩产物与压缩后加密的中间归档）。
     *
     * @param ctx 操作上下文
     * @throws IOException 删除失败
     */
    private static void deleteTempFiles(OperationContext ctx) throws IOException {
        if (ctx.tempFile != null) {
            Files.deleteIfExists(Path.of(ctx.tempFile));
        }
        if (ctx.preArchiveTempFile != null) {
            Files.deleteIfExists(Path.of(ctx.preArchiveTempFile));
        }
    }

    /**
     * 加密失败时清理临时文件与不完整输出。
     */
    private static void cleanupEncrypt(OperationContext ctx, EncryptRequest req) {
        try {
            deleteTempFiles(ctx);
        } catch (IOException ignored) {
            // 清理失败不影响向上抛出的原始异常
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
