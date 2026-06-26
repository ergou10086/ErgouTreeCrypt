package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.*;
import hbnu.project.ergoutreecrypt.encoding.Padding;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.header.*;
import hbnu.project.ergoutreecrypt.keyfile.KeyfileProcessor;
import hbnu.project.ergoutreecrypt.password.PasswordNormalizer;
import hbnu.project.ergoutreecrypt.password.Passwordless;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.List;

/**
 * 8 阶段加密编排，对应 Go {@code internal/volume/encrypt.go}。
 *
 * <p>流水线：
 * <ol>
 *   <li>preprocess — 多文件 zip</li>
 *   <li>generateValues — 随机 salt/nonce/IV + header</li>
 *   <li>writeHeader — RS 编码写 header（占位 auth）</li>
 *   <li>deriveKeys — Argon2id 密码派生（无密码时用随机 key）</li>
 *   <li>processKeyfiles — keyfile 哈希 + XOR</li>
 *   <li>computeAuth — v2 header HMAC</li>
 *   <li>encryptPayload — XChaCha20(+Serpent) + MAC + 可选 RS</li>
 *   <li>finalize — writeAt 回填 auth → rename</li>
 * </ol>
 *
 * @author ErgouTree
 */
public final class Encryptor {

    private Encryptor() {
    }

    /**
     * 主入口
     */
    public static void encrypt(EncryptRequest req) throws Exception {
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

    // ================================================================
    // Phase 1: Preprocess
    // ================================================================
    private static void encryptPreprocess(OperationContext ctx, EncryptRequest req) throws Exception {
        List<String> files = req.getInputFiles();
        if (files != null && !files.isEmpty()) {
            if (files.size() > 1 || req.isCompress()) {
                ctx.setStatus("Compressing...");
                // 简化版：单文件直接加密，多文件逐个追加（后续迭代补 zip）
                Path tmp = Files.createTempFile("ergou", ".tmp");
                ctx.tempFile = tmp.toString();
                try (OutputStream out = Files.newOutputStream(tmp)) {
                    for (String f : files) {
                        Files.copy(Path.of(f), out);
                    }
                }
                ctx.inputFile = ctx.tempFile;
                return;
            }
            ctx.inputFile = files.get(0);
        } else {
            ctx.inputFile = req.getInputFile();
        }
    }

    // ================================================================
    // Phase 2: Generate values
    // ================================================================
    private static void encryptGenerateValues(OperationContext ctx, EncryptRequest req) throws IOException {
        ctx.setStatus("Generating values...");

        byte[] salt = RandomBytes.generate(VolumeHeader.SALT_SIZE);
        byte[] hkdfSalt = RandomBytes.generate(VolumeHeader.HKDF_SALT_SIZE);
        byte[] serpentIV = RandomBytes.generate(VolumeHeader.SERPENT_IV_SIZE);
        byte[] nonce = RandomBytes.generate(VolumeHeader.NONCE_SIZE);

        Path inPath = Path.of(ctx.inputFile);
        ctx.total = Files.size(inPath);

        // Padded = last partial < 1 MiB - 128 bytes
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

    // ================================================================
    // Phase 3: Write header
    // ================================================================
    private static void encryptWriteHeader(OperationContext ctx, EncryptRequest req) throws IOException {
        String incomplete = req.getOutputFile() + ".incomplete";
        try (OutputStream out = Files.newOutputStream(Path.of(incomplete))) {
            HeaderWriter writer = new HeaderWriter(out, req.getRsCodecs());
            writer.writeHeader(ctx.header);
        }
    }

    // ================================================================
    // Phase 4: Derive keys
    // ================================================================
    private static void encryptDeriveKeys(OperationContext ctx, EncryptRequest req) {
        ctx.setStatus("Deriving key...");

        // 无密码时使用公开默认密码，保证"无密码"文件人人可解密
        String effectivePw = Passwordless.effectivePassword(req.getPassword());
        byte[] pwBytes = PasswordNormalizer.encodeForKdf(effectivePw);
        byte[] key = Argon2Kdf.deriveKey(pwBytes, ctx.header.getSalt(), req.isParanoid());
        SecureZero.zero(pwBytes);
        ctx.setKey(key);
    }

    // ================================================================
    // Phase 5: Process keyfiles
    // ================================================================
    private static void encryptProcessKeyfiles(OperationContext ctx, EncryptRequest req) throws IOException {
        List<String> kfPaths = req.getKeyfiles();
        if (kfPaths == null || kfPaths.isEmpty()) {
            ctx.keyfileHash = new byte[32];
            ctx.useKeyfiles = false;
            return;
        }
        ctx.setStatus("Processing keyfiles...");
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

    // ================================================================
    // Phase 6: Compute auth
    // ================================================================
    private static void encryptComputeAuth(OperationContext ctx, EncryptRequest req) {
        ctx.setStatus("Computing auth...");

        // v2: HKDF BEFORE keyfile XOR
        HkdfStream hkdf = new HkdfStream(ctx.key, ctx.header.getHkdfSalt());
        ctx.subkeyReader = new SubkeyReader(hkdf);

        byte[] subkeyHeader = ctx.subkeyReader.headerSubkey();
        ctx.header.setKeyHash(HeaderAuth.computeV2HeaderMac(subkeyHeader, ctx.header, ctx.keyfileHash));
        ctx.header.setKeyfileHash(ctx.keyfileHash);
    }

    // ================================================================
    // Phase 7: Encrypt payload
    // ================================================================
    private static void encryptPayload(OperationContext ctx, EncryptRequest req) throws Exception {
        // Keyfile XOR (AFTER HKDF init for v2) — only when password is present
        // For keyfile-only mode, key was already set to keyfileKey in encryptProcessKeyfiles
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

                cs.encrypt(dst, src, n);

                byte[] writeData;
                if (req.isReedSolomon()) {
                    writeData = encodeWithRS(dst, n, req.getRsCodecs());
                } else {
                    writeData = new byte[n];
                    System.arraycopy(dst, 0, writeData, 0, n);
                }

                fout.write(writeData);
                done += n;
                counter += CryptoConstants.MIB;

                if (ctx.total > 0) {
                    float progress = (float) done / ctx.total;
                    long elapsed = System.currentTimeMillis() - startMs;
                    String speed = elapsed > 0 ? String.format("%.1f MiB/s", done / 1048576.0 / (elapsed / 1000.0)) : "";
                    ctx.updateProgress(progress, speed);
                }

                // Rekey every 60 GiB
                if (counter >= CryptoConstants.REKEY_THRESHOLD) {
                    cs.rekey();
                    counter = 0;
                }
            }
        }

        SecureZero.zero(macSubkey);
        SecureZero.zero(serpentKey);
    }

    // ================================================================
    // Phase 8: Finalize
    // ================================================================
    private static void encryptFinalize(OperationContext ctx, EncryptRequest req) throws Exception {
        ctx.setStatus("Finalizing...");

        byte[] authTag = ctx.cipherSuite.sum();
        String incomplete = req.getOutputFile() + ".incomplete";

        try (FileChannel ch = FileChannel.open(Path.of(incomplete), StandardOpenOption.WRITE)) {
            HeaderWriter.writeAuthValues(ch,
                    HeaderLayout.authValuesOffset(
                            ctx.header.getComments().getBytes(java.nio.charset.StandardCharsets.UTF_8).length),
                    ctx.header.getKeyHash(), ctx.header.getKeyfileHash(), authTag,
                    req.getRsCodecs());
        }

        // Rename .incomplete → final
        Files.move(Path.of(incomplete), Path.of(req.getOutputFile()),
                StandardCopyOption.REPLACE_EXISTING);

        // Add deniability wrapper if requested
        if (req.isDeniability()) {
            Deniability.addDeniability(req.getOutputFile(),
                    Passwordless.effectivePassword(req.getPassword()), ctx.reporter);
        }

        boolean archive = req.getArchiveFormat() != null && !req.getArchiveFormat().isEmpty();
        boolean split = req.isSplit() && req.getChunkSize() > 0;

        // 顺序约定：先分卷得到一块块加密文件，再（若启用压缩）将它们整体打成一个压缩包。
        // 压缩永远是最后一步。
        Path chunkDir = null; // 记录分卷碎片所在文件夹（单文件场景会自动创建）
        if (split) {
            ctx.setStatus("Splitting...");
            long chunkBytes = (long) req.getChunkSize() * CryptoConstants.MIB; // 每卷大小，单位 MiB
            Path outPath = Path.of(req.getOutputFile());
            String outName = outPath.getFileName().toString();

            // 检查是否已经在分卷碎片文件夹内（FolderCrypt 已预先创建）
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
                // 单文件分卷：创建以原文件同名的文件夹，把分卷加密结果输出到其中
                chunkDir = parent.resolve(folderName);
                // 若同名文件已存在（如源文件与输出同目录），使用带后缀的文件夹名
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
            Files.deleteIfExists(fileToSplit); // 删除未分卷的原始文件
        }

        if (archive) {
            ctx.setStatus("Archiving...");
            ArchivePacker.Format fmt = ArchivePacker.parseFormat(req.getArchiveFormat());
            Path outPath = Path.of(req.getOutputFile());
            Path parent = outPath.getParent() != null ? outPath.getParent() : Path.of(".");

            if (split) {
                // 收集所有分卷碎片 base.0, base.1, ... 打入单一压缩包
                List<Path> chunks = Splitter.listChunks(outPath);
                // 归档放在分卷文件夹的父目录中，以分卷文件夹名命名
                Path archiveParent = parent.getParent() != null ? parent.getParent() : Path.of(".");
                String archiveName = parent.getFileName().toString() + ArchivePacker.extOf(fmt);
                Path archivePath = archiveParent.resolve(archiveName);
                ArchivePacker.packEntries(archivePath, parent, chunks, fmt,
                        req.getArchivePassword());
                for (Path c : chunks) {
                    Files.deleteIfExists(c);
                }
                // 删除空的分卷碎片文件夹
                try {
                    Files.deleteIfExists(parent);
                } catch (IOException ignored) {
                }
                req.setOutputFile(archivePath.toString());
            } else {
                Path archivePath = Path.of(req.getOutputFile() + ArchivePacker.extOf(fmt));
                ArchivePacker.pack(archivePath, outPath, fmt, req.getArchivePassword());
                Files.deleteIfExists(outPath);
                req.setOutputFile(archivePath.toString());
            }
        }

        // Cleanup temp
        if (ctx.tempFile != null) {
            Files.deleteIfExists(Path.of(ctx.tempFile));
        }
    }

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

    // ================================================================
    // RS 编码辅助
    // ================================================================
    static byte[] encodeWithRS(byte[] data, int len, RsCodecs rs) {
        boolean isFullBlock = len == CryptoConstants.MIB;

        if (isFullBlock) {
            // 整 1 MiB 块：8192 个 128B 块，无 padding。
            int fullChunks = len / Padding.BLOCK_SIZE;
            byte[] result = new byte[fullChunks * 136];
            int pos = 0;
            for (int i = 0; i < fullChunks; i++) {
                byte[] chunk = new byte[Padding.BLOCK_SIZE];
                System.arraycopy(data, i * Padding.BLOCK_SIZE, chunk, 0, Padding.BLOCK_SIZE);
                byte[] enc = ReedSolomon.encode(rs.rs128, chunk);
                System.arraycopy(enc, 0, result, pos, 136);
                pos += 136;
            }
            return result;
        }

        // 部分块（< 1 MiB）：编码全部 128B 块 + 恰好一个 padding 块（即使整除 128）。
        // 与 Go encodeWithRS 一致：解密端对部分块的最后一块总是 unpad。
        int fullChunks = len / Padding.BLOCK_SIZE;
        int remaining = len - fullChunks * Padding.BLOCK_SIZE;
        int chunkCount = fullChunks + 1; // 总是补一个 padding 块

        byte[] result = new byte[chunkCount * 136];
        int pos = 0;
        for (int i = 0; i < fullChunks; i++) {
            byte[] chunk = new byte[Padding.BLOCK_SIZE];
            System.arraycopy(data, i * Padding.BLOCK_SIZE, chunk, 0, Padding.BLOCK_SIZE);
            byte[] enc = ReedSolomon.encode(rs.rs128, chunk);
            System.arraycopy(enc, 0, result, pos, 136);
            pos += 136;
        }

        byte[] last = new byte[remaining];
        System.arraycopy(data, fullChunks * Padding.BLOCK_SIZE, last, 0, remaining);
        byte[] padded = Padding.pad(last);
        byte[] enc = ReedSolomon.encode(rs.rs128, padded);
        System.arraycopy(enc, 0, result, pos, 136);

        return result;
    }

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
