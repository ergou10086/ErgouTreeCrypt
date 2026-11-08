package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard;
import hbnu.project.ergoutreecrypt.volume.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** 下载改名场景的共享回归入口，在桌面 JVM 和真实 Android ART 中分别执行。 */
public final class SplitDownloadSupport {
    private static final String PASSWORD = "download-互通🔑";
    private static final List<String> MODES = List.of("embedded", "rs-keyfiles", "legacy", "sidecar");

    /** 禁止实例化工具类。 */
    private SplitDownloadSupport() { }

    /**
     * 生成小型真实文件片段语料，覆盖内嵌、旧原始字节、旧清单、RS 和 FAST。
     * @param root 本轮独占语料目录
     * @param source 真实文件
     * @throws Exception 生成失败
     */
    public static void generate(Path root, Path source) throws Exception {
        Files.createDirectories(root);
        try (InputStream in = Files.newInputStream(source)) {
            Files.write(root.resolve("source.bin"), in.readNBytes(128 * 1024 + 13));
        }
        Files.write(root.resolve("key"), "keyfile-下载".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        for (String mode : MODES) {
            Path folder = Files.createDirectories(root.resolve(mode));
            Path base = folder.resolve("下载 样本.bin.ergou");
            EncryptRequest e = new EncryptRequest();
            e.setInputFile(root.resolve("source.bin").toString());
            e.setOutputFile(base.toString());
            e.setPassword(PASSWORD);
            e.setRsCodecs(new RsCodecs());
            e.setArgon2MemoryKib(64);
            e.setArgon2Passes(1);
            e.setArgon2Threads(1);
            if (mode.equals("rs-keyfiles")) {
                e.setReedSolomon(true);
                e.setParanoid(true);
                e.setKeyfiles(List.of(root.resolve("key").toString()));
            }
            Encryptor.encrypt(e);
            if (mode.equals("legacy") || mode.equals("sidecar")) {
                Splitter.splitWithManifest(base, 32768, null);
                if (mode.equals("legacy")) Files.delete(Splitter.manifestPath(base));
            } else Splitter.split(base, 32768);
            Files.delete(base);
        }
    }

    /**
     * 验证同一批实际分卷在本运行时的认证和解密，逐字节比对输出。
     * @param corpus 生产端语料
     * @param work 本读取端独占工作目录
     * @return 通过的认证／解密用例对数
     * @throws Exception 改名兼容、错误拒绝或输出保护不符合预期
     */
    public static int verify(Path corpus, Path work) throws Exception {
        int cases = 0;
        for (String mode : MODES) {
            Path original = corpus.resolve(mode).resolve("下载 样本.bin.ergou");
            List<Path> chunks = Splitter.listChunks(original);
            List<String> keys = mode.equals("rs-keyfiles") ? List.of(corpus.resolve("key").toString()) : List.of();
            List<String> variants = new ArrayList<>(List.of("original", "suffix", "duplicate"));
            if (!mode.equals("legacy") && !mode.equals("sidecar")) variants.addAll(List.of("arbitrary", "partial", "number-changed"));
            for (String variant : variants) {
                Path dir = Files.createDirectories(work.resolve(mode + "-" + variant));
                List<Path> selected = new ArrayList<>();
                for (int i = 0; i < chunks.size(); i++) {
                    String name = "下载 样本.bin.ergou." + i;
                    if (variant.equals("number-changed")) name = "下载 样本.bin.ergou." + (chunks.size() - 1 - i);
                    if (variant.equals("suffix")) name = switch (i % 4) {
                        case 0 -> name + ".下载";
                        case 1 -> name + " (2)";
                        case 2 -> name + "(1).bin";
                        default -> "下载 样本.bin.ergou (1)." + i;
                    };
                    if (variant.equals("arbitrary") || variant.equals("partial") && i > 0) {
                        name = "QQ-" + (chunks.size() - i) + (i % 2 == 0 ? ".zip" : ".data");
                    }
                    selected.add(Files.copy(chunks.get(i), dir.resolve(name), StandardCopyOption.REPLACE_EXISTING));
                }
                Path sidecar = Splitter.manifestPath(original);
                if (Files.exists(sidecar)) Files.copy(sidecar, dir.resolve(sidecar.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                if (variant.equals("duplicate")) {
                    Files.copy(selected.get(1), dir.resolve("下载 样本.bin.ergou.1 (3)"), StandardCopyOption.REPLACE_EXISTING);
                }
                Path input = selected.get(selected.size() - 1);
                Path base = Splitter.inputBase(input);
                require(base != null, "Renamed chunk was not identified");
                Splitter.inspect(base).requireComplete();
                require(Splitter.inputBases(selected).size() == 1, "A split batch was handled more than once");
                require(FileInputGuard.check(FileInputGuard.Feature.GENERIC_DECRYPT, FileInputGuard.Options.none(), input).accepted(), "Decrypt guard rejected a renamed volume");
                require(FileInputGuard.check(FileInputGuard.Feature.VERIFY_INTEGRITY, FileInputGuard.Options.none(), input).accepted(), "Verify guard rejected a renamed volume");
                authenticateAndDecrypt(input, dir.resolve("plain"), PASSWORD, keys);
                require(Arrays.equals(Files.readAllBytes(corpus.resolve("source.bin")), Files.readAllBytes(dir.resolve("plain"))), "Plaintext differs");
                FolderCrypt.DecryptOptions opts = new FolderCrypt.DecryptOptions();
                opts.password = PASSWORD;
                opts.keyfiles = keys;
                opts.rsCodecs = new RsCodecs();
                FolderCrypt.decryptFiles(selected, dir.resolve("batch"), opts);
                require(opts.batchResult.succeededCount() == 1 && opts.batchResult.failedCount() == 0, "Batch did not deduplicate renamed chunks");
                try (var outputs = Files.list(dir.resolve("batch"))) {
                    Path output = outputs.findFirst().orElseThrow();
                    require(Arrays.equals(Files.readAllBytes(corpus.resolve("source.bin")), Files.readAllBytes(output)), "Batch output differs");
                }
                if (variant.equals("arbitrary")) {
                    Path folder = Files.createDirectories(dir.resolve("folder-input"));
                    for (Path source : selected) Files.copy(source, folder.resolve(source.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                    FolderCrypt.decryptAuto(folder, dir.resolve("folder-result"), opts);
                    try (var outputs = Files.list(dir.resolve("folder-result"))) {
                        require(Arrays.equals(Files.readAllBytes(corpus.resolve("source.bin")), Files.readAllBytes(outputs.findFirst().orElseThrow())), "Folder recovery differs");
                    }
                }
                for (Path source : selected) {
                    boolean protectedInput = false;
                    try { Splitter.requireSeparateOutput(source, base); }
                    catch (IOException expected) { protectedInput = true; }
                    require(protectedInput, "Renamed source was not protected");
                }
                cases++;
            }
            for (int index : List.of(0, 1, chunks.size() - 1)) {
                Path dir = Files.createDirectories(work.resolve(mode + "-missing-" + index));
                for (Path chunk : chunks) Files.copy(chunk, dir.resolve(chunk.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                Path sidecar = Splitter.manifestPath(original);
                if (Files.exists(sidecar)) Files.copy(sidecar, dir.resolve(sidecar.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                Files.delete(dir.resolve(chunks.get(index).getFileName()));
                Path input = dir.resolve(chunks.get(index == 0 ? 1 : 0).getFileName());
                Path base = Splitter.inputBase(input);
                var info = Splitter.inspect(base);
                if (info.totalKnown() || index != chunks.size() - 1) require(info.missing().contains(index), "Missing index was not reported");
                reject(input, dir.resolve("preserved"), PASSWORD, keys);
                cases++;
            }
            Path conflict = Files.createDirectories(work.resolve(mode + "-conflict"));
            for (Path chunk : chunks) Files.copy(chunk, conflict.resolve(chunk.getFileName()), StandardCopyOption.REPLACE_EXISTING);
            byte[] changed = Files.readAllBytes(chunks.get(1));
            changed[32] ^= 1;
            Files.write(conflict.resolve(chunks.get(1).getFileName() + " (1)"), changed);
            reject(conflict.resolve(chunks.get(0).getFileName()), conflict.resolve("preserved"), PASSWORD, keys);
            cases++;
            if (mode.equals("embedded") || mode.equals("rs-keyfiles")) {
                Path damaged = Files.createDirectories(work.resolve(mode + "-renamed-ciphertext"));
                for (int i = 0; i < chunks.size(); i++) {
                    byte[] bytes = Files.readAllBytes(chunks.get(i));
                    if (i == 1) bytes[32] ^= 1;
                    Files.write(damaged.resolve("attachment-" + i + ".bin"), bytes);
                }
                Path input = damaged.resolve("attachment-0.bin");
                if (mode.equals("rs-keyfiles")) {
                    authenticateAndDecrypt(input, damaged.resolve("plain"), PASSWORD, keys);
                    require(Arrays.equals(Files.readAllBytes(corpus.resolve("source.bin")), Files.readAllBytes(damaged.resolve("plain"))), "RS repair of a renamed volume differs");
                } else reject(input, damaged.resolve("preserved"), PASSWORD, keys);
                cases++;
            }
        }
        System.out.println("DOWNLOAD PASS: " + cases + " authenticate/decrypt pairs");
        return cases;
    }

    /**
     * 对用户指定样本执行真实认证和解密，返回输出摘要，不更改输入。
     * @param input 样本的一个分卷
     * @param output 本轮独占明文输出
     * @param password 密码
     * @return 明文长度及 SHA-256
     * @throws Exception 认证、解密或摘要失败
     */
    public static String sample(Path input, Path output, String password) throws Exception {
        authenticateAndDecrypt(input, output, password, List.of());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream stream = Files.newInputStream(output)) {
            byte[] buffer = new byte[1024 * 1024];
            int count;
            while ((count = stream.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return Files.size(output) + " bytes SHA-256=" + HexFormat.of().formatHex(digest.digest());
    }

    /**
     * @param input 所选碎片
     * @param output 明文输出
     * @param password 密码
     * @param keys 密钥文件
     * @throws Exception 认证或解密失败
     */
    private static void authenticateAndDecrypt(Path input, Path output, String password, List<String> keys) throws Exception {
        VerifyRequest v = new VerifyRequest();
        v.setInputFile(input.toString());
        v.setPassword(password);
        v.setKeyfiles(keys);
        v.setRsCodecs(new RsCodecs());
        require(Verifier.verify(v), "Authentication failed");
        DecryptRequest d = new DecryptRequest();
        d.setInputFile(input.toString());
        d.setOutputFile(output.toString());
        d.setPassword(password);
        d.setKeyfiles(keys);
        d.setRsCodecs(new RsCodecs());
        Decryptor.decrypt(d);
    }

    /**
     * @param input 异常碎片
     * @param output 已存在的输出
     * @param password 密码
     * @param keys 密钥文件
     * @throws Exception 错误输入被接受或破坏已有输出
     */
    private static void reject(Path input, Path output, String password, List<String> keys) throws Exception {
        VerifyRequest v = new VerifyRequest();
        v.setInputFile(input.toString()); v.setPassword(password); v.setKeyfiles(keys); v.setRsCodecs(new RsCodecs());
        boolean rejected = false;
        try { rejected = !Verifier.verify(v); } catch (Exception expected) { rejected = true; }
        require(rejected, "Verifier accepted an incomplete/conflicting group");
        Files.write(output, new byte[]{107,101,101,112});
        DecryptRequest d = new DecryptRequest();
        d.setInputFile(input.toString()); d.setOutputFile(output.toString()); d.setPassword(password); d.setKeyfiles(keys); d.setRsCodecs(new RsCodecs());
        rejected = false;
        try { Decryptor.decrypt(d); } catch (Exception expected) { rejected = true; }
        require(rejected && Arrays.equals(Files.readAllBytes(output), new byte[]{107,101,101,112}), "Decryptor accepted bad input or destroyed existing output");
    }

    /**
     * @param condition 必须成立的条件
     * @param message 失败说明
     * @throws IOException 条件不成立
     */
    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}
