package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Properties;

/** 共享 JVM/ART 归档语料，七类格式各覆盖前后归档与独立密码。 */
public final class FastArchiveInteropSupport {
    private static final String PASSWORD = "归档极速🔐";
    /** 禁止实例化测试工具。 */
    private FastArchiveInteropSupport() {}

    /**
     * 生产前后归档与独立密码的完整组合。
     * @param corpus 原始输入语料
     * @param output 本端密文目录
     * @throws Exception 生产失败
     */
    public static void produce(Path corpus, Path output) throws Exception {
        Path archives = Files.createDirectory(output.resolve("archives"));
        boolean saved = SettingsManager.isArchiveCustomEncryption();
        boolean savedFallback = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true);
        SettingsManager.setArchivePasswordFallback(false);
        try {
            var manifest = new Properties();
            for (var format : ArchivePacker.Format.values()) {
                for (boolean before : new boolean[]{true, false}) {
                    for (boolean protectedArchive : new boolean[]{false, true}) {
                        String id = format.name() + "-" + before + "-" + protectedArchive;
                        Path directory = Files.createDirectory(archives.resolve(id));
                        var request = new EncryptRequest();
                        request.setMode(EncryptionMode.FAST);
                        request.setPassword(PASSWORD);
                        request.setInputFile(corpus.resolve("inputs/日本語.bin").toString());
                        request.setOutputFile(directory.resolve("中文🔐.ergou").toString());
                        String password = protectedArchive ? "独立归档密码" : null;
                        if (before) {
                            request.setInputFiles(List.of(corpus.resolve("inputs/中文🔐.bin").toString(),
                                    corpus.resolve("inputs/日本語.bin").toString()));
                            request.setPreArchiveFormat(format.name());
                            request.setPreArchivePassword(password);
                        } else {
                            request.setArchiveFormat(format.name());
                            request.setArchivePassword(password);
                        }
                        long started = System.nanoTime();
                        Encryptor.encrypt(request);
                        manifest.setProperty(id + ".taskNanos", Long.toString(System.nanoTime() - started));
                        Path cipher = Path.of(request.getOutputFile());
                        manifest.setProperty(id + ".file", archives.relativize(cipher).toString().replace('\\', '/'));
                        manifest.setProperty(id + ".sha256", FastInteropSupport.sha256(cipher));
                    }
                }
            }
            try (var out = Files.newOutputStream(archives.resolve("manifest.properties"))) {
                manifest.store(out, null);
            }
        } finally {
            SettingsManager.setArchiveCustomEncryption(saved);
            SettingsManager.setArchivePasswordFallback(savedFallback);
        }
    }

    /**
     * 验证指定生产端归档的搬运完整性、认证及还原。
     * @param corpus 原始桌面语料
     * @param ciphers 指定生产端产物
     * @param scratch 空临时目录
     * @throws Exception 任一方向失败
     */
    public static void verify(Path corpus, Path ciphers, Path scratch) throws Exception {
        var manifest = new Properties();
        Path archives = ciphers.resolve("archives");
        try (var in = Files.newInputStream(archives.resolve("manifest.properties"))) { manifest.load(in); }
        for (var format : ArchivePacker.Format.values()) {
            for (boolean before : new boolean[]{true, false}) {
                for (boolean protectedArchive : new boolean[]{false, true}) {
                    String id = format.name() + "-" + before + "-" + protectedArchive;
                    Path cipher = archives.resolve(manifest.getProperty(id + ".file"));
                    if (!FastInteropSupport.sha256(cipher).equals(manifest.getProperty(id + ".sha256")))
                        throw new AssertionError("归档搬运摘要错误：" + id);
                    Path work = Files.createDirectory(scratch.resolve(id));
                    try {
                        String archivePassword = protectedArchive ? "独立归档密码" : null;
                        Path fast = before ? cipher : ArchiveExtractor.extractPreserving(cipher,
                                Files.createDirectory(work.resolve("外层")), archivePassword).getFirst();
                        var auth = new VerifyRequest();
                        auth.setInputFile(fast.toString()); auth.setPassword(PASSWORD);
                        long filesBefore;
                        try (var walk = Files.walk(work)) { filesBefore = walk.count(); }
                        if (!Verifier.verify(auth)) throw new AssertionError("归档 FAST 认证失败：" + id);
                        try (var walk = Files.walk(work)) {
                            if (filesBefore != walk.count()) throw new AssertionError("认证产生文件");
                        }
                        Path plain = work.resolve("还原" + (before ? ArchivePacker.extOf(
                                ArchivePacker.effectiveFormat(format, 2)) : ".bin"));
                        var decrypt = new DecryptRequest();
                        decrypt.setInputFile(fast.toString()); decrypt.setOutputFile(plain.toString());
                        decrypt.setPassword(PASSWORD);
                        Decryptor.decrypt(decrypt);
                        if (before) {
                            List<Path> entries = ArchiveExtractor.extractPreserving(plain,
                                    Files.createDirectory(work.resolve("明文")), archivePassword);
                            if (entries.size() != 2) throw new AssertionError("多条目丢失：" + id);
                            for (Path entry : entries) {
                                Path source = corpus.resolve("inputs").resolve(entry.getFileName());
                                if (!FastInteropSupport.equalBytes(source, entry)) throw new AssertionError("前归档还原不同");
                            }
                        } else if (!FastInteropSupport.equalBytes(corpus.resolve("inputs/日本語.bin"), plain))
                            throw new AssertionError("后归档还原不同");
                    } finally {
                        try (var walk = Files.walk(work)) {
                            for (Path entry : walk.sorted(Comparator.reverseOrder()).toList()) Files.delete(entry);
                        }
                    }
                }
            }
        }
    }
}
