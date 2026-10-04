package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.volume.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Cross-runtime harness: desktop JVM and Android ART exchange the same files. */
public final class Lz4InteropSupport {
    public static final String VOLUME_PASSWORD = "volume-密码🔑";
    public static final String ARCHIVE_PASSWORD = "archive-密码🔑";
    public static Properties generate(Path output, Path source, boolean mobile) throws Exception {
        Files.createDirectories(output);
        Path input = output.resolve("source.m4a");
        if (!input.equals(source)) Files.copy(source, input, StandardCopyOption.REPLACE_EXISTING);
        Path notes = output.resolve("notes.txt");
        Files.write(notes, "桌面 ↔ Android: TAR.LZ4 第二条目\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Properties manifest = new Properties();
        manifest.setProperty("source.sha256", sha256(input));
        manifest.setProperty("source.size", Long.toString(Files.size(input)));
        manifest.setProperty("notes.sha256", sha256(notes));
        int count = 0;
        boolean custom = SettingsManager.isArchiveCustomEncryption(), fallback = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true); SettingsManager.setArchivePasswordFallback(false);
        try {
            for (String workflow : List.of("archive", "pre", "post")) {
                for (ArchivePacker.Format fmt : List.of(ArchivePacker.Format.LZ4, ArchivePacker.Format.TAR_LZ4)) {
                    for (boolean password : List.of(false, true)) {
                        String id = workflow + "-" + fmt + "-" + (password ? "password" : "empty");
                        String prefix = "case." + count + ".";
                        String artifact = id + (workflow.equals("archive") ? ".m4a" + ArchivePacker.extOf(fmt)
                                : workflow.equals("pre") ? ArchivePacker.extOf(fmt) + ".ergou" : ".ergou" + ArchivePacker.extOf(fmt));
                        boolean reusable = Boolean.getBoolean("lz4.interop.resume") && Files.isRegularFile(output.resolve(artifact));
                        if (!reusable) artifact = produce(output, input, notes, id, workflow, fmt, password, mobile);
                        manifest.setProperty(prefix + "id", id);
                        manifest.setProperty(prefix + "workflow", workflow);
                        manifest.setProperty(prefix + "format", fmt.name());
                        manifest.setProperty(prefix + "password", Boolean.toString(password));
                        manifest.setProperty(prefix + "artifact", artifact);
                        manifest.setProperty(prefix + "artifact.sha256", sha256(output.resolve(artifact)));
                        Path self = output.resolve("self-" + id);
                        try { verify(output, self, manifest, count); }
                        catch (IOException failure) {
                            if (!reusable) throw failure;
                            artifact = produce(output, input, notes, id, workflow, fmt, password, mobile);
                            manifest.setProperty(prefix + "artifact.sha256", sha256(output.resolve(artifact)));
                            verify(output, self, manifest, count);
                        }
                        try (var walk = Files.walk(self)) {
                            for (Path path : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
                        }
                        count++;
                    }
                }
            }
        } finally { SettingsManager.setArchiveCustomEncryption(custom); SettingsManager.setArchivePasswordFallback(fallback); }
        manifest.setProperty("count", Integer.toString(count));
        manifest.setProperty("runtime", mobile ? "Android ART" : "Desktop JVM");
        try (OutputStream out = Files.newOutputStream(output.resolve("manifest.properties"))) { manifest.store(out, "LZ4 real-file cross-runtime corpus"); }
        return manifest;
    }
    private static String produce(Path root, Path source, Path notes, String id, String workflow,
                                  ArchivePacker.Format fmt, boolean password, boolean mobile) throws Exception {
        String pwd = password ? ARCHIVE_PASSWORD : null;
        if (workflow.equals("archive")) {
            Path archive = root.resolve(id + ".m4a" + ArchivePacker.extOf(fmt));
            if (fmt == ArchivePacker.Format.LZ4) ArchivePacker.pack(archive, source, fmt, pwd);
            else ArchivePacker.packEntries(archive, root, List.of(source, notes), List.of("目录/source.m4a", "notes.txt"), fmt, pwd, null);
            return archive.getFileName().toString();
        }
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(source.toString()); req.setOutputFile(root.resolve(id + ".ergou").toString());
        req.setPassword(VOLUME_PASSWORD); req.setRsCodecs(new RsCodecs());
        // Small but distinct test KDF profiles; production defaults remain unchanged.
        req.setArgon2MemoryKib(mobile ? 8192 : 16384); req.setArgon2Passes(1); req.setArgon2Threads(1);
        if (workflow.equals("pre")) {
            if (fmt == ArchivePacker.Format.TAR_LZ4) req.setInputFiles(List.of(source.toString(), notes.toString()));
            req.setPreArchiveFormat(fmt.name()); req.setPreArchivePassword(pwd);
        } else { req.setArchiveFormat(fmt.name()); req.setArchivePassword(pwd); }
        Encryptor.encrypt(req);
        return Path.of(req.getOutputFile()).getFileName().toString();
    }
    public static void verify(Path corpus, Path output, Properties manifest, int index) throws Exception {
        Files.createDirectories(output);
        String prefix = "case." + index + ".";
        String workflow = manifest.getProperty(prefix + "workflow");
        ArchivePacker.Format fmt = ArchivePacker.parseFormat(manifest.getProperty(prefix + "format"));
        String pwd = Boolean.parseBoolean(manifest.getProperty(prefix + "password")) ? ARCHIVE_PASSWORD : null;
        Path artifact = corpus.resolve(manifest.getProperty(prefix + "artifact"));
        require(manifest.getProperty(prefix + "artifact.sha256").equals(sha256(artifact)), "Artifact changed: " + artifact);
        List<Path> restored;
        if (workflow.equals("pre")) {
            Path plainArchive = output.resolve("restored.m4a" + ArchivePacker.extOf(fmt));
            decrypt(artifact, plainArchive);
            require(ArchiveExtractor.isEncryptedFile(plainArchive) == (pwd != null), "Pre-archive password was ignored");
            restored = ArchiveExtractor.extractPreserving(plainArchive, output.resolve("files"), pwd);
        } else if (workflow.equals("post")) {
            require(ArchiveExtractor.isEncryptedFile(artifact) == (pwd != null), "Post-archive password was ignored");
            List<Path> volumes = ArchiveExtractor.extractPreserving(artifact, output.resolve("volumes"), pwd);
            require(volumes.size() == 1, "Expected one encrypted volume");
            Path plain = output.resolve("source.m4a"); decrypt(volumes.getFirst(), plain); restored = List.of(plain);
        } else {
            require(ArchiveExtractor.isEncryptedFile(artifact) == (pwd != null), "Archive password was ignored");
            restored = ArchiveExtractor.extractPreserving(artifact, output.resolve("files"), pwd);
        }
        boolean sourceFound = false, notesFound = false;
        for (Path file : restored) {
            String hash = sha256(file);
            if (hash.equals(manifest.getProperty("source.sha256"))) {
                require(Files.size(file) == Long.parseLong(manifest.getProperty("source.size")), "Source size mismatch"); sourceFound = true;
            } else if (hash.equals(manifest.getProperty("notes.sha256"))) notesFound = true;
            else throw new IOException("Unexpected restored bytes: " + file);
        }
        require(sourceFound, "Source missing: " + artifact);
        if (fmt == ArchivePacker.Format.TAR_LZ4 && !workflow.equals("post")) {
            require(notesFound && restored.size() == 2, "Second TAR entry missing");
        } else require(restored.size() == 1, "Unexpected file count");
        System.out.println("LZ4 VERIFIED " + manifest.getProperty(prefix + "id") + " | " + manifest.getProperty("source.sha256"));
    }
    public static void verifyAll(Path corpus, Path output) throws Exception {
        Properties manifest = new Properties();
        try (InputStream in = Files.newInputStream(corpus.resolve("manifest.properties"))) { manifest.load(in); }
        int count = Integer.parseInt(manifest.getProperty("count"));
        require(count == 12, "Incomplete interop matrix: " + count);
        for (int i=0;i<count;i++) verify(corpus, output.resolve("case-" + i), manifest, i);
    }
    private static void decrypt(Path input, Path output) throws Exception {
        DecryptRequest req = new DecryptRequest(); req.setInputFile(input.toString()); req.setOutputFile(output.toString());
        req.setPassword(VOLUME_PASSWORD); req.setRsCodecs(new RsCodecs()); Decryptor.decrypt(req);
    }
    public static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(path)) { byte[] buf = new byte[65536]; int n; while ((n=in.read(buf)) != -1) digest.update(buf,0,n); }
        StringBuilder hex = new StringBuilder();
        for (byte value : digest.digest()) hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return hex.toString();
    }
    private static void require(boolean ok, String message) throws IOException { if (!ok) throw new IOException(message); }
}
