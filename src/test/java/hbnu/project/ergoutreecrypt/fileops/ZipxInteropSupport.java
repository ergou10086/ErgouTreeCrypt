package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.settings.SplitMetadataMode;
import hbnu.project.ergoutreecrypt.volume.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Exchanges real ZIPX artifacts between desktop JVM and Android ART, verifying before decrypting. */
public final class ZipxInteropSupport {
    public static final String ARCHIVE_PASSWORD = "zipx-归档🔐";
    public static final String VOLUME_PASSWORD = "zipx-加密🔑";

    /** Prevents construction. */
    private ZipxInteropSupport() { }

    /**
     * Produces full real-file codec, volume and split-volume cases and verifies the producer's own output.
     * @param output corpus directory
     * @param source real M4A file
     * @param mobile whether the producer runs on ART
     * @return corpus manifest
     * @throws Exception production or producer self-verification failed
     */
    public static Properties generate(Path output, Path source, boolean mobile) throws Exception {
        Files.createDirectories(output);
        Path real = output.resolve("source.m4a");
        if (!real.equals(source)) Files.copy(source, real, StandardCopyOption.REPLACE_EXISTING);
        Path notes = output.resolve("notes.txt"), empty = output.resolve("empty");
        Files.write(notes, "ZIPX 双端真实文件互操作\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Files.write(empty, new byte[0]);
        Properties manifest = new Properties();
        manifest.setProperty("source.sha256", sha256(real));
        manifest.setProperty("source.size", Long.toString(Files.size(real)));
        manifest.setProperty("notes.sha256", sha256(notes));
        manifest.setProperty("runtime", mobile ? "Android ART" : "Desktop JVM");
        int index = 0;
        for (ZipxMethod codec : ZipxMethod.values()) for (boolean password : List.of(false, true)) {
            index = produce(output, manifest, index, "archive-" + codec + "-" + password, "archive", codec,
                    password, false, SplitMetadataMode.EMBEDDED, mobile);
        }
        for (String workflow : List.of("pre", "post")) for (boolean password : List.of(false, true)) {
            index = produce(output, manifest, index, workflow + "-" + password, workflow, ZipxMethod.XZ,
                    password, false, SplitMetadataMode.EMBEDDED, mobile);
        }
        for (SplitMetadataMode mode : SplitMetadataMode.values()) for (String workflow : List.of("pre", "post")) {
            index = produce(output, manifest, index, "split-" + workflow + "-" + mode, workflow, ZipxMethod.XZ,
                    true, true, mode, mobile);
        }
        manifest.setProperty("count", Integer.toString(index));
        try (OutputStream out = Files.newOutputStream(output.resolve("manifest.properties"))) {
            manifest.store(out, "ZIPX real-file interop: authentication and extraction/decryption separately");
        }
        return manifest;
    }

    /**
     * Produces one artifact and immediately runs independent authentication and restoration phases.
     * @param root corpus root
     * @param manifest case inventory
     * @param index case number
     * @param id stable case identifier
     * @param workflow archive, pre or post
     * @param codec compression method
     * @param password whether the archive is encrypted
     * @param split whether the volume is split
     * @param mode split metadata format
     * @param mobile whether the producer runs on ART
     * @return next case number
     * @throws Exception production or self-verification failed
     */
    private static int produce(Path root, Properties manifest, int index, String id, String workflow,
                                ZipxMethod codec, boolean password, boolean split, SplitMetadataMode mode,
                                boolean mobile) throws Exception {
        Path artifact;
        String pwd = password ? ARCHIVE_PASSWORD : null;
        if (workflow.equals("archive")) {
            artifact = root.resolve(id + ".zipx");
            ZipxArchive.pack(artifact, List.of(root.resolve("source.m4a"), root.resolve("notes.txt"), root.resolve("empty")),
                    List.of("目录/[ひなみ桜花][2024-01-25].m4a", "notes.txt", "empty"), codec, pwd, null);
        } else {
            Path caseRoot = Files.createDirectories(root.resolve(id));
            EncryptRequest request = new EncryptRequest();
            request.setInputFile(root.resolve("source.m4a").toString());
            request.setOutputFile(caseRoot.resolve("data.ergou").toString());
            request.setPassword(VOLUME_PASSWORD); request.setRsCodecs(new RsCodecs());
            request.setArgon2MemoryKib(mobile ? 4096 : 8192); request.setArgon2Passes(1); request.setArgon2Threads(1);
            request.setSplit(split); request.setChunkSize(8); request.setSplitMetadataMode(mode);
            if (workflow.equals("pre")) {
                request.setPreArchiveFormat("ZIPX"); request.setPreArchivePassword(pwd);
            } else {
                request.setArchiveFormat("ZIPX"); request.setArchivePassword(pwd);
            }
            Encryptor.encrypt(request);
            artifact = split && workflow.equals("pre") ? caseRoot : Path.of(request.getOutputFile());
        }
        String prefix = "case." + index + ".";
        manifest.setProperty(prefix + "id", id);
        manifest.setProperty(prefix + "workflow", workflow);
        manifest.setProperty(prefix + "password", Boolean.toString(password));
        manifest.setProperty(prefix + "split", Boolean.toString(split));
        manifest.setProperty(prefix + "artifact", root.relativize(artifact).toString().replace('\\', '/'));
        manifest.setProperty(prefix + "artifact.sha256", treeHash(artifact));
        Path output = root.resolve("self-" + index);
        verify(root, output, manifest, index);
        deleteWork(output);
        return index + 1;
    }

    /**
     * Authenticates and restores one transferred artifact, comparing complete bytes by SHA-256 and size.
     * @param corpus producer corpus directory
     * @param output operation-owned output directory
     * @param manifest producer inventory
     * @param index case number
     * @throws Exception any authentication or restoration check failed
     */
    public static void verify(Path corpus, Path output, Properties manifest, int index) throws Exception {
        Files.createDirectories(output);
        String prefix = "case." + index + ".";
        String id = manifest.getProperty(prefix + "id"), workflow = manifest.getProperty(prefix + "workflow");
        boolean split = Boolean.parseBoolean(manifest.getProperty(prefix + "split"));
        String pwd = Boolean.parseBoolean(manifest.getProperty(prefix + "password")) ? ARCHIVE_PASSWORD : null;
        Path artifact = corpus.resolve(manifest.getProperty(prefix + "artifact"));
        require(treeHash(artifact).equals(manifest.getProperty(prefix + "artifact.sha256")), "Transferred artifact changed: " + id);
        List<Path> restored;
        if (workflow.equals("archive")) {
            ZipxArchive.verify(artifact, pwd);
            System.out.println("ZIPX AUTHENTICATED " + id);
            restored = ArchiveExtractor.extract(artifact, output.resolve("files"), pwd);
            require(restored.size() == 3, "Missing Unicode, notes or empty entry");
            require(Files.size(output.resolve("files/empty")) == 0, "Empty file changed");
            require(sha256(output.resolve("files/notes.txt")).equals(manifest.getProperty("notes.sha256")), "Notes changed");
        } else {
            Path volume;
            if (workflow.equals("post")) {
                ZipxArchive.verify(artifact, pwd);
                Path extracted = output.resolve("volumes");
                List<Path> volumes = ArchiveExtractor.extract(artifact, extracted, pwd);
                volume = split ? splitInput(extracted) : volumes.getFirst();
            } else volume = split ? splitInput(artifact) : artifact;
            VerifyRequest verify = new VerifyRequest();
            verify.setInputFile(volume.toString()); verify.setPassword(VOLUME_PASSWORD);
            verify.setRsCodecs(new RsCodecs()); verify.setRecombine(split);
            require(Verifier.verify(verify), "Volume authentication failed: " + id);
            System.out.println("ZIPX AUTHENTICATED " + id);
            Path plain = output.resolve(workflow.equals("pre") ? "restored.zipx" : "restored.m4a");
            DecryptRequest decrypt = new DecryptRequest();
            decrypt.setInputFile(volume.toString()); decrypt.setOutputFile(plain.toString());
            decrypt.setPassword(VOLUME_PASSWORD); decrypt.setRsCodecs(new RsCodecs()); decrypt.setRecombine(split);
            Decryptor.decrypt(decrypt);
            if (workflow.equals("pre")) {
                require(ArchiveExtractor.hasEncryptedEntries(plain) == (pwd != null), "Pre-archive password ignored");
                ZipxArchive.verify(plain, pwd);
                restored = ArchiveExtractor.extract(plain, output.resolve("files"), pwd);
            } else restored = List.of(plain);
        }
        boolean found = false;
        for (Path file : restored) if (sha256(file).equals(manifest.getProperty("source.sha256"))) {
            require(Files.size(file) == Long.parseLong(manifest.getProperty("source.size")), "Source size changed");
            found = true;
        }
        require(found, "Real source file missing or changed: " + id);
        System.out.println("ZIPX RESTORED " + id + " SHA256=" + manifest.getProperty("source.sha256"));
    }

    /**
     * Verifies all cases received from the other runtime.
     * @param corpus producer corpus root
     * @param output operation-owned output directory
     * @throws Exception incomplete matrix or failed case
     */
    public static void verifyAll(Path corpus, Path output) throws Exception {
        Properties manifest = new Properties();
        try (InputStream in = Files.newInputStream(corpus.resolve("manifest.properties"))) { manifest.load(in); }
        int count = Integer.parseInt(manifest.getProperty("count"));
        require(count == 14, "Incomplete ZIPX matrix: " + count);
        for (int index = 0; index < count; index++) {
            Path work = output.resolve("case-" + index);
            verify(corpus, work, manifest, index);
            deleteWork(work);
        }
    }

    /**
     * Regenerates XZ cases after an empty-entry interoperability fix, preserving unaffected cases.
     * @param corpus existing complete producer corpus
     * @param mobile whether the producer runs on ART
     * @throws Exception regeneration or producer verification failed
     */
    public static void refreshXzArchives(Path corpus, boolean mobile) throws Exception {
        Properties manifest = manifest(corpus);
        int index = 4;
        for (boolean password : List.of(false, true)) {
            index = produce(corpus, manifest, index, "archive-XZ-" + password, "archive", ZipxMethod.XZ,
                    password, false, SplitMetadataMode.EMBEDDED, mobile);
        }
        try (OutputStream out = Files.newOutputStream(corpus.resolve("manifest.properties"))) {
            manifest.store(out, "ZIPX XZ archives refreshed; unaffected codec and volume cases retained");
        }
    }

    /**
     * Verifies affected raw archives without repeating unchanged full-file volume workflows.
     * @param corpus producer corpus
     * @param output operation-owned verification directory
     * @throws Exception any authentication or restoration failed
     */
    public static void verifyRawArchives(Path corpus, Path output) throws Exception {
        Properties manifest = manifest(corpus);
        for (int index = 0; index < 6; index++) {
            require("archive".equals(manifest.getProperty("case." + index + ".workflow")), "Missing raw archive case");
            Path work = output.resolve("case-" + index);
            verify(corpus, work, manifest, index);
            deleteWork(work);
        }
    }

    /**
     * Loads an existing complete corpus for targeted revalidation.
     * @param corpus producer corpus
     * @return validated inventory
     * @throws IOException incomplete corpus
     */
    private static Properties manifest(Path corpus) throws IOException {
        Properties manifest = new Properties();
        try (InputStream in = Files.newInputStream(corpus.resolve("manifest.properties"))) { manifest.load(in); }
        require("14".equals(manifest.getProperty("count")), "Incomplete ZIPX corpus");
        return manifest;
    }

    /**
     * Selects a real split chunk, testing automatic metadata-format detection.
     * @param directory extracted split directory
     * @return selected chunk
     * @throws IOException split files missing
     */
    private static Path splitInput(Path directory) throws IOException {
        try (var paths = Files.walk(directory)) {
            List<Path> chunks = paths.filter(Files::isRegularFile).filter(p -> Splitter.isSplitChunkPath(p.toString())).sorted().toList();
            require(chunks.size() > 1, "Real test file was not split");
            return chunks.getLast();
        }
    }

    /**
     * Hashes an artifact or a complete split tree, including each relative filename.
     * @param artifact file or directory
     * @return SHA-256 digest
     * @throws Exception hashing failed
     */
    private static String treeHash(Path artifact) throws Exception {
        if (Files.isRegularFile(artifact)) return sha256(artifact);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var paths = Files.walk(artifact)) {
            for (Path path : paths.filter(Files::isRegularFile).sorted().toList()) {
                digest.update(artifact.relativize(path).toString().replace('\\', '/').getBytes(java.nio.charset.StandardCharsets.UTF_8));
                digest.update(sha256(path).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            }
        }
        return hex(digest.digest());
    }

    /**
     * Hashes every byte of a file without loading it into memory.
     * @param path source file
     * @return SHA-256 digest
     * @throws Exception hashing failed
     */
    public static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(path)) {
            byte[] buffer = new byte[65536]; int count;
            while ((count = in.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return hex(digest.digest());
    }

    /**
     * Converts digest bytes to portable lowercase hexadecimal.
     * @param bytes digest bytes
     * @return hexadecimal string
     */
    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte value : bytes) text.append(String.format(Locale.ROOT, "%02x", value & 255));
        return text.toString();
    }

    /**
     * Enforces a regression invariant.
     * @param condition required condition
     * @param message failure explanation
     * @throws IOException invariant failed
     */
    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }

    /**
     * Removes only a generated verification directory.
     * @param work operation-owned test output
     * @throws IOException cleanup failed
     */
    private static void deleteWork(Path work) throws IOException {
        try (var paths = Files.walk(work)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }
}
