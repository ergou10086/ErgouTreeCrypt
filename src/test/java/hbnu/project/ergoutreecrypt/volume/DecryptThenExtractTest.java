package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.fileops.ArchivePostExtract;
import hbnu.project.ergoutreecrypt.fileops.ArchivePasswordProvider;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 解密后解压与解压后解密的隔离、深度限制与单文件路径测试。
 *
 * @author ErgouTree
 */
class DecryptThenExtractTest {

    private static final String PW = "dte-pw";

    /**
     * zip.ergou 解密后保留明文 zip，并解压到同名文件夹且保留内部目录结构。
     */
    @Test
    void zipErgou_extractsToNamedFolderAndKeepsArchive() throws Exception {
        Path tmp = Files.createTempDirectory("dte-zip-");
        try {
            byte[] a = rand(80);
            byte[] b = rand(120);
            Path src = tmp.resolve("src");
            Files.createDirectories(src.resolve("sub/dir"));
            Files.write(src.resolve("root.txt"), a);
            Files.write(src.resolve("sub/dir/nested.txt"), b);
            Path zip = tmp.resolve("photos.zip");
            packZip(zip, src, List.of(src.resolve("root.txt"), src.resolve("sub/dir/nested.txt")));

            Path enc = tmp.resolve("photos.zip.ergou");
            encryptOne(zip, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(enc, dec, decryptThenExtractOpts(false));

            assertTrue(Files.isRegularFile(dec.resolve("photos.zip")), "应保留明文压缩包");
            assertTrue(Files.isDirectory(dec.resolve("photos")));
            assertArrayEquals(a, Files.readAllBytes(dec.resolve("photos/root.txt")));
            assertArrayEquals(b, Files.readAllBytes(dec.resolve("photos/sub/dir/nested.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 7z.ergou 同样解压到同名文件夹并保留 7z。
     */
    @Test
    void sevenZErgou_extractsToNamedFolderAndKeepsArchive() throws Exception {
        Path tmp = Files.createTempDirectory("dte-7z-");
        try {
            byte[] data = rand(90);
            Path src = tmp.resolve("src");
            Files.createDirectories(src.resolve("inner"));
            Files.write(src.resolve("inner/pack.bin"), data);
            Path sevenZ = tmp.resolve("pack.7z");
            ArchivePacker.packEntries(sevenZ, src, List.of(src.resolve("inner/pack.bin")),
                    ArchivePacker.Format._7Z, null);

            Path enc = tmp.resolve("pack.7z.ergou");
            encryptOne(sevenZ, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(enc, dec, decryptThenExtractOpts(false));

            assertTrue(Files.isRegularFile(dec.resolve("pack.7z")));
            assertArrayEquals(data, Files.readAllBytes(dec.resolve("pack/inner/pack.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 默认最多 2 层：第 3 层明文 zip 原样保留。
     */
    @Test
    void nestedPlainZips_defaultStopsAtDepth2() throws Exception {
        Path tmp = Files.createTempDirectory("dte-d2-");
        try {
            Path leaf = tmp.resolve("file.txt");
            Files.write(leaf, rand(40));
            Path chain = nestZips(tmp, leaf, 3);
            Path enc = tmp.resolve(chain.getFileName().toString() + ".ergou");
            encryptOne(chain, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(enc, dec, decryptThenExtractOpts(false));

            assertNotNull(findPath(dec, "L3.zip"), "第 3 层应原样保留");
            assertNull(findPath(dec, "file.txt"), "默认不应解开第 3 层");
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 勾选递归后最多 5 层：第 6 层明文 zip 原样保留。
     */
    @Test
    void nestedPlainZips_recursiveStopsAtDepth5() throws Exception {
        Path tmp = Files.createTempDirectory("dte-d5-");
        try {
            Path leaf = tmp.resolve("file.txt");
            Files.write(leaf, rand(40));
            Path chain = nestZips(tmp, leaf, 6);
            Path enc = tmp.resolve(chain.getFileName().toString() + ".ergou");
            encryptOne(chain, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(enc, dec, decryptThenExtractOpts(true));

            assertNotNull(findPath(dec, "L6.zip"), "第 6 层应原样保留");
            assertNull(findPath(dec, "file.txt"), "递归最多 5 层，不应解开第 6 层");
            assertNotNull(findPath(dec, "L5.zip"), "第 5 层压缩包应保留");
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 带密码 zip：跳过解压，压缩包仍在，不出现明文内容。
     */
    @Test
    void passwordProtectedZip_skippedAndKept() throws Exception {
        Path tmp = Files.createTempDirectory("dte-pwd-");
        try {
            byte[] secret = "secret-plain".getBytes(StandardCharsets.UTF_8);
            Path src = tmp.resolve("src");
            Files.createDirectories(src);
            Path secretFile = src.resolve("secret.txt");
            Files.write(secretFile, secret);
            Path zip = tmp.resolve("locked.zip");
            ArchivePacker.packEntries(zip, src, List.of(secretFile),
                    ArchivePacker.Format.ZIP, "arch-pw");

            Path enc = tmp.resolve("locked.zip.ergou");
            encryptOne(zip, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(enc, dec, decryptThenExtractOpts(false));

            assertTrue(Files.isRegularFile(dec.resolve("locked.zip")));
            assertNull(findPath(dec, "secret.txt"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 带密码 zip + 提供者给出正确密码：解密后解压应成功解出内容。
     */
    @Test
    void passwordProtectedZip_providerSuppliesPassword_extracts() throws Exception {
        Path tmp = Files.createTempDirectory("dte-prov-ok-");
        try {
            byte[] secret = "secret-plain".getBytes(StandardCharsets.UTF_8);
            Path src = tmp.resolve("src");
            Files.createDirectories(src);
            Path secretFile = src.resolve("secret.txt");
            Files.write(secretFile, secret);
            Path zip = tmp.resolve("locked.zip");
            ArchivePacker.packEntries(zip, src, List.of(secretFile),
                    ArchivePacker.Format.ZIP, "arch-pw");

            Path enc = tmp.resolve("locked.zip.ergou");
            encryptOne(zip, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.DecryptOptions opts = decryptThenExtractOpts(false);
            opts.archivePasswordProvider = (a, retry) -> "arch-pw";
            FolderCrypt.decryptAuto(enc, dec, opts);

            assertTrue(Files.isRegularFile(dec.resolve("locked.zip")));
            assertArrayEquals(secret, Files.readAllBytes(dec.resolve("locked/secret.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 带密码 zip + 提供者先给错密码，重试（retry=true）给正确密码：应成功解压并确认重试。
     */
    @Test
    void passwordProtectedZip_wrongThenCorrectPassword_retriesPrompt() throws Exception {
        Path tmp = Files.createTempDirectory("dte-prov-retry-");
        try {
            byte[] secret = "secret-plain".getBytes(StandardCharsets.UTF_8);
            Path src = tmp.resolve("src");
            Files.createDirectories(src);
            Path secretFile = src.resolve("secret.txt");
            Files.write(secretFile, secret);
            Path zip = tmp.resolve("locked.zip");
            ArchivePacker.packEntries(zip, src, List.of(secretFile),
                    ArchivePacker.Format.ZIP, "arch-pw");

            Path enc = tmp.resolve("locked.zip.ergou");
            encryptOne(zip, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            java.util.concurrent.atomic.AtomicBoolean retried = new java.util.concurrent.atomic.AtomicBoolean();
            FolderCrypt.DecryptOptions opts = decryptThenExtractOpts(false);
            opts.archivePasswordProvider = (a, retry) -> {
                if (!retry) {
                    return "wrong";
                }
                retried.set(true);
                return "arch-pw";
            };
            FolderCrypt.decryptAuto(enc, dec, opts);

            assertTrue(retried.get(), "第一次密码错误后应以 retry=true 再次询问");
            assertArrayEquals(secret, Files.readAllBytes(dec.resolve("locked/secret.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 带密码 zip + 提供者放弃（返回 null）：跳过解压，压缩包保留，不出现明文内容。
     */
    @Test
    void passwordProtectedZip_providerDeclines_skippedAndKept() throws Exception {
        Path tmp = Files.createTempDirectory("dte-prov-skip-");
        try {
            byte[] secret = "secret-plain".getBytes(StandardCharsets.UTF_8);
            Path src = tmp.resolve("src");
            Files.createDirectories(src);
            Path secretFile = src.resolve("secret.txt");
            Files.write(secretFile, secret);
            Path zip = tmp.resolve("locked.zip");
            ArchivePacker.packEntries(zip, src, List.of(secretFile),
                    ArchivePacker.Format.ZIP, "arch-pw");

            Path enc = tmp.resolve("locked.zip.ergou");
            encryptOne(zip, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.DecryptOptions opts = decryptThenExtractOpts(false);
            opts.archivePasswordProvider = (a, retry) -> null;
            FolderCrypt.decryptAuto(enc, dec, opts);

            assertTrue(Files.isRegularFile(dec.resolve("locked.zip")));
            assertNull(findPath(dec, "secret.txt"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 解压后解密：明文加密 zip 内的 .ergou，通过提供者获得归档密码后成功解密内部文件。
     */
    @Test
    void extractThenDecrypt_providerSuppliesArchivePassword_decryptsInner() throws Exception {
        Path tmp = Files.createTempDirectory("dte-etd-pw-");
        try {
            byte[] data = rand(55);
            Path f = tmp.resolve("doc.txt");
            Files.write(f, data);
            Path e = tmp.resolve("doc.txt.ergou");
            encryptOne(f, e);

            Path locked = tmp.resolve("locked.zip");
            ArchivePacker.packEntries(locked, tmp, List.of(e),
                    ArchivePacker.Format.ZIP, "arch-pw");

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.DecryptOptions opts = new FolderCrypt.DecryptOptions();
            opts.password = PW;
            opts.rsCodecs = new RsCodecs();
            opts.extractThenDecrypt = true;
            opts.decryptThenExtract = false;
            opts.archivePasswordProvider = (a, retry) -> "arch-pw";
            FolderCrypt.decryptAuto(locked, dec, opts);

            assertArrayEquals(data, Files.readAllBytes(dec.resolve("locked/doc.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 解压后解密：提供者先给错密码，重试（retry=true）给正确密码后成功解密内部文件。
     */
    @Test
    void extractThenDecrypt_wrongThenCorrectArchivePassword_retries() throws Exception {
        Path tmp = Files.createTempDirectory("dte-etd-retry-");
        try {
            byte[] data = rand(60);
            Path f = tmp.resolve("doc.txt");
            Files.write(f, data);
            Path e = tmp.resolve("doc.txt.ergou");
            encryptOne(f, e);

            Path locked = tmp.resolve("locked.zip");
            ArchivePacker.packEntries(locked, tmp, List.of(e),
                    ArchivePacker.Format.ZIP, "arch-pw");

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            java.util.concurrent.atomic.AtomicBoolean retried = new java.util.concurrent.atomic.AtomicBoolean();
            FolderCrypt.DecryptOptions opts = new FolderCrypt.DecryptOptions();
            opts.password = PW;
            opts.rsCodecs = new RsCodecs();
            opts.extractThenDecrypt = true;
            opts.decryptThenExtract = false;
            opts.archivePasswordProvider = (a, retry) -> {
                if (!retry) {
                    return "wrong";
                }
                retried.set(true);
                return "arch-pw";
            };
            FolderCrypt.decryptAuto(locked, dec, opts);

            assertTrue(retried.get(), "归档密码错误后应以 retry=true 再次询问");
            assertArrayEquals(data, Files.readAllBytes(dec.resolve("locked/doc.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 解密后解压不得解密解压出来的 .ergou。
     */
    @Test
    void doesNotDecryptErgouInsideExtractedZip() throws Exception {
        Path tmp = Files.createTempDirectory("dte-iso-");
        try {
            byte[] plain = rand(70);
            Path inner = tmp.resolve("hidden.txt");
            Files.write(inner, plain);
            Path innerEnc = tmp.resolve("hidden.txt.ergou");
            encryptOne(inner, innerEnc);

            Path wrapDir = tmp.resolve("wrap");
            Files.createDirectories(wrapDir);
            Path copied = wrapDir.resolve("hidden.txt.ergou");
            Files.copy(innerEnc, copied);
            Path zip = tmp.resolve("photos.zip");
            packZip(zip, wrapDir, List.of(copied));

            Path enc = tmp.resolve("photos.zip.ergou");
            encryptOne(zip, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.DecryptOptions opts = decryptThenExtractOpts(false);
            opts.extractThenDecrypt = false;
            FolderCrypt.decryptAuto(enc, dec, opts);

            assertTrue(Files.isRegularFile(dec.resolve("photos/hidden.txt.ergou")));
            assertNull(findPath(dec, "hidden.txt"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 仅解压后解密：明文 zip 内的 .ergou 被解密；不会把输入 zip 再当解密后解压。
     */
    @Test
    void extractThenDecryptOnly_doesNotPostExtractPlainZip() throws Exception {
        Path tmp = Files.createTempDirectory("dte-etd-");
        try {
            byte[] data = rand(55);
            Path f = tmp.resolve("doc.txt");
            Files.write(f, data);
            Path e = tmp.resolve("doc.txt.ergou");
            encryptOne(f, e);

            Path zip = tmp.resolve("bundle.zip");
            packZip(zip, tmp, List.of(e));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.DecryptOptions opts = new FolderCrypt.DecryptOptions();
            opts.password = PW;
            opts.rsCodecs = new RsCodecs();
            opts.extractThenDecrypt = true;
            opts.decryptThenExtract = false;
            FolderCrypt.decryptAuto(zip, dec, opts);

            assertArrayEquals(data, Files.readAllBytes(dec.resolve("bundle/doc.txt")));
            assertNull(findPath(dec, "bundle.zip"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 两选项同时开：zip 内 inner.zip.ergou → 先解压后解密得到 inner.zip，再解压到 inner/ 且保留 zip。
     */
    @Test
    void bothFlags_extractThenDecryptThenExtractRecoveredZip() throws Exception {
        Path tmp = Files.createTempDirectory("dte-both-");
        try {
            byte[] data = rand(66);
            Path src = tmp.resolve("innerSrc");
            Files.createDirectories(src);
            Files.write(src.resolve("pic.bin"), data);
            Path innerZip = tmp.resolve("inner.zip");
            packZip(innerZip, src, List.of(src.resolve("pic.bin")));
            Path innerEnc = tmp.resolve("inner.zip.ergou");
            encryptOne(innerZip, innerEnc);

            Path outer = tmp.resolve("outer.zip");
            packZip(outer, tmp, List.of(innerEnc));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.DecryptOptions opts = new FolderCrypt.DecryptOptions();
            opts.password = PW;
            opts.rsCodecs = new RsCodecs();
            opts.extractThenDecrypt = true;
            opts.decryptThenExtract = true;
            FolderCrypt.decryptAuto(outer, dec, opts);

            assertTrue(Files.isRegularFile(findPath(dec, "inner.zip")));
            assertArrayEquals(data, findFile(dec, "pic.bin"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 分卷 zip.ergou 合并解密后再解压到同名文件夹。
     */
    @Test
    void splitZipErgou_recombineThenExtract() throws Exception {
        Path tmp = Files.createTempDirectory("dte-split-");
        try {
            byte[] data = rand(1024 * 1024 + 2048);
            Path src = tmp.resolve("src");
            Files.createDirectories(src);
            Files.write(src.resolve("big.bin"), data);
            Path zip = tmp.resolve("file.zip");
            packZip(zip, src, List.of(src.resolve("big.bin")));

            Path dest = tmp.resolve("enc/file.zip.ergou");
            Files.createDirectories(dest.getParent());
            EncryptRequest req = new EncryptRequest();
            req.setInputFile(zip.toString());
            req.setOutputFile(dest.toString());
            req.setPassword(PW);
            req.setRsCodecs(new RsCodecs());
            req.setSplit(true);
            req.setChunkSize(1);
            applyFastKdf(req);
            Encryptor.encrypt(req);

            Path chunkDir = tmp.resolve("enc/file.zip");
            assertTrue(Files.isDirectory(chunkDir));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(chunkDir, dec, decryptThenExtractOpts(false));

            assertTrue(Files.isRegularFile(dec.resolve("file.zip")));
            assertArrayEquals(data, Files.readAllBytes(dec.resolve("file/big.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 单文件 Decryptor 路径：调用方 post-extract。
     */
    @Test
    void decryptorSingleFile_callerPostExtract() throws Exception {
        Path tmp = Files.createTempDirectory("dte-single-");
        try {
            byte[] data = rand(45);
            Path src = tmp.resolve("src");
            Files.createDirectories(src);
            Files.write(src.resolve("a.txt"), data);
            Path zip = tmp.resolve("photos.zip");
            packZip(zip, src, List.of(src.resolve("a.txt")));
            Path enc = tmp.resolve("photos.zip.ergou");
            encryptOne(zip, enc);

            Path out = tmp.resolve("photos.zip");
            DecryptRequest req = new DecryptRequest();
            req.setInputFile(enc.toString());
            req.setOutputFile(out.toString());
            req.setPassword(PW);
            req.setRsCodecs(new RsCodecs());
            req.setDecryptThenExtract(true);
            Decryptor.decrypt(req);
            ArchivePostExtract.extractIfArchive(out, ArchivePostExtract.maxDepth(false), null);

            assertTrue(Files.isRegularFile(out));
            assertArrayEquals(data, Files.readAllBytes(tmp.resolve("photos/a.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * zip-slip 条目被拒绝，明文 zip 仍保留。
     */
    @Test
    void zipSlip_rejectedAndArchiveKept() throws Exception {
        Path tmp = Files.createTempDirectory("dte-slip-");
        try {
            Path zip = tmp.resolve("evil.zip");
            try (OutputStream fos = Files.newOutputStream(zip);
                 ZipArchiveOutputStream zos = new ZipArchiveOutputStream(fos)) {
                ZipArchiveEntry entry = new ZipArchiveEntry("../../evil.txt");
                zos.putArchiveEntry(entry);
                zos.write("pwned".getBytes(StandardCharsets.UTF_8));
                zos.closeArchiveEntry();
            }
            Path enc = tmp.resolve("evil.zip.ergou");
            encryptOne(zip, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(enc, dec, decryptThenExtractOpts(false));

            assertTrue(Files.isRegularFile(dec.resolve("evil.zip")), "zip-slip 失败后仍应保留明文 zip");
            assertFalse(Files.exists(tmp.resolve("evil.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 未勾选解密后解压时，zip.ergou 只还原为 zip。
     */
    @Test
    void withoutFlag_onlyRecoversArchive() throws Exception {
        Path tmp = Files.createTempDirectory("dte-off-");
        try {
            byte[] data = rand(30);
            Path src = tmp.resolve("src");
            Files.createDirectories(src);
            Files.write(src.resolve("a.txt"), data);
            Path zip = tmp.resolve("photos.zip");
            packZip(zip, src, List.of(src.resolve("a.txt")));
            Path enc = tmp.resolve("photos.zip.ergou");
            encryptOne(zip, enc);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.DecryptOptions opts = new FolderCrypt.DecryptOptions();
            opts.password = PW;
            opts.rsCodecs = new RsCodecs();
            opts.decryptThenExtract = false;
            FolderCrypt.decryptAuto(enc, dec, opts);

            assertTrue(Files.isRegularFile(dec.resolve("photos.zip")));
            assertFalse(Files.isDirectory(dec.resolve("photos")));
        } finally {
            rmrf(tmp);
        }
    }

    private static FolderCrypt.DecryptOptions decryptThenExtractOpts(boolean recursive) {
        FolderCrypt.DecryptOptions opts = new FolderCrypt.DecryptOptions();
        opts.password = PW;
        opts.rsCodecs = new RsCodecs();
        opts.decryptThenExtract = true;
        opts.extractThenDecrypt = false;
        opts.recursiveExtract = recursive;
        return opts;
    }

    private static void encryptOne(Path src, Path out) throws Exception {
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(src.toString());
        req.setOutputFile(out.toString());
        req.setPassword(PW);
        req.setRsCodecs(new RsCodecs());
        applyFastKdf(req);
        Encryptor.encrypt(req);
    }

    private static void applyFastKdf(EncryptRequest req) {
        req.setArgon2MemoryKib(32);
        req.setArgon2Passes(1);
        req.setArgon2Threads(1);
    }

    /**
     * 从 leaf 向外包装 {@code layers} 层 zip：L{n}.zip 包着 L{n-1} 或 leaf。
     *
     * @param tmp    临时目录
     * @param leaf   最内层文件
     * @param layers 层数
     * @return 最外层 zip
     * @throws IOException 打包失败
     */
    private static Path nestZips(Path tmp, Path leaf, int layers) throws IOException {
        Path current = leaf;
        Path last = null;
        for (int i = layers; i >= 1; i--) {
            Path zip = tmp.resolve("L" + i + ".zip");
            packZip(zip, current.getParent(), List.of(current));
            last = zip;
            current = zip;
        }
        return last;
    }

    private static void packZip(Path zip, Path baseDir, List<Path> files) throws IOException {
        try (OutputStream fos = Files.newOutputStream(zip);
             ZipArchiveOutputStream zos = new ZipArchiveOutputStream(fos)) {
            for (Path p : files) {
                String name = baseDir.relativize(p).toString().replace('\\', '/');
                ZipArchiveEntry entry = new ZipArchiveEntry(name);
                zos.putArchiveEntry(entry);
                Files.copy(p, zos);
                zos.closeArchiveEntry();
            }
        }
    }

    private static byte[] rand(int n) {
        byte[] b = new byte[n];
        new java.util.Random(n).nextBytes(b);
        return b;
    }

    private static Path findPath(Path root, String name) throws IOException {
        try (Stream<Path> w = Files.walk(root)) {
            return w.filter(Files::isRegularFile)
                    .filter(x -> x.getFileName().toString().equals(name))
                    .findFirst()
                    .orElse(null);
        }
    }

    private static byte[] findFile(Path root, String name) throws Exception {
        Path p = findPath(root, name);
        assertNotNull(p, "not found: " + name);
        return Files.readAllBytes(p);
    }

    private static void rmrf(Path dir) throws Exception {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> w = Files.walk(dir)) {
            w.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                }
            });
        }
    }
}
