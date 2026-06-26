package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class FolderCryptRoundtripTest {

    private static byte[] rand(int n) {
        byte[] b = new byte[n];
        new java.util.Random(n).nextBytes(b);
        return b;
    }

    private static void rmrf(Path dir) throws Exception {
        if (!Files.exists(dir)) return;
        try (Stream<Path> w = Files.walk(dir)) {
            w.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (Exception ignored) {}
            });
        }
    }

    @Test
    void folderSplitArchiveRoundtrip() throws Exception {
        Path tmp = Files.createTempDirectory("fc-test-");
        try {
            // 构造输入文件夹（含子目录）
            Path in = tmp.resolve("src");
            Files.createDirectories(in.resolve("sub"));
            byte[] a = rand(3 * 1024 * 1024 + 123);
            byte[] b = rand(500 * 1024);
            Files.write(in.resolve("a.bin"), a);
            Files.write(in.resolve("sub/b.bin"), b);

            // 加密：分卷 1MiB + ZIP 压缩
            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "pw123456";
            eo.split = true;
            eo.chunkSize = 1; // MiB
            eo.archiveFormat = "ZIP";
            eo.rsCodecs = new RsCodecs();
            FolderCrypt.encryptFolder(in, encOut, eo);

            Path archive = encOut.resolve("src.zip");
            assertTrue(Files.exists(archive), "should produce single zip");

            // 解密归档
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw123456";
            dop.rsCodecs = new RsCodecs();
            FolderCrypt.decryptAuto(archive, decOut, dop);

            // 校验结果
            Path root = decOut.resolve("src");
            assertArrayEquals(a, Files.readAllBytes(root.resolve("a.bin")));
            assertArrayEquals(b, Files.readAllBytes(root.resolve("sub/b.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    @Test
    void folderNoArchiveRoundtrip() throws Exception {
        Path tmp = Files.createTempDirectory("fc-test2-");
        try {
            Path in = tmp.resolve("docs");
            Files.createDirectories(in);
            byte[] a = rand(200 * 1024);
            Files.write(in.resolve("note.txt"), a);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "secret";
            eo.rsCodecs = new RsCodecs();
            FolderCrypt.encryptFolder(in, encOut, eo);

            Path encFolder = encOut.resolve("docs");
            assertTrue(Files.isDirectory(encFolder));
            assertTrue(Files.exists(encFolder.resolve("note.txt.ergou")));

            // 解密文件夹
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "secret";
            dop.rsCodecs = new RsCodecs();
            FolderCrypt.decryptAuto(encFolder, decOut, dop);

            assertArrayEquals(a, Files.readAllBytes(decOut.resolve("docs/note.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 用普通 DEFLATE ZIP 打包多个独立加密文件（来自"加密后压缩"得到的多个 .ergou），
     * 再用第三方方式套一层 zip 的典型场景。解密该 zip 应输出一个文件夹，内部为解密结果。
     */
    @Test
    void zipOfMultipleEncryptedFilesRoundtrip() throws Exception {
        Path tmp = Files.createTempDirectory("fc-test4-");
        try {
            byte[] d1 = rand(120 * 1024);
            byte[] d2 = rand(64 * 1024);
            Path f1 = tmp.resolve("alpha.txt");
            Path f2 = tmp.resolve("beta.dat");
            Files.write(f1, d1);
            Files.write(f2, d2);

            // 分别独立加密为 .ergou
            Path e1 = tmp.resolve("alpha.txt.ergou");
            Path e2 = tmp.resolve("beta.dat.ergou");
            encryptOne(f1, e1, "pw");
            encryptOne(f2, e2, "pw");

            // 用普通 DEFLATE ZIP 把两个 .ergou 打成一个 zip（无内部 AES 层）
            Path zip = tmp.resolve("bundle.zip");
            try (OutputStream fos = Files.newOutputStream(zip);
                 ZipArchiveOutputStream zos = new ZipArchiveOutputStream(fos)) {
                for (Path p : List.of(e1, e2)) {
                    ZipArchiveEntry entry = new ZipArchiveEntry(p.getFileName().toString());
                    zos.putArchiveEntry(entry);
                    Files.copy(p, zos);
                    zos.closeArchiveEntry();
                }
            }

            // 解密该 zip
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            FolderCrypt.decryptAuto(zip, decOut, dop);

            Path root = decOut.resolve("bundle");
            assertArrayEquals(d1, Files.readAllBytes(root.resolve("alpha.txt")));
            assertArrayEquals(d2, Files.readAllBytes(root.resolve("beta.dat")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * zip 中混有不可解密后缀的文件（如 readme.txt），应跳过它们只解密 .ergou，不报错。
     */
    @Test
    void zipWithMixedFilesSkipsNonDecryptable() throws Exception {
        Path tmp = Files.createTempDirectory("fc-test5-");
        try {
            byte[] d1 = rand(50 * 1024);
            Path f1 = tmp.resolve("doc.txt");
            Files.write(f1, d1);
            Path e1 = tmp.resolve("doc.txt.ergou");
            encryptOne(f1, e1, "pw");

            Path readme = tmp.resolve("readme.txt");
            Files.write(readme, "hello".getBytes());

            Path zip = tmp.resolve("mixed.zip");
            try (OutputStream fos = Files.newOutputStream(zip);
                 ZipArchiveOutputStream zos = new ZipArchiveOutputStream(fos)) {
                for (Path p : List.of(e1, readme)) {
                    ZipArchiveEntry entry = new ZipArchiveEntry(p.getFileName().toString());
                    zos.putArchiveEntry(entry);
                    Files.copy(p, zos);
                    zos.closeArchiveEntry();
                }
            }

            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            FolderCrypt.decryptAuto(zip, decOut, dop);

            Path root = decOut.resolve("mixed");
            assertArrayEquals(d1, Files.readAllBytes(root.resolve("doc.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 嵌套压缩包：外层 zip 内含一个"加密后压缩"得到的 zip（其中是多个 .ergou）。
     * 解密外层 zip 应递归解压解密，输出文件夹中包含全部解密结果。
     */
    @Test
    void nestedArchiveOfEncryptedFilesRoundtrip() throws Exception {
        Path tmp = Files.createTempDirectory("fc-nested-");
        try {
            // 文件夹加密 + 压缩，得到 inner zip（内部是多个 .ergou）
            Path in = tmp.resolve("payload");
            Files.createDirectories(in);
            byte[] d1 = rand(80 * 1024);
            byte[] d2 = rand(40 * 1024);
            Files.write(in.resolve("one.txt"), d1);
            Files.write(in.resolve("two.txt"), d2);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "pw";
            eo.archiveFormat = "ZIP";
            eo.rsCodecs = new RsCodecs();
            FolderCrypt.encryptFolder(in, encOut, eo);
            Path innerZip = encOut.resolve("payload.zip");
            assertTrue(Files.exists(innerZip));

            // 把 inner zip 再套一层外层 zip
            Path outerZip = tmp.resolve("outer.zip");
            try (OutputStream fos = Files.newOutputStream(outerZip);
                 ZipArchiveOutputStream zos = new ZipArchiveOutputStream(fos)) {
                ZipArchiveEntry entry = new ZipArchiveEntry(innerZip.getFileName().toString());
                zos.putArchiveEntry(entry);
                Files.copy(innerZip, zos);
                zos.closeArchiveEntry();
            }

            // 解密外层 zip：开启递归解压才会深入 inner zip
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.recursiveExtract = true;
            dop.rsCodecs = new RsCodecs();
            FolderCrypt.decryptAuto(outerZip, decOut, dop);

            // 在输出目录里递归找解密结果（结构: outer/payload/payload/one.txt ...）
            byte[] r1 = findFile(decOut, "one.txt");
            byte[] r2 = findFile(decOut, "two.txt");
            assertArrayEquals(d1, r1);
            assertArrayEquals(d2, r2);
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 默认不递归：解密外层 zip 只解压一层，内部嵌套的 zip 应原样输出，不被深入解密。
     */
    @Test
    void nestedArchiveNotRecursedByDefault() throws Exception {
        Path tmp = Files.createTempDirectory("fc-nonrec-");
        try {
            Path in = tmp.resolve("payload");
            Files.createDirectories(in);
            byte[] d1 = rand(60 * 1024);
            Files.write(in.resolve("one.txt"), d1);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "pw";
            eo.archiveFormat = "ZIP";
            eo.rsCodecs = new RsCodecs();
            FolderCrypt.encryptFolder(in, encOut, eo);
            Path innerZip = encOut.resolve("payload.zip");

            Path outerZip = tmp.resolve("outer.zip");
            try (OutputStream fos = Files.newOutputStream(outerZip);
                 ZipArchiveOutputStream zos = new ZipArchiveOutputStream(fos)) {
                ZipArchiveEntry entry = new ZipArchiveEntry(innerZip.getFileName().toString());
                zos.putArchiveEntry(entry);
                Files.copy(innerZip, zos);
                zos.closeArchiveEntry();
            }

            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            // recursiveExtract 默认为 false
            dop.rsCodecs = new RsCodecs();
            FolderCrypt.decryptAuto(outerZip, decOut, dop);

            // 内部 zip 被原样拷贝输出，one.txt 不应出现（未被深入解密）
            Path passthrough = findPathOrNull(decOut, "payload.zip");
            assertNotNull(passthrough, "嵌套压缩包应被原样输出");
            assertNull(findPathOrNull(decOut, "one.txt"), "默认不应深入解密内部内容");
        } finally {
            rmrf(tmp);
        }
    }

    private static Path findPathOrNull(Path root, String name) throws Exception {
        try (Stream<Path> w = Files.walk(root)) {
            return w.filter(Files::isRegularFile)
                    .filter(x -> x.getFileName().toString().equals(name))
                    .findFirst().orElse(null);
        }
    }

    private static byte[] findFile(Path root, String name) throws Exception {
        try (Stream<Path> w = Files.walk(root)) {
            Path p = w.filter(Files::isRegularFile)
                    .filter(x -> x.getFileName().toString().equals(name))
                    .findFirst().orElseThrow(() -> new AssertionError("not found: " + name));
            return Files.readAllBytes(p);
        }
    }

    /**
     * 单个不可解密文件应报错提示。
     */
    @Test
    void singleNonDecryptableFileThrows() throws Exception {
        Path tmp = Files.createTempDirectory("fc-test6-");
        try {
            Path plain = tmp.resolve("plain.txt");
            Files.write(plain, "not encrypted".getBytes());
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            assertThrows(FolderCrypt.NoDecryptableFilesException.class,
                    () -> FolderCrypt.decryptAuto(plain, decOut, dop));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 整个文件夹中没有任何可解密文件时应报错。
     */
    @Test
    void folderWithNoDecryptableFilesThrows() throws Exception {
        Path tmp = Files.createTempDirectory("fc-test7-");
        try {
            Path dir = tmp.resolve("stuff");
            Files.createDirectories(dir);
            Files.write(dir.resolve("a.txt"), "x".getBytes());
            Files.write(dir.resolve("b.log"), "y".getBytes());

            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            assertThrows(FolderCrypt.NoDecryptableFilesException.class,
                    () -> FolderCrypt.decryptAuto(dir, decOut, dop));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 用户场景：文件夹「加密后压缩」并为压缩包设置了独立密码（条目变成 .ergou.enc）。
     * 解密该压缩包应正确去掉 AES 层并解密，恢复原始文件。
     */
    @Test
    void folderArchiveWithPasswordRoundtrip() throws Exception {
        Path tmp = Files.createTempDirectory("fc-archpw-");
        try {
            Path in = tmp.resolve("vault");
            Files.createDirectories(in.resolve("inner"));
            byte[] a = rand(90 * 1024);
            byte[] b = rand(30 * 1024);
            Files.write(in.resolve("x.txt"), a);
            Files.write(in.resolve("inner/y.txt"), b);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "mainpw";
            eo.archiveFormat = "ZIP";
            eo.archivePassword = "archpw"; // 独立归档密码 → 条目 .ergou.enc
            eo.rsCodecs = new RsCodecs();
            FolderCrypt.encryptFolder(in, encOut, eo);

            Path zip = encOut.resolve("vault.zip");
            assertTrue(Files.exists(zip));

            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "mainpw";
            dop.archivePassword = "archpw"; // 归档密码用于去 AES 层
            dop.rsCodecs = new RsCodecs();
            FolderCrypt.decryptAuto(zip, decOut, dop);

            byte[] r1 = findFile(decOut, "x.txt");
            byte[] r2 = findFile(decOut, "y.txt");
            assertArrayEquals(a, r1);
            assertArrayEquals(b, r2);
        } finally {
            rmrf(tmp);
        }
    }

    private static void encryptOne(Path src, Path out, String pw) throws Exception {
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(src.toString());
        req.setOutputFile(out.toString());
        req.setPassword(pw);
        req.setRsCodecs(new RsCodecs());
        Encryptor.encrypt(req);
    }

    @Test
    void singleFileSplitArchiveRoundtrip() throws Exception {
        Path tmp = Files.createTempDirectory("fc-test3-");
        try {
            byte[] data = rand(5 * 1024 * 1024 + 77);
            Path src = tmp.resolve("movie.bin");
            Files.write(src, data);

            EncryptRequest req = new EncryptRequest();
            req.setInputFile(src.toString());
            // 输出 movie.bin.ergou，分卷时创建 movie.bin_ergou_split/ 文件夹
            // （因为 movie.bin 已作为源文件存在，使用降级名称）
            req.setOutputFile(tmp.resolve("movie.bin.ergou").toString());
            req.setPassword("pw");
            req.setSplit(true);
            req.setChunkSize(2); // 2 MiB
            req.setArchiveFormat("ZIP");
            req.setRsCodecs(new RsCodecs());
            Encryptor.encrypt(req);

            // 归档以分卷文件夹名命名，位于父目录中
            Path archive = tmp.resolve("movie.bin_ergou_split.zip");
            assertTrue(Files.exists(archive), "single file split+zip should produce one zip");

            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            FolderCrypt.decryptAuto(archive, decOut, dop);

            // 解归档后顶层即碎片，重组解密为单文件
            try (Stream<Path> w = Files.walk(decOut)) {
                Path result = w.filter(Files::isRegularFile).findFirst().orElseThrow();
                assertArrayEquals(data, Files.readAllBytes(result));
            }
        } finally {
            rmrf(tmp);
        }
    }
}
