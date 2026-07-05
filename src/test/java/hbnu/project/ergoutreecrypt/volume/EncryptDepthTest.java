package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 迭代加密深度功能的往返测试。
 *
 * @author ErgouTree
 */
class EncryptDepthTest {

    private static byte[] rand(int n) {
        byte[] b = new byte[n];
        new java.util.Random(n).nextBytes(b);
        return b;
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

    /**
     * 创建三层目录结构：
     * <pre>
     * in/
     *   f0.txt          (depth 1)
     *   sub1/            (depth 1)
     *     f1.txt         (depth 2)
     *     sub2/           (depth 2)
     *       f2.txt        (depth 3)
     *       sub3/          (depth 3)
     *         f3.txt       (depth 4)
     * </pre>
     */
    private static Path createDeepTree(Path tmp) throws Exception {
        Path in = tmp.resolve("in");
        Files.createDirectories(in.resolve("sub1/sub2/sub3"));
        Files.write(in.resolve("f0.txt"), rand(100));
        Files.write(in.resolve("sub1/f1.txt"), rand(200));
        Files.write(in.resolve("sub1/sub2/f2.txt"), rand(300));
        Files.write(in.resolve("sub1/sub2/sub3/f3.txt"), rand(400));
        return in;
    }

    // ================================================================
    // Depth 2 (default): 深度 1-2 逐一加密，深度 3+ 整体打包加密
    // ================================================================

    /**
     * 深度=2 加密 + 不压缩输出：深度内文件为独立 .ergou，深目录为 .ergou 归档。
     */
    @Test
    void depth2NoArchive() throws Exception {
        Path tmp = Files.createTempDirectory("ed-d2-");
        try {
            Path in = createDeepTree(tmp);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);

            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "pw";
            eo.rsCodecs = new RsCodecs();
            eo.encryptDepth = 2;
            FolderCrypt.encryptFolder(in, encOut, eo);

            Path work = encOut.resolve("in");
            // depth 1-2 文件独立加密：
            assertTrue(Files.exists(work.resolve("f0.txt.ergou")), "root file f0.txt→.ergou");
            assertTrue(Files.exists(work.resolve("sub1/f1.txt.ergou")), "depth-2 file f1.txt→.ergou");

            // depth >= 2 的目录整体打包加密为 .zip.ergou：
            assertTrue(Files.exists(work.resolve("sub1/sub2.zip.ergou")),
                    "sub2 (depth=2) should be archived+encrypted as .zip.ergou");

            // 深目录内的文件不应出现独立 .ergou
            assertFalse(Files.exists(work.resolve("sub1/sub2/f2.txt.ergou")),
                    "f2.txt inside archived dir should NOT have individual .ergou");
            assertFalse(Files.exists(work.resolve("sub1/sub2/sub3")),
                    "sub3 (depth=3) should be inside sub2 archive");

            // 解密验证
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            dop.autoUnzip = true; // 自动解压解密后新出现的归档
            // 解密工作目录
            FolderCrypt.decryptAuto(work, decOut, dop);

            // 整体加密的 f0.txt 和 f1.txt 应恢复
            byte[] r0 = findFile(decOut, "f0.txt");
            byte[] r1 = findFile(decOut, "f1.txt");
            assertArrayEquals(rand(100), r0);
            assertArrayEquals(rand(200), r1);

            // 深目录 sub2.zip.ergou 解密后是 archive → 内部文件也被还原
            byte[] r2 = findFile(decOut, "f2.txt");
            byte[] r3 = findFile(decOut, "f3.txt");
            assertArrayEquals(rand(300), r2);
            assertArrayEquals(rand(400), r3);
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 深度=2 加密 + 输出为 ZIP：全部结果打成一个压缩包。
     */
    @Test
    void depth2WithArchive() throws Exception {
        Path tmp = Files.createTempDirectory("ed-d2a-");
        try {
            Path in = createDeepTree(tmp);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);

            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "pw";
            eo.rsCodecs = new RsCodecs();
            eo.encryptDepth = 2;
            eo.archiveFormat = "ZIP";
            FolderCrypt.encryptFolder(in, encOut, eo);

            Path zip = encOut.resolve("in.zip");
            assertTrue(Files.exists(zip), "should produce output archive");

            // 解密压缩包
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            dop.autoUnzip = true;
            FolderCrypt.decryptAuto(zip, decOut, dop);

            byte[] r0 = findFile(decOut, "f0.txt");
            byte[] r1 = findFile(decOut, "f1.txt");
            byte[] r2 = findFile(decOut, "f2.txt");
            byte[] r3 = findFile(decOut, "f3.txt");
            assertArrayEquals(rand(100), r0);
            assertArrayEquals(rand(200), r1);
            assertArrayEquals(rand(300), r2);
            assertArrayEquals(rand(400), r3);
        } finally {
            rmrf(tmp);
        }
    }

    // ================================================================
    // Depth 1: 仅根目录文件逐一加密，所有子目录整体打包加密
    // ================================================================

    @Test
    void depth1EncryptsRootOnly() throws Exception {
        Path tmp = Files.createTempDirectory("ed-d1-");
        try {
            Path in = createDeepTree(tmp);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);

            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "pw";
            eo.rsCodecs = new RsCodecs();
            eo.encryptDepth = 1; // 仅加密根目录的直接文件
            FolderCrypt.encryptFolder(in, encOut, eo);

            Path work = encOut.resolve("in");
            // 根文件加密
            assertTrue(Files.exists(work.resolve("f0.txt.ergou")));
            // 子目录整体打包加密为 .zip.ergou
            assertTrue(Files.exists(work.resolve("sub1.zip.ergou")),
                    "sub1 (depth=1) should be archived+encrypted as .zip.ergou");
            // 子目录内不应有独立 .ergou
            assertFalse(Files.isDirectory(work.resolve("sub1")),
                    "sub1 should not appear as directory when depth=1");

            // 解密验证
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            dop.autoUnzip = true;
            FolderCrypt.decryptAuto(work, decOut, dop);

            assertArrayEquals(rand(100), findFile(decOut, "f0.txt"));
            assertArrayEquals(rand(200), findFile(decOut, "f1.txt"));
            assertArrayEquals(rand(300), findFile(decOut, "f2.txt"));
            assertArrayEquals(rand(400), findFile(decOut, "f3.txt"));
        } finally {
            rmrf(tmp);
        }
    }

    // ================================================================
    // Depth 3: 正常递归三层
    // ================================================================

    @Test
    void depth3EncryptsThreeLevels() throws Exception {
        Path tmp = Files.createTempDirectory("ed-d3-");
        try {
            Path in = createDeepTree(tmp);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);

            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "pw";
            eo.rsCodecs = new RsCodecs();
            eo.encryptDepth = 3;
            FolderCrypt.encryptFolder(in, encOut, eo);

            Path work = encOut.resolve("in");
            // depth 1-3 独立加密
            assertTrue(Files.exists(work.resolve("f0.txt.ergou")));
            assertTrue(Files.exists(work.resolve("sub1/f1.txt.ergou")));
            assertTrue(Files.exists(work.resolve("sub1/sub2/f2.txt.ergou")));
            // sub3 在 depth 3 >= 3 → 深目录 → 打包加密
            assertTrue(Files.exists(work.resolve("sub1/sub2/sub3.zip.ergou")),
                    "sub3 (depth=3) should be archived+encrypted as .zip.ergou");

            // 解密验证
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            dop.autoUnzip = true;
            FolderCrypt.decryptAuto(work, decOut, dop);

            assertArrayEquals(rand(100), findFile(decOut, "f0.txt"));
            assertArrayEquals(rand(200), findFile(decOut, "f1.txt"));
            assertArrayEquals(rand(300), findFile(decOut, "f2.txt"));
            assertArrayEquals(rand(400), findFile(decOut, "f3.txt"));
        } finally {
            rmrf(tmp);
        }
    }

    // ================================================================
    // 空目录处理
    // ================================================================

    @Test
    void emptyDirectoryIsSkipped() throws Exception {
        Path tmp = Files.createTempDirectory("ed-empty-");
        try {
            Path in = tmp.resolve("in");
            Files.createDirectories(in.resolve("sub1"));
            Files.createDirectories(in.resolve("sub1/emptyDir")); // 空目录
            Files.write(in.resolve("f0.txt"), rand(50));
            Files.write(in.resolve("sub1/f1.txt"), rand(60));

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);

            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "pw";
            eo.rsCodecs = new RsCodecs();
            eo.encryptDepth = 1;
            FolderCrypt.encryptFolder(in, encOut, eo);

            Path work = encOut.resolve("in");
            assertTrue(Files.exists(work.resolve("f0.txt.ergou")));
            // sub1 非空 → 打包加密为 .zip.ergou（空子目录被跳过）
            assertTrue(Files.exists(work.resolve("sub1.zip.ergou")));

            // 解密验证
            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw";
            dop.rsCodecs = new RsCodecs();
            dop.autoUnzip = true;
            FolderCrypt.decryptAuto(work, decOut, dop);

            assertArrayEquals(rand(50), findFile(decOut, "f0.txt"));
            assertArrayEquals(rand(60), findFile(decOut, "f1.txt"));
        } finally {
            rmrf(tmp);
        }
    }

    // ================================================================
    // Helper
    // ================================================================

    private static byte[] findFile(Path root, String name) throws Exception {
        try (Stream<Path> w = Files.walk(root)) {
            Path p = w.filter(Files::isRegularFile)
                    .filter(x -> x.getFileName().toString().equals(name))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("not found: " + name));
            return Files.readAllBytes(p);
        }
    }
}
