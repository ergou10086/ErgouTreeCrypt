package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 分卷加密 / 解密往返：单文件、文件夹、子目录、压缩包，以及自动识别入口。
 *
 * <p>使用低内存 Argon2 覆写，避免默认 1 GiB 使本套场景无法在合理时间内跑完。
 * 桌面端与 Android 解密均调用 {@link FolderCrypt#decryptAuto}，因此本类同时覆盖两端核心路径。
 *
 * @author ErgouTree
 */
class SplitRoundtripTest {

    private static final String PW = "split-pw-测试";
    private static final int CHUNK_MIB = 1;
    /** 略大于 1 MiB，加密后必产生至少两片。 */
    private static final int BIG = 1024 * 1024 + 4096;
    private static final int SMALL = 777;

    /**
     * 单文件分卷、不压缩：碎片落在同名文件夹，选该文件夹解密还原。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void singleFileSplit_noArchive_decryptChunkFolder() throws Exception {
        Path tmp = Files.createTempDirectory("sp-sf-");
        try {
            byte[] data = rand(BIG);
            Path src = tmp.resolve("src").resolve("movie.bin");
            Files.createDirectories(src.getParent());
            Files.write(src, data);
            Path dest = tmp.resolve("enc").resolve("movie.bin.ergou");
            Files.createDirectories(dest.getParent());
            encryptSingle(src, dest, true, null);

            Path chunkDir = tmp.resolve("enc/movie.bin");
            assertTrue(Files.isDirectory(chunkDir));
            assertTrue(Files.exists(chunkDir.resolve("movie.bin.ergou.0")));
            assertTrue(countChunks(chunkDir) >= 2);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(chunkDir, dec, decryptOpts(false));
            assertArrayEquals(data, Files.readAllBytes(dec.resolve("movie.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 输出路径与源文件同名冲突时，碎片夹降级为 {@code *_ergou_split}。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void singleFileSplit_nameCollisionUsesErgouSplitFolder() throws Exception {
        Path tmp = Files.createTempDirectory("sp-col-");
        try {
            byte[] data = rand(BIG);
            Path src = tmp.resolve("movie.bin");
            Files.write(src, data);
            encryptSingle(src, tmp.resolve("movie.bin.ergou"), true, null);

            Path chunkDir = tmp.resolve("movie.bin_ergou_split");
            assertTrue(Files.isDirectory(chunkDir), "源文件占名时应降级为 *_ergou_split");
            assertTrue(countChunks(chunkDir) >= 2);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(chunkDir, dec, decryptOpts(false));
            assertArrayEquals(data, Files.readAllBytes(dec.resolve("movie.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 小于一卷的文件只产生 {@code .0}，仍可按碎片夹解密。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void singleFileSmallerThanChunk_onlyZero() throws Exception {
        Path tmp = Files.createTempDirectory("sp-tiny-");
        try {
            byte[] data = rand(SMALL);
            Path src = tmp.resolve("note.txt");
            Files.write(src, data);
            Path dest = tmp.resolve("enc").resolve("note.txt.ergou");
            Files.createDirectories(dest.getParent());
            encryptSingle(src, dest, true, null);

            Path chunkDir = dest.getParent().resolve("note.txt");
            assertTrue(Files.isDirectory(chunkDir));
            assertTrue(Files.exists(chunkDir.resolve("note.txt.ergou.0")));
            assertFalse(Files.exists(chunkDir.resolve("note.txt.ergou.1")));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(chunkDir, dec, decryptOpts(false));
            assertArrayEquals(data, Files.readAllBytes(dec.resolve("note.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 单文件分卷后再打 ZIP（压缩永远最后一步）。选压缩包解密应还原。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void singleFileSplitThenZip_decryptArchive() throws Exception {
        Path tmp = Files.createTempDirectory("sp-sfz-");
        try {
            byte[] data = rand(BIG);
            Path src = tmp.resolve("clip.bin");
            Files.write(src, data);
            Path dest = tmp.resolve("enc").resolve("clip.bin.ergou");
            Files.createDirectories(dest.getParent());
            encryptSingle(src, dest, true, "ZIP");

            Path zip = tmp.resolve("enc").resolve("clip.bin.zip");
            assertTrue(Files.exists(zip), "分卷文件夹应被打成 clip.bin.zip");

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.DecryptOptions d = decryptOpts(false);
            FolderCrypt.decryptAuto(zip, dec, d);
            assertArrayEquals(data, findFile(dec, "clip.bin"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 勾选「解压后解密」对「分卷后再压缩」得到的普通 ZIP 无额外影响：
     * 选中压缩包时 {@link FolderCrypt#decryptAuto} 总会先解压再解密碎片。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void singleFileSplitThenZip_autoUnzipFlagDoesNotChangeResult() throws Exception {
        Path tmp = Files.createTempDirectory("sp-sfz-au-");
        try {
            byte[] data = rand(BIG);
            Path src = tmp.resolve("clip.bin");
            Files.write(src, data);
            Path dest = tmp.resolve("enc").resolve("clip.bin.ergou");
            Files.createDirectories(dest.getParent());
            encryptSingle(src, dest, true, "ZIP");
            Path zip = tmp.resolve("enc").resolve("clip.bin.zip");

            Path decOn = tmp.resolve("dec-on");
            Path decOff = tmp.resolve("dec-off");
            Files.createDirectories(decOn);
            Files.createDirectories(decOff);
            FolderCrypt.decryptAuto(zip, decOn, decryptOpts(true));
            FolderCrypt.decryptAuto(zip, decOff, decryptOpts(false));
            assertArrayEquals(data, findFile(decOn, "clip.bin"));
            assertArrayEquals(data, findFile(decOff, "clip.bin"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 选中任意一片（包括非 .0）应合并兄弟碎片后解密。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void decryptByPickingNonZeroChunkFile() throws Exception {
        Path tmp = Files.createTempDirectory("sp-pick1-");
        try {
            byte[] data = rand(BIG);
            Path src = tmp.resolve("v.bin");
            Files.write(src, data);
            Path dest = tmp.resolve("enc").resolve("v.bin.ergou");
            Files.createDirectories(dest.getParent());
            encryptSingle(src, dest, true, null);

            Path chunk1 = tmp.resolve("enc/v.bin/v.bin.ergou.1");
            assertTrue(Files.exists(chunk1));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(chunk1, dec, decryptOpts(false));
            assertArrayEquals(data, Files.readAllBytes(dec.resolve("v.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 文件夹内多个文件分卷、不压缩。选加密结果文件夹解密应还原全部文件。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void folderMultiFileSplit_noArchive() throws Exception {
        Path tmp = Files.createTempDirectory("sp-fm-");
        try {
            Path in = tmp.resolve("docs");
            Files.createDirectories(in);
            byte[] a = rand(BIG);
            byte[] b = rand(SMALL);
            Files.write(in.resolve("a.bin"), a);
            Files.write(in.resolve("b.txt"), b);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.encryptFolder(in, encOut, encryptFolderOpts(true, null));

            Path encFolder = encOut.resolve("docs");
            assertTrue(Files.isDirectory(encFolder.resolve("a.bin")));
            assertTrue(Files.exists(encFolder.resolve("a.bin/a.bin.ergou.0")));
            assertTrue(Files.isDirectory(encFolder.resolve("b.txt")));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(encFolder, dec, decryptOpts(false));
            assertArrayEquals(a, Files.readAllBytes(dec.resolve("docs/a.bin")));
            assertArrayEquals(b, Files.readAllBytes(dec.resolve("docs/b.txt")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 多个文件分卷分别落在不同子文件夹下，解密应镜像还原路径。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void folderSplit_filesInDifferentSubdirs() throws Exception {
        Path tmp = Files.createTempDirectory("sp-sub-");
        try {
            Path in = tmp.resolve("proj");
            Files.createDirectories(in.resolve("alpha"));
            Files.createDirectories(in.resolve("beta"));
            byte[] a = rand(BIG);
            byte[] b = rand(BIG);
            byte[] c = rand(SMALL);
            Files.write(in.resolve("alpha/one.bin"), a);
            Files.write(in.resolve("beta/two.bin"), b);
            Files.write(in.resolve("root.dat"), c);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.encryptFolder(in, encOut, encryptFolderOpts(true, null));

            Path encFolder = encOut.resolve("proj");
            assertTrue(Files.exists(encFolder.resolve("alpha/one.bin/one.bin.ergou.0")));
            assertTrue(Files.exists(encFolder.resolve("beta/two.bin/two.bin.ergou.0")));
            assertTrue(Files.exists(encFolder.resolve("root.dat/root.dat.ergou.0")));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(encFolder, dec, decryptOpts(false));
            Path root = dec.resolve("proj");
            assertArrayEquals(a, Files.readAllBytes(root.resolve("alpha/one.bin")));
            assertArrayEquals(b, Files.readAllBytes(root.resolve("beta/two.bin")));
            assertArrayEquals(c, Files.readAllBytes(root.resolve("root.dat")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 默认加密深度=2 时，二级子目录会被打成 zip 再分卷；不勾选 autoUnzip 时明文仍在 zip 内。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void folderSplit_defaultDepthPacksSecondLevelAsZip() throws Exception {
        Path tmp = Files.createTempDirectory("sp-d2pack-");
        try {
            Path in = tmp.resolve("proj");
            Files.createDirectories(in.resolve("beta/nested"));
            byte[] inner = rand(SMALL);
            Files.write(in.resolve("beta/nested/two.bin"), inner);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.encryptFolder(in, encOut, encryptFolderOpts(true, null));
            Path encFolder = encOut.resolve("proj");
            assertTrue(Files.isDirectory(encFolder.resolve("beta/nested.zip")),
                    "二级目录应成为 nested.zip 分卷夹");
            assertFalse(Files.exists(encFolder.resolve("beta/nested/two.bin/two.bin.ergou.0")));

            Path decNo = tmp.resolve("dec-no");
            Files.createDirectories(decNo);
            FolderCrypt.decryptAuto(encFolder, decNo, decryptOpts(false));
            assertNotNull(findPath(decNo, "nested.zip"), "未勾选解压后解密时应留下明文 zip");
            assertNull(findPath(decNo, "two.bin"));

            Path decYes = tmp.resolve("dec-yes");
            Files.createDirectories(decYes);
            FolderCrypt.decryptAuto(encFolder, decYes, decryptOpts(true));
            assertArrayEquals(inner, findFile(decYes, "two.bin"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 提高加密深度后，深层文件仍按路径分卷，解密镜像还原。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void folderSplit_highDepthPreservesNestedChunkDirs() throws Exception {
        Path tmp = Files.createTempDirectory("sp-d4-");
        try {
            Path in = tmp.resolve("proj");
            Files.createDirectories(in.resolve("beta/nested"));
            byte[] inner = rand(BIG);
            Files.write(in.resolve("beta/nested/two.bin"), inner);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.EncryptOptions eo = encryptFolderOpts(true, null);
            eo.encryptDepth = 4;
            FolderCrypt.encryptFolder(in, encOut, eo);
            Path encFolder = encOut.resolve("proj");
            assertTrue(Files.exists(encFolder.resolve("beta/nested/two.bin/two.bin.ergou.0")));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(encFolder, dec, decryptOpts(false));
            assertArrayEquals(inner, Files.readAllBytes(dec.resolve("proj/beta/nested/two.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 文件夹分卷后再打成一个 ZIP。选压缩包解密（对应 UI「选中压缩包」，不必勾选解压后解密）。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void folderSplitThenZip_decryptArchive() throws Exception {
        Path tmp = Files.createTempDirectory("sp-fz-");
        try {
            Path in = tmp.resolve("src");
            Files.createDirectories(in.resolve("sub"));
            byte[] a = rand(BIG);
            byte[] b = rand(SMALL);
            Files.write(in.resolve("a.bin"), a);
            Files.write(in.resolve("sub/b.bin"), b);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.encryptFolder(in, encOut, encryptFolderOpts(true, "ZIP"));
            Path zip = encOut.resolve("src.zip");
            assertTrue(Files.exists(zip));
            assertFalse(Files.exists(encOut.resolve("src")), "打包后工作目录应删除");

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(zip, dec, decryptOpts(true));
            Path root = dec.resolve("src");
            assertArrayEquals(a, Files.readAllBytes(root.resolve("a.bin")));
            assertArrayEquals(b, Files.readAllBytes(root.resolve("sub/b.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 压缩包内只有一套分卷（单文件加密后压缩）。解压后顶层即碎片。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void zipContainingOnlyOneFilesChunks() throws Exception {
        Path tmp = Files.createTempDirectory("sp-z1-");
        try {
            byte[] data = rand(BIG);
            Path src = tmp.resolve("only.bin");
            Files.write(src, data);
            Path dest = tmp.resolve("pack").resolve("only.bin.ergou");
            Files.createDirectories(dest.getParent());
            encryptSingle(src, dest, true, "ZIP");
            Path zip = tmp.resolve("pack/only.bin.zip");

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(zip, dec, decryptOpts(true));
            assertArrayEquals(data, findFile(dec, "only.bin"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 压缩包内多套分卷且位于不同子目录。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void zipContainingChunksInDifferentSubdirs() throws Exception {
        Path tmp = Files.createTempDirectory("sp-zsub-");
        try {
            Path in = tmp.resolve("tree");
            Files.createDirectories(in.resolve("l"));
            Files.createDirectories(in.resolve("r"));
            byte[] a = rand(BIG);
            byte[] b = rand(BIG);
            Files.write(in.resolve("l/left.bin"), a);
            Files.write(in.resolve("r/right.bin"), b);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.encryptFolder(in, encOut, encryptFolderOpts(true, "ZIP"));
            Path zip = encOut.resolve("tree.zip");

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(zip, dec, decryptOpts(true));
            Path root = dec.resolve("tree");
            assertArrayEquals(a, Files.readAllBytes(root.resolve("l/left.bin")));
            assertArrayEquals(b, Files.readAllBytes(root.resolve("r/right.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 带 ZIP 条目密码的分卷压缩包，需同时提供归档密码。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void folderSplitZipWithArchivePassword() throws Exception {
        Path tmp = Files.createTempDirectory("sp-zpw-");
        try {
            Path in = tmp.resolve("vault");
            Files.createDirectories(in);
            byte[] a = rand(BIG);
            Files.write(in.resolve("secret.bin"), a);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.EncryptOptions eo = encryptFolderOpts(true, "ZIP");
            eo.archivePassword = "arch-pw";
            FolderCrypt.encryptFolder(in, encOut, eo);
            Path zip = encOut.resolve("vault.zip");

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.DecryptOptions d = decryptOpts(true);
            d.archivePassword = "arch-pw";
            FolderCrypt.decryptAuto(zip, dec, d);
            assertArrayEquals(a, findFile(dec, "secret.bin"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 同一文件夹内松散放置多套 {@code .ergou.N}（不在各自子目录里）应分组解密。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void looseChunksOfMultipleFilesInOneFolder() throws Exception {
        Path tmp = Files.createTempDirectory("sp-loose-");
        try {
            byte[] a = rand(BIG);
            byte[] b = rand(BIG);
            Path aSrc = tmp.resolve("a.bin");
            Path bSrc = tmp.resolve("b.bin");
            Files.write(aSrc, a);
            Files.write(bSrc, b);
            Path aEnc = tmp.resolve("stage-a/a.bin.ergou");
            Path bEnc = tmp.resolve("stage-b/b.bin.ergou");
            Files.createDirectories(aEnc.getParent());
            Files.createDirectories(bEnc.getParent());
            encryptSingle(aSrc, aEnc, true, null);
            encryptSingle(bSrc, bEnc, true, null);

            Path mix = tmp.resolve("mix");
            Files.createDirectories(mix);
            copyChunks(tmp.resolve("stage-a/a.bin"), mix);
            copyChunks(tmp.resolve("stage-b/b.bin"), mix);

            assertNull(FolderCrypt.detectChunkBase(mix), "多套 base 不应被当成单文件碎片夹");

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(mix, dec, decryptOpts(false));
            assertArrayEquals(a, findFile(dec, "a.bin"));
            assertArrayEquals(b, findFile(dec, "b.bin"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 文件夹里只有一套松散碎片时，{@link FolderCrypt#detectChunkBase} 命中，输出不包一层文件夹名。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void folderWithOnlyOneLooseChunkSet_detectsAsSingleFile() throws Exception {
        Path tmp = Files.createTempDirectory("sp-one-loose-");
        try {
            byte[] data = rand(BIG);
            Path src = tmp.resolve("solo.bin");
            Files.write(src, data);
            Path dest = tmp.resolve("stage/solo.bin.ergou");
            Files.createDirectories(dest.getParent());
            encryptSingle(src, dest, true, null);

            Path only = tmp.resolve("only");
            Files.createDirectories(only);
            copyChunks(tmp.resolve("stage/solo.bin"), only);
            assertEquals("solo.bin.ergou", FolderCrypt.detectChunkBase(only));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(only, dec, decryptOpts(false));
            assertArrayEquals(data, Files.readAllBytes(dec.resolve("solo.bin")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 未分卷的 .ergou 与分卷文件夹混放，应都能解密。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void mixedUnsplitErgouAndChunkFolder() throws Exception {
        Path tmp = Files.createTempDirectory("sp-mix2-");
        try {
            byte[] plain = rand(SMALL);
            byte[] big = rand(BIG);
            Path p = tmp.resolve("plain.txt");
            Path v = tmp.resolve("video.bin");
            Files.write(p, plain);
            Files.write(v, big);

            Path folder = tmp.resolve("mix");
            Files.createDirectories(folder);
            encryptSingle(p, folder.resolve("plain.txt.ergou"), false, null);
            Path vDest = folder.resolve("video.bin.ergou");
            encryptSingle(v, vDest, true, null);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(folder, dec, decryptOpts(false));
            assertArrayEquals(plain, findFile(dec, "plain.txt"));
            assertArrayEquals(big, findFile(dec, "video.bin"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 缺中间片时解密应失败。
     *
     * @throws Exception 准备失败
     */
    @Test
    void missingMiddleChunk_decryptFails() throws Exception {
        Path tmp = Files.createTempDirectory("sp-gap-");
        try {
            byte[] data = rand(BIG);
            Path src = tmp.resolve("g.bin");
            Files.write(src, data);
            Path dest = tmp.resolve("enc/g.bin.ergou");
            Files.createDirectories(dest.getParent());
            encryptSingle(src, dest, true, null);
            Path mid = tmp.resolve("enc/g.bin/g.bin.ergou.1");
            assertTrue(Files.exists(mid));
            Files.delete(mid);

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            assertThrows(Exception.class,
                    () -> FolderCrypt.decryptAuto(tmp.resolve("enc/g.bin"), dec, decryptOpts(false)));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 深度=1 时子目录打成 zip.ergou 再分卷；勾选 autoUnzip 应展开明文 zip。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void encryptDepth1_split_autoUnzipExtractsDeepZip() throws Exception {
        Path tmp = Files.createTempDirectory("sp-d1-");
        try {
            Path in = tmp.resolve("in");
            Files.createDirectories(in.resolve("sub"));
            byte[] root = rand(SMALL);
            byte[] nested = rand(SMALL);
            Files.write(in.resolve("root.txt"), root);
            Files.write(in.resolve("sub/nested.txt"), nested);

            Path encOut = tmp.resolve("encout");
            Files.createDirectories(encOut);
            FolderCrypt.EncryptOptions eo = encryptFolderOpts(true, null);
            eo.encryptDepth = 1;
            FolderCrypt.encryptFolder(in, encOut, eo);

            Path encFolder = encOut.resolve("in");
            assertTrue(Files.isDirectory(encFolder.resolve("root.txt")));
            assertTrue(Files.isDirectory(encFolder.resolve("sub.zip")),
                    "深目录应加密为 sub.zip 的分卷夹");

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(encFolder, dec, decryptOpts(true));
            assertArrayEquals(root, findFile(dec, "root.txt"));
            assertArrayEquals(nested, findFile(dec, "nested.txt"));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * {@link FolderCrypt#detectChunkBase} 边界：子目录、多 base、缺 .0。
     *
     * @throws Exception 建临时文件失败
     */
    @Test
    void detectChunkBase_edgeCases() throws Exception {
        Path tmp = Files.createTempDirectory("sp-det-");
        try {
            Path empty = tmp.resolve("empty");
            Files.createDirectories(empty);
            assertNull(FolderCrypt.detectChunkBase(empty));

            Path one = tmp.resolve("one");
            Files.createDirectories(one);
            Files.write(one.resolve("x.ergou.0"), new byte[]{1});
            assertEquals("x.ergou", FolderCrypt.detectChunkBase(one));

            Path multi = tmp.resolve("multi");
            Files.createDirectories(multi);
            Files.write(multi.resolve("a.ergou.0"), new byte[]{1});
            Files.write(multi.resolve("b.ergou.0"), new byte[]{1});
            assertNull(FolderCrypt.detectChunkBase(multi));

            Path nested = tmp.resolve("nested");
            Files.createDirectories(nested.resolve("sub"));
            Files.write(nested.resolve("x.ergou.0"), new byte[]{1});
            assertNull(FolderCrypt.detectChunkBase(nested));

            Path noZero = tmp.resolve("nz");
            Files.createDirectories(noZero);
            Files.write(noZero.resolve("x.ergou.1"), new byte[]{1});
            assertNull(FolderCrypt.detectChunkBase(noZero));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 单文件分卷 + 7Z，解密压缩包应还原。
     *
     * @throws Exception 加解密失败
     */
    @Test
    void singleFileSplitThen7z() throws Exception {
        Path tmp = Files.createTempDirectory("sp-7z-");
        try {
            byte[] data = rand(BIG);
            Path src = tmp.resolve("d.bin");
            Files.write(src, data);
            Path dest = tmp.resolve("enc/d.bin.ergou");
            Files.createDirectories(dest.getParent());
            encryptSingle(src, dest, true, "7Z");
            Path archive = tmp.resolve("enc/d.bin.7z");
            assertTrue(Files.exists(archive));

            Path dec = tmp.resolve("dec");
            Files.createDirectories(dec);
            FolderCrypt.decryptAuto(archive, dec, decryptOpts(false));
            assertArrayEquals(data, findFile(dec, "d.bin"));
        } finally {
            rmrf(tmp);
        }
    }

    // ---------------------------------------------------------------- helpers

    /**
     * 写入小内存 Argon2 的单文件加密请求并执行。
     *
     * @param src     明文
     * @param dest    目标 .ergou 路径
     * @param split   是否分卷
     * @param archive 归档格式，null 表示不分卷后压缩
     * @throws Exception 加密失败
     */
    private static void encryptSingle(Path src, Path dest, boolean split, String archive) throws Exception {
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(src.toString());
        req.setOutputFile(dest.toString());
        req.setPassword(PW);
        req.setRsCodecs(new RsCodecs());
        applyFastKdf(req);
        req.setSplit(split);
        if (split) {
            req.setChunkSize(CHUNK_MIB);
        }
        if (archive != null) {
            req.setArchiveFormat(archive);
        }
        Encryptor.encrypt(req);
    }

    /**
     * 构造文件夹加密选项（小内存 KDF + 可选分卷/压缩）。
     *
     * @param split   是否分卷
     * @param archive 归档格式
     * @return 选项
     */
    private static FolderCrypt.EncryptOptions encryptFolderOpts(boolean split, String archive) {
        FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
        eo.password = PW;
        eo.rsCodecs = new RsCodecs();
        eo.split = split;
        eo.chunkSize = CHUNK_MIB;
        eo.archiveFormat = archive;
        eo.threadCount = 1;
        applyFastKdf(eo);
        return eo;
    }

    /**
     * 构造解密选项。
     *
     * @param autoUnzip 是否解密后自动解压新出现的归档（深目录 zip.ergou）
     * @return 选项
     */
    private static FolderCrypt.DecryptOptions decryptOpts(boolean autoUnzip) {
        FolderCrypt.DecryptOptions d = new FolderCrypt.DecryptOptions();
        d.password = PW;
        d.rsCodecs = new RsCodecs();
        d.autoUnzip = autoUnzip;
        d.threadCount = 1;
        return d;
    }

    /**
     * 为单文件请求写入测试用低内存 Argon2 参数。
     *
     * @param req 加密请求
     */
    private static void applyFastKdf(EncryptRequest req) {
        req.setArgon2MemoryKib(32);
        req.setArgon2Passes(1);
        req.setArgon2Threads(1);
    }

    /**
     * 为文件夹加密写入测试用低内存 Argon2 参数。
     *
     * @param opts 加密选项
     */
    private static void applyFastKdf(FolderCrypt.EncryptOptions opts) {
        opts.argon2MemoryKib = 32;
        opts.argon2Passes = 1;
        opts.argon2Threads = 1;
    }

    /**
     * 生成可复现的随机字节。
     *
     * @param n 长度
     * @return 数据
     */
    private static byte[] rand(int n) {
        byte[] b = new byte[n];
        new java.util.Random(n).nextBytes(b);
        return b;
    }

    /**
     * 统计目录中分卷碎片数量。
     *
     * @param dir 目录
     * @return 碎片数
     * @throws Exception 列举失败
     */
    private static long countChunks(Path dir) throws Exception {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> Splitter.isSplitChunkPath(p.toString())).count();
        }
    }

    /**
     * 将某碎片夹内的 {@code .ergou.N} 复制到目标目录（扁平）。
     *
     * @param chunkDir 源碎片夹
     * @param dest     目标目录
     * @throws Exception 复制失败
     */
    private static void copyChunks(Path chunkDir, Path dest) throws Exception {
        try (Stream<Path> s = Files.list(chunkDir)) {
            for (Path p : s.filter(Files::isRegularFile).toList()) {
                Files.copy(p, dest.resolve(p.getFileName()));
            }
        }
    }

    /**
     * 在树中按文件名查找第一个常规文件并读出。
     *
     * @param root 根
     * @param name 文件名
     * @return 内容
     * @throws Exception 未找到或读取失败
     */
    private static byte[] findFile(Path root, String name) throws Exception {
        try (Stream<Path> w = Files.walk(root)) {
            Path p = w.filter(Files::isRegularFile)
                    .filter(x -> x.getFileName().toString().equals(name))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("not found: " + name));
            return Files.readAllBytes(p);
        }
    }

    /**
     * 按文件名查找路径，找不到返回 null。
     *
     * @param root 根
     * @param name 文件名
     * @return 路径或 null
     * @throws Exception 列举失败
     */
    private static Path findPath(Path root, String name) throws Exception {
        try (Stream<Path> w = Files.walk(root)) {
            return w.filter(Files::isRegularFile)
                    .filter(x -> x.getFileName().toString().equals(name))
                    .findFirst()
                    .orElse(null);
        }
    }

    /**
     * 递归删除。
     *
     * @param dir 目录
     * @throws Exception 列举失败
     */
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
