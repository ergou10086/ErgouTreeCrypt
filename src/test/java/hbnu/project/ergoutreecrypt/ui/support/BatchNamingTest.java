package hbnu.project.ergoutreecrypt.ui.support;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 多文件批处理的输出目录 / 批名推导测试。
 *
 * <p>这两条规则决定用户看到的最终产物位置与名字（{@code 输出目录/批名/} 或
 * {@code 输出目录/批名.扩展名}），属于多文件功能最直观的对外契约。
 * 不启动 JavaFX 工具包，因此可在常规 Maven 与 CI 环境稳定运行。
 *
 * @author ErgouTree
 */
final class BatchNamingTest {

    /**
     * 同一目录下的多个文件：输出目录取该目录本身，批名取该目录名。
     */
    @Test
    void sameDirectoryUsesThatDirectoryName(@TempDir Path tempDir) throws IOException {
        Path album = Files.createDirectories(tempDir.resolve("album"));
        List<File> files = List.of(
                Files.write(album.resolve("1.mp3"), new byte[]{1}).toFile(),
                Files.write(album.resolve("2.mp3"), new byte[]{2}).toFile(),
                Files.write(album.resolve("3.mp3"), new byte[]{3}).toFile());

        assertEquals(album.toFile().getAbsolutePath(), MainViewSupport.batchOutputDir(files));
        assertEquals("album", MainViewSupport.batchName(files));
    }

    /**
     * 跨目录的多个文件：退化到首个文件所在目录，批名随之变化。
     */
    @Test
    void differentDirectoriesFallBackToFirstParent(@TempDir Path tempDir) throws IOException {
        Path a = Files.createDirectories(tempDir.resolve("a"));
        Path b = Files.createDirectories(tempDir.resolve("b"));
        File first = Files.write(a.resolve("x.bin"), new byte[]{1}).toFile();
        File second = Files.write(b.resolve("y.bin"), new byte[]{2}).toFile();

        assertEquals(a.toFile().getAbsolutePath(), MainViewSupport.batchOutputDir(List.of(first, second)));
        assertEquals("a", MainViewSupport.batchName(List.of(first, second)));
    }

    /**
     * 只有选一个文件时同样按上述规则推导，保证单文件与多文件行为一致。
     */
    @Test
    void singleFileYieldsItsParentDirectory(@TempDir Path tempDir) throws IOException {
        Path docs = Files.createDirectories(tempDir.resolve("docs"));
        File one = Files.write(docs.resolve("f.txt"), new byte[]{1}).toFile();

        assertEquals(docs.toFile().getAbsolutePath(), MainViewSupport.batchOutputDir(List.of(one)));
        assertEquals("docs", MainViewSupport.batchName(List.of(one)));
    }

    /**
     * 空列表必须给出空目录与兜底批名，不能抛异常。
     */
    @Test
    void emptyListIsSafe() {
        assertEquals("", MainViewSupport.batchOutputDir(List.of()));
        assertEquals("", MainViewSupport.batchOutputDir(null));
        assertEquals("files", MainViewSupport.batchName(List.of()));
        assertEquals("files", MainViewSupport.batchName(null));
    }

    /**
     * 目录名不可用（盘符根目录）时批名回退为 {@code files}，产物名恒非空。
     */
    @Test
    void rootDirectoryNameFallsBackToDefault() {
        File[] roots = File.listRoots();
        org.junit.jupiter.api.Assumptions.assumeTrue(roots.length > 0,
                "运行环境没有可见的根目录，跳过");
        File root = new File(roots[0].getAbsolutePath());
        String dir = MainViewSupport.batchOutputDir(List.of(new File(root, "x.bin")));
        assertFalse(dir.isEmpty(), "根目录下的文件也应能推出输出目录");
        assertEquals("files", MainViewSupport.batchName(List.of(new File(root, "x.bin"))));
    }
}
