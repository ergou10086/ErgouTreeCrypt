package hbnu.project.ergoutreecrypt.volume;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.file.Files;
import java.nio.file.Path;

/** 由可复用脚本显式启用的真实 JVM／ART 搬运入口，普通单元测试不创建大语料。 */
final class FastInteropTest {
    /** @throws Exception 生成、认证或解密失败 */
    @Test
    @EnabledIfSystemProperty(named = "fast.interop.generate", matches = "true")
    void desktopProducerAndReader() throws Exception {
        Path root = Path.of(System.getProperty("fast.interop.root"));
        FastInteropSupport.generate(Path.of(System.getProperty("fast.interop.source")), root);
        FastInteropSupport.verify(
                root, root.resolve("ciphers"), Files.createDirectory(root.resolve("scratch")));
    }

    /** @throws Exception Android 产物认证或解密失败 */
    @Test
    @EnabledIfSystemProperty(named = "fast.interop.android", matches = "true")
    void desktopReadsAndroid() throws Exception {
        Path root = Path.of(System.getProperty("fast.interop.root"));
        FastInteropSupport.verify(
                root, Path.of(System.getProperty("fast.interop.ciphers")), root.resolve("scratch"));
    }
}
