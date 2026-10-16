package hbnu.project.ergoutreecrypt.keyfile;

import hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

/** 不依赖设备的密钥文件目录、损坏及强制解密回归。 */
public class KeyfileBatchLocalTest {
    @TempDir Path root;

    /**
     * 目录深度、串并行和有无顺序要求应保留路径和内容。
     * @throws Exception 测试失败
     */
    @Test void directoryMatrix() throws Exception {
        byte[] bytes = new byte[8193]; new java.util.Random(63).nextBytes(bytes);
        Path source = Files.write(root.resolve("source"), bytes), corpus = root.resolve("corpus");
        KeyfileInteropSupport.prepare(source, corpus);
        assertEquals(12, KeyfileBatchInteropSupport.produce(corpus, root.resolve("ciphers"), false, false));
        assertEquals(12, KeyfileBatchInteropSupport.verify(corpus, root.resolve("ciphers"), root.resolve("scratch")));
    }

    /**
     * 覆盖 RS 恢复、认证拒绝、强制解密、缺卷和只读源目录。
     * @throws Exception 测试失败
     */
    @Test void corruptionAndForcePolicies() throws Exception {
        SplitInteropSupport.corruptionRegression(root.resolve("corruption"));
        SplitInteropSupport.advancedOptionsRegression(root.resolve("force"));
        SplitInteropSupport.readOnlySourceRegression(root.resolve("readonly"));
    }
}
