package hbnu.project.ergoutreecrypt.volume;

import java.nio.file.Files;
import java.nio.file.Path;

/** 通过发行包捆绑 JVM 直接运行互通助手，不依赖 JUnit 运行时。 */
public final class FastInteropCli {
    /** 禁止实例化入口类。 */
    private FastInteropCli() {}

    /**
     * 分派发行 JVM 的语料生产或读取校验。
     * @param args generate/verify、语料目录、源文件或本端密文目录
     * @throws Exception 任一校验失败
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("generate/verify corpus source/ciphers");
        Path corpus = Path.of(args[1]);
        if (args[0].equals("generate")) {
            FastInteropSupport.generate(Path.of(args[2]), corpus);
            FastInteropSupport.verify(corpus, corpus.resolve("ciphers"), Files.createDirectory(corpus.resolve("scratch")));
        } else if (args[0].equals("verify")) {
            FastInteropSupport.verify(corpus, Path.of(args[2]), corpus.resolve("scratch"));
        } else throw new IllegalArgumentException(args[0]);
        System.out.println("PASS bundled JVM " + args[0] + " " + System.getProperty("java.runtime.version"));
    }
}
