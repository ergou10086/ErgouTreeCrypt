package hbnu.project.ergoutreecrypt.volume;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** 桌面使用新硬链接，ART 使用内核 RENAME_NOREPLACE；两者均不能替换已有目标。 */
final class FastNativeCommit {
    /** 禁止实例化工具类。 */
    private FastNativeCommit() {}

    /**
     * 原子发布已 force 的同目录私有文件，平台不支持时失败关闭。
     *
     * @param temporary 本任务拥有的完整文件
     * @param destination 尚不存在的最终名称
     * @throws IOException 不支持、目标冲突或 I/O 失败
     */
    static void publish(Path temporary, Path destination) throws IOException {
        if (!"Dalvik".equals(System.getProperty("java.vm.name"))) {
            Files.createLink(destination, temporary);
            return;
        }
        try {
            System.loadLibrary("ergou_argon2");
            int result = renameNoReplace(utf8Path(temporary), utf8Path(destination));
            if (result == -1) throw new FileAlreadyExistsException(destination.toString());
            if (result != 0) throw new IOException("FAST 原子提交失败，errno=" + result);
        } catch (LinkageError failure) {
            throw new IOException("FAST 原子提交原生桥不可用", failure);
        }
    }

    /**
     * 用标准 UTF-8 传给原生文件系统，避免 JNI 修改版 UTF-8 损坏补充平面字符。
     *
     * @param path 真实绝对路径
     * @return 以零结尾的 UTF-8 路径
     */
    private static byte[] utf8Path(Path path) {
        byte[] bytes = path.toString().getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(bytes, bytes.length + 1);
    }

    /**
     * 执行 Linux renameat2，绝不降级为会替换目标的 rename。
     *
     * @param source 零结尾的 UTF-8 源路径
     * @param target 零结尾的 UTF-8 目标路径
     * @return 成功为零，目标存在为负一，其他失败为 errno
     */
    private static native int renameNoReplace(byte[] source, byte[] target);
}
