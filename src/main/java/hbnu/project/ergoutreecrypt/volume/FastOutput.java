package hbnu.project.ergoutreecrypt.volume;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.List;

/** 本任务私有的同目录临时文件；安全提交只创建新名称，绝不替换已有目标。 */
final class FastOutput implements AutoCloseable {
    private final Path temporary;
    private final Path destination;

    /**
     * 接管已限制权限的文件。
     *
     * @param temporary 本任务拥有的临时文件
     * @param destination 最终输出，为空时仅作中间文件
     */
    private FastOutput(Path temporary, Path destination) {
        this.temporary = temporary;
        this.destination = destination;
    }

    /**
     * 检查输出不存在并在其真实父目录创建私有临时文件。
     *
     * @param output 最终路径
     * @return 本任务独占的输出句柄
     * @throws IOException 路径非法、目标已存在或权限不满足
     */
    static FastOutput create(Path output) throws IOException {
        Path absolute = output.toAbsolutePath().normalize();
        if (absolute.getFileName() == null || absolute.getParent() == null)
            throw new IOException("FAST 输出路径非法");
        Path destination = absolute.getParent().toRealPath().resolve(absolute.getFileName());
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS))
            throw new FileAlreadyExistsException(destination.toString());
        return createPrivate(destination.getParent(), destination);
    }

    /**
     * 创建仅在本任务内使用的私有中间文件。
     *
     * @param directory 输出所在目录
     * @return 未绑定最终名称的文件句柄
     * @throws IOException 创建失败
     */
    static FastOutput temporary(Path directory) throws IOException {
        return createPrivate(directory.toRealPath(), null);
    }

    /**
     * 在写入任何内容之前限制权限，不能提供私有权限时直接失败。
     *
     * @param directory 已存在的真实目录
     * @param destination 最终路径，可为空
     * @return 私有文件句柄
     * @throws IOException 创建或设置权限失败
     */
    private static FastOutput createPrivate(Path directory, Path destination) throws IOException {
        boolean posix = Files.getFileAttributeView(directory, PosixFileAttributeView.class) != null;
        Path temporary =
                posix
                        ? Files.createTempFile(
                                directory,
                                ".ergou-fast-",
                                ".part",
                                PosixFilePermissions.asFileAttribute(
                                        PosixFilePermissions.fromString("rw-------")))
                        : Files.createTempFile(directory, ".ergou-fast-", ".part");
        try {
            if (!posix) {
                var view = Files.getFileAttributeView(temporary, AclFileAttributeView.class);
                if (view == null) throw new IOException("文件系统不能提供 FAST 私有临时文件权限");
                AclEntry owner =
                        AclEntry.newBuilder()
                                .setType(AclEntryType.ALLOW)
                                .setPrincipal(view.getOwner())
                                .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                                .build();
                view.setAcl(List.of(owner));
            }
            return new FastOutput(temporary, destination);
        } catch (IOException | RuntimeException failure) {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw failure;
        }
    }

    /** @return 本任务临时文件路径，仅供核心内部使用 */
    Path path() {
        return temporary;
    }

    /**
     * 完整内容先 force，再执行平台原子且不覆盖提交；目标在竞争窗口出现时也必须失败。
     *
     * @throws IOException 提交失败，已有输出不会被替换
     */
    void commit() throws IOException {
        if (destination == null) throw new IllegalStateException("中间文件不能提交");
        try (var channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
        FastNativeCommit.publish(temporary, destination);
    }

    /**
     * 只删除本对象创建的临时名称，已提交的最终名称不受影响。
     *
     * @throws IOException 清理失败
     */
    @Override
    public void close() throws IOException {
        Files.deleteIfExists(temporary);
    }
}
