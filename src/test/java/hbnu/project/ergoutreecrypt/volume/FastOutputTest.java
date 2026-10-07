package hbnu.project.ergoutreecrypt.volume;

import static hbnu.project.ergoutreecrypt.volume.FastVolumeRoundtripTest.*;

import static org.junit.jupiter.api.Assertions.*;

import hbnu.project.ergoutreecrypt.exception.CancelledException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;

/** 输出权限、提交竞争、取消及任务失败的文件保护回归。 */
final class FastOutputTest {
    /**
     * @param directory 独占测试目录
     * @throws Exception 权限或提交行为不满足契约
     */
    @Test
    void privatePermissionsAndCommitRaceAreSafe(@TempDir Path directory) throws Exception {
        Path target = directory.resolve("target");
        try (var stage = FastOutput.create(target)) {
            if (Files.getFileAttributeView(stage.path(), PosixFileAttributeView.class) != null) {
                assertEquals(
                        PosixFilePermissions.fromString("rw-------"),
                        Files.getPosixFilePermissions(stage.path()));
            } else {
                var acl = Files.getFileAttributeView(stage.path(), AclFileAttributeView.class);
                assertNotNull(acl);
                assertFalse(acl.getAcl().isEmpty());
                assertTrue(
                        acl.getAcl().stream()
                                .allMatch(entry -> entry.principal().equals(aclOwner(acl))));
            }
            Files.writeString(stage.path(), "本任务完整内容");
            Files.writeString(target, "竞争窗口内创建的用户文件");
            assertThrows(FileAlreadyExistsException.class, stage::commit);
        }
        assertEquals("竞争窗口内创建的用户文件", Files.readString(target));
        assertEquals(java.util.List.of("target"), entries(directory));
    }

    /**
     * 在断言中读取 ACL 所有者。
     *
     * @param view 权限视图
     * @return 文件所有者
     */
    private static java.nio.file.attribute.UserPrincipal aclOwner(AclFileAttributeView view) {
        try {
            return view.getOwner();
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * @param directory 独占测试目录
     * @throws Exception 取消或保护行为失败
     */
    @Test
    void cancellationAndCallbackFailureLeaveNoPartialOutput(@TempDir Path directory)
            throws Exception {
        Path input = directory.resolve("input"), cipher = directory.resolve("cipher");
        byte[] data = new byte[3 * (1 << 20)];
        new java.util.Random(44).nextBytes(data);
        Files.write(input, data);
        Encryptor.encrypt(encryption(input, cipher, "密码"));
        Path output = directory.resolve("output"),
                sentinel = directory.resolve("output.incomplete");
        Files.writeString(sentinel, "用户已有文件");
        var before = entries(directory);
        var cancelled = decryption(cipher, output, "密码");
        cancelled.setReporter(new FailingProgress(false));
        assertThrows(CancelledException.class, () -> Decryptor.decrypt(cancelled));
        assertEquals(before, entries(directory));
        var failure = decryption(cipher, output, "密码");
        failure.setReporter(new FailingProgress(true));
        assertThrows(IllegalStateException.class, () -> Decryptor.decrypt(failure));
        assertEquals(before, entries(directory));
        var encode = encryption(input, output, "密码");
        encode.setReporter(new FailingProgress(false));
        assertThrows(CancelledException.class, () -> Encryptor.encrypt(encode));
        assertEquals(before, entries(directory));
        var auth = verification(cipher, "密码");
        auth.setReporter(new FailingProgress(false));
        assertThrows(CancelledException.class, () -> Verifier.verify(auth));
        assertEquals(before, entries(directory));
        assertArrayEquals(data, Files.readAllBytes(input));
        assertEquals("用户已有文件", Files.readString(sentinel));
        Files.writeString(output, "已有输出");
        assertThrows(
                FileAlreadyExistsException.class,
                () -> Decryptor.decrypt(decryption(cipher, output, "密码")));
        assertThrows(
                FileAlreadyExistsException.class,
                () -> Encryptor.encrypt(encryption(input, output, "密码")));
        assertThrows(
                FileAlreadyExistsException.class,
                () -> Encryptor.encrypt(encryption(input, input, "密码")));
        assertEquals("已有输出", Files.readString(output));
        assertArrayEquals(data, Files.readAllBytes(input));
    }

    /** 通过真实进度回调触发取消或故障。 */
    private static final class FailingProgress implements ProgressReporter {
        private final boolean throwing;
        private boolean cancelled;

        /** @param throwing 是否抛出回调异常 */
        FailingProgress(boolean throwing) {
            this.throwing = throwing;
        }

        /** @param text 状态 */
        @Override
        public void setStatus(String text) {}

        /**
         * @param fraction 进度
         * @param info 附加文本
         */
        @Override
        public void setProgress(float fraction, String info) {
            if (throwing) throw new IllegalStateException("模拟回调故障");
            cancelled = true;
        }

        /** @param can 是否允许取消 */
        @Override
        public void setCanCancel(boolean can) {}

        /** @return 是否取消 */
        @Override
        public boolean isCancelled() {
            return cancelled;
        }
    }
}
