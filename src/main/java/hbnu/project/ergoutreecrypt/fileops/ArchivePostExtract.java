package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.log.LogService;
import hbnu.project.ergoutreecrypt.volume.ProgressPhase;
import hbnu.project.ergoutreecrypt.volume.ProgressReporter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * 解密后解压：把明文归档解压到与压缩包同名的文件夹，保留内部目录结构，并保留原压缩包。
 *
 * <p>与「解压后解密」（先解压明文压缩包再解密内部 {@code .ergou}）完全独立：
 * 本类<strong>不解密</strong>解压出来的加密文件，只处理明文归档。
 *
 * <p>嵌套明文归档的处理深度：默认 {@link #DEFAULT_MAX_DEPTH} 层；
 * 勾选递归时最多 {@link #RECURSIVE_MAX_DEPTH} 层。
 *
 * @author ErgouTree
 */
public final class ArchivePostExtract {

    /**
     * 未勾选「递归解压嵌套压缩包」时的最大处理层数（最外层为第 0 层）。
     */
    public static final int DEFAULT_MAX_DEPTH = 2;

    /**
     * 勾选「递归解压嵌套压缩包」时的最大处理层数。
     */
    public static final int RECURSIVE_MAX_DEPTH = 5;

    /**
     * 归档密码重试上限：连续输入错误密码达到该次数后放弃解压该归档。
     */
    private static final int MAX_PASSWORD_ATTEMPTS = 3;

    private ArchivePostExtract() {
    }

    /**
     * 根据是否勾选递归解压返回最大处理层数。
     *
     * @param recursiveExtract 是否勾选递归解压嵌套压缩包
     * @return {@link #RECURSIVE_MAX_DEPTH} 或 {@link #DEFAULT_MAX_DEPTH}
     */
    public static int maxDepth(boolean recursiveExtract) {
        return recursiveExtract ? RECURSIVE_MAX_DEPTH : DEFAULT_MAX_DEPTH;
    }

    /**
     * 由归档文件名得到同名文件夹名（去掉归档扩展名）。
     *
     * <p>例如 {@code photos.zip} → {@code photos}，{@code a.tar.gz} → {@code a}。
     *
     * @param archive 归档路径
     * @return 不含归档扩展名的文件夹名；无法剥离时返回原文件名
     */
    public static String folderNameFor(Path archive) {
        if (archive == null) {
            return "extracted";
        }
        String name = archive.getFileName().toString();
        String lower = name.toLowerCase();
        if (lower.endsWith(".tar.gz")) {
            return name.substring(0, name.length() - ".tar.gz".length());
        }
        if (lower.endsWith(".tgz")) {
            return name.substring(0, name.length() - ".tgz".length());
        }
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            return name.substring(0, dot);
        }
        return name;
    }

    /**
     * 若 {@code decryptedFile} 是明文归档，则解压到同名文件夹（保留压缩包）。
     *
     * <p>非归档文件直接返回。供单文件解密路径在 {@code Decryptor.decrypt} 之后调用。
     *
     * @param decryptedFile 解密得到的文件
     * @param maxDepth      最大嵌套层数
     * @param reporter      进度回调，可为 null
     * @throws Exception 解压失败或用户取消
     */
    public static void extractIfArchive(Path decryptedFile, int maxDepth,
                                        ProgressReporter reporter) throws Exception {
        extractIfArchive(decryptedFile, 0, maxDepth, reporter, null, null);
    }

    /**
     * 若 {@code decryptedFile} 是明文归档，则解压到同名文件夹。
     *
     * <p>带密码归档且提供了密码提供者时，通过提供者获取密码并解压；
     * 用户放弃输入时跳过该归档并保留原文件。
     *
     * @param decryptedFile     解密得到的文件
     * @param maxDepth          最大嵌套层数
     * @param reporter          进度回调，可为 null
     * @param passwordProvider  归档密码提供者（弹窗），可为 null
     * @throws Exception 解压失败或用户取消
     */
    public static void extractIfArchive(Path decryptedFile, int maxDepth,
                                        ProgressReporter reporter,
                                        ArchivePasswordProvider passwordProvider) throws Exception {
        extractIfArchive(decryptedFile, 0, maxDepth, reporter, null, passwordProvider);
    }

    /**
     * 若 {@code decryptedFile} 是明文归档，则解压到同名文件夹。
     *
     * @param decryptedFile 解密得到的文件
     * @param depth         当前层数（最外层为 0）
     * @param maxDepth      最大嵌套层数
     * @param reporter      进度回调，可为 null
     * @param listener      结果回调，可为 null
     * @throws Exception 解压失败或用户取消
     */
    public static void extractIfArchive(Path decryptedFile, int depth, int maxDepth,
                                        ProgressReporter reporter, Listener listener)
            throws Exception {
        extractIfArchive(decryptedFile, depth, maxDepth, reporter, listener, null);
    }

    /**
     * 若 {@code decryptedFile} 是明文归档，则解压到同名文件夹。
     *
     * <p>带密码归档且提供了密码提供者时，通过提供者获取密码并解压；
     * 用户放弃输入时跳过该归档并保留原文件。
     *
     * @param decryptedFile     解密得到的文件
     * @param depth             当前层数（最外层为 0）
     * @param maxDepth          最大嵌套层数
     * @param reporter          进度回调，可为 null
     * @param listener          结果回调，可为 null
     * @param passwordProvider  归档密码提供者（弹窗），可为 null
     * @throws Exception 解压失败或用户取消
     */
    public static void extractIfArchive(Path decryptedFile, int depth, int maxDepth,
                                        ProgressReporter reporter, Listener listener,
                                        ArchivePasswordProvider passwordProvider)
            throws Exception {
        if (decryptedFile == null || !Files.isRegularFile(decryptedFile)) {
            return;
        }
        if (!ArchiveExtractor.isArchive(decryptedFile)) {
            return;
        }
        extractToNamedFolder(decryptedFile, depth, maxDepth, reporter, listener, passwordProvider);
    }

    /**
     * 扫描目录中新出现的明文归档并解压到各自的同名文件夹，保留压缩包。
     *
     * <p>解压失败时跳过该归档并保留原文件，不中断其余归档。
     *
     * @param root     扫描根目录
     * @param depth    当前层数（最外层为 0）
     * @param maxDepth 最大嵌套层数
     * @param reporter 进度回调，可为 null
     * @param listener 结果回调，可为 null
     * @throws Exception 用户取消
     */
    public static void extractNewArchives(Path root, int depth, int maxDepth,
                                          ProgressReporter reporter, Listener listener)
            throws Exception {
        extractNewArchives(root, depth, maxDepth, reporter, listener, null);
    }

    /**
     * 扫描目录中新出现的明文归档并解压到各自的同名文件夹，保留压缩包。
     *
     * <p>解压失败时跳过该归档并保留原文件，不中断其余归档。带密码归档且提供了
     * 密码提供者时，通过提供者获取密码并解压。
     *
     * @param root             扫描根目录
     * @param depth            当前层数（最外层为 0）
     * @param maxDepth         最大嵌套层数
     * @param reporter         进度回调，可为 null
     * @param listener         结果回调，可为 null
     * @param passwordProvider 归档密码提供者（弹窗），可为 null
     * @throws Exception 用户取消
     */
    public static void extractNewArchives(Path root, int depth, int maxDepth,
                                          ProgressReporter reporter, Listener listener,
                                          ArchivePasswordProvider passwordProvider)
            throws Exception {
        if (root == null || !Files.isDirectory(root) || depth >= maxDepth) {
            return;
        }
        List<Path> archives = listArchives(root);
        archives.sort(Comparator.comparingInt(ArchivePostExtract::pathDepth)
                .thenComparing(p -> p.toString()));
        for (Path archive : archives) {
            if (reporter != null && reporter.isCancelled()) {
                throw new InterruptedException("cancelled");
            }
            try {
                extractToNamedFolder(archive, depth, maxDepth, reporter, listener, passwordProvider);
            } catch (InterruptedException e) {
                throw e;
            } catch (Exception e) {
                if (listener != null) {
                    listener.onFailed(archive, e.getMessage());
                }
                LogService.warn("ArchivePostExtract", "解压失败，已保留 " + archive.getFileName()
                        + ": " + e.getMessage());
            }
        }
    }

    /**
     * 将明文归档解压到兄弟同名文件夹，保留压缩包，并按深度限制递归处理内部嵌套归档。
     *
     * <p>带密码归档：提供了密码提供者时通过弹窗获取密码（密码错误自动重试），
     * 用户放弃输入时跳过解压、保留原包；未提供密码提供者时快速失败跳过。
     * 本方法不解密 {@code .ergou} 文件。
     *
     * @param archive  明文归档
     * @param depth    当前层数（最外层为 0）
     * @param maxDepth 最大嵌套层数
     * @param reporter 进度回调，可为 null
     * @param listener 结果回调，可为 null
     * @throws Exception 解压失败或用户取消
     */
    public static void extractToNamedFolder(Path archive, int depth, int maxDepth,
                                            ProgressReporter reporter, Listener listener)
            throws Exception {
        extractToNamedFolder(archive, depth, maxDepth, reporter, listener, null);
    }

    /**
     * 将明文归档解压到兄弟同名文件夹，保留压缩包，并按深度限制递归处理内部嵌套归档。
     *
     * <p>带密码归档且提供了密码提供者时，通过弹窗获取密码（密码错误自动重试），
     * 用户放弃输入时跳过解压、保留原包；未提供密码提供者时快速失败跳过。
     * 本方法不解密 {@code .ergou} 文件。
     *
     * @param archive          明文归档
     * @param depth            当前层数（最外层为 0）
     * @param maxDepth         最大嵌套层数
     * @param reporter         进度回调，可为 null
     * @param listener         结果回调，可为 null
     * @param passwordProvider 归档密码提供者（弹窗），可为 null
     * @throws Exception 解压失败或用户取消
     */
    public static void extractToNamedFolder(Path archive, int depth, int maxDepth,
                                            ProgressReporter reporter, Listener listener,
                                            ArchivePasswordProvider passwordProvider)
            throws Exception {
        if (archive == null || !Files.isRegularFile(archive)) {
            return;
        }
        if (depth >= maxDepth) {
            return;
        }
        if (reporter != null && reporter.isCancelled()) {
            throw new InterruptedException("cancelled");
        }
        if (isPasswordProtected(archive)) {
            if (passwordProvider == null) {
                skipPasswordProtected(archive, reporter, listener);
                return;
            }
            int attempts = 0;
            while (true) {
                String password = passwordProvider.providePassword(archive, attempts > 0);
                if (password == null || password.isEmpty()) {
                    skipPasswordProtected(archive, reporter, listener);
                    return;
                }
                try {
                    extractToNamedFolderInner(archive, depth, maxDepth, reporter, listener,
                            password, passwordProvider);
                    return;
                } catch (InterruptedException e) {
                    throw e;
                } catch (Exception e) {
                    if (ArchiveExtractor.isPasswordRelatedError(e)
                            && attempts < MAX_PASSWORD_ATTEMPTS - 1) {
                        attempts++;
                        continue;
                    }
                    throw e;
                }
            }
        }
        extractToNamedFolderInner(archive, depth, maxDepth, reporter, listener, null, passwordProvider);
    }

    /**
     * 实际解压到同名文件夹（已持有最终密码），并按深度限制递归处理内部嵌套归档。
     *
     * @param archive          明文归档
     * @param depth            当前层数（最外层为 0）
     * @param maxDepth         最大嵌套层数
     * @param reporter         进度回调，可为 null
     * @param listener         结果回调，可为 null
     * @param password         归档密码（可为 null/空）
     * @param passwordProvider 归档密码提供者，用于递归时传递给嵌套归档
     * @throws Exception 解压失败或用户取消
     */
    private static void extractToNamedFolderInner(Path archive, int depth, int maxDepth,
                                                  ProgressReporter reporter, Listener listener,
                                                  String password,
                                                  ArchivePasswordProvider passwordProvider)
            throws Exception {
        Path parent = archive.getParent();
        if (parent == null) {
            parent = Path.of(".");
        }
        Path destDir = parent.resolve(folderNameFor(archive));
        Files.createDirectories(destDir);

        if (reporter != null) {
            reporter.setStatus(Messages.format("status.extracting.file",
                    archive.getFileName()), ProgressPhase.ARCHIVE);
        }
        ArchiveExtractor.extractPreserving(archive, destDir, password, reporter);
        if (listener != null) {
            listener.onExtracted(archive, destDir);
        }
        LogService.info("ArchivePostExtract", "已解压 " + archive.getFileName()
                + " → " + destDir.getFileName());

        if (depth + 1 < maxDepth) {
            extractNewArchives(destDir, depth + 1, maxDepth, reporter, listener, passwordProvider);
        }
    }

    /**
     * 跳过带密码归档：通知监听器与进度回调，保留原文件。
     *
     * @param archive  明文归档
     * @param reporter 进度回调，可为 null
     * @param listener 结果回调，可为 null
     */
    private static void skipPasswordProtected(Path archive, ProgressReporter reporter,
                                              Listener listener) {
        if (listener != null) {
            listener.onSkipped(archive, Messages.get("status.archive.passwordProtected"));
        }
        if (reporter != null) {
            reporter.setStatus(Messages.format("status.skipped",
                    archive.getFileName(),
                    Messages.get("status.archive.passwordProtected")),
                    ProgressPhase.ARCHIVE);
        }
    }

    /**
     * 解密后解压的结果回调。
     */
    public interface Listener {

        /**
         * 归档已解压到同名文件夹（压缩包仍保留）。
         *
         * @param archive 明文归档
         * @param destDir 解压目标文件夹
         */
        void onExtracted(Path archive, Path destDir);

        /**
         * 因密码保护等原因跳过解压，原文件已保留。
         *
         * @param archive 归档路径
         * @param reason  跳过原因
         */
        void onSkipped(Path archive, String reason);

        /**
         * 解压失败，原文件已保留。
         *
         * @param archive 归档路径
         * @param reason  失败原因
         */
        void onFailed(Path archive, String reason);
    }

    /**
     * 列出目录树中的明文归档文件。
     *
     * @param root 扫描根
     * @return 归档路径列表
     * @throws IOException 列举失败
     */
    private static List<Path> listArchives(Path root) throws IOException {
        List<Path> archives = new ArrayList<>();
        int walkDepth = Math.max(1, RECURSIVE_MAX_DEPTH);
        try (Stream<Path> walk = Files.walk(root, walkDepth)) {
            for (Path f : walk.toList()) {
                if (Files.isRegularFile(f) && ArchiveExtractor.isArchive(f)) {
                    archives.add(f);
                }
            }
        }
        return archives;
    }

    /**
     * 路径相对深度（名称元素个数），用于浅层归档优先解压。
     *
     * @param path 路径
     * @return 名称元素个数
     */
    private static int pathDepth(Path path) {
        return path.getNameCount();
    }

    /**
     * 检测归档是否为带密码保护。检测失败时按需要密码处理，避免静默损坏。
     *
     * @param archive 归档路径
     * @return true 表示需要密码
     */
    private static boolean isPasswordProtected(Path archive) {
        try {
            return ArchiveExtractor.hasEncryptedEntries(archive);
        } catch (IOException e) {
            return true;
        }
    }
}
