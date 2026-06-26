package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.regex.Pattern;

/**
 * 文件切分与合并工具。
 *
 * <p>切分命名规则：{@code base.0, base.1, ...}（无头无尾，纯拼接即可还原）。
 * 支持 .pcv.N 和 .ergou.N 两种分卷文件名模式，写入时先写 .incomplete 后缀再原子重命名。
 *
 * @author ErgouTree
 */
public final class Splitter {

    /**
     * 分卷文件名匹配模式：.pcv.N 或 .ergou.N（N 为数字）。
     */
    private static final Pattern SPLIT_CHUNK_RE = Pattern.compile("(?i)\\.pcv\\.[0-9]+$|\\.ergou\\.[0-9]+$");

    private Splitter() {
    }

    /**
     * 将文件切分为固定大小的分片。
     *
     * <p>每片写入时先使用 .incomplete 临时后缀，写入完成后再原子重命名为最终文件名，
     * 避免中途失败产生不完整的分片。执行前会清理已有的同名前缀分片。
     *
     * @param inputPath 待切分的文件路径
     * @param chunkSize 每片最大字节数
     * @throws IOException 文件读写错误
     */
    public static void split(Path inputPath, long chunkSize) throws IOException {
        long total = Files.size(inputPath);
        long numChunks = (total + chunkSize - 1) / chunkSize;
        String baseName = inputPath.toString();

        // 清理已有的同名前缀分片，避免新旧混杂
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(
                inputPath.getParent() != null ? inputPath.getParent() : Path.of("."),
                p -> shouldDeleteSplitArtifact(baseName, p.getFileName().toString()))) {
            for (Path p : ds) {
                Files.delete(p);
            }
        }

        try (InputStream in = Files.newInputStream(inputPath)) {
            byte[] buf = new byte[CryptoConstants.MIB];
            for (int i = 0; i < numChunks; i++) {
                long remaining = Math.min(chunkSize, total - i * chunkSize);
                String tmpPath = baseName + "." + i + ".incomplete";
                String finalPath = baseName + "." + i;

                // 先写临时文件，完成后再原子重命名
                try (OutputStream out = Files.newOutputStream(Path.of(tmpPath))) {
                    long written = 0;
                    while (written < remaining) {
                        int toRead = (int) Math.min(buf.length, remaining - written);
                        int n = in.read(buf, 0, toRead);
                        if (n < 0) {
                            break;
                        }
                        out.write(buf, 0, n);
                        written += n;
                    }
                }
                Files.move(Path.of(tmpPath), Path.of(finalPath),
                        StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    /**
     * 将全部分片顺序合并为单个文件。
     *
     * @param outputPath 合并输出文件路径
     * @param inputBase  分片的基础路径前缀（不含 .N 后缀）
     * @throws IOException 若找不到分片或读写错误
     */
    public static void recombine(Path outputPath, String inputBase) throws IOException {
        int count = countChunks(inputBase);
        if (count == 0) {
            throw new IOException("no chunks found for: " + inputBase);
        }

        Files.deleteIfExists(outputPath);
        try (OutputStream out = Files.newOutputStream(outputPath)) {
            byte[] buf = new byte[CryptoConstants.MIB];
            for (int i = 0; i < count; i++) {
                Path chunkPath = Path.of(inputBase + "." + i);
                try (InputStream in = Files.newInputStream(chunkPath)) {
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        out.write(buf, 0, n);
                    }
                }
            }
        }
    }

    /**
     * 列出给定基础路径对应的全部分片（base.0, base.1, ...），按序号升序返回。
     *
     * @param basePath 基础路径（不含 .N 后缀）
     * @return 有序的分片路径列表
     * @throws IOException 扫描目录失败
     */
    public static java.util.List<Path> listChunks(Path basePath) throws IOException {
        int count = countChunks(basePath.toString());
        java.util.List<Path> result = new java.util.ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(Path.of(basePath + "." + i));
        }
        return result;
    }

    /**
     * 判断路径是否为分卷碎片（匹配 .pcv.N 或 .ergou.N 模式）。
     *
     * @param path 文件路径字符串
     * @return 若匹配分卷命名模式则返回 true
     */
    public static boolean isSplitChunkPath(String path) {
        return SPLIT_CHUNK_RE.matcher(Path.of(path).getFileName().toString()).find();
    }

    /**
     * 从分卷文件名提取基础路径（去掉 .N 后缀）。
     *
     * @param path 分卷文件路径（如 "file.ergou.3"）
     * @return 基础路径（如 "dir/file.ergou"），若不匹配模式则返回 null
     */
    public static String splitChunkBase(String path) {
        if (!isSplitChunkPath(path)) {
            return null;
        }
        String name = Path.of(path).getFileName().toString();
        int dotIdx = name.lastIndexOf('.');
        if (dotIdx < 0) {
            return null;
        }
        String baseName = name.substring(0, dotIdx);
        Path p = Path.of(path);
        return (p.getParent() != null ? p.getParent().resolve(baseName) : Path.of(baseName)).toString();
    }

    /**
     * 统计给定基础路径下的分片数量（最大编号 + 1）。
     */
    private static int countChunks(String basePath) throws IOException {
        Path base = Path.of(basePath);
        Path dir = base.getParent() != null ? base.getParent() : Path.of(".");
        String prefix = base.getFileName().toString() + ".";

        int maxIdx = -1;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir,
                p -> p.getFileName().toString().startsWith(prefix))) {
            for (Path p : ds) {
                String suffix = p.getFileName().toString().substring(prefix.length());
                try {
                    int idx = Integer.parseInt(suffix);
                    if (idx > maxIdx) {
                        maxIdx = idx;
                    }
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return maxIdx + 1;
    }

    /**
     * 判断文件名是否为基础路径对应的待清理分片产物（含 .incomplete 后缀的也一并处理）。
     */
    private static boolean shouldDeleteSplitArtifact(String basePath, String name) {
        String base = Path.of(basePath).getFileName().toString();
        if (!name.startsWith(base + ".")) {
            return false;
        }
        String suffix = name.substring(base.length() + 1);

        // 去除 .incomplete 后缀
        if (suffix.endsWith(".incomplete")) {
            suffix = suffix.substring(0, suffix.length() - 11);
        }
        if (suffix.isEmpty()) {
            return false;
        }

        // 检查剩余后缀是否为纯数字
        for (char c : suffix.toCharArray()) {
            if (!Character.isDigit(c)) {
                return false;
            }
        }
        return true;
    }
}
