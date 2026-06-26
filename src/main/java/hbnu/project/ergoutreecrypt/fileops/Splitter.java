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
 * 文件切分与合并
 *
 * <p>切分命名：{@code base.0, base.1, ...}（无头无尾，纯拼接即可还原）。
 *
 * @author ErgouTree
 */
public final class Splitter {

    private static final Pattern SPLIT_CHUNK_RE = Pattern.compile("(?i)\\.pcv\\.[0-9]+$|\\.ergou\\.[0-9]+$");

    private Splitter() {
    }

    // ---- Split ----
    public static void split(Path inputPath, long chunkSize) throws IOException {
        long total = Files.size(inputPath);
        long numChunks = (total + chunkSize - 1) / chunkSize;
        String baseName = inputPath.toString();

        // Clean up pre-existing chunks
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

    // ---- Recombine ----
    public static void recombine(Path outputPath, String inputBase) throws IOException {
        // Count chunks
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
     * 列出某个 base 路径对应的全部分卷碎片（base.0, base.1, ...），按序号升序返回。
     */
    public static java.util.List<Path> listChunks(Path basePath) throws IOException {
        int count = countChunks(basePath.toString());
        java.util.List<Path> result = new java.util.ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            result.add(Path.of(basePath + "." + i));
        }
        return result;
    }

    // ---- chunk detection ----
    public static boolean isSplitChunkPath(String path) {
        return SPLIT_CHUNK_RE.matcher(Path.of(path).getFileName().toString()).find();
    }

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
        // Reconstruct base path
        Path p = Path.of(path);
        return (p.getParent() != null ? p.getParent().resolve(baseName) : Path.of(baseName)).toString();
    }

    // ---- internal ----
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

    private static boolean shouldDeleteSplitArtifact(String basePath, String name) {
        String base = Path.of(basePath).getFileName().toString();
        if (!name.startsWith(base + ".")) {
            return false;
        }
        String suffix = name.substring(base.length() + 1);
        // Remove .incomplete
        if (suffix.endsWith(".incomplete")) {
            suffix = suffix.substring(0, suffix.length() - 11);
        }
        if (suffix.isEmpty()) {
            return false;
        }
        for (char c : suffix.toCharArray()) {
            if (!Character.isDigit(c)) {
                return false;
            }
        }
        return true;
    }
}
