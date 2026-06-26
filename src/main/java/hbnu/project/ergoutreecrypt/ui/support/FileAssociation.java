package hbnu.project.ergoutreecrypt.ui.support;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.TimeUnit;

/**
 * Windows 文件类型关联工具：将 {@code .ergou} 扩展名注册到 HKCU，
 * 使加密文件在资源管理器中显示应用图标。
 *
 * <p>写 {@code HKEY_CURRENT_USER} 不需要管理员权限。注册后会通知 Shell 刷新图标缓存
 *
 * @author ErgouTree
 */
public final class FileAssociation {

    private static final String EXT = ".ergou";
    private static final String PROG_ID = "ErgouTreeCrypt.ergou";
    private static final String APP_NAME = "ErgouTreeCrypt 加密文件";

    /**
     * classpath 中作为应用图标的 .ico 资源。
     */
    private static final String APP_ICON_RESOURCE =
            "/hbnu/project/ergoutreecrypt/ui/img/logo-96x.ico";

    /**
     * classpath 中作为加密文件图标的 .png 资源（运行时转换为 .ico）。
     */
    private static final String FILE_ICON_RESOURCE =
            "/hbnu/project/ergoutreecrypt/ui/img/file.png";

    private FileAssociation() {
    }

    /**
     * 将 {@code .ergou} → {@code ErgouTreeCrypt.ergou} 写入 HKCU，
     * 并将图标指向指定路径的 .ico 文件。
     *
     * @param iconPath 已落盘的 .ico 文件绝对路径
     * @return 是否注册成功
     */
    public static boolean register(String iconPath) {
        if (!isWindows()) {
            return false;
        }
        try {
            String extKey = "HKCU\\Software\\Classes\\" + EXT;
            String progKey = "HKCU\\Software\\Classes\\" + PROG_ID;
            String iconKey = progKey + "\\DefaultIcon";

            // 1) .ergou → ProgID
            runReg("add", extKey, "/ve", "/d", PROG_ID, "/f");
            // 2) ProgID → 显示名
            runReg("add", progKey, "/ve", "/d", APP_NAME, "/f");
            // 3) DefaultIcon → .ico 路径（带 ,0 指定图标索引）
            runReg("add", iconKey, "/ve", "/d", iconPath + ",0", "/f");

            notifyShellIconChanged();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从 classpath 资源提取图标到用户 AppData 并写入注册表。
     *
     * <p>应用图标（logo-96x.ico）和文件类型图标（file.png→file.ico）
     * 均落盘到 {@code %APPDATA%/ErgouTreeCrypt/}。若已注册且两个图标均存在则跳过。
     *
     * <p>加密文件（.ergou）在 Windows 资源管理器中会显示 {@code file.png} 的图案。
     */
    public static void autoRegister() {
        if (!isWindows()) {
            return;
        }
        try {
            Path iconDir = Paths.get(System.getenv("APPDATA"), "ErgouTreeCrypt");
            Files.createDirectories(iconDir);
            Path appIconFile = iconDir.resolve("ergou-app.ico");
            Path fileIconFile = iconDir.resolve("ergou-file.ico");

            boolean bothExist = Files.exists(appIconFile) && Files.exists(fileIconFile);
            if (isRegistered() && bothExist) {
                return;
            }

            // 1) 提取应用图标（logo-96x.ico）
            try (InputStream in = FileAssociation.class.getResourceAsStream(APP_ICON_RESOURCE)) {
                if (in != null) {
                    Files.copy(in, appIconFile, StandardCopyOption.REPLACE_EXISTING);
                }
            }

            // 2) 将 file.png 转换为 .ico 并落盘 —— 作为 .ergou 文件类型图标
            try (InputStream in = FileAssociation.class.getResourceAsStream(FILE_ICON_RESOURCE)) {
                if (in != null) {
                    byte[] icoBytes = IconUtils.pngToIco(in);
                    Files.write(fileIconFile, icoBytes);
                }
            }

            // 3) 注册 .ergou 文件关联，使用转换后的文件图标
            register(fileIconFile.toAbsolutePath().toString());
        } catch (IOException ignored) {
            // 静默失败，不影响应用启动
        }
    }

    /**
     * 已注册 .ergou 关联则返回 true。
     */
    private static boolean isRegistered() {
        try {
            Process p = new ProcessBuilder(
                    "reg", "query", "HKCU\\Software\\Classes\\.ergou", "/ve")
                    .redirectErrorStream(true)
                    .start();
            p.waitFor(3, TimeUnit.SECONDS);
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 执行 {@code reg add ...}。注意首参必须是 {@code reg} 可执行文件本身。
     */
    private static void runReg(String... regArgs)
            throws IOException, InterruptedException {
        String[] cmd = new String[regArgs.length + 1];
        cmd[0] = "reg";
        System.arraycopy(regArgs, 0, cmd, 1, regArgs.length);
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        p.waitFor(5, TimeUnit.SECONDS);
    }

    /**
     * 通知 Windows Shell 重新读取文件关联与图标（清理图标缓存）。
     * 调用 {@code ie4uinit.exe -show}，无需管理员权限。
     */
    private static void notifyShellIconChanged() {
        try {
            new ProcessBuilder("ie4uinit.exe", "-show")
                    .redirectErrorStream(true)
                    .start()
                    .waitFor(3, TimeUnit.SECONDS);
        } catch (Exception ignored) {
            // 刷新失败不影响关联本身，重启资源管理器后仍会生效
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "")
                .toLowerCase().contains("win");
    }
}
