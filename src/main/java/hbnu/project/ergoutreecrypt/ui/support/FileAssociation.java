package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.log.LogService;

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

    private static final String APP_ID = "ErgouTreeCrypt";
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
    public static boolean register(String iconPath, String openCommand) {
        if (!isWindows() || openCommand == null || openCommand.isBlank()) {
            return false;
        }
        try {
            String extKey = "HKCU\\Software\\Classes\\" + EXT;
            String progKey = "HKCU\\Software\\Classes\\" + PROG_ID;
            String iconKey = progKey + "\\DefaultIcon";
            String openKey = progKey + "\\shell\\open";
            String commandKey = openKey + "\\command";

            // 1) .ergou → ProgID
            runReg("add", extKey, "/ve", "/d", PROG_ID, "/f");
            // 2) ProgID → 显示名
            runReg("add", progKey, "/ve", "/d", APP_NAME, "/f");
            // 3) DefaultIcon → .ico 路径（带 ,0 指定图标索引）
            runReg("add", iconKey, "/ve", "/d", iconPath + ",0", "/f");
            // 4) 直接手动打开.ergou后缀文件的动作
            runReg("add", openKey, "/ve", "/d", "打开(&O)", "/f");
            runReg("add", commandKey, "/ve", "/d", openCommand, "/f");

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

            String openCommand = buildOpenCommand();
            String exeName = currentExecutableName();
            if (openCommand == null || openCommand.isBlank()
                    || exeName == null || exeName.isBlank()) {
                return;
            }

            String appIconPath = appIconFile.toAbsolutePath().toString();
            String fileIconPath = fileIconFile.toAbsolutePath().toString();

            // 3) 注册默认打开关联（.ergou → ProgID → open command）
            registerFileAssociation(fileIconPath, openCommand);

            // 4) 补齐 Default Programs 的应用注册层
            registerApplication(exeName, appIconPath, openCommand);
        } catch (IOException ignored) {
            // 静默失败，不影响应用启动
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
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
        String output = new String(p.getInputStream().readAllBytes());
        if (!p.waitFor(5, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            LogService.warn("FileAssociation", "reg 超时: " + String.join(" ", regArgs));
            return;
        }
        if (p.exitValue() != 0) {
            LogService.warn("FileAssociation",
                    "reg 失败(" + p.exitValue() + "): " + String.join(" ", regArgs)
                            + (output.isBlank() ? "" : " | " + output.strip()));
        }
    }

    private static String buildOpenCommand() {
        // 此函数只支持直接用.exe打开的情况, 若对.jar文件直接运行 则无效
        return currentExecutablePath()
                .map(path -> regQuoted(path.toAbsolutePath().toString()) + " " + regQuoted("%1"))
                .orElse(null);
    }

    private static String currentExecutableName() {
        return currentExecutablePath()
                .map(path -> path.getFileName().toString())
                .orElse(null);
    }

    private static java.util.Optional<Path> currentExecutablePath() {
        return ProcessHandle.current()
                .info()
                .command()
                .map(Path::of)
                .filter(Files::isRegularFile)
                .filter(FileAssociation::isAppExe);
    }

    private static boolean isAppExe(Path path) {
        String name = path.getFileName().toString().toLowerCase();
        return name.endsWith(".exe")
                && !name.equals("java.exe")
                && !name.equals("javaw.exe");
    }

    private static String regQuoted(String value) {
        return "\\\"" + value + "\\\"";
    }

    private static void registerFileAssociation(String fileIconPath, String openCommand)
            throws IOException, InterruptedException {
        String extKey = "HKCU\\Software\\Classes\\" + EXT;
        String progKey = "HKCU\\Software\\Classes\\" + PROG_ID;
        String iconKey = progKey + "\\DefaultIcon";
        String openKey = progKey + "\\shell\\open";
        String commandKey = openKey + "\\command";

        // 1) .ergou → ProgID
        runReg("add", extKey, "/ve", "/d", PROG_ID, "/f");
        // 2) ProgID → 显示名
        runReg("add", progKey, "/ve", "/d", APP_NAME, "/f");
        // 3) DefaultIcon → .ico 路径（带 ,0 指定图标索引）
        runReg("add", iconKey, "/ve", "/d", regQuoted(fileIconPath) + ",0", "/f");
        // 4) 直接手动打开 .ergou 后缀文件的动作
        runReg("add", openKey, "/ve", "/d", "打开(&O)", "/f");
        runReg("add", commandKey, "/ve", "/d", openCommand, "/f");
    }

    private static void registerApplication(String exeName, String appIconPath, String openCommand)
            throws IOException, InterruptedException {
        String appKey = "HKCU\\Software\\Classes\\Applications\\" + exeName;
        String appIconKey = appKey + "\\DefaultIcon";
        String appShellKey = appKey + "\\shell\\open";
        String appCommandKey = appShellKey + "\\command";
        String supportedTypesKey = appKey + "\\SupportedTypes";
        String capabilitiesKey = appKey + "\\Capabilities";
        String capabilitiesFileAssocKey = capabilitiesKey + "\\FileAssociations";
        String registeredApplicationsKey = "HKCU\\Software\\RegisteredApplications";
        String capabilitiesPath = "Software\\Classes\\Applications\\" + exeName + "\\Capabilities";

        runReg("add", appKey, "/ve", "/d", APP_NAME, "/f");
        runReg("add", appKey, "/v", "FriendlyAppName", "/t", "REG_SZ", "/d", APP_NAME, "/f");
        runReg("add", appIconKey, "/ve", "/d", regQuoted(appIconPath) + ",0", "/f");
        runReg("add", supportedTypesKey, "/v", EXT, "/t", "REG_SZ", "/d", "", "/f");
        runReg("add", appShellKey, "/ve", "/d", "打开(&O)", "/f");
        runReg("add", appCommandKey, "/ve", "/d", openCommand, "/f");

        runReg("add", capabilitiesKey, "/v", "ApplicationName", "/t", "REG_SZ", "/d", APP_ID, "/f");
        runReg("add", capabilitiesKey, "/v", "ApplicationDescription", "/t", "REG_SZ", "/d", APP_NAME, "/f");
        runReg("add", capabilitiesFileAssocKey, "/v", EXT, "/t", "REG_SZ", "/d", PROG_ID, "/f");
        runReg("add", registeredApplicationsKey, "/v", APP_ID, "/t", "REG_SZ", "/d", capabilitiesPath, "/f");
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
