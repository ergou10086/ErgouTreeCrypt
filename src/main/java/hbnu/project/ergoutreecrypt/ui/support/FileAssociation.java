package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.log.LogService;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.TimeUnit;

/**
 * Windows 外壳集成工具：将 {@code .ergou} 扩展名注册到 HKCU，
 * 使加密文件在资源管理器中显示应用图标；并提供资源管理器右键菜单的注入与移除。
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
     * 资源管理器右键菜单「使用 ErgouTreeCrypt 打开」的注册表位置。
     *
     * <p>挂在 {@code HKCU\Software\Classes\*} 下表示对所有文件类型生效。
     * 键名固定为 {@code ErgouTreeCrypt}，既不含版本号也不含可执行文件路径，
     * 因此不同版本注入的是同一个位置：新版本启动时能检测到旧版本的注入，
     * 新版本重新注入会直接覆盖旧版本的命令行（旧 exe 路径随之失效也不会残留）。
     */
    private static final String MENU_KEY =
            "HKCU\\Software\\Classes\\*\\shell\\ErgouTreeCrypt";

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
     * 均落盘到 {@code %APPDATA%/ErgouTreeCrypt/}，每次启动覆盖写入。
     *
     * <p>加密文件（.ergou）在 Windows 资源管理器中会显示 {@code file.png} 的图案。
     * 本方法只负责文件关联与图标，不涉及右键菜单；右键菜单由用户在设置中
     * 通过 {@link #installContextMenu()} 手动注入。
     */
    public static void autoRegister() {
        if (!isWindows()) {
            return;
        }
        try {
            String[] icons = extractIcons();
            if (icons == null) {
                return;
            }
            String appIconPath = icons[0];
            String fileIconPath = icons[1];

            String openCommand = buildOpenCommand();
            String exeName = currentExecutableName();
            if (openCommand == null || openCommand.isBlank()
                    || exeName == null || exeName.isBlank()) {
                return;
            }

            // 1) 注册默认打开关联（.ergou → ProgID → open command）
            registerFileAssociation(fileIconPath, openCommand);

            // 2) 补齐 Default Programs 的应用注册层
            registerApplication(exeName, appIconPath, openCommand);
        } catch (IOException ignored) {
            // 静默失败，不影响应用启动
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 把两个图标资源提取到 {@code %APPDATA%/ErgouTreeCrypt/}。
     *
     * @return 长度为 2 的数组，依次为应用图标路径与 .ergou 文件类型图标路径；
     *         任一图标缺失或落盘失败时返回 {@code null}
     */
    private static String[] extractIcons() throws IOException {
        Path iconDir = Paths.get(System.getenv("APPDATA"), "ErgouTreeCrypt");
        Files.createDirectories(iconDir);
        Path appIconFile = iconDir.resolve("ergou-app.ico");
        Path fileIconFile = iconDir.resolve("ergou-file.ico");

        // 1) 提取应用图标（logo-96x.ico）
        try (InputStream in = FileAssociation.class.getResourceAsStream(APP_ICON_RESOURCE)) {
            if (in == null) {
                return null;
            }
            Files.copy(in, appIconFile, StandardCopyOption.REPLACE_EXISTING);
        }

        // 2) 将 file.png 转换为 .ico 并落盘 —— 作为 .ergou 文件类型图标
        try (InputStream in = FileAssociation.class.getResourceAsStream(FILE_ICON_RESOURCE)) {
            if (in == null) {
                return null;
            }
            Files.write(fileIconFile, IconUtils.pngToIco(in));
        }

        return new String[]{
                appIconFile.toAbsolutePath().toString(),
                fileIconFile.toAbsolutePath().toString()};
    }

    // ================================================================
    // 资源管理器右键菜单
    // ================================================================

    /**
     * 当前系统是否支持外壳集成（非 Windows 平台一律不支持）。
     *
     * @return Windows 平台返回 {@code true}
     */
    public static boolean isSupported() {
        return isWindows();
    }

    /**
     * 右键菜单是否已注入。
     *
     * <p>只在固定的 {@link #MENU_KEY} 上做存在性判断，与注入时用的版本、
     * 可执行文件路径均无关，因此升级后依旧能识别出旧版本留下的菜单。
     *
     * @return 已注入时返回 {@code true}
     */
    public static boolean isContextMenuInstalled() {
        return isWindows() && regKeyExists(MENU_KEY);
    }

    /**
     * 注入「使用 ErgouTreeCrypt 打开」到所有文件的右键菜单。
     *
     * <p>菜单命令指向当前正在运行的可执行文件，图标复用应用图标资源。
     * 重复注入等价于覆盖，不会产生多余条目。
     *
     * @return 注入并复检成功后返回 {@code true}
     */
    public static boolean installContextMenu() {
        if (!isWindows()) {
            return false;
        }
        try {
            java.util.Optional<Path> exe = currentExecutablePath();
            if (exe.isEmpty()) {
                LogService.warn("FileAssociation", "右键菜单注入失败: 未能定位当前可执行文件");
                return false;
            }
            String[] icons = extractIcons();
            if (icons == null) {
                LogService.warn("FileAssociation", "右键菜单注入失败: 图标资源缺失");
                return false;
            }
            String command = regQuoted(exe.get().toAbsolutePath().toString())
                    + " " + regQuoted("%1");

            runReg("add", MENU_KEY, "/ve", "/d", Messages.get("shell.openWith"), "/f");
            runReg("add", MENU_KEY, "/v", "Icon", "/t", "REG_SZ",
                    "/d", regQuoted(icons[0]) + ",0", "/f");
            runReg("add", MENU_KEY + "\\command", "/ve", "/d", command, "/f");

            notifyShellIconChanged();
            return isContextMenuInstalled();
        } catch (Exception e) {
            LogService.warn("FileAssociation", "右键菜单注入失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 移除已注入的右键菜单。
     *
     * @return 确认已不存在时返回 {@code true}
     */
    public static boolean uninstallContextMenu() {
        if (!isWindows()) {
            return false;
        }
        try {
            if (regKeyExists(MENU_KEY)) {
                runReg("delete", MENU_KEY, "/f");
            }
            notifyShellIconChanged();
            return !isContextMenuInstalled();
        } catch (Exception e) {
            LogService.warn("FileAssociation", "右键菜单移除失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 查询注册表键是否存在。
     *
     * @param key 完整键路径（如 {@code HKCU\Software\Classes\*\shell\X}）
     * @return 键存在时返回 {@code true}
     */
    private static boolean regKeyExists(String key) {
        try {
            Process p = new ProcessBuilder("reg", "query", key)
                    .redirectErrorStream(true)
                    .start();
            p.getInputStream().readAllBytes();
            if (!p.waitFor(5, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return false;
            }
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
