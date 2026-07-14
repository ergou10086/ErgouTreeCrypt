package hbnu.project.ergoutreecrypt.ui;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.ui.support.*;
import hbnu.project.ergoutreecrypt.volume.*;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.Cursor;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 主界面控制器：负责拖拽选文件、密码与高级选项收集、加解密任务的提交与进度展示。
 *
 * <p>UI 仅依赖 {@code volume} 层（{@link Encryptor} / {@link Decryptor}）与 {@code i18n}，
 * 不直接触碰任何密码学原语，符合架构的分层约束。
 *
 * @author ErgouTree
 */
public class MainController {

    // ---- 运行期状态 ----
    private final ThemeManager themeManager = new ThemeManager();
    private final TaskRunner taskRunner = new TaskRunner();
    private final List<File> keyfiles = new ArrayList<>();

    // ---- 根 / 标题栏 ----
    @FXML
    private StackPane rootStack;
    @FXML
    private VBox rootPane;
    @FXML
    private HBox titleBar;
    @FXML
    private Label appTitleLabel;
    @FXML
    private Button langButton;
    @FXML
    private Button themeButton;

    // ---- 菜单栏 ----
    @FXML
    private MenuBar menuBar;
    @FXML
    private Menu settingsMenu;
    @FXML
    private MenuItem settingsMenuItem;
    @FXML
    private MenuItem aboutMenuItem;

    // ---- 标签页 ----
    @FXML
    private TabPane mainTabs;
    @FXML
    private Tab fileTab;
    @FXML
    private Tab mediaTab;
    @FXML
    private MediaCryptController mediaViewController;
    @FXML
    private Tab classicalTab;
    @FXML
    private ClassicalCryptController classicalViewController;
    @FXML
    private Tab stegoTab;
    @FXML
    private ImageStegoController stegoViewController;

    // ---- 模式切换 ----
    @FXML
    private ToggleButton encryptTab;
    @FXML
    private ToggleButton decryptTab;

    // ---- 文件区 ----
    @FXML
    private VBox dropZone;
    @FXML
    private Label dropHintLabel;
    @FXML
    private Label dropSubLabel;
    @FXML
    private Button chooseFileBtn;
    @FXML
    private Button chooseFolderBtn;
    @FXML
    private VBox fileCard;
    @FXML
    private Label fileNameLabel;
    @FXML
    private Label fileMetaLabel;
    @FXML
    private Button clearFileBtn;

    // ---- 输出路径 ----
    @FXML
    private VBox outputCard;
    @FXML
    private Label outputLabel;
    @FXML
    private TextField outputFileField;
    @FXML
    private Button outputBrowseBtn;
    private boolean outputPathUserEdited = false;

    // ---- 密码区 ----
    @FXML
    private Label passwordCardTitle;
    @FXML
    private PasswordField passwordField;
    @FXML
    private TextField passwordVisibleField;
    @FXML
    private Label strengthLabel;
    @FXML
    private CheckBox showPasswordCheck;
    @FXML
    private Button genPasswordBtn;
    @FXML
    private Button copyPasswordBtn;
    @FXML
    private VBox confirmBox;
    @FXML
    private PasswordField confirmField;
    @FXML
    private Label mismatchLabel;

    // ---- 高级选项 ----
    @FXML
    private HBox optionsHeader;
    @FXML
    private Label optionsTitle;
    @FXML
    private Label optionsChevron;
    @FXML
    private VBox optionsBody;
    @FXML
    private VBox encryptOptions;
    @FXML
    private VBox decryptOptions;
    @FXML
    private Label commentsLabel;
    @FXML
    private TextArea commentsArea;
    @FXML
    private CheckBox paranoidCheck;
    @FXML
    private Label paranoidInfo;
    @FXML
    private CheckBox reedSolomonCheck;
    @FXML
    private Label reedSolomonInfo;
    @FXML
    private CheckBox deniabilityCheck;
    @FXML
    private Label deniabilityInfo;
    @FXML
    private HBox decoyFileRow;
    @FXML
    private TextField decoyFilePathField;
    @FXML
    private Button decoyFileDefaultBtn;
    @FXML
    private Button decoyFileBrowseBtn;
    @FXML
    private HBox fakePasswordRow;
    @FXML
    private PasswordField fakePasswordField;
    @FXML
    private PasswordField fakePasswordVisibleField;
    @FXML
    private HBox fakePasswordConfirmRow;
    @FXML
    private PasswordField fakeConfirmField;
    @FXML
    private Button fakeShowToggle;
    @FXML
    private CheckBox compressCheck;
    @FXML
    private Label compressInfo;
    @FXML
    private CheckBox compressAfterCheck;
    @FXML
    private Label compressAfterInfo;
    @FXML
    private ComboBox<String> compressFormatCombo;
    @FXML
    private PasswordField archivePasswordField;
    @FXML
    private CheckBox splitCheck;
    @FXML
    private Label splitInfo;
    @FXML
    private Spinner<Integer> splitSizeSpinner;
    @FXML
    private Label splitUnitLabel;
    @FXML
    private Label encryptDepthLabel;
    @FXML
    private Spinner<Integer> encryptDepthSpinner;
    @FXML
    private Label encryptDepthInfo;
    @FXML
    private CheckBox forceDecryptCheck;
    @FXML
    private Label forceDecryptInfo;
    @FXML
    private CheckBox autoUnzipCheck;
    @FXML
    private Label autoUnzipInfo;
    @FXML
    private CheckBox verifyFirstCheck;
    @FXML
    private Label verifyFirstInfo;
    @FXML
    private CheckBox recursiveExtractCheck;
    @FXML
    private Label recursiveExtractInfo;
    @FXML
    private Label keyfilesLabel;
    @FXML
    private CheckBox keyfileOrderedCheck;
    @FXML
    private Label keyfileOrderedInfo;
    @FXML
    private Button addKeyfileBtn;
    @FXML
    private VBox keyfileList;
    @FXML
    private Label keyfileEmptyLabel;

    // ---- 底部 ----
    @FXML
    private VBox progressBox;
    @FXML
    private Label statusLabel;
    @FXML
    private Label progressInfoLabel;
    @FXML
    private Label cryptoProgressCaption;
    @FXML
    private ProgressBar progressBar;
    @FXML
    private VBox archiveProgressBox;
    @FXML
    private Label archiveProgressCaption;
    @FXML
    private ProgressBar archiveProgressBar;
    @FXML
    private Button cancelBtn;
    @FXML
    private Button verifyBtn;
    @FXML
    private Button actionBtn;

    private Toast toast;

    private Mode mode = Mode.ENCRYPT;
    private File selectedFile;
    private boolean optionsExpanded = false;
    private boolean running = false;
    private FxProgressReporter activeReporter;

    private static void setTip(Label label, String text) {
        if (label == null) {
            return;
        }
        Tooltip tip = new Tooltip(text);
        tip.getStyleClass().add("info-tooltip");
        tip.setShowDelay(Duration.millis(120));   // 几乎即时显示
        tip.setShowDuration(Duration.seconds(20)); // 停留足够长
        tip.setHideDelay(Duration.millis(120));
        tip.setWrapText(true);
        tip.setMaxWidth(300);
        // 直接安装到节点，比 Label.setTooltip 更稳定地响应 hover
        Tooltip.install(label, tip);
        label.setTooltip(tip);
    }

    private static void setVisible(Region node, boolean visible) {
        node.setVisible(visible);
        node.setManaged(visible);
    }

    private static List<String> toPaths(List<File> files) {
        List<String> paths = new ArrayList<>(files.size());
        for (File f : files) {
            paths.add(f.getAbsolutePath());
        }
        return paths;
    }

    /**
     * 判断异常是否与加密/密码相关（ZIP 加密条目、AES 封装等）。
     */
    private static boolean isEncryptionRelated(Throwable t) {
        if (t == null) {
            return false;
        }
        String msg = t.getMessage();
        if (msg == null) {
            msg = "";
        }
        String lower = msg.toLowerCase();
        return lower.contains("encrypt") || lower.contains("password")
                || lower.contains("unsupported compression method")
                || lower.contains("unsupported feature");
    }

    @FXML
    private void initialize() {
        toast = new Toast(rootStack);

        // Spinner 范围：1..102400 MiB，允许手动输入数字
        splitSizeSpinner.setValueFactory(
                new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 102400, 100));
        splitSizeSpinner.setEditable(true);
        splitSizeSpinner.disableProperty().bind(splitCheck.selectedProperty().not());

        // 迭代加密深度 Spinner：1..10 层，默认 2，允许手动输入
        encryptDepthSpinner.setValueFactory(
                new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 10, 2));
        encryptDepthSpinner.setEditable(true);

        // 加密后压缩：格式下拉绑定
        compressFormatCombo.getItems().setAll("ZIP", "GZ", "TAR.GZ", "7Z");
        compressFormatCombo.managedProperty().bind(compressAfterCheck.selectedProperty());
        compressFormatCombo.visibleProperty().bind(compressAfterCheck.selectedProperty());
        // 归档密码框：ZIP 始终可填；GZ/TAR.GZ/7Z 仅在开启「工具特有加密」时才显示
        compressAfterCheck.selectedProperty().addListener((o, a, b) -> updateArchivePasswordVisibility());
        compressFormatCombo.valueProperty().addListener((o, a, b) -> updateArchivePasswordVisibility());
        updateArchivePasswordVisibility();

        // 应用默认设置到 UI
        paranoidCheck.setSelected(SettingsManager.isDefaultParanoid());
        reedSolomonCheck.setSelected(SettingsManager.isDefaultReedSolomon());
        splitSizeSpinner.getValueFactory().setValue(SettingsManager.getDefaultSplitSize());
        compressFormatCombo.setValue(SettingsManager.getDefaultCompressFormat());

        // 模式切换
        encryptTab.setOnAction(e -> switchMode(Mode.ENCRYPT));
        decryptTab.setOnAction(e -> switchMode(Mode.DECRYPT));

        // 拖拽区交互 —— 同时在 dropZone 和 rootStack 上注册，
        // 防止 ScrollPane 等父容器吞掉拖拽事件。
        dropZone.setOnMouseClicked(this::onChooseFile);
        dropZone.setOnDragOver(this::onDragOver);
        dropZone.setOnDragDropped(this::onDragDropped);
        dropZone.setOnDragEntered(this::onDragEntered);
        dropZone.setOnDragExited(this::onDragExited);

        // rootStack 兜底：确保从窗口任意位置拖入都能触发。
        rootStack.setOnDragOver(this::onDragOver);
        rootStack.setOnDragDropped(this::onDragDropped);
        rootStack.setOnDragEntered(this::onDragEntered);
        rootStack.setOnDragExited(this::onDragExited);

        // 折叠头点击
        optionsHeader.setOnMouseClicked(e -> toggleOptions());

        // 密码联动
        passwordVisibleField.textProperty().bindBidirectional(passwordField.textProperty());
        passwordField.textProperty().addListener((o, a, b) -> updatePasswordFeedback());
        confirmField.textProperty().addListener((o, a, b) -> updatePasswordFeedback());

        // 输出路径：检测用户手动编辑
        outputFileField.textProperty().addListener((o, a, b) -> {
            if (b != null && !b.equals(a)) {
                outputPathUserEdited = true;
            }
        });

        // 双卷可否认加密：勾选时显示钓鱼文件/伪密码输入栏
        deniabilityCheck.selectedProperty().addListener((o, a, checked) -> {
            boolean show = checked != null && checked;
            decoyFileRow.setManaged(show);
            decoyFileRow.setVisible(show);
            fakePasswordRow.setManaged(show);
            fakePasswordRow.setVisible(show);
            fakePasswordConfirmRow.setManaged(show);
            fakePasswordConfirmRow.setVisible(show);
            if (show && (decoyFilePathField.getText() == null
                    || decoyFilePathField.getText().isEmpty())) {
                setDefaultDecoyFile();
            }
        });

        // 伪密码显示/隐藏切换
        fakeShowToggle.setOnAction(e -> {
            boolean showing = fakePasswordVisibleField.isVisible();
            if (showing) {
                fakePasswordVisibleField.setVisible(false);
                fakePasswordVisibleField.setManaged(false);
                fakePasswordField.setVisible(true);
                fakePasswordField.setManaged(true);
                fakePasswordField.setText(fakePasswordVisibleField.getText());
                fakeShowToggle.setText("👁");
            } else {
                fakePasswordField.setVisible(false);
                fakePasswordField.setManaged(false);
                fakePasswordVisibleField.setVisible(true);
                fakePasswordVisibleField.setManaged(true);
                fakePasswordVisibleField.setText(fakePasswordField.getText());
                fakeShowToggle.setText("🙈");
            }
        });

        // 钓鱼文件浏览按钮
        decoyFileBrowseBtn.setOnAction(e -> {
            FileChooser chooser = new FileChooser();
            chooser.setTitle(Messages.get("options.deniability.decoyFile.choose"));
            File f = chooser.showOpenDialog(stage());
            if (f != null) {
                decoyFilePathField.setText(f.getAbsolutePath());
            }
        });

        // 默认钓鱼文件按钮
        decoyFileDefaultBtn.setOnAction(e -> setDefaultDecoyFile());

        setupInfoTooltips();
        applyTexts();
        switchMode(Mode.ENCRYPT);
        updatePasswordFeedback();
        refreshKeyfileList();
    }

    /**
     * 由应用入口在场景就绪后调用，绑定主题、窗口拖动与最大化监听。
     */
    public void attachScene() {
        if (rootStack.getScene() != null) {
            themeManager.attach(rootStack.getScene());
            // 监听窗口最大化/还原，添加/移除 .maximized 样式类
            javafx.stage.Stage stage = stage();
            stage.maximizedProperty().addListener((obs, oldVal, newVal) -> {
                if (newVal) {
                    rootPane.getStyleClass().add("maximized");
                } else {
                    rootPane.getStyleClass().remove("maximized");
                }
            });
            // 如果窗口启动时已最大化（少见但防御性处理）
            if (stage.isMaximized()) {
                rootPane.getStyleClass().add("maximized");
            }
        }
        updateThemeButton();
        enableWindowDrag();
        enableCornerResize();
    }

    /**
     * 根据当前「加密后压缩」勾选状态、所选归档格式与「工具特有加密」设置，
     * 更新归档密码框的显隐与提示文案。
     *
     * <p>ZIP 始终可填密码；GZ / TAR.GZ / 7Z 仅在开启工具特有加密时才显示密码框。
     */
    private void updateArchivePasswordVisibility() {
        boolean compressOn = compressAfterCheck.isSelected();
        String fmt = compressFormatCombo.getValue();
        boolean isZip = fmt == null || "ZIP".equalsIgnoreCase(fmt);
        boolean customEnc = SettingsManager.isArchiveCustomEncryption();
        boolean canPassword = isZip || customEnc;
        boolean show = compressOn && canPassword;
        archivePasswordField.setManaged(show);
        archivePasswordField.setVisible(show);

        String key;
        if (isZip) {
            key = SettingsManager.isArchivePasswordFallback()
                    ? "options.archivePassword.placeholder"
                    : "options.archivePassword.placeholder.nofallback";
        } else {
            key = SettingsManager.isArchivePasswordFallback()
                    ? "options.archivePassword.placeholder.custom"
                    : "options.archivePassword.placeholder.custom.nofallback";
        }
        archivePasswordField.setPromptText(Messages.get(key));
    }

    // ================================================================
    // 文案 / 主题 / 语言
    // ================================================================
    private void applyTexts() {
        appTitleLabel.setText("ErgouTreeCrypt");
        langButton.setText(Messages.get("lang.toggle"));
        encryptTab.setText(Messages.get("nav.encrypt"));
        decryptTab.setText(Messages.get("nav.decrypt"));

        if (fileTab != null) {
            fileTab.setText(Messages.get("tab.file"));
        }
        if (mediaTab != null) {
            mediaTab.setText(Messages.get("tab.media"));
        }
        if (mediaViewController != null) {
            mediaViewController.applyTexts();
        }
        if (classicalTab != null) {
            classicalTab.setText(Messages.get("tab.classical"));
        }
        if (classicalViewController != null) {
            classicalViewController.applyTexts();
        }
        if (stegoTab != null) {
            stegoTab.setText(Messages.get("tab.stego"));
        }
        if (stegoViewController != null) {
            stegoViewController.applyTexts();
        }

        dropHintLabel.setText(Messages.get("file.drop.hint"));
        dropSubLabel.setText(Messages.get("file.drop.sub"));
        clearFileBtn.setText(Messages.get("file.clear"));
        chooseFileBtn.setText(Messages.get("file.choose.file"));
        chooseFolderBtn.setText(Messages.get("file.choose.folder"));

        outputLabel.setText(Messages.get("file.output.label"));
        outputBrowseBtn.setText(Messages.get("file.output.browse"));

        passwordCardTitle.setText(Messages.get("password.label"));
        passwordField.setPromptText(Messages.get("password.placeholder"));
        passwordVisibleField.setPromptText(Messages.get("password.placeholder"));
        showPasswordCheck.setText(Messages.get("password.show"));
        genPasswordBtn.setText(Messages.get("password.generate"));
        copyPasswordBtn.setText(Messages.get("password.copy"));
        confirmField.setPromptText(Messages.get("password.confirm.placeholder"));

        optionsTitle.setText(Messages.get("options.title"));
        commentsLabel.setText(Messages.get("options.comments"));
        commentsArea.setPromptText(Messages.get("options.comments.placeholder"));
        paranoidCheck.setText(Messages.get("options.paranoid"));
        reedSolomonCheck.setText(Messages.get("options.reedSolomon"));
        deniabilityCheck.setText(Messages.get("options.deniability"));
        decoyFilePathField.setPromptText(Messages.get("options.deniability.decoyFile.choose"));
        decoyFileDefaultBtn.setText(Messages.get("options.deniability.decoyFile.default"));
        decoyFileBrowseBtn.setText("...");
        fakePasswordField.setPromptText(Messages.get("options.deniability.fakePassword.placeholder"));
        fakePasswordVisibleField.setPromptText(Messages.get("options.deniability.fakePassword.placeholder"));
        fakeConfirmField.setPromptText(Messages.get("options.deniability.fakePassword.confirm.placeholder"));
        compressCheck.setText(Messages.get("options.compress"));
        compressAfterCheck.setText(Messages.get("options.compressAfter"));
        compressFormatCombo.setValue(SettingsManager.getDefaultCompressFormat());
        updateArchivePasswordVisibility();
        // 菜单
        settingsMenu.setText(Messages.get("menu.settings"));
        settingsMenuItem.setText(Messages.get("menu.settings.open"));
        aboutMenuItem.setText(Messages.get("menu.about"));
        splitCheck.setText(Messages.get("options.split"));
        splitUnitLabel.setText(Messages.get("options.split.size"));
        encryptDepthLabel.setText(Messages.get("options.encryptDepth"));
        forceDecryptCheck.setText(Messages.get("options.forceDecrypt"));
        autoUnzipCheck.setText(Messages.get("options.autoUnzip"));
        verifyFirstCheck.setText(Messages.get("options.verifyFirst"));
        recursiveExtractCheck.setText(Messages.get("options.recursiveExtract"));
        keyfilesLabel.setText(Messages.get("options.keyfiles"));
        keyfileOrderedCheck.setText(Messages.get("options.keyfiles.ordered"));
        addKeyfileBtn.setText(Messages.get("options.keyfiles.add"));
        keyfileEmptyLabel.setText(Messages.get("options.keyfiles.none"));
        clearFileBtn.setText(Messages.get("file.clear"));
        cancelBtn.setText(Messages.get("action.cancel"));
        verifyBtn.setText(Messages.get("action.verify"));

        if (!running) {
            statusLabel.setText(Messages.get("status.ready"));
        }
        cryptoProgressCaption.setText(Messages.get("progress.crypto"));
        archiveProgressCaption.setText(Messages.get("progress.archive"));
        setupInfoTooltips();
        updateActionButtonText();
        updatePasswordFeedback();
        refreshKeyfileList();
        if (selectedFile != null) {
            showFileInfo();
        }
    }

    /**
     * 为每个选项后面的 ⓘ 图标挂载 Tooltip，语言切换时重新调用以刷新文案。
     */
    private void setupInfoTooltips() {
        setTip(paranoidInfo, Messages.get("options.paranoid.tip"));
        setTip(reedSolomonInfo, Messages.get("options.reedSolomon.tip"));
        setTip(deniabilityInfo, Messages.get("options.deniability.tip"));
        setTip(compressInfo, Messages.get("options.compress.tip"));
        setTip(compressAfterInfo, Messages.get(
                SettingsManager.isArchiveCustomEncryption()
                        ? "options.compressAfter.tip"
                        : "options.compressAfter.tip.nocustom"));
        setTip(splitInfo, Messages.get("options.split.tip"));
        setTip(encryptDepthInfo, Messages.get("options.encryptDepth.tip"));
        setTip(forceDecryptInfo, Messages.get("options.forceDecrypt.tip"));
        setTip(autoUnzipInfo, Messages.get("options.autoUnzip.tip"));
        setTip(verifyFirstInfo, Messages.get("options.verifyFirst.tip"));
        setTip(recursiveExtractInfo, Messages.get("options.recursiveExtract.tip"));
        setTip(keyfileOrderedInfo, Messages.get("options.keyfiles.ordered.tip"));
    }

    /**
     * 将内置的高考真题 ZIP 解包到用户临时目录，设为默认钓鱼文件。
     */
    private void setDefaultDecoyFile() {
        try {
            java.nio.file.Path tmp = java.nio.file.Files.createTempFile("ergou_decoy_", ".zip");
            try (java.io.InputStream in = getClass().getResourceAsStream(
                    "/other/2025年高考全国一卷语文高考真题文档版（含答案）.zip")) {
                if (in == null) {
                    return;
                }
                java.nio.file.Files.copy(in, tmp,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            decoyFilePathField.setText(tmp.toAbsolutePath().toString());
        } catch (java.io.IOException ignored) {
        }
    }

    @FXML
    private void onToggleLang() {
        Messages.toggleLocale();
        applyTexts();
    }

    @FXML
    private void onToggleTheme() {
        // 循环切换模式：当前 → 下一个
        ThemeManager.Mode next = switch (themeManager.getMode()) {
            case LIGHT -> ThemeManager.Mode.DARK;
            case DARK -> ThemeManager.Mode.SYSTEM;
            case SYSTEM -> ThemeManager.Mode.LIGHT;
        };
        themeManager.setMode(next);
        updateThemeButton();
    }

    /**
     * 根据当前主题模式和视觉主题更新按钮图标。
     */
    private void updateThemeButton() {
        switch (themeManager.getMode()) {
            // ☀ 太阳 = 浅色
            case LIGHT -> themeButton.setText("☀");
            // ☽ 月亮 = 深色
            case DARK -> themeButton.setText("☽");
            // ⇄ = 跟随系统
            case SYSTEM -> themeButton.setText("⇄");
            default -> throw new IllegalStateException("Unexpected theme mode: " + themeManager.getMode());
        }
    }

    @FXML
    private void onMinimize() {
        stage().setIconified(true);
    }

    @FXML
    private void onClose() {
        themeManager.shutdown();
        taskRunner.shutdown();
        if (mediaViewController != null) {
            mediaViewController.shutdown();
        }
        if (classicalViewController != null) {
            classicalViewController.shutdown();
        }
        if (stegoViewController != null) {
            stegoViewController.shutdown();
        }
        Platform.exit();
    }

    @FXML
    private void onOpenSettings() {
        SettingsDialog.show(stage(), themeManager);
        // 设置变更后刷新占位符与 tip（如归档密码回退开关）
        applyTexts();
    }

    @FXML
    private void onAbout() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.initOwner(stage());
        alert.setTitle(Messages.get("menu.about"));
        alert.setHeaderText("ErgouTreeCrypt");
        alert.setContentText(Messages.get("about.text") + "\n\n" + Messages.get("about.version"));
        alert.showAndWait();
    }

    // ================================================================
    // 模式切换
    // ================================================================
    private void switchMode(Mode m) {
        this.mode = m;
        encryptTab.setSelected(m == Mode.ENCRYPT);
        decryptTab.setSelected(m == Mode.DECRYPT);

        boolean encrypting = m == Mode.ENCRYPT;
        setVisible(encryptOptions, encrypting);
        setVisible(decryptOptions, !encrypting);
        setVisible(confirmBox, encrypting);
        setVisible(verifyBtn, !encrypting && selectedFile != null);

        // 切换模式时，若用户未手动编辑输出路径，则根据当前模式重新计算默认输出路径。
        // 例如从 DECRYPT 切回 ENCRYPT 时，输出应从“父目录”更新为“文件名.ergou”。
        if (selectedFile != null && !outputPathUserEdited) {
            outputFileField.setText(computeDefaultOutput());
        }

        updateActionButtonText();
        updatePasswordFeedback();
    }

    private void updateActionButtonText() {
        actionBtn.setText(mode == Mode.ENCRYPT
                ? Messages.get("action.encrypt") : Messages.get("action.decrypt"));
    }

    // ================================================================
    // 文件选择 / 拖拽
    // ================================================================
    private void onChooseFile(MouseEvent e) {
        chooseFile();
    }

    @FXML
    private void onChooseFileBtn() {
        chooseFile();
    }

    @FXML
    private void onChooseFolderBtn() {
        javafx.stage.DirectoryChooser chooser = new javafx.stage.DirectoryChooser();
        chooser.setTitle(Messages.get("file.choose.folder"));
        File f = chooser.showDialog(stage());
        if (f != null) {
            setSelectedFile(f);
        }
    }

    private void chooseFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("file.choose"));
        File f = chooser.showOpenDialog(stage());
        if (f != null) {
            setSelectedFile(f);
        }
    }

    private void onDragEntered(DragEvent e) {
        if (e.getDragboard().hasFiles()) {
            dropZone.getStyleClass().add("drag-over");
        }
        e.consume();
    }

    private void onDragExited(DragEvent e) {
        // 仅当拖拽真正离开窗口时才移除样式；
        // 在子控件间移动导致的短暂 exited 由 rootStack 兜底容忍。
        if (!rootStack.isHover()) {
            dropZone.getStyleClass().remove("drag-over");
        }
        e.consume();
    }

    private void onDragOver(DragEvent e) {
        if (e.getDragboard().hasFiles()) {
            e.acceptTransferModes(TransferMode.COPY);
            if (!dropZone.getStyleClass().contains("drag-over")) {
                dropZone.getStyleClass().add("drag-over");
            }
        }
        e.consume();
    }

    private void onDragDropped(DragEvent e) {
        Dragboard db = e.getDragboard();
        boolean ok = false;
        if (db.hasFiles() && !db.getFiles().isEmpty()) {
            setSelectedFile(db.getFiles().getFirst());
            ok = true;
        }
        dropZone.getStyleClass().remove("drag-over");
        e.setDropCompleted(ok);
        e.consume();
    }

    private void setSelectedFile(File f) {
        this.selectedFile = f;
        this.outputPathUserEdited = false;
        // 依据扩展名智能切换模式：仅 .ergou/.pcv 加密卷和分卷碎片自动切到解密模式。
        // 普通压缩包（.zip/.7z/.rar 等）不再自动切换，因为用户可能想加密压缩包本身。
        String name = f.getName().toLowerCase();
        if (name.endsWith(".pcv") || name.endsWith(".ergou")
                || Splitter.isSplitChunkPath(f.getAbsolutePath())) {
            switchMode(Mode.DECRYPT);
        }
        showFileInfo();
    }

    private void showFileInfo() {
        fileNameLabel.setText(selectedFile.getName());
        if (selectedFile.isDirectory()) {
            fileMetaLabel.setText(Messages.get("file.folder"));
        } else {
            fileMetaLabel.setText(Messages.format("file.size", FileSizes.human(selectedFile.length())));
        }
        setVisible(fileCard, true);
        setVisible(dropZone, false);
        setVisible(outputCard, true);
        setVisible(verifyBtn, mode == Mode.DECRYPT);
        if (!outputPathUserEdited) {
            outputFileField.setText(computeDefaultOutput());
        }
    }

    private String computeDefaultOutput() {
        if (selectedFile == null) {
            return "";
        }
        String path = selectedFile.getAbsolutePath();
        if (mode == Mode.ENCRYPT) {
            // 文件夹：默认输出到其父目录（结果会是同名文件夹或同名压缩包）
            if (selectedFile.isDirectory()) {
                File parent = selectedFile.getParentFile();
                return parent != null ? parent.getAbsolutePath() : path;
            }
            return path + ".ergou";
        }
        // 解密：文件夹/压缩包/分卷碎片输出到父目录；单文件去扩展名
        if (selectedFile.isDirectory()
                || ArchiveExtractor.isArchive(selectedFile.toPath())
                || Splitter.isSplitChunkPath(path)) {
            File parent = selectedFile.getParentFile();
            return parent != null ? parent.getAbsolutePath() : path;
        }
        return deriveDecryptOutput(path);
    }

    @FXML
    private void onClearFile() {
        selectedFile = null;
        outputPathUserEdited = false;
        setVisible(fileCard, false);
        setVisible(outputCard, false);
        setVisible(verifyBtn, false);
        setVisible(dropZone, true);
    }

    @FXML
    private void onBrowseOutput() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("file.output.choose"));
        File cur = new File(outputFileField.getText());
        if (cur.getParentFile() != null && cur.getParentFile().exists()) {
            chooser.setInitialDirectory(cur.getParentFile());
        }
        chooser.setInitialFileName(cur.getName());
        File f = chooser.showSaveDialog(stage());
        if (f != null) {
            outputFileField.setText(f.getAbsolutePath());
            outputPathUserEdited = true;
        }
    }

    // ================================================================
    // 密码
    // ================================================================
    @FXML
    private void onToggleShowPassword() {
        boolean show = showPasswordCheck.isSelected();
        setVisible(passwordVisibleField, show);
        setVisible(passwordField, !show);
    }

    @FXML
    private void onGeneratePassword() {
        String pwd = PasswordStrength.generate(20);
        passwordField.setText(pwd);
        if (mode == Mode.ENCRYPT) {
            confirmField.setText(pwd);
        }
        showPasswordCheck.setSelected(true);
        onToggleShowPassword();
        toast.success(Messages.get("toast.generated"));
    }

    @FXML
    private void onCopyPassword() {
        String pwd = passwordField.getText();
        if (pwd == null || pwd.isEmpty()) {
            return;
        }
        ClipboardContent content = new ClipboardContent();
        content.putString(pwd);
        Clipboard.getSystemClipboard().setContent(content);
        toast.info(Messages.get("toast.copied"));
    }

    private void updatePasswordFeedback() {
        String pwd = passwordField.getText();
        PasswordStrength.Level level = PasswordStrength.evaluate(pwd);
        String label = switch (level) {
            case EMPTY -> Messages.get("password.strength.empty");
            case WEAK -> Messages.get("password.strength.weak");
            case MEDIUM -> Messages.get("password.strength.medium");
            case STRONG -> Messages.get("password.strength.strong");
        };
        strengthLabel.setText(level == PasswordStrength.Level.EMPTY
                ? label : Messages.format("password.strength", label));

        // 仅加密模式校验确认密码
        boolean mismatch = mode == Mode.ENCRYPT
                && pwd != null && !pwd.isEmpty()
                && !pwd.equals(confirmField.getText());
        mismatchLabel.setText(mismatch ? Messages.get("password.mismatch") : "");
        setVisible(mismatchLabel, mismatch);
    }

    // ================================================================
    // 高级选项折叠
    // ================================================================
    private void toggleOptions() {
        optionsExpanded = !optionsExpanded;
        setVisible(optionsBody, optionsExpanded);
        optionsChevron.setText(optionsExpanded ? "⌃" : "⌄");
    }

    // ================================================================
    // 设置栏折叠
    // ================================================================
    // ================================================================
    // 密钥文件
    // ================================================================
    @FXML
    private void onAddKeyfile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("options.keyfiles.add"));
        List<File> files = chooser.showOpenMultipleDialog(stage());
        if (files != null) {
            keyfiles.addAll(files);
            refreshKeyfileList();
        }
    }

    private void refreshKeyfileList() {
        keyfileList.getChildren().clear();
        for (File f : keyfiles) {
            HBox row = new HBox(8);
            row.getStyleClass().add("keyfile-row");
            Label name = new Label(f.getName());
            Region spacer = new Region();
            HBox.setHgrow(spacer, javafx.scene.layout.Priority.ALWAYS);
            Button remove = new Button("✕");
            remove.getStyleClass().add("btn-ghost");
            remove.setOnAction(e -> {
                keyfiles.remove(f);
                refreshKeyfileList();
            });
            row.getChildren().addAll(name, spacer, remove);
            keyfileList.getChildren().add(row);
        }
        setVisible(keyfileEmptyLabel, keyfiles.isEmpty());
    }

    // ================================================================
    // 加 / 解密执行
    // ================================================================
    @FXML
    private void onAction() {
        if (running) {
            return;
        }
        if (selectedFile == null) {
            toast.error(Messages.get("toast.no.file"));
            return;
        }
        String pwd = passwordField.getText();
        if (mode == Mode.ENCRYPT && pwd != null && !pwd.isEmpty()
                && !pwd.equals(confirmField.getText())) {
            toast.error(Messages.get("toast.no.password.confirm"));
            return;
        }
        // 双卷可否认加密：验证钓鱼文件已选择且伪密码确认匹配
        if (mode == Mode.ENCRYPT && deniabilityCheck.isSelected()) {
            String decoyPath = decoyFilePathField.getText();
            if (decoyPath == null || decoyPath.isEmpty()
                    || !java.nio.file.Files.exists(java.nio.file.Path.of(decoyPath))) {
                toast.error(Messages.get("toast.no.file"));
                return;
            }
            String fakePwd = fakePasswordField.getText();
            if (fakePwd != null && !fakePwd.isEmpty()
                    && !fakePwd.equals(fakeConfirmField.getText())) {
                toast.error(Messages.get("toast.no.password.confirm"));
                return;
            }
            // 真密码和伪密码不能相同（否则无法区分两个卷）
            String realPwd = pwd != null ? pwd : "";
            String actualFakePwd = fakePwd != null ? fakePwd : "";
            if (!realPwd.isEmpty() && !actualFakePwd.isEmpty()
                    && realPwd.equals(actualFakePwd)) {
                toast.error(Messages.get("toast.deniability.samePassword"));
                return;
            }
        }
        if (mode == Mode.ENCRYPT) {
            startEncrypt(pwd);
        } else {
            startDecrypt(pwd);
        }
    }

    @FXML
    private void onVerifyIntegrity() {
        if (running) {
            return;
        }
        if (selectedFile == null) {
            toast.error(Messages.get("toast.no.file"));
            return;
        }
        String pwd = passwordField.getText();
        startVerify(pwd);
    }

    /**
     * 启动通用文件的完整性校验（只读，不输出明文）。
     *
     * @param pwd 密码（可为空字符串）
     */
    private void startVerify(String pwd) {
        String in = selectedFile.getAbsolutePath();

        // 自动检测分卷与可否认加密
        boolean isSplit = Splitter.isSplitChunkPath(in);

        VerifyRequest req = new VerifyRequest();
        req.setInputFile(in);
        req.setPassword(pwd == null ? "" : pwd);
        req.setRecombine(isSplit);
        req.setForceDecrypt(forceDecryptCheck.isSelected());
        req.setRsCodecs(new RsCodecs());
        if (!keyfiles.isEmpty()) {
            req.setKeyfiles(toPaths(keyfiles));
        }

        FxProgressReporter reporter = newReporter();
        req.setReporter(reporter);
        runTask(() -> Verifier.verify(req), Messages.get("status.success.verify"));
    }

    private void startEncrypt(String pwd) {
        String out = outputFileField.getText();

        String archiveFormat = null;
        String archivePwd = null;
        if (compressAfterCheck.isSelected() && compressFormatCombo.getValue() != null) {
            archiveFormat = compressFormatCombo.getValue().replace(".", "_");
            String ap = archivePasswordField.getText();
            archivePwd = (ap == null || ap.isEmpty()) ? null : ap;
        }

        // 文件夹加密：走 FolderCrypt 编排
        if (selectedFile.isDirectory()) {
            if (out == null || out.isEmpty()) {
                File parent = selectedFile.getParentFile();
                out = parent != null ? parent.getAbsolutePath() : selectedFile.getAbsolutePath();
            }
            final String outputDir = out;
            FolderCrypt.EncryptOptions opts = new FolderCrypt.EncryptOptions();
            opts.password = pwd == null ? "" : pwd;
            opts.comments = commentsArea.getText() == null ? "" : commentsArea.getText();
            opts.paranoid = paranoidCheck.isSelected();
            opts.reedSolomon = reedSolomonCheck.isSelected();
            opts.deniability = deniabilityCheck.isSelected();
            opts.split = splitCheck.isSelected();
            opts.chunkSize = splitSizeSpinner.getValue();
            opts.archiveFormat = archiveFormat;
            opts.archivePassword = archivePwd;
            opts.rsCodecs = new RsCodecs();
            if (!keyfiles.isEmpty()) {
                opts.keyfiles = toPaths(keyfiles);
                opts.keyfileOrdered = keyfileOrderedCheck.isSelected();
            }
            opts.threadCount = SettingsManager.getThreadCount();
            opts.encryptDepth = encryptDepthSpinner.getValue();
            FxProgressReporter reporter = newReporter();
            opts.reporter = reporter;
            runTask(() -> FolderCrypt.encryptFolder(
                            selectedFile.toPath(), Path.of(outputDir), opts),
                    Messages.get("status.success.encrypt"));
            return;
        }

        // 单文件加密
        if (out == null || out.isEmpty()) {
            out = selectedFile.getAbsolutePath() + ".ergou";
        }
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(selectedFile.getAbsolutePath());
        req.setOutputFile(out);
        req.setPassword(pwd == null ? "" : pwd);
        req.setComments(commentsArea.getText() == null ? "" : commentsArea.getText());
        req.setParanoid(paranoidCheck.isSelected());
        req.setReedSolomon(reedSolomonCheck.isSelected());
        // 双卷可否认加密
        boolean deniability = deniabilityCheck.isSelected();
        if (deniability) {
            req.setDualDeniability(true);
            req.setDecoyFilePath(decoyFilePathField.getText());
            req.setFakePassword(fakePasswordField.getText());
            // 旧版 deniability 不再同时启用
            req.setDeniability(false);
        } else {
            req.setDeniability(false);
        }
        req.setCompress(compressCheck.isSelected());
        req.setArchiveFormat(archiveFormat);
        req.setArchivePassword(archivePwd);
        req.setSplit(splitCheck.isSelected());
        req.setChunkSize(splitSizeSpinner.getValue());
        req.setRsCodecs(new RsCodecs());
        if (!keyfiles.isEmpty()) {
            req.setKeyfiles(toPaths(keyfiles));
            req.setKeyfileOrdered(keyfileOrderedCheck.isSelected());
        }

        FxProgressReporter reporter = newReporter();
        req.setReporter(reporter);
        runTask(() -> Encryptor.encrypt(req), Messages.get("status.success.encrypt"));
    }

    private void startDecrypt(String pwd) {
        String in = selectedFile.getAbsolutePath();

        // 文件夹 / 压缩包 / 分卷碎片：自动识别并整体解密（含分卷碎片合并、递归解密）
        if (selectedFile.isDirectory()
                || ArchiveExtractor.isArchive(selectedFile.toPath())
                || Splitter.isSplitChunkPath(in)) {
            startAutoDecrypt(pwd);
            return;
        }

        String out = outputFileField.getText();
        if (out == null || out.isEmpty()) {
            out = deriveDecryptOutput(in);
        }
        DecryptRequest req = new DecryptRequest();
        req.setInputFile(in);
        req.setOutputFile(out);
        req.setPassword(pwd == null ? "" : pwd);
        req.setForceDecrypt(forceDecryptCheck.isSelected());
        req.setAutoUnzip(autoUnzipCheck.isSelected());
        req.setVerifyFirst(verifyFirstCheck.isSelected());
        req.setRsCodecs(new RsCodecs());
        if (!keyfiles.isEmpty()) {
            req.setKeyfiles(toPaths(keyfiles));
        }

        FxProgressReporter reporter = newReporter();
        req.setReporter(reporter);
        runTask(() -> Decryptor.decrypt(req), Messages.get("status.success.decrypt"));
    }

    private void startAutoDecrypt(String pwd) {
        String outText = outputFileField.getText();
        Path input = selectedFile.toPath();
        Path outDir;
        if (outText != null && !outText.isEmpty()) {
            Path p = Path.of(outText);
            outDir = (selectedFile.isDirectory() || ArchiveExtractor.isArchive(input))
                    ? p : (p.getParent() != null ? p.getParent() : p);
        } else {
            outDir = input.getParent() != null ? input.getParent() : Path.of(".");
        }

        FolderCrypt.DecryptOptions opts = new FolderCrypt.DecryptOptions();
        opts.password = pwd == null ? "" : pwd;
        opts.archivePassword = null;
        opts.forceDecrypt = forceDecryptCheck.isSelected();
        opts.recursiveExtract = recursiveExtractCheck.isSelected();
        opts.autoUnzip = autoUnzipCheck.isSelected();
        opts.rsCodecs = new RsCodecs();
        if (!keyfiles.isEmpty()) {
            opts.keyfiles = toPaths(keyfiles);
        }
        opts.threadCount = SettingsManager.getThreadCount();

        // 快速预检：若归档受密码保护，优先用解密密码作为归档密码（加密后压缩回退场景）；
        // 二者皆空时再弹窗询问。
        boolean needPrecheck = ArchiveExtractor.isArchive(input);
        if (needPrecheck) {
            try {
                if (ArchiveExtractor.hasEncryptedEntries(input)) {
                    String effectiveArch = ArchivePacker.resolveArchivePassword(
                            opts.archivePassword, opts.password);
                    if (effectiveArch == null || effectiveArch.isEmpty()) {
                        String archPwd = showArchivePasswordDialog();
                        if (archPwd == null || archPwd.isEmpty()) {
                            return;
                        }
                        opts.archivePassword = archPwd;
                    } else {
                        opts.archivePassword = effectiveArch;
                    }
                }
            } catch (IOException ignored) {
                // 预检失败（极少发生），回退到运行时检测
            }
        }

        setRunning(true);
        progressBar.setProgress(0);
        archiveProgressBar.setProgress(0);
        setVisible(archiveProgressBox, false);
        statusLabel.setText(Messages.get("status.decrypting"));

        FxProgressReporter reporter = newReporter();
        opts.reporter = reporter;

        final Path finalOutDir = outDir;
        taskRunner.submit(() -> {
            try {
                FolderCrypt.decryptAuto(input, finalOutDir, opts);
            } catch (Exception firstErr) {
                // 若预检遗漏了加密条目（如部分 TAR.GZ），运行时仍可弹窗重试
                boolean needPassword = firstErr instanceof ArchiveExtractor.PasswordNeededException
                        || isEncryptionRelated(firstErr);
                if (!needPassword) {
                    throw firstErr;
                }
                java.util.concurrent.CompletableFuture<String> future =
                        new java.util.concurrent.CompletableFuture<>();
                Platform.runLater(() -> future.complete(showArchivePasswordDialog()));
                String archPwd;
                try {
                    archPwd = future.get();
                } catch (Exception ignored) {
                    throw new IOException("Archive password required but dialog interrupted", firstErr);
                }
                if (archPwd == null || archPwd.isEmpty()) {
                    throw new IOException("Archive password required but not provided", firstErr);
                }
                opts.archivePassword = archPwd;
                FolderCrypt.decryptAuto(input, finalOutDir, opts);
            }
        }, () -> {
            progressBar.setProgress(1);
            statusLabel.setText(Messages.get("status.success.decrypt"));
            toast.success(Messages.get("status.success.decrypt"));
            setRunning(false);
        }, err -> {
            String msg = err.getMessage() == null ? err.toString() : err.getMessage();
            statusLabel.setText(Messages.format("status.failed", msg));
            toast.error(Messages.format("status.failed", msg));
            setRunning(false);
        });
    }

    private String showArchivePasswordDialog() {
        javafx.scene.control.TextInputDialog dlg = new javafx.scene.control.TextInputDialog();
        dlg.initOwner(stage());
        dlg.setTitle(Messages.get("archivePassword.title"));
        dlg.setHeaderText(Messages.get("archivePassword.prompt"));
        dlg.setContentText(Messages.get("archivePassword.label"));
        return dlg.showAndWait().orElse("");
    }

    private String deriveDecryptOutput(String in) {
        String lower = in.toLowerCase();
        if (lower.endsWith(".ergou")) {
            return in.substring(0, in.length() - ".ergou".length());
        }
        if (lower.endsWith(".pcv")) {
            return in.substring(0, in.length() - ".pcv".length());
        }
        return in + ".decrypted";
    }

    private FxProgressReporter newReporter() {
        FxProgressReporter reporter = new FxProgressReporter(
                statusLabel::setText,
                (fraction, info) -> {
                    progressBar.setProgress(fraction);
                    progressInfoLabel.setText(info == null ? "" : info);
                },
                (fraction, info) -> {
                    archiveProgressBar.setProgress(fraction);
                    if (info != null && !info.isEmpty()) {
                        progressInfoLabel.setText(info);
                    }
                },
                visible -> setVisible(archiveProgressBox, visible),
                cancelBtn::setVisible);
        activeReporter = reporter;
        return reporter;
    }

    private void runTask(TaskRunner.CheckedRunnable work, String successMsg) {
        setRunning(true);
        progressBar.setProgress(0);
        archiveProgressBar.setProgress(0);
        setVisible(archiveProgressBox, false);
        statusLabel.setText(Messages.get("action.processing"));
        taskRunner.submit(work,
                () -> {
                    progressBar.setProgress(1);
                    statusLabel.setText(successMsg);
                    toast.success(successMsg);
                    setRunning(false);
                },
                err -> {
                    // 区分用户主动取消与真正的操作失败
                    if (err instanceof InterruptedException) {
                        statusLabel.setText(Messages.get("status.cancelled"));
                        toast.info(Messages.get("status.cancelled"));
                    } else {
                        String msg = err.getMessage() == null ? err.toString() : err.getMessage();
                        statusLabel.setText(Messages.format("status.failed", msg));
                        toast.error(Messages.format("status.failed", msg));
                    }
                    setRunning(false);
                });
    }

    @FXML
    private void onCancel() {
        if (activeReporter != null) {
            activeReporter.cancel();
            statusLabel.setText(Messages.get("status.cancelled"));
        }
    }

    private void setRunning(boolean r) {
        this.running = r;
        actionBtn.setDisable(r);
        setVisible(progressBox, r);
        setVisible(cancelBtn, r);
        encryptTab.setDisable(r);
        decryptTab.setDisable(r);
        verifyBtn.setDisable(r);
        if (!r) {
            actionBtn.setDisable(false);
        }
    }

    // ================================================================
    // 工具类
    // ================================================================

    private void enableWindowDrag() {
        final double[] offset = new double[2];
        titleBar.setOnMousePressed(e -> {
            offset[0] = e.getSceneX();
            offset[1] = e.getSceneY();
        });
        titleBar.setOnMouseDragged(e -> {
            Stage s = stage();
            s.setX(e.getScreenX() - offset[0]);
            s.setY(e.getScreenY() - offset[1]);
        });
    }

    /**
     * 在窗口四角放置不可见的拖拽手柄，实现等比例缩放。
     *
     * <p>仅四角可拖拽，边框中点不响应。拖拽时保持窗口当前宽高比不变。
     * 最大化时手柄自动禁用（由 {@code .maximized} CSS 类配合隐藏）。
     */
    private void enableCornerResize() {
        final double gripSize = 8;
        Region tl = cornerGrip(gripSize, Cursor.NW_RESIZE, -1, -1);
        Region tr = cornerGrip(gripSize, Cursor.NE_RESIZE, 1, -1);
        Region bl = cornerGrip(gripSize, Cursor.SW_RESIZE, -1, 1);
        Region br = cornerGrip(gripSize, Cursor.SE_RESIZE, 1, 1);

        StackPane.setAlignment(tl, Pos.TOP_LEFT);
        StackPane.setAlignment(tr, Pos.TOP_RIGHT);
        StackPane.setAlignment(bl, Pos.BOTTOM_LEFT);
        StackPane.setAlignment(br, Pos.BOTTOM_RIGHT);

        // 手柄置于最顶层，但不阻挡内容交互（尺寸极小，仅角部区域）
        tl.setViewOrder(-100);
        tr.setViewOrder(-100);
        bl.setViewOrder(-100);
        br.setViewOrder(-100);

        rootStack.getChildren().addAll(tl, tr, bl, br);
    }

    /**
     * 创建一个透明的角部拖拽手柄。
     *
     * @param size   手柄尺寸 (px)
     * @param cursor 鼠标悬停光标
     * @param signX  宽度变化方向：1=向右扩展，-1=向左扩展
     * @param signY  高度变化方向：1=向下扩展，-1=向上扩展
     */
    private Region cornerGrip(double size, Cursor cursor, int signX, int signY) {
        Region grip = new Region();
        grip.setPrefSize(size, size);
        grip.setMinSize(size, size);
        grip.setMaxSize(size, size);
        grip.setCursor(cursor);
        grip.setStyle("-fx-background-color: transparent;");

        final double[] startScreenX = new double[1];
        final double[] startScreenY = new double[1];
        final double[] startW = new double[1];
        final double[] startH = new double[1];
        final double[] startStageX = new double[1];
        final double[] startStageY = new double[1];

        grip.setOnMousePressed(e -> {
            if (stage().isMaximized()) {
                return;
            }
            startScreenX[0] = e.getScreenX();
            startScreenY[0] = e.getScreenY();
            startW[0] = stage().getWidth();
            startH[0] = stage().getHeight();
            startStageX[0] = stage().getX();
            startStageY[0] = stage().getY();
            e.consume();
        });

        grip.setOnMouseDragged(e -> {
            if (stage().isMaximized()) {
                return;
            }
            double dx = (e.getScreenX() - startScreenX[0]) * signX;
            double dy = (e.getScreenY() - startScreenY[0]) * signY;

            double aspect = startW[0] / startH[0];

            // 以变化较大的维度为基准，另一维度按比例跟随
            double newW, newH;
            if (Math.abs(dx / aspect) > Math.abs(dy)) {
                newW = startW[0] + dx;
                newH = newW / aspect;
            } else {
                newH = startH[0] + dy;
                newW = newH * aspect;
            }

            // 应用最小尺寸约束
            if (newW < stage().getMinWidth()) {
                newW = stage().getMinWidth();
                newH = newW / aspect;
            }
            if (newH < stage().getMinHeight()) {
                newH = stage().getMinHeight();
                newW = newH * aspect;
            }

            // 对于左/上角拖拽，同步调整窗口位置
            if (signX < 0) {
                stage().setX(startStageX[0] + (startW[0] - newW));
            }
            if (signY < 0) {
                stage().setY(startStageY[0] + (startH[0] - newH));
            }

            stage().setWidth(newW);
            stage().setHeight(newH);
            e.consume();
        });

        return grip;
    }

    private Stage stage() {
        return (Stage) rootStack.getScene().getWindow();
    }

    /**
     * 操作模式。
     */
    private enum Mode {ENCRYPT, DECRYPT}
}
