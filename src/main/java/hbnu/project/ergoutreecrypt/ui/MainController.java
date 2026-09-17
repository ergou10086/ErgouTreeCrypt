package hbnu.project.ergoutreecrypt.ui;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.fileops.ArchivePasswordProvider;
import hbnu.project.ergoutreecrypt.fileops.ArchivePostExtract;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.exception.ExceptionMapper;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard;
import hbnu.project.ergoutreecrypt.filetypes.OutputNaming;
import hbnu.project.ergoutreecrypt.history.HistoryService;
import hbnu.project.ergoutreecrypt.history.OperationType;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.settings.Argon2DesktopMode;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.ui.support.*;
import hbnu.project.ergoutreecrypt.volume.*;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

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
    @FXML
    private Menu historyMenu;
    @FXML
    private Menu logsMenu;

    /** 本次点击已由 MenuBar 拦截处理，避免 showing 回调再次触发。 */
    private final java.util.Set<Menu> menuClickHandled = new java.util.HashSet<>();

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
    private Tab imageCryptTab;
    @FXML
    private ImageCryptController imageCryptViewController;
    @FXML
    private Tab classicalTab;
    @FXML
    private ClassicalCryptController classicalViewController;
    @FXML
    private Tab stegoTab;
    @FXML
    private ImageStegoController stegoViewController;
    @FXML
    private Tab fileStegoTab;
    @FXML
    private FileStegoController fileStegoViewController;

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
    @FXML
    private VBox fileListCard;
    @FXML
    private Label fileListTitleLabel;
    @FXML
    private Label fileListMetaLabel;
    @FXML
    private ScrollPane fileListScroll;
    @FXML
    private VBox fileListBox;
    @FXML
    private Button addFilesBtn;
    @FXML
    private Button clearFilesBtn;

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
    private HBox compressLevelRow;
    @FXML
    private Label compressLevelLabel;
    @FXML
    private Slider compressLevelSlider;
    @FXML
    private Label compressLevelValueLabel;
    @FXML
    private CheckBox compressBeforeCheck;
    @FXML
    private Label compressBeforeInfo;
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
    private CheckBox decryptThenExtractCheck;
    @FXML
    private Label decryptThenExtractInfo;
    @FXML
    private PasswordField decryptArchivePasswordField;
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
    /**
     * 通用加解密的全部选中项：可能是单个文件、单个文件夹，或一批文件。
     *
     * <p>只选一个文件夹时按「文件夹模式」处理；多选时一律按「一批文件」处理
     * （其中夹带的文件夹会被跳过并记入批处理失败列表）。
     */
    private final List<File> selectedFiles = new ArrayList<>();
    private boolean optionsExpanded = false;
    private boolean running = false;
    private FxProgressReporter activeReporter;

    private static void setVisible(Region node, boolean visible) {
        node.setVisible(visible);
        node.setManaged(visible);
    }

    /**
     * 读取压缩级别滑条的当前整数值（四舍五入）。
     *
     * @return 压缩级别（1–22）
     */
    private int currentCompressLevel() {
        return (int) Math.round(compressLevelSlider.getValue());
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

        // 加密前压缩：压缩级别滑条绑定
        compressLevelRow.managedProperty().bind(compressCheck.selectedProperty());
        compressLevelRow.visibleProperty().bind(compressCheck.selectedProperty());
        compressLevelSlider.valueProperty().addListener((o, a, b) ->
                compressLevelValueLabel.setText(String.valueOf(currentCompressLevel())));

        // 加密前压缩：Zstandard 压缩的内容移动端无法解密，勾选时弹出提示
        compressCheck.selectedProperty().addListener((o, wasSelected, isSelected) -> {
            if (isSelected) {
                Alert alert = new Alert(Alert.AlertType.WARNING);
                alert.initOwner(stage());
                alert.setTitle(Messages.get("options.compress"));
                alert.setHeaderText(Messages.get("options.compress.mobile.warning.header"));
                alert.setContentText(Messages.get("options.compress.mobile.warning"));
                alert.showAndWait();
            }
        });

        // 压缩后加密 / 加密后压缩：共用同一组归档格式与归档密码控件
        compressFormatCombo.getItems().setAll("ZIP", "GZ", "TAR.GZ", "7Z");
        // 两者都是「压缩策略」，语义互斥：勾选一个自动取消另一个，避免出现
        // 「先打包再加密、加密完再打包」这类无意义组合
        compressBeforeCheck.selectedProperty().addListener((o, wasOn, isOn) -> {
            if (isOn && compressAfterCheck.isSelected()) {
                compressAfterCheck.setSelected(false);
            }
            updateArchivePasswordVisibility();
        });
        compressAfterCheck.selectedProperty().addListener((o, wasOn, isOn) -> {
            if (isOn && compressBeforeCheck.isSelected()) {
                compressBeforeCheck.setSelected(false);
            }
            updateArchivePasswordVisibility();
        });
        javafx.beans.binding.BooleanBinding archiving = compressAfterCheck.selectedProperty()
                .or(compressBeforeCheck.selectedProperty());
        compressFormatCombo.managedProperty().bind(archiving);
        compressFormatCombo.visibleProperty().bind(archiving);
        // 归档密码框：ZIP 始终可填；GZ/TAR.GZ/7Z 仅在开启「工具特有加密」时才显示
        compressFormatCombo.valueProperty().addListener((o, a, b) -> updateArchivePasswordVisibility());
        updateArchivePasswordVisibility();

        // 解密归档密码框：解压后解密 / 解密后解压任一勾选时显示
        autoUnzipCheck.selectedProperty().addListener((o, a, b) -> updateDecryptArchivePasswordVisibility());
        decryptThenExtractCheck.selectedProperty().addListener((o, a, b) -> updateDecryptArchivePasswordVisibility());
        updateDecryptArchivePasswordVisibility();

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

        installMenuAsButton(historyMenu, this::onOpenHistory);
        installMenuAsButton(logsMenu, this::onToggleLogs);

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
        new WindowChrome(rootStack, titleBar, this::stage).install();
        installTabShortcuts();
    }

    /**
     * 为顶部标签条注册键盘切换手势。
     *
     * <p>标签多、窗口窄时总有标签排不下，键盘切换比伸手去点更顺手：
     * {@code Ctrl+Tab} / {@code Ctrl+Shift+Tab} 前后循环，{@code Ctrl+1..9} 直达第 n 个标签。
     */
    private void installTabShortcuts() {
        Scene scene = rootStack.getScene();
        if (scene == null) {
            return;
        }
        scene.addEventFilter(KeyEvent.KEY_PRESSED, e -> {
            if (!e.isControlDown() || e.isAltDown() || e.isMetaDown()) {
                return;
            }
            int count = mainTabs.getTabs().size();
            if (count == 0) {
                return;
            }
            if (e.getCode() == KeyCode.TAB) {
                int current = Math.max(0, mainTabs.getSelectionModel().getSelectedIndex());
                int next = e.isShiftDown()
                        ? (current - 1 + count) % count
                        : (current + 1) % count;
                mainTabs.getSelectionModel().select(next);
                e.consume();
                return;
            }
            int index = tabIndexForKey(e.getCode());
            if (index >= 0 && index < count) {
                mainTabs.getSelectionModel().select(index);
                e.consume();
            }
        });
    }

    /**
     * 把数字键映射为从 0 开始的标签序号。
     *
     * @param code 按键
     * @return 0..8 对应第 1..9 个标签；非数字键返回 -1
     */
    private static int tabIndexForKey(KeyCode code) {
        if (!code.isDigitKey()) {
            return -1;
        }
        String name = code.name();
        int digit = name.charAt(name.length() - 1) - '0';
        return digit >= 1 && digit <= 9 ? digit - 1 : -1;
    }

    /**
     * 根据当前「加密后压缩」勾选状态、所选归档格式与「工具特有加密」设置，
     * 更新归档密码框的显隐与提示文案。
     *
     * <p>ZIP 始终可填密码；GZ / TAR.GZ / 7Z 仅在开启工具特有加密时才显示密码框。
     */
    private void updateArchivePasswordVisibility() {
        boolean compressOn = compressAfterCheck.isSelected() || compressBeforeCheck.isSelected();
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

    /**
     * 更新解密归档密码框的可见性：解压后解密 / 解密后解压任一勾选时显示。
     */
    private void updateDecryptArchivePasswordVisibility() {
        boolean show = autoUnzipCheck.isSelected() || decryptThenExtractCheck.isSelected();
        decryptArchivePasswordField.setManaged(show);
        decryptArchivePasswordField.setVisible(show);
    }

    /**
     * 读取解密归档密码框的输入。
     *
     * @return 非空密码；输入为空时返回 null
     */
    private String readDecryptArchivePassword() {
        String text = decryptArchivePasswordField.getText();
        return text == null || text.isEmpty() ? null : text;
    }

    /**
     * 创建归档密码提供者：优先复用密码框中的输入，否则在后台线程弹窗询问用户。
     *
     * <p>核心层在后台线程调用该回调，弹窗需切回 FX 线程并以
     * {@link CompletableFuture} 阻塞等待用户输入。
     *
     * @return 归档密码提供者
     */
    private ArchivePasswordProvider createArchivePasswordProvider() {
        return (archive, retry) -> {
            if (!retry) {
                String prefilled = readDecryptArchivePassword();
                if (prefilled != null) {
                    return prefilled;
                }
            }
            CompletableFuture<String> future = new CompletableFuture<>();
            Platform.runLater(() -> future.complete(showArchivePasswordDialog(retry)));
            try {
                return future.get();
            } catch (Exception e) {
                Thread.currentThread().interrupt();
                return null;
            }
        };
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
        if (imageCryptTab != null) {
            imageCryptTab.setText(Messages.get("tab.imageCrypt"));
        }
        if (imageCryptViewController != null) {
            imageCryptViewController.applyTexts();
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
        if (fileStegoTab != null) {
            fileStegoTab.setText(Messages.get("tab.fileStego"));
        }
        if (fileStegoViewController != null) {
            fileStegoViewController.applyTexts();
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
        compressLevelLabel.setText(Messages.get("options.compress.level"));
        compressBeforeCheck.setText(Messages.get("options.compressBefore"));
        compressAfterCheck.setText(Messages.get("options.compressAfter"));
        compressFormatCombo.setValue(SettingsManager.getDefaultCompressFormat());
        updateArchivePasswordVisibility();
        // 菜单
        settingsMenu.setText(Messages.get("menu.settings"));
        settingsMenuItem.setText(Messages.get("menu.settings.open"));
        aboutMenuItem.setText(Messages.get("menu.about"));
        historyMenu.setText(Messages.get("menu.history"));
        logsMenu.setText(Messages.get("menu.logs"));
        LogCompanionWindow.applyTextsIfOpen();
        splitCheck.setText(Messages.get("options.split"));
        splitUnitLabel.setText(Messages.get("options.split.size"));
        encryptDepthLabel.setText(Messages.get("options.encryptDepth"));
        forceDecryptCheck.setText(Messages.get("options.forceDecrypt"));
        autoUnzipCheck.setText(Messages.get("options.autoUnzip"));
        decryptThenExtractCheck.setText(Messages.get("options.decryptThenExtract"));
        decryptArchivePasswordField.setPromptText(Messages.get("options.decryptArchivePassword.placeholder"));
        verifyFirstCheck.setText(Messages.get("options.verifyFirst"));
        recursiveExtractCheck.setText(Messages.get("options.recursiveExtract"));
        keyfilesLabel.setText(Messages.get("options.keyfiles"));
        keyfileOrderedCheck.setText(Messages.get("options.keyfiles.ordered"));
        addKeyfileBtn.setText(Messages.get("options.keyfiles.add"));
        keyfileEmptyLabel.setText(Messages.get("options.keyfiles.none"));
        clearFileBtn.setText(Messages.get("file.clear"));
        clearFilesBtn.setText(Messages.get("file.clear"));
        addFilesBtn.setText(Messages.get("file.choose.multiple"));
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
        if (!selectedFiles.isEmpty()) {
            showFileInfo();
        }
    }

    /**
     * 为每个选项后面的 ⓘ 图标挂载 Tooltip，语言切换时重新调用以刷新文案。
     */
    private void setupInfoTooltips() {
        MainViewSupport.installTooltip(paranoidInfo, Messages.get("options.paranoid.tip"));
        MainViewSupport.installTooltip(reedSolomonInfo, Messages.get("options.reedSolomon.tip"));
        MainViewSupport.installTooltip(deniabilityInfo, Messages.get("options.deniability.tip"));
        MainViewSupport.installTooltip(compressInfo, Messages.get("options.compress.tip"));
        MainViewSupport.installTooltip(compressBeforeInfo,
                Messages.get("options.compressBefore.tip"));
        MainViewSupport.installTooltip(compressAfterInfo, Messages.get(
                SettingsManager.isArchiveCustomEncryption()
                        ? "options.compressAfter.tip"
                        : "options.compressAfter.tip.nocustom"));
        MainViewSupport.installTooltip(splitInfo, Messages.get("options.split.tip"));
        MainViewSupport.installTooltip(encryptDepthInfo, Messages.get("options.encryptDepth.tip"));
        MainViewSupport.installTooltip(forceDecryptInfo, Messages.get("options.forceDecrypt.tip"));
        MainViewSupport.installTooltip(autoUnzipInfo, Messages.get("options.autoUnzip.tip"));
        MainViewSupport.installTooltip(decryptThenExtractInfo, Messages.get("options.decryptThenExtract.tip"));
        MainViewSupport.installTooltip(verifyFirstInfo, Messages.get("options.verifyFirst.tip"));
        MainViewSupport.installTooltip(recursiveExtractInfo, Messages.get("options.recursiveExtract.tip"));
        MainViewSupport.installTooltip(keyfileOrderedInfo, Messages.get("options.keyfiles.ordered.tip"));
    }

    /**
     * 将内置的高考真题 ZIP 解包到用户临时目录，设为默认钓鱼文件。
     */
    private void setDefaultDecoyFile() {
        String decoyPath = MainViewSupport.extractDefaultDecoyFile();
        if (decoyPath != null) {
            decoyFilePathField.setText(decoyPath);
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
        LogCompanionWindow.closeIfOpen();
        themeManager.shutdown();
        taskRunner.shutdown();
        if (mediaViewController != null) {
            mediaViewController.shutdown();
        }
        if (imageCryptViewController != null) {
            imageCryptViewController.shutdown();
        }
        if (classicalViewController != null) {
            classicalViewController.shutdown();
        }
        if (stegoViewController != null) {
            stegoViewController.shutdown();
        }
        if (fileStegoViewController != null) {
            fileStegoViewController.shutdown();
        }
        Platform.exit();
    }

    @FXML
    private void onOpenSettings() {
        SettingsDialog.show(stage(), themeManager);
        // 设置变更后刷新占位符与 tip（如归档密码回退开关）
        applyTexts();
    }

    /**
     * 打开操作历史对话框。
     */
    @FXML
    private void onOpenHistory() {
        HistoryDialog.show(stage());
    }

    /**
     * 将顶栏菜单当作按钮：点击直接触发 {@code action}，不弹出子菜单。
     *
     * <p>仅含不可见菜单项时 JavaFX 不会触发 {@code showing}，因此必须在 MenuBar
     * 上拦截鼠标按下。若拦截未命中，再以 showing 回调作为后备。
     *
     * @param menu     菜单
     * @param onActivate 点击时执行的动作
     */
    private void installMenuAsButton(Menu menu, Runnable onActivate) {
        menuBar.addEventFilter(MouseEvent.MOUSE_PRESSED, event -> {
            if (event.getButton() != MouseButton.PRIMARY) {
                return;
            }
            if (!isClickOnMenu(menu, event)) {
                return;
            }
            event.consume();
            menuClickHandled.add(menu);
            menu.hide();
            onActivate.run();
            Platform.runLater(() -> menuClickHandled.remove(menu));
        });
        menu.setOnShowing(e -> {
            menu.hide();
            if (!menuClickHandled.contains(menu)) {
                onActivate.run();
            }
        });
    }

    /**
     * 判断事件是否点在指定菜单按钮上。
     *
     * @param menu  目标菜单
     * @param event 鼠标事件
     * @return 点在目标菜单上时返回 {@code true}
     */
    private boolean isClickOnMenu(Menu menu, MouseEvent event) {
        String text = menu.getText();
        if (text == null || text.isBlank()) {
            return false;
        }
        Node node = event.getTarget() instanceof Node n ? n : null;
        while (node != null && node != menuBar) {
            if (node instanceof MenuButton button && text.equals(button.getText())) {
                return true;
            }
            node = node.getParent();
        }
        return false;
    }

    /**
     * 打开或关闭右侧翻书式日志窗。
     */
    private void onToggleLogs() {
        LogCompanionWindow.toggle(stage());
    }

    /**
     * 打开「关于」对话框：分页展示工具信息、许可证、使用规约与开源致谢。
     *
     * <p>许可证与使用规约是长文本，单独分页并以只读文本域承载，
     * 便于阅读与复制；正文继承主窗当前的浅色/深色主题。
     */
    @FXML
    private void onAbout() {
        Dialog<Void> dialog = new Dialog<>();
        dialog.initOwner(stage());
        dialog.setTitle(Messages.get("about.title"));
        dialog.setHeaderText(null);
        dialog.setResizable(true);

        DialogPane pane = dialog.getDialogPane();
        pane.getStyleClass().add("root");
        pane.getStyleClass().add(currentThemeClass());
        pane.getStylesheets().add(MainController.class.getResource(
                "/hbnu/project/ergoutreecrypt/ui/styles/win11.css").toExternalForm());
        pane.getButtonTypes().add(new ButtonType(
                Messages.get("dialog.close"), ButtonBar.ButtonData.OK_DONE));

        TabPane tabs = new TabPane();
        // 与主窗口顶部标签条共用同一套外观（下划线指示器 + 主题色文字）
        tabs.getStyleClass().add("tab-strip");
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        tabs.getTabs().addAll(
                aboutOverviewTab(),
                aboutTextTab(Messages.get("about.tab.license"),
                        Messages.get("about.license.title") + "\n\n"
                                + Messages.get("about.license.body")),
                aboutTextTab(Messages.get("about.tab.terms"), Messages.get("about.terms.body")),
                aboutTextTab(Messages.get("about.tab.credits"), Messages.get("about.credits.body")));

        pane.setContent(tabs);
        pane.setPrefSize(640, 480);
        dialog.showAndWait();
    }

    /**
     * 构建「关于」对话框的概览页签：名称、标语、版本与简介。
     *
     * @return 概览页签
     */
    private static Tab aboutOverviewTab() {
        Label name = new Label(Messages.get("about.name"));
        name.getStyleClass().add("about-name");
        Label tagline = new Label(Messages.get("about.tagline"));
        tagline.getStyleClass().add("about-tagline");
        Label version = new Label(Messages.get("about.version"));
        version.getStyleClass().add("about-version");
        Label author = new Label(Messages.get("about.author"));
        author.getStyleClass().add("about-author");
        Label desc = new Label(Messages.get("about.text"));
        desc.getStyleClass().add("about-desc");
        desc.setWrapText(true);

        VBox box = new VBox(6, name, tagline, version, new Separator(), desc, author);
        box.getStyleClass().add("about-overview");
        box.setPadding(new Insets(20));
        return new Tab(Messages.get("about.tab.about"), box);
    }

    /**
     * 构建「关于」对话框中的长文本页签。
     *
     * @param title 页签标题
     * @param body  正文，可含换行
     * @return 只读文本页签
     */
    private static Tab aboutTextTab(String title, String body) {
        TextArea area = new TextArea(body);
        area.getStyleClass().add("about-text");
        area.setEditable(false);
        area.setWrapText(true);
        return new Tab(title, area);
    }

    /**
     * 取当前窗口正在使用的主题样式类名，供独立对话框继承主题。
     *
     * @return {@code "dark"} 或 {@code "light"}
     */
    private String currentThemeClass() {
        if (rootStack != null) {
            for (String cls : rootStack.getStyleClass()) {
                if ("dark".equals(cls) || "light".equals(cls)) {
                    return cls;
                }
            }
        }
        return "light";
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
        setVisible(verifyBtn, !encrypting && !selectedFiles.isEmpty() && !isBatchMode());

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
        List<File> files = chooser.showOpenMultipleDialog(stage());
        if (files != null && !files.isEmpty()) {
            setSelectedFiles(files);
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
            List<File> dropped = db.getFiles();
            // 已经处于多文件列表时，再拖入视为追加，便于分几次凑齐要处理的一批文件
            if (isBatchMode()) {
                addSelectedFiles(dropped);
            } else {
                setSelectedFiles(dropped);
            }
            ok = true;
        }
        dropZone.getStyleClass().remove("drag-over");
        e.setDropCompleted(ok);
        e.consume();
    }

    private void setSelectedFile(File f) {
        setSelectedFiles(f == null ? List.of() : List.of(f));
    }

    /**
     * 替换当前的整个选中集合（文件或文件夹均可）。
     *
     * <p>单选一个普通文件或一个文件夹时保持原有单文件/文件夹语义；选中两个及以上条目时
     * 进入批处理模式，把这些文件视作「同一个文件夹里的多个文件」。
     *
     * @param files 新的选中集合，可为 null
     */
    private void setSelectedFiles(List<File> files) {
        selectedFiles.clear();
        if (files != null) {
            for (File f : files) {
                if (f != null && !selectedFiles.contains(f)) {
                    selectedFiles.add(f);
                }
            }
        }
        selectedFile = selectedFiles.size() == 1 ? selectedFiles.getFirst() : null;
        this.outputPathUserEdited = false;
        if (selectedFiles.isEmpty()) {
            // 清空选择时回到初始拖拽界面，避免界面停留在过期的文件信息上
            onClearFile();
            return;
        }
        autoSwitchModeIfNeeded();
        showFileInfo();
    }

    /**
     * 在已有选中项后追加文件（不替换），用于列表中的「添加文件」与多次拖拽。
     *
     * @param files 追加的文件列表，可为 null
     */
    private void addSelectedFiles(List<File> files) {
        if (files == null || files.isEmpty()) {
            return;
        }
        boolean changed = false;
        for (File f : files) {
            if (f != null && !selectedFiles.contains(f)) {
                selectedFiles.add(f);
                changed = true;
            }
        }
        if (!changed) {
            return;
        }
        selectedFile = selectedFiles.size() == 1 ? selectedFiles.getFirst() : null;
        this.outputPathUserEdited = false;
        autoSwitchModeIfNeeded();
        showFileInfo();
    }

    /**
     * 从选中集合中移除一项；移空时回到初始拖拽界面。
     *
     * @param f 待移除的文件
     */
    private void removeSelectedFile(File f) {
        if (!selectedFiles.remove(f)) {
            return;
        }
        if (selectedFiles.isEmpty()) {
            selectedFile = null;
            onClearFile();
            return;
        }
        if (selectedFiles.size() == 1) {
            setSelectedFiles(List.of(selectedFiles.getFirst()));
            return;
        }
        selectedFile = null;
        this.outputPathUserEdited = false;
        showFileInfo();
    }

    /**
     * 依据当前选中项自动切换加密/解密模式。
     *
     * <p>仅当全部选中项都是 {@code .ergou}/{@code .pcv} 加密卷或分卷碎片时才切到解密；
     * 普通压缩包（.zip/.7z/.rar 等）不自动切换，因为用户可能想加密压缩包本身。
     */
    private void autoSwitchModeIfNeeded() {
        if (selectedFiles.isEmpty()) {
            return;
        }
        boolean allEncrypted = true;
        for (File f : selectedFiles) {
            String name = f.getName().toLowerCase();
            boolean encrypted = name.endsWith(".pcv") || name.endsWith(".ergou")
                    || Splitter.isSplitChunkPath(f.getAbsolutePath());
            if (!encrypted) {
                allEncrypted = false;
                break;
            }
        }
        if (allEncrypted) {
            switchMode(Mode.DECRYPT);
        }
    }

    /**
     * 当前是否为「多文件」批处理模式。
     *
     * @return true 表示选中了两个及以上条目
     */
    private boolean isBatchMode() {
        return selectedFiles.size() > 1;
    }

    /**
     * 把选中的文件列表转换为路径列表，供核心批处理 API 使用。
     *
     * @param files 文件列表
     * @return 对应的路径列表
     */
    private static List<Path> toPaths(List<File> files) {
        List<Path> paths = new ArrayList<>(files.size());
        for (File f : files) {
            paths.add(f.toPath());
        }
        return paths;
    }

    /**
     * 计算多文件批处理的输出目录（纯函数，规则见 {@link MainViewSupport#batchOutputDir}）。
     *
     * @return 输出目录路径
     */
    private String batchOutputDir() {
        return MainViewSupport.batchOutputDir(selectedFiles);
    }

    /**
     * 计算多文件批处理的虚拟文件夹名（纯函数，规则见 {@link MainViewSupport#batchName}）。
     *
     * @return 非空的批名
     */
    private String batchName() {
        return MainViewSupport.batchName(selectedFiles);
    }

    /** 用于直接打开目标解压文件, 而非先打开本软件再去找文件路径时的处理 */
    public void openStartupFile(Path path) {
        if(path == null) {
            return;
        }
        File file = path.toFile();
        if(!file.isFile()){
            return;
        }

        mainTabs.getSelectionModel().select(fileTab);
        setSelectedFile(file);
        passwordField.requestFocus();
    }

    private void showFileInfo() {
        if (selectedFiles.isEmpty()) {
            return;
        }
        if (isBatchMode()) {
            showBatchFileInfo();
        } else {
            fileNameLabel.setText(selectedFile.getName());
            if (selectedFile.isDirectory()) {
                fileMetaLabel.setText(Messages.get("file.folder"));
            } else {
                fileMetaLabel.setText(Messages.format("file.size", FileSizes.human(selectedFile.length())));
            }
            setVisible(fileCard, true);
            setVisible(fileListCard, false);
        }
        setVisible(dropZone, false);
        setVisible(outputCard, true);
        setVisible(verifyBtn, mode == Mode.DECRYPT && !isBatchMode());
        if (!outputPathUserEdited) {
            outputFileField.setText(computeDefaultOutput());
        }
    }

    /**
     * 刷新多文件列表卡片：标题、总大小、可滚动列表行。
     */
    private void showBatchFileInfo() {
        long total = 0L;
        for (File f : selectedFiles) {
            if (!f.isDirectory()) {
                total += f.length();
            }
        }
        fileListTitleLabel.setText(
                Messages.format("file.list.title", selectedFiles.size()));
        fileListMetaLabel.setText(Messages.format("file.list.size", FileSizes.human(total)));
        refreshFileList();
        setVisible(fileCard, false);
        setVisible(fileListCard, true);
    }

    /**
     * 重建多文件列表的每一行（文件名、大小、移除按钮）。
     */
    private void refreshFileList() {
        fileListBox.getChildren().clear();
        for (File f : List.copyOf(selectedFiles)) {
            HBox row = new HBox(8);
            row.getStyleClass().add("file-list-row");

            Label name = new Label(f.getName());
            name.setTooltip(new Tooltip(f.getAbsolutePath()));
            name.setMinWidth(0);
            HBox.setHgrow(name, javafx.scene.layout.Priority.ALWAYS);

            Label size = new Label(f.isDirectory()
                    ? Messages.get("file.folder")
                    : FileSizes.human(f.length()));
            size.getStyleClass().add("file-list-size");

            Button remove = new Button("✕");
            remove.getStyleClass().add("btn-ghost");
            remove.setTooltip(new Tooltip(Messages.get("file.list.remove")));
            remove.setOnAction(e -> removeSelectedFile(f));

            row.getChildren().addAll(name, size, remove);
            fileListBox.getChildren().add(row);
        }
        fileListScroll.setVvalue(0);
    }

    /**
     * 列表中「添加文件」按钮：追加选择文件（不替换已有选择）。
     */
    @FXML
    private void onAddFiles() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("file.choose"));
        List<File> files = chooser.showOpenMultipleDialog(stage());
        if (files != null && !files.isEmpty()) {
            addSelectedFiles(files);
        }
    }

    private String computeDefaultOutput() {
        if (selectedFiles.isEmpty()) {
            return "";
        }
        // 多文件：输出目录取公共父级，产物是「批名」文件夹或「批名.扩展名」压缩包
        if (isBatchMode()) {
            return batchOutputDir();
        }
        String path = selectedFile.getAbsolutePath();
        if (mode == Mode.ENCRYPT) {
            // 文件夹：默认输出到其父目录（结果会是同名文件夹或同名压缩包）
            if (selectedFile.isDirectory()) {
                File parent = selectedFile.getParentFile();
                return parent != null ? parent.getAbsolutePath() : path;
            }
            return OutputNaming.encryptOutput(selectedFile.toPath()).toString();
        }
        // 解密：文件夹/压缩包/分卷碎片输出到父目录；单文件去扩展名
        if (selectedFile.isDirectory()
                || ArchiveExtractor.isArchive(selectedFile.toPath())
                || Splitter.isSplitChunkPath(path)) {
            File parent = selectedFile.getParentFile();
            return parent != null ? parent.getAbsolutePath() : path;
        }
        return MainViewSupport.deriveDecryptOutput(path);
    }

    @FXML
    private void onClearFile() {
        selectedFiles.clear();
        selectedFile = null;
        outputPathUserEdited = false;
        setVisible(fileCard, false);
        setVisible(fileListCard, false);
        setVisible(outputCard, false);
        setVisible(verifyBtn, false);
        setVisible(dropZone, true);
    }

    @FXML
    private void onBrowseOutput() {
        // 文件夹与多文件批处理的输出是「目录」，用目录选择器；单文件才用保存对话框
        boolean dirOutput = isBatchMode() || (selectedFile != null && selectedFile.isDirectory());
        if (dirOutput) {
            javafx.stage.DirectoryChooser chooser = new javafx.stage.DirectoryChooser();
            chooser.setTitle(Messages.get("file.output.choose"));
            File cur = new File(outputFileField.getText());
            if (cur.isDirectory()) {
                chooser.setInitialDirectory(cur);
            }
            File f = chooser.showDialog(stage());
            if (f != null) {
                outputFileField.setText(f.getAbsolutePath());
                outputPathUserEdited = true;
            }
            return;
        }
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
        if (selectedFiles.isEmpty()) {
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
        // 启动前拦截：按「当前功能 + 当前选项」校验输入文件，不合规则立即给出引导
        if (mode == Mode.ENCRYPT) {
            if (!guardAllows(FileInputGuard.Feature.GENERIC_ENCRYPT, FileInputGuard.Options.none())) {
                return;
            }
            startEncrypt(pwd);
        } else {
            FileInputGuard.Options opts = FileInputGuard.Options.builder()
                    .autoUnzip(autoUnzipCheck.isSelected())
                    .decryptThenExtract(decryptThenExtractCheck.isSelected())
                    .build();
            if (!guardAllows(FileInputGuard.Feature.GENERIC_DECRYPT, opts)) {
                return;
            }
            startDecrypt(pwd);
        }
    }

    /**
     * 对当前所选文件执行启动前预检，不合规则弹出引导提示。
     *
     * @param feature 当前功能
     * @param options 与输入类型相关的当前选项
     * @return true 表示可以继续启动；false 表示已提示并应中止
     */
    private boolean guardAllows(final FileInputGuard.Feature feature,
                                final FileInputGuard.Options options) {
        if (isBatchMode()) {
            // 多文件批处理不做整体拦截：不可处理的条目由核心跳过并计入批处理失败列表，
            // 在结束弹窗中统一汇报，避免一个坏文件让整批无法启动。
            return true;
        }
        if (selectedFile == null) {
            return true;
        }
        FileInputGuard.GuardResult result =
                FileInputGuard.check(feature, options, selectedFile.toPath());
        if (result.rejected()) {
            toast.error(result.message());
            return false;
        }
        return true;
    }

    @FXML
    private void onVerifyIntegrity() {
        if (running) {
            return;
        }
        if (selectedFiles.isEmpty() || isBatchMode()) {
            toast.error(Messages.get("toast.verify.singleOnly"));
            return;
        }
        if (!guardAllows(FileInputGuard.Feature.VERIFY_INTEGRITY, FileInputGuard.Options.none())) {
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
            req.setKeyfiles(MainViewSupport.toPaths(keyfiles));
        }

        ProgressReporter reporter = newReporter();
        req.setReporter(reporter);
        runTask("VERIFY", () -> Verifier.verify(req), Messages.get("status.success.verify"));
    }

    private void startEncrypt(String pwd) {
        String out = outputFileField.getText();

        // 「压缩后加密」与「加密后压缩」共用同一个归档格式与归档密码控件
        String archiveFormat = null;
        String archivePwd = null;
        if ((compressBeforeCheck.isSelected() || compressAfterCheck.isSelected())
                && compressFormatCombo.getValue() != null) {
            archiveFormat = compressFormatCombo.getValue().replace(".", "_");
            String ap = archivePasswordField.getText();
            archivePwd = (ap == null || ap.isEmpty()) ? null : ap;
        }
        boolean compressBefore = compressBeforeCheck.isSelected();
        final String preArchiveFormat = compressBefore ? archiveFormat : null;
        final String preArchivePwd = compressBefore ? archivePwd : null;
        final String postArchiveFormat = compressAfterCheck.isSelected() ? archiveFormat : null;
        final String postArchivePwd = compressAfterCheck.isSelected() ? archivePwd : null;

        // 多文件批处理：视为「同一个文件夹里的多个文件」
        if (isBatchMode()) {
            String outDir = (out == null || out.isEmpty()) ? batchOutputDir() : out;
            FolderCrypt.EncryptOptions opts =
                    buildFolderEncryptOptions(pwd, preArchiveFormat, preArchivePwd,
                            postArchiveFormat, postArchivePwd);
            opts.batchName = batchName();
            final String outputDir = outDir;
            final String name = opts.batchName;
            runTask("GENERIC_ENCRYPT", () -> {
                FolderCrypt.encryptFiles(toPaths(selectedFiles),
                        Path.of(outputDir), opts);
                HistoryService.record(OperationType.GENERIC_ENCRYPT, name, outputDir, null);
            }, () -> showBatchOutcome(opts.batchResult, Messages.get("status.success.encrypt")),
                err -> showBatchError(opts.batchResult, err));
            return;
        }

        // 文件夹加密：走 FolderCrypt 编排
        if (selectedFile.isDirectory()) {
            if (out == null || out.isEmpty()) {
                File parent = selectedFile.getParentFile();
                out = parent != null ? parent.getAbsolutePath() : selectedFile.getAbsolutePath();
            }
            final String outputDir = out;
            FolderCrypt.EncryptOptions opts =
                    buildFolderEncryptOptions(pwd, preArchiveFormat, preArchivePwd,
                            postArchiveFormat, postArchivePwd);
            ProgressReporter reporter = newReporter();
            opts.reporter = reporter;
        runTask("GENERIC_ENCRYPT", () -> {
                FolderCrypt.encryptFolder(selectedFile.toPath(), Path.of(outputDir), opts);
                HistoryService.record(OperationType.GENERIC_ENCRYPT, selectedFile.getName(),
                        outputDir, null);
            }, () -> showBatchOutcome(opts.batchResult, Messages.get("status.success.encrypt")),
                err -> showBatchError(opts.batchResult, err));
            return;
        }

        // 单文件加密
        if (out == null || out.isEmpty()) {
            out = selectedFile.getAbsolutePath() + ".ergou";
        }
        // 压缩后加密时核心会在输出名后补「.归档扩展名」，此处只给基础名
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(selectedFile.getAbsolutePath());
        req.setOutputFile(out);
        req.setPassword(pwd == null ? "" : pwd);
        req.setComments(commentsArea.getText() == null ? "" : commentsArea.getText());
        req.setParanoid(paranoidCheck.isSelected());
        // B2：按所选 KDF 档位覆写 Argon2 参数（默认 256 MiB，移动端友好）
        Argon2DesktopMode kdfMode = SettingsManager.getKdfMode();
        req.setArgon2MemoryKib(kdfMode.getMemoryKib());
        req.setArgon2Passes(kdfMode.getPasses());
        req.setArgon2Threads(kdfMode.getThreads());
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
        req.setCompressionLevel(currentCompressLevel());
        req.setArchiveFormat(postArchiveFormat);
        req.setArchivePassword(postArchivePwd);
        req.setPreArchiveFormat(preArchiveFormat);
        req.setPreArchivePassword(preArchivePwd);
        req.setSplit(splitCheck.isSelected());
        req.setChunkSize(splitSizeSpinner.getValue());
        req.setRsCodecs(new RsCodecs());
        if (!keyfiles.isEmpty()) {
            req.setKeyfiles(MainViewSupport.toPaths(keyfiles));
            req.setKeyfileOrdered(keyfileOrderedCheck.isSelected());
        }

        ProgressReporter reporter = newReporter();
        req.setReporter(reporter);
        runTask(() -> {
            Encryptor.encrypt(req);
            // 分卷 / 归档等场景下核心会改写 req.outputFile，此处取最终输出路径
            Path finalOut = Path.of(req.getOutputFile());
            HistoryService.record(OperationType.GENERIC_ENCRYPT,
                    finalOut.getFileName().toString(), finalOut.toString(), null);
        }, Messages.get("status.success.encrypt"));
    }

    /**
     * 收集「文件夹 / 多文件」批处理共用的加密选项。
     *
     * @param pwd               文件加密密码
     * @param preArchiveFormat  压缩后加密的归档格式，可为 null
     * @param preArchivePwd     压缩后加密的归档密码，可为 null
     * @param postArchiveFormat 加密后压缩的归档格式，可为 null
     * @param postArchivePwd    加密后压缩的归档密码，可为 null
     * @return 填充完毕的选项对象
     */
    private FolderCrypt.EncryptOptions buildFolderEncryptOptions(String pwd, String preArchiveFormat,
                                                                 String preArchivePwd,
                                                                 String postArchiveFormat,
                                                                 String postArchivePwd) {
        FolderCrypt.EncryptOptions opts = new FolderCrypt.EncryptOptions();
        opts.password = pwd == null ? "" : pwd;
        opts.comments = commentsArea.getText() == null ? "" : commentsArea.getText();
        opts.paranoid = paranoidCheck.isSelected();
        // B2：按所选 KDF 档位覆写 Argon2 参数（默认 256 MiB，移动端友好）
        Argon2DesktopMode kdfMode = SettingsManager.getKdfMode();
        opts.argon2MemoryKib = kdfMode.getMemoryKib();
        opts.argon2Passes = kdfMode.getPasses();
        opts.argon2Threads = kdfMode.getThreads();
        opts.reedSolomon = reedSolomonCheck.isSelected();
        opts.deniability = deniabilityCheck.isSelected();
        opts.compress = compressCheck.isSelected();
        opts.compressionLevel = currentCompressLevel();
        opts.split = splitCheck.isSelected();
        opts.chunkSize = splitSizeSpinner.getValue();
        opts.archiveFormat = postArchiveFormat;
        opts.archivePassword = postArchivePwd;
        opts.preArchiveFormat = preArchiveFormat;
        opts.preArchivePassword = preArchivePwd;
        opts.rsCodecs = new RsCodecs();
        if (!keyfiles.isEmpty()) {
            opts.keyfiles = MainViewSupport.toPaths(keyfiles);
            opts.keyfileOrdered = keyfileOrderedCheck.isSelected();
        }
        opts.threadCount = SettingsManager.getThreadCount();
        opts.encryptDepth = encryptDepthSpinner.getValue();
        return opts;
    }

    private void startDecrypt(String pwd) {
        // 多文件批处理：逐个自动识别类型并解密，产物平铺到输出目录
        if (isBatchMode()) {
            startBatchDecrypt(pwd);
            return;
        }
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
            out = MainViewSupport.deriveDecryptOutput(in);
        }
        DecryptRequest req = new DecryptRequest();
        req.setInputFile(in);
        req.setOutputFile(out);
        req.setPassword(pwd == null ? "" : pwd);
        req.setArchivePassword(readDecryptArchivePassword());
        req.setArchivePasswordProvider(createArchivePasswordProvider());
        req.setForceDecrypt(forceDecryptCheck.isSelected());
        req.setDecryptThenExtract(decryptThenExtractCheck.isSelected());
        req.setRecursiveExtract(recursiveExtractCheck.isSelected());
        req.setVerifyFirst(verifyFirstCheck.isSelected());
        req.setRsCodecs(new RsCodecs());
        if (!keyfiles.isEmpty()) {
            req.setKeyfiles(MainViewSupport.toPaths(keyfiles));
        }

        ProgressReporter reporter = newReporter();
        req.setReporter(reporter);
        runTask(() -> {
            Decryptor.decrypt(req);
            if (req.isDecryptThenExtract()) {
                ArchivePostExtract.extractIfArchive(Path.of(req.getOutputFile()),
                        ArchivePostExtract.maxDepth(req.isRecursiveExtract()),
                        reporter, req.getArchivePasswordProvider());
            }
            Path finalOut = Path.of(req.getOutputFile());
            HistoryService.record(OperationType.GENERIC_DECRYPT,
                    finalOut.getFileName().toString(), finalOut.toString(), null);
        }, Messages.get("status.success.decrypt"));
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

        FolderCrypt.DecryptOptions opts = buildAutoDecryptOptions(pwd);

        // 快速预检：若归档受密码保护，优先用解密密码作为归档密码（加密后压缩回退场景）；
        // 二者皆空时再弹窗询问。
        boolean needPrecheck = ArchiveExtractor.isArchive(input);
        if (needPrecheck) {
            try {
                if (ArchiveExtractor.hasEncryptedEntries(input)) {
                    String effectiveArch = ArchivePacker.resolveArchivePassword(
                            opts.archivePassword, opts.password);
                    if (effectiveArch == null || effectiveArch.isEmpty()) {
                        String archPwd = showArchivePasswordDialog(false);
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

        ProgressReporter reporter = newReporter();
        opts.reporter = reporter;

        final Path finalOutDir = outDir;
        // 归档密码的运行时询问（嵌套归档、预检遗漏、密码错误重试）统一由
        // opts.archivePasswordProvider 处理，无需在此处捕获重试。
        taskRunner.submit("GENERIC_DECRYPT", input.getFileName().toString(), () -> {
            FolderCrypt.decryptAuto(input, finalOutDir, opts);
        }, () -> {
            HistoryService.record(OperationType.GENERIC_DECRYPT,
                    input.getFileName().toString(), finalOutDir.toString(), null);
            showBatchOutcome(opts.batchResult, Messages.get("status.success.decrypt"));
        }, err -> showBatchError(opts.batchResult, err));
    }

    /**
     * 启动多文件批处理解密：逐个自动识别类型，产物平铺到输出目录。
     *
     * <p>不可解密的条目由核心记入批处理失败列表，不会中断整批；
     * 结束后统一在弹窗中汇报成功 / 失败 / 跳过数量。
     *
     * @param pwd 密码（可为空字符串）
     */
    private void startBatchDecrypt(String pwd) {
        String outText = outputFileField.getText();
        String outDir = (outText == null || outText.isEmpty()) ? batchOutputDir() : outText;
        FolderCrypt.DecryptOptions opts = buildAutoDecryptOptions(pwd);
        ProgressReporter reporter = newReporter();
        opts.reporter = reporter;

        final String finalOutDir = outDir;
        final String name = batchName();
        runTask("GENERIC_DECRYPT", () -> {
            FolderCrypt.decryptFiles(toPaths(selectedFiles),
                    Path.of(finalOutDir), opts);
            HistoryService.record(OperationType.GENERIC_DECRYPT, name, finalOutDir, null);
        }, () -> showBatchOutcome(opts.batchResult, Messages.get("status.success.decrypt")),
            err -> showBatchError(opts.batchResult, err));
    }

    /**
     * 收集「文件夹 / 多文件」批处理共用的解密选项。
     *
     * @param pwd 文件解密密码
     * @return 填充完毕的选项对象
     */
    private FolderCrypt.DecryptOptions buildAutoDecryptOptions(String pwd) {
        FolderCrypt.DecryptOptions opts = new FolderCrypt.DecryptOptions();
        opts.password = pwd == null ? "" : pwd;
        opts.archivePassword = readDecryptArchivePassword();
        opts.archivePasswordProvider = createArchivePasswordProvider();
        opts.forceDecrypt = forceDecryptCheck.isSelected();
        opts.recursiveExtract = recursiveExtractCheck.isSelected();
        opts.extractThenDecrypt = autoUnzipCheck.isSelected();
        opts.decryptThenExtract = decryptThenExtractCheck.isSelected();
        opts.rsCodecs = new RsCodecs();
        if (!keyfiles.isEmpty()) {
            opts.keyfiles = MainViewSupport.toPaths(keyfiles);
        }
        opts.threadCount = SettingsManager.getThreadCount();
        return opts;
    }

    /**
     * 弹出归档密码输入对话框。
     *
     * @param retry 是否为重试（上一次密码错误），文案据此切换
     * @return 用户输入的密码；未输入或取消时返回空字符串
     */
    private String showArchivePasswordDialog(boolean retry) {
        javafx.scene.control.TextInputDialog dlg = new javafx.scene.control.TextInputDialog();
        dlg.initOwner(stage());
        dlg.setTitle(Messages.get(retry ? "archivePassword.title.retry" : "archivePassword.title"));
        dlg.setHeaderText(Messages.get(retry ? "archivePassword.prompt.retry" : "archivePassword.prompt"));
        dlg.setContentText(Messages.get("archivePassword.label"));
        return dlg.showAndWait().orElse("");
    }

    private ProgressReporter newReporter() {
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
        return new LoggingProgressReporter(reporter, "Volume");
    }

    /**
     * 提交后台任务（操作名由当前加/解密模式决定）。
     *
     * @param work       后台工作
     * @param successMsg 成功文案
     */
    private void runTask(TaskRunner.CheckedRunnable work, String successMsg) {
        runTask(mode == Mode.ENCRYPT ? "GENERIC_ENCRYPT" : "GENERIC_DECRYPT", work, successMsg);
    }

    /**
     * 提交后台任务并开启日志会话。
     *
     * @param opName     操作名称
     * @param work       后台工作
     * @param successMsg 成功文案
     */
    private void runTask(String opName, TaskRunner.CheckedRunnable work, String successMsg) {
        runTask(opName, work,
                () -> {
                    progressBar.setProgress(1);
                    statusLabel.setText(successMsg);
                    toast.success(successMsg);
                    setRunning(false);
                },
                err -> {
                    if (ExceptionMapper.isCancellation(err)) {
                        statusLabel.setText(Messages.get("status.cancelled"));
                        toast.info(Messages.get("status.cancelled"));
                    } else {
                        String msg = ExceptionMapper.friendlyMessage(err);
                        statusLabel.setText(msg);
                        toast.error(msg);
                    }
                    setRunning(false);
                });
    }

    /**
     * 提交后台任务，自定义成功/失败回调（仍负责 setRunning 与进度条初值）。
     *
     * @param opName    操作名称
     * @param work      后台工作
     * @param onSuccess 成功回调（FX 线程）；须自行 {@code setRunning(false)}
     * @param onError   失败回调（FX 线程）；须自行 {@code setRunning(false)}
     */
    private void runTask(String opName, TaskRunner.CheckedRunnable work,
                         Runnable onSuccess, java.util.function.Consumer<Throwable> onError) {
        setRunning(true);
        progressBar.setProgress(0);
        archiveProgressBar.setProgress(0);
        setVisible(archiveProgressBox, false);
        statusLabel.setText(Messages.get("action.processing"));
        String fileName = isBatchMode() ? batchName()
                : (selectedFile == null ? null : selectedFile.getName());
        taskRunner.submit(opName, fileName, work, onSuccess, onError);
    }

    /**
     * 展示批处理汇总：多文件或有失败时弹窗，否则保持 toast。
     *
     * @param result     批结果，可为 null
     * @param successMsg 全成功时的短文案
     */
    private void showBatchOutcome(BatchResult result, String successMsg) {
        progressBar.setProgress(1);
        if (result == null || !shouldShowBatchDialog(result)) {
            statusLabel.setText(successMsg);
            toast.success(successMsg);
            setRunning(false);
            return;
        }
        statusLabel.setText(result.formatSummary());
        if (result.hasFailures()) {
            toast.info(result.formatSummary());
        } else {
            toast.success(result.formatSummary());
        }
        Alert alert = new Alert(result.hasFailures()
                ? Alert.AlertType.WARNING : Alert.AlertType.INFORMATION);
        alert.initOwner(stage());
        alert.setTitle(Messages.get("batch.summary.title"));
        alert.setHeaderText(result.formatSummary());
        String detail = result.formatDetail();
        alert.setContentText(detail.isEmpty() ? successMsg : detail);
        alert.getDialogPane().setPrefWidth(520);
        alert.showAndWait();
        setRunning(false);
    }

    /**
     * 批处理失败（整批无成功或被取消）时的展示。
     *
     * @param result 可能已部分入账的汇总
     * @param err    抛出的异常
     */
    private void showBatchError(BatchResult result, Throwable err) {
        if (ExceptionMapper.isCancellation(err)) {
            statusLabel.setText(Messages.get("status.cancelled"));
            toast.info(Messages.get("status.cancelled"));
            setRunning(false);
            return;
        }
        if (result != null && result.hasSuccesses()) {
            showBatchOutcome(result, Messages.get("batch.summary.partial"));
            return;
        }
        String errMsg = ExceptionMapper.friendlyMessage(err);
        statusLabel.setText(errMsg);
        toast.error(errMsg);
        if (result != null && result.hasFailures()) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.initOwner(stage());
            alert.setTitle(Messages.get("batch.summary.title"));
            alert.setHeaderText(result.formatSummary());
            alert.setContentText(result.formatDetail());
            alert.getDialogPane().setPrefWidth(520);
            alert.showAndWait();
        }
        setRunning(false);
    }

    /**
     * 是否需要弹出批处理汇总（多文件或存在失败）。
     *
     * @param result 批结果
     * @return true 表示弹窗
     */
    private static boolean shouldShowBatchDialog(BatchResult result) {
        return result.hasFailures()
                || result.succeededCount() + result.failedCount() > 1;
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

    private Stage stage() {
        return (Stage) rootStack.getScene().getWindow();
    }

    /**
     * 操作模式。
     */
    private enum Mode {ENCRYPT, DECRYPT}
}
