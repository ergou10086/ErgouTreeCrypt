package hbnu.project.ergoutreecrypt.ui;

import hbnu.project.ergoutreecrypt.filestego.FileStegoCodec;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierRegistry;
import hbnu.project.ergoutreecrypt.history.HistoryService;
import hbnu.project.ergoutreecrypt.history.OperationType;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.ui.support.FileSizes;
import hbnu.project.ergoutreecrypt.ui.support.TaskRunner;
import hbnu.project.ergoutreecrypt.ui.support.Toast;
import javafx.beans.value.ChangeListener;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Tooltip;
import javafx.scene.input.DragEvent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.util.Duration;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * 文件隐写标签页控制器（M2）。
 *
 * <p>提供通用文件隐写的完整交互流程，与 {@link ImageStegoController} 风格一致：
 * <ul>
 *   <li>隐藏 / 提取 两种模式切换</li>
 *   <li>载体文件拖拽 / 选择 + 格式自动检测（依据已注册的 {@link CarrierAdapter}）</li>
 *   <li>高级选项：偏执模式、压缩、完整性、隐蔽、混淆大小、防暴力、嵌入方式</li>
 *   <li>容量信息实时估算（容量无关，可用容量恒为无限）</li>
 *   <li>{@link TaskRunner} 后台执行，{@link Toast} 提示结果</li>
 * </ul>
 *
 * <p>所有隐写业务逻辑委托给门面 {@link FileStegoCodec}，本控制器不触碰密码学细节。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public class FileStegoController {

    /** 文件隐写门面。 */
    private final FileStegoCodec codec = new FileStegoCodec();

    /** 后台任务执行器。 */
    private final TaskRunner taskRunner = new TaskRunner();

    /** 轻量提示气泡。 */
    private Toast toast;

    // ---- 根 ----
    @FXML private StackPane fsRoot;

    // ---- 模式切换 ----
    @FXML private ToggleButton fsHideTab;
    @FXML private ToggleButton fsExtractTab;
    @FXML private ToggleGroup fsModeGroup;

    // ---- 载体文件 ----
    @FXML private Label fsCarrierLabel;
    @FXML private StackPane fsCarrierStack;
    @FXML private Label fsCarrierPlaceholder;
    @FXML private Label fsCarrierHint;
    @FXML private Label fsCarrierSub;
    @FXML private Label fsCarrierInfo;
    @FXML private Button fsCarrierBtn;
    @FXML private Button fsCarrierClearBtn;

    // ---- 待隐藏文件 ----
    @FXML private VBox fsSecretCard;
    @FXML private Label fsSecretLabel;
    @FXML private StackPane fsSecretStack;
    @FXML private Label fsSecretName;
    @FXML private Label fsSecretSize;
    @FXML private Label fsSecretPlaceholder;
    @FXML private Button fsSecretBtn;
    @FXML private Button fsSecretClearBtn;

    // ---- 输出目录 ----
    @FXML private VBox fsOutputCard;
    @FXML private Label fsOutputLabel;
    @FXML private TextField fsOutputField;
    @FXML private Button fsOutputBtn;

    // ---- 密码 ----
    @FXML private Label fsPasswordLabel;
    @FXML private PasswordField fsPasswordField;
    @FXML private TextField fsPasswordVisibleField;
    @FXML private CheckBox fsShowPasswordCheck;

    // ---- 高级选项 ----
    @FXML private VBox fsOptionsCard;
    @FXML private Label fsOptionsLabel;
    @FXML private HBox fsParanoidRow;
    @FXML private CheckBox fsParanoidCheck;
    @FXML private Label fsParanoidInfo;
    @FXML private HBox fsCompressRow;
    @FXML private CheckBox fsCompressCheck;
    @FXML private Label fsCompressInfo;
    @FXML private HBox fsIntegrityRow;
    @FXML private CheckBox fsIntegrityCheck;
    @FXML private Label fsIntegrityInfo;
    @FXML private HBox fsStealthRow;
    @FXML private CheckBox fsStealthCheck;
    @FXML private Label fsStealthInfo;
    @FXML private HBox fsObfuscateRow;
    @FXML private CheckBox fsObfuscateCheck;
    @FXML private Label fsObfuscateInfo;
    @FXML private HBox fsObfuscateSizeRow;
    @FXML private Label fsObfuscateSizeLabel;
    @FXML private TextField fsObfuscateSizeField;
    @FXML private HBox fsBruteForceRow;
    @FXML private CheckBox fsBruteForceCheck;
    @FXML private Label fsBruteForceInfo;
    @FXML private Label fsEmbedModeLabel;
    @FXML private HBox fsEmbedModeRow;
    @FXML private RadioButton fsEmbedChunkRadio;
    @FXML private RadioButton fsEmbedAppendRadio;
    @FXML private Label fsEmbedModeInfo;
    @FXML private ToggleGroup fsEmbedGroup;

    // ---- 容量信息 ----
    @FXML private VBox fsCapacityCard;
    @FXML private Label fsCapacityLabel;
    @FXML private Label fsPayloadSizeText;
    @FXML private Label fsCarrierCapText;
    @FXML private Label fsOutputEstText;
    @FXML private Label fsCapacityWarn;

    // ---- 底部 ----
    @FXML private VBox fsProgressBox;
    @FXML private Label fsStatusLabel;
    @FXML private ProgressBar fsProgressBar;
    @FXML private Button fsCancelBtn;
    @FXML private Button fsActionBtn;

    // ---- 状态 ----
    /** 当前选中的载体文件。 */
    private File carrierFile;

    /** 当前选中的待隐藏文件。 */
    private File secretFile;

    /** 当前选中的输出目录。 */
    private File outputDir;

    /** 是否处于隐藏模式（false 为提取模式）。 */
    private boolean isHideMode = true;

    /** 匹配当前载体文件的适配器（按扩展名，可能为空）。 */
    private CarrierAdapter matchedAdapter;

    /** 密码变更监听器（联动选项可用性与容量显示）。 */
    private final ChangeListener<String> passwordListener = (obs, old, val) -> {
        updateOptionLinkage();
        updateCapacityDisplay();
    };

    /**
     * FXML 加载完成后由 JavaFX 调用，完成初始化与事件绑定。
     */
    @FXML
    private void initialize() {
        toast = new Toast(fsRoot);

        fsModeGroup.selectedToggleProperty().addListener((obs, old, val) -> onModeChanged());

        fsPasswordField.textProperty().addListener(passwordListener);
        fsPasswordVisibleField.textProperty().addListener(passwordListener);

        // 混淆大小联动
        fsObfuscateCheck.selectedProperty().addListener((obs, old, val) ->
                setVisibility(fsObfuscateSizeRow, val && isHideMode));

        // 隐蔽模式需要密码
        fsStealthCheck.selectedProperty().addListener((obs, old, val) -> updateOptionLinkage());

        // 选项影响容量估算
        fsParanoidCheck.selectedProperty().addListener((obs, old, val) -> updateCapacityDisplay());
        fsCompressCheck.selectedProperty().addListener((obs, old, val) -> updateCapacityDisplay());

        setupDragDrop();
        applyTexts();
        updateModeUI();
        updateOptionLinkage();
    }

    // ================================================================
    // 模式切换
    // ================================================================

    private void onModeChanged() {
        isHideMode = fsHideTab.isSelected();
        updateModeUI();
        updateCapacityDisplay();
    }

    private void updateModeUI() {
        setVisibility(fsSecretCard, isHideMode);
        setVisibility(fsOutputCard, !isHideMode);
        setVisibility(fsOptionsCard, isHideMode);
        setVisibility(fsCapacityCard, isHideMode);
        fsActionBtn.setText(isHideMode
                ? Messages.get("fileStego.btn.hide")
                : Messages.get("fileStego.btn.extract"));
    }

    // ================================================================
    // 载体文件
    // ================================================================

    @FXML
    private void onChooseCarrier() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("fileStego.carrier.choose"));
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                Messages.get("fileStego.carrier.filter"),
                "*.png", "*.zip", "*.pdf", "*.wav",
                "*.flac", "*.mp4", "*.m4a", "*.m4v"));
        File f = chooser.showOpenDialog(window());
        if (f != null) {
            setCarrierFile(f);
        }
    }

    @FXML
    private void onClearCarrier() {
        carrierFile = null;
        matchedAdapter = null;
        fsCarrierInfo.setText("");
        setVisibility(fsCarrierClearBtn, false);
        setVisibility(fsCarrierPlaceholder, true);
        setVisibility(fsCarrierHint, true);
        setVisibility(fsCarrierSub, true);
        updateCapacityDisplay();
    }

    private void setCarrierFile(final File file) {
        carrierFile = file;
        String ext = getExtension(file.getName());
        matchedAdapter = CarrierRegistry.findByExtension(ext).orElse(null);

        setVisibility(fsCarrierPlaceholder, false);
        setVisibility(fsCarrierHint, false);
        setVisibility(fsCarrierSub, false);

        String detected;
        if (isHideMode) {
            // 隐藏模式：按扩展名判断是否支持
            detected = (matchedAdapter != null)
                    ? Messages.format("fileStego.detect.format", matchedAdapter.displayName())
                    : Messages.format("fileStego.toast.invalid.carrier", ext);
        } else {
            // 提取模式：尝试魔数检测
            Optional<CarrierAdapter> byMagic = CarrierRegistry.detectByMagic(file.toPath());
            detected = byMagic.isPresent()
                    ? Messages.format("fileStego.detect.format", byMagic.get().displayName())
                    : Messages.get("fileStego.detect.failed");
        }
        fsCarrierInfo.setText(file.getName() + " | " + FileSizes.human(file.length())
                + "\n" + detected);
        setVisibility(fsCarrierClearBtn, true);

        updateCapacityDisplay();
    }

    // ================================================================
    // 待隐藏文件
    // ================================================================

    @FXML
    private void onChooseSecret() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("fileStego.secret.choose"));
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                Messages.get("fileStego.secret.filter"), "*.*"));
        File f = chooser.showOpenDialog(window());
        if (f != null) {
            setSecretFile(f);
        }
    }

    @FXML
    private void onClearSecret() {
        secretFile = null;
        fsSecretName.setText("");
        fsSecretSize.setText("");
        setVisibility(fsSecretClearBtn, false);
        setVisibility(fsSecretPlaceholder, true);
        updateCapacityDisplay();
    }

    private void setSecretFile(final File file) {
        secretFile = file;
        fsSecretName.setText(file.getName());
        fsSecretSize.setText(FileSizes.human(file.length()));
        setVisibility(fsSecretPlaceholder, false);
        setVisibility(fsSecretClearBtn, true);
        updateCapacityDisplay();
    }

    // ================================================================
    // 输出目录
    // ================================================================

    @FXML
    private void onChooseOutput() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle(Messages.get("fileStego.output.choose"));
        File f = chooser.showDialog(window());
        if (f != null) {
            outputDir = f;
            fsOutputField.setText(f.getAbsolutePath());
        }
    }

    // ================================================================
    // 密码
    // ================================================================

    @FXML
    private void onToggleShowPassword() {
        boolean show = fsShowPasswordCheck.isSelected();
        if (show) {
            fsPasswordVisibleField.setText(fsPasswordField.getText());
            setVisibility(fsPasswordVisibleField, true);
            setVisibility(fsPasswordField, false);
        } else {
            fsPasswordField.setText(fsPasswordVisibleField.getText());
            setVisibility(fsPasswordField, true);
            setVisibility(fsPasswordVisibleField, false);
        }
    }

    /**
     * 获取当前密码字节（UTF-8）；空密码返回空数组。
     */
    private byte[] getPasswordBytes() {
        String pwd = fsPasswordField.isVisible()
                ? fsPasswordField.getText()
                : fsPasswordVisibleField.getText();
        return (pwd == null || pwd.isEmpty())
                ? new byte[0] : pwd.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 获取当前密码长度（用于选项联动）。
     */
    private int getPasswordLength() {
        String pwd = fsPasswordField.isVisible()
                ? fsPasswordField.getText()
                : fsPasswordVisibleField.getText();
        return (pwd == null) ? 0 : pwd.length();
    }

    // ================================================================
    // 选项联动
    // ================================================================

    /**
     * 更新与密码相关的选项可用性：隐蔽模式需要密码。
     */
    private void updateOptionLinkage() {
        boolean hasPassword = getPasswordLength() > 0;
        if (!hasPassword && fsStealthCheck.isSelected()) {
            fsStealthCheck.setSelected(false);
        }
        fsStealthCheck.setDisable(!hasPassword);
    }

    // ================================================================
    // 容量信息
    // ================================================================

    /**
     * 刷新容量信息：查询实际载体适配器容量（可能有限），并与待隐藏文件大小对比。
     */
    private void updateCapacityDisplay() {
        if (!isHideMode || carrierFile == null) {
            fsPayloadSizeText.setText("");
            fsCarrierCapText.setText("");
            fsOutputEstText.setText("");
            setVisibility(fsCapacityWarn, false);
            return;
        }
        long secretSize = (secretFile != null) ? secretFile.length() : 0;
        fsPayloadSizeText.setText(Messages.format("fileStego.capacity.payloadSize",
                FileSizes.human(secretSize)));

        // 查询载体适配器的实际容量（可能有限，如 FLAC 约 16 MB）
        long capacity = Long.MAX_VALUE;
        if (matchedAdapter != null) {
            try {
                capacity = matchedAdapter.capacity(carrierFile.toPath());
            } catch (Exception ignored) {
                // 查询失败时回退到默认无限
            }
        }
        String capText;
        if (capacity == Long.MAX_VALUE) {
            capText = Messages.get("fileStego.capacity.unlimited");
        } else {
            capText = FileSizes.human(capacity);
        }
        fsCarrierCapText.setText(Messages.format("fileStego.capacity.carrierAvailable", capText));

        long est = carrierFile.length() + secretSize;
        fsOutputEstText.setText(Messages.format("fileStego.capacity.outputEstimate",
                FileSizes.human(est)));

        // 待隐藏文件超过载体容量时显示警告
        boolean overflow = (capacity != Long.MAX_VALUE && secretSize > capacity);
        setVisibility(fsCapacityWarn, overflow);
        if (overflow) {
            fsCapacityWarn.setText(Messages.get("fileStego.capacity.insufficient"));
        }
    }

    // ================================================================
    // 操作
    // ================================================================

    @FXML
    private void onAction() {
        if (isHideMode) {
            doHide();
        } else {
            doExtract();
        }
    }

    private void doHide() {
        if (carrierFile == null) {
            toast.info(Messages.get("fileStego.toast.no.carrier"));
            return;
        }
        if (secretFile == null) {
            toast.info(Messages.get("fileStego.toast.no.secret"));
            return;
        }
        if (matchedAdapter == null) {
            toast.error(Messages.format("fileStego.toast.invalid.carrier",
                    getExtension(carrierFile.getName())));
            return;
        }

        // 容量检查：若载体有容量限制且待隐藏文件过大，提前拦截避免打开保存对话框
        long capacity = Long.MAX_VALUE;
        try {
            capacity = matchedAdapter.capacity(carrierFile.toPath());
        } catch (Exception ignored) {
            // 查询失败时不拦截
        }
        if (capacity != Long.MAX_VALUE && secretFile.length() > capacity) {
            toast.error(Messages.format("fileStego.toast.capacity.exceeded",
                    FileSizes.human(secretFile.length()),
                    FileSizes.human(capacity)));
            return;
        }

        // 解析混淆目标大小
        long targetSizeBytes = 0;
        if (fsObfuscateCheck.isSelected() && !fsObfuscateCheck.isDisabled()) {
            targetSizeBytes = parseTargetSize(fsObfuscateSizeField.getText());
            if (targetSizeBytes <= 0) {
                toast.info(Messages.get("fileStego.toast.invalid.size"));
                return;
            }
        }

        // 输出文件：默认放在载体同目录，文件名加 "stego_" 前缀
        String ext = matchedAdapter.outputExtension();
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("fileStego.save.title"));
        chooser.setInitialFileName("stego_" + carrierFile.getName());
        if (carrierFile.getParentFile() != null) {
            chooser.setInitialDirectory(carrierFile.getParentFile());
        }
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                matchedAdapter.displayName(), "*" + ext));
        File outFile = chooser.showSaveDialog(window());
        if (outFile == null) {
            return;
        }

        FileStegoOptions options = FileStegoOptions.builder()
                .paranoid(fsParanoidCheck.isSelected())
                .compressed(fsCompressCheck.isSelected())
                .storeIntegrity(fsIntegrityCheck.isSelected())
                .stealth(fsStealthCheck.isSelected() && getPasswordLength() > 0)
                .obfuscateSize(fsObfuscateCheck.isSelected())
                .targetSizeBytes(targetSizeBytes)
                .bruteForceGuard(fsBruteForceCheck.isSelected())
                .preferChunk(fsEmbedChunkRadio.isSelected())
                .build();

        byte[] pwd = getPasswordBytes();
        Path carrierPath = carrierFile.toPath();
        Path secretPath = secretFile.toPath();
        Path outputPath = outFile.toPath();

        showProgress(true, Messages.get("fileStego.status.hide"));
        taskRunner.submit(
                () -> codec.hide(carrierPath, secretPath, outputPath, pwd, options),
                () -> {
                    showProgress(false, null);
                    toast.success(Messages.format("fileStego.status.success.hide",
                            outputPath.getFileName()));
                    // 隐写成功后记录历史
                    HistoryService.record(OperationType.STEGO_ENCODE,
                            outputPath.getFileName().toString(), outputPath.toString(), null);
                },
                ex -> {
                    showProgress(false, null);
                    toast.error(Messages.format("fileStego.toast.error", errorMessage(ex)));
                    tryDelete(outputPath);
                });
    }

    private void doExtract() {
        if (carrierFile == null) {
            toast.info(Messages.get("fileStego.toast.no.carrier"));
            return;
        }
        if (outputDir == null) {
            // 未选输出目录时直接弹出目录选择器
            onChooseOutput();
            if (outputDir == null) {
                return;
            }
        }

        byte[] pwd = getPasswordBytes();
        Path stegoPath = carrierFile.toPath();
        Path outDirPath = outputDir.toPath();

        final Path[] extractedHolder = new Path[1];
        showProgress(true, Messages.get("fileStego.status.extract"));
        taskRunner.submit(
                () -> extractedHolder[0] = codec.extract(stegoPath, outDirPath, pwd),
                () -> {
                    showProgress(false, null);
                    Path extracted = extractedHolder[0];
                    toast.success(Messages.format("fileStego.status.success.extract",
                            extracted != null ? extracted.getFileName() : ""));
                    // 提取成功后记录历史（提取产物未知时退化为输出目录）
                    Path recordPath = extracted != null ? extracted : outDirPath;
                    HistoryService.record(OperationType.STEGO_EXTRACT,
                            recordPath.getFileName().toString(), recordPath.toString(), null);
                },
                ex -> {
                    showProgress(false, null);
                    toast.error(Messages.format("fileStego.toast.error", errorMessage(ex)));
                });
    }

    // ================================================================
    // 拖拽
    // ================================================================

    private void setupDragDrop() {
        fsCarrierStack.setOnDragOver(this::onDragOver);
        fsCarrierStack.setOnDragEntered(e -> onDragEntered(e, fsCarrierStack));
        fsCarrierStack.setOnDragExited(e -> onDragExited(e, fsCarrierStack));
        fsCarrierStack.setOnDragDropped(this::onCarrierDragDropped);

        fsSecretStack.setOnDragOver(this::onDragOver);
        fsSecretStack.setOnDragEntered(e -> onDragEntered(e, fsSecretStack));
        fsSecretStack.setOnDragExited(e -> onDragExited(e, fsSecretStack));
        fsSecretStack.setOnDragDropped(this::onSecretDragDropped);
    }

    private void onDragOver(final DragEvent e) {
        if (e.getDragboard().hasFiles()) {
            e.acceptTransferModes(TransferMode.COPY);
        }
    }

    private void onDragEntered(final DragEvent e, final StackPane zone) {
        if (e.getDragboard().hasFiles()) {
            zone.setStyle("-fx-background-color: #d0e4f7; -fx-background-radius: 6;");
        }
    }

    private void onDragExited(final DragEvent e, final StackPane zone) {
        zone.setStyle("-fx-background-color: #e8e8e8; -fx-background-radius: 6;");
    }

    private void onCarrierDragDropped(final DragEvent e) {
        fsCarrierStack.setStyle("-fx-background-color: #e8e8e8; -fx-background-radius: 6;");
        Dragboard db = e.getDragboard();
        if (db.hasFiles() && !db.getFiles().isEmpty()) {
            setCarrierFile(db.getFiles().get(0));
        }
        e.setDropCompleted(true);
    }

    private void onSecretDragDropped(final DragEvent e) {
        fsSecretStack.setStyle("-fx-background-color: #e8e8e8; -fx-background-radius: 6;");
        Dragboard db = e.getDragboard();
        if (db.hasFiles() && !db.getFiles().isEmpty()) {
            setSecretFile(db.getFiles().get(0));
        }
        e.setDropCompleted(true);
    }

    // ================================================================
    // 进度
    // ================================================================

    private void showProgress(final boolean show, final String status) {
        setVisibility(fsProgressBox, show);
        setVisibility(fsCancelBtn, show);
        fsActionBtn.setDisable(show);
        fsProgressBar.setProgress(show ? ProgressBar.INDETERMINATE_PROGRESS : 0);
        if (status != null) {
            fsStatusLabel.setText(status);
        }
    }

    @FXML
    private void onCancel() {
        taskRunner.shutdown();
        showProgress(false, null);
    }

    // ================================================================
    // 工具
    // ================================================================

    private static void setVisibility(final javafx.scene.Node node, final boolean visible) {
        if (node != null) {
            node.setVisible(visible);
            node.setManaged(visible);
        }
    }

    private static String getExtension(final String name) {
        String lower = name.toLowerCase();
        int dot = lower.lastIndexOf('.');
        return (dot >= 0) ? lower.substring(dot) : "";
    }

    /**
     * 解析目标大小字符串（支持 "500"=500KB、"1.5"=1.5MB、"200KB"、"3MB"）。
     */
    private static long parseTargetSize(final String text) {
        if (text == null || text.isBlank()) {
            return 0;
        }
        String t = text.trim().toUpperCase();
        try {
            if (t.endsWith("KB")) {
                return (long) (Double.parseDouble(t.replace("KB", "").trim()) * 1024);
            } else if (t.endsWith("MB")) {
                return (long) (Double.parseDouble(t.replace("MB", "").trim()) * 1024 * 1024);
            } else if (t.endsWith("GB")) {
                return (long) (Double.parseDouble(t.replace("GB", "").trim()) * 1024 * 1024 * 1024);
            } else if (t.endsWith("B")) {
                return Long.parseLong(t.replace("B", "").trim());
            } else {
                return (long) (Double.parseDouble(t) * 1024);
            }
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static void tryDelete(final Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // 清理失败无需处理
        }
    }

    private static String errorMessage(final Throwable ex) {
        return (ex.getMessage() != null) ? ex.getMessage() : ex.toString();
    }

    /**
     * 安装带样式的提示气泡到 info-icon 标签上。
     */
    private static void setTip(final Label label, final String text) {
        if (label == null) {
            return;
        }
        Tooltip tip = new Tooltip(text);
        tip.getStyleClass().add("info-tooltip");
        tip.setShowDelay(Duration.millis(120));
        tip.setShowDuration(Duration.seconds(20));
        tip.setHideDelay(Duration.millis(120));
        tip.setWrapText(true);
        tip.setMaxWidth(300);
        Tooltip.install(label, tip);
        label.setTooltip(tip);
    }

    private javafx.stage.Window window() {
        return fsRoot.getScene().getWindow();
    }

    // ================================================================
    // 国际化
    // ================================================================

    /**
     * 应用当前语言的文案，供 {@code MainController} 在 i18n 切换时调用。
     */
    public void applyTexts() {
        if (fsHideTab == null) {
            return;
        }
        fsHideTab.setText(Messages.get("fileStego.mode.hide"));
        fsExtractTab.setText(Messages.get("fileStego.mode.extract"));

        fsCarrierLabel.setText(Messages.get("fileStego.carrier.label"));
        fsCarrierHint.setText(Messages.get("fileStego.carrier.hint"));
        fsCarrierSub.setText(Messages.get("fileStego.carrier.sub"));
        fsCarrierBtn.setText(Messages.get("fileStego.carrier.choose"));
        fsCarrierClearBtn.setText(Messages.get("fileStego.carrier.clear"));

        fsSecretLabel.setText(Messages.get("fileStego.secret.label"));
        fsSecretPlaceholder.setText(Messages.get("fileStego.secret.hint"));
        fsSecretBtn.setText(Messages.get("fileStego.secret.choose"));
        fsSecretClearBtn.setText(Messages.get("fileStego.secret.clear"));

        fsOutputLabel.setText(Messages.get("fileStego.output.label"));
        fsOutputBtn.setText(Messages.get("fileStego.output.choose"));

        fsPasswordLabel.setText(Messages.get("fileStego.password.label"));
        fsPasswordField.setPromptText(Messages.get("fileStego.password.placeholder"));
        fsPasswordVisibleField.setPromptText(Messages.get("fileStego.password.placeholder"));
        fsShowPasswordCheck.setText(Messages.get("fileStego.password.show"));

        fsOptionsLabel.setText(Messages.get("fileStego.options.label"));
        fsParanoidCheck.setText(Messages.get("fileStego.option.paranoid"));
        fsCompressCheck.setText(Messages.get("fileStego.option.compress"));
        fsIntegrityCheck.setText(Messages.get("fileStego.option.integrity"));
        fsStealthCheck.setText(Messages.get("fileStego.option.stealth"));
        fsObfuscateCheck.setText(Messages.get("fileStego.option.obfuscate"));
        fsObfuscateSizeLabel.setText(Messages.get("fileStego.option.obfuscateSize"));
        fsBruteForceCheck.setText(Messages.get("fileStego.option.bruteForce"));
        fsEmbedModeLabel.setText(Messages.get("fileStego.option.embedMode"));
        fsEmbedChunkRadio.setText(Messages.get("fileStego.option.embedChunk"));
        fsEmbedAppendRadio.setText(Messages.get("fileStego.option.embedAppend"));

        fsCapacityLabel.setText(Messages.get("fileStego.capacity.label"));

        fsCancelBtn.setText(Messages.get("action.cancel"));
        fsActionBtn.setText(isHideMode
                ? Messages.get("fileStego.btn.hide")
                : Messages.get("fileStego.btn.extract"));

        // 提示气泡
        setTip(fsParanoidInfo, Messages.get("fileStego.option.paranoid.tip"));
        setTip(fsCompressInfo, Messages.get("fileStego.option.compress.tip"));
        setTip(fsIntegrityInfo, Messages.get("fileStego.option.integrity.tip"));
        setTip(fsStealthInfo, Messages.get("fileStego.option.stealth.tip"));
        setTip(fsObfuscateInfo, Messages.get("fileStego.option.obfuscate.tip"));
        setTip(fsBruteForceInfo, Messages.get("fileStego.option.bruteForce.tip"));
        setTip(fsEmbedModeInfo, Messages.get("fileStego.option.embedMode.tip"));

        // 刷新载体信息文案（若已选文件）
        if (carrierFile != null) {
            setCarrierFile(carrierFile);
        } else {
            updateCapacityDisplay();
        }
    }

    /**
     * 关闭后台线程池，应用退出时调用。
     */
    public void shutdown() {
        taskRunner.shutdown();
    }
}
