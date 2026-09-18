package hbnu.project.ergoutreecrypt.ui;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.exception.ExceptionMapper;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard;
import hbnu.project.ergoutreecrypt.filetypes.OutputNaming;
import hbnu.project.ergoutreecrypt.history.HistoryService;
import hbnu.project.ergoutreecrypt.history.OperationType;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptCodec;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMetadata;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptPhase;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProgress;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageProbe;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.ui.support.FileSizes;
import hbnu.project.ergoutreecrypt.ui.support.BoundedImagePreviewLoader;
import hbnu.project.ergoutreecrypt.ui.support.ImageCryptDesktopWorkflow;
import hbnu.project.ergoutreecrypt.ui.support.TaskRunner;
import hbnu.project.ergoutreecrypt.ui.support.Toast;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.DragEvent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.MouseEvent;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.awt.Desktop;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 桌面端 EGTC-IMG 图片加密与还原页面控制器。
 *
 * <p>控制器只编排 JavaFX 状态、后台任务和平台服务；协议、密码规范化与文件提交均委托共享核心。
 * 文件探测和所有图片处理都在 {@link TaskRunner} 的后台线程执行，用户切换主标签页不会终止任务。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public final class ImageCryptController {

    /** 缩略预览请求宽度，避免按原图尺寸分配像素。 */
    private static final double PREVIEW_WIDTH = 360.0;

    /** 缩略预览请求高度，避免按原图尺寸分配像素。 */
    private static final double PREVIEW_HEIGHT = 220.0;

    /** 进度界面最短刷新间隔。 */
    private static final long PROGRESS_REFRESH_NANOS = 80_000_000L;

    /** 图片加密共享门面，用于有界元数据探测。 */
    private final ImageCryptCodec codec = new ImageCryptCodec();

    /** 桌面端无界面业务工作流。 */
    private final ImageCryptDesktopWorkflow workflow = new ImageCryptDesktopWorkflow();

    /** 页面后台任务执行器。 */
    private final TaskRunner taskRunner = new TaskRunner();

    /** 缩略图后台解码执行器，避免预览阻塞加解密队列。 */
    private final TaskRunner previewTaskRunner = new TaskRunner();

    @FXML
    private StackPane imageRoot;
    @FXML
    private ToggleButton imageEncryptTab;
    @FXML
    private ToggleButton imageDecryptTab;
    @FXML
    private VBox imageDropZone;
    @FXML
    private Label imageDropIcon;
    @FXML
    private Label imageDropHint;
    @FXML
    private Label imageDropSub;
    @FXML
    private VBox imageFileCard;
    @FXML
    private Label imageFileName;
    @FXML
    private Label imageFileMeta;
    @FXML
    private Label imageProtocolMeta;
    @FXML
    private Label imageExtensionWarning;
    @FXML
    private ImageView imageInputPreview;
    @FXML
    private Label imageInputPreviewCaption;
    @FXML
    private Button imageReselectFileBtn;
    @FXML
    private Button imageClearFileBtn;
    @FXML
    private Label imageProtectionTitle;
    @FXML
    private ToggleButton imagePublicModeBtn;
    @FXML
    private ToggleButton imagePasswordModeBtn;
    @FXML
    private VBox imagePasswordBox;
    @FXML
    private Label imagePasswordLabel;
    @FXML
    private PasswordField imagePasswordField;
    @FXML
    private TextField imagePasswordVisibleField;
    @FXML
    private CheckBox imageShowPasswordCheck;
    @FXML
    private PasswordField imageConfirmField;
    @FXML
    private Label imageMismatchLabel;
    @FXML
    private Label imageKdfHint;
    @FXML
    private Label imageTransportTitle;
    @FXML
    private CheckBox imageErrorCorrectionCheck;
    @FXML
    private Label imageErrorCorrectionHint;
    @FXML
    private CheckBox imageBestEffortCheck;
    @FXML
    private Label imageBestEffortHint;
    @FXML
    private VBox imagePublicWarningCard;
    @FXML
    private Label imagePublicWarning;
    @FXML
    private Label imageSendAsFileHint;
    @FXML
    private VBox imageOutputCard;
    @FXML
    private Label imageOutputTitle;
    @FXML
    private TextField imageOutputDirectoryField;
    @FXML
    private Button imageOutputBrowseBtn;
    @FXML
    private Label imageOutputNameTitle;
    @FXML
    private Label imageOutputName;
    @FXML
    private VBox imagePreviewCard;
    @FXML
    private Label imagePreviewTitle;
    @FXML
    private ImageView imagePreview;
    @FXML
    private Label imagePreviewCaption;
    @FXML
    private VBox imageResultCard;
    @FXML
    private Label imageResultTitle;
    @FXML
    private Label imageResultPath;
    @FXML
    private Button imageOpenDirectoryBtn;
    @FXML
    private Button imageCopyPathBtn;
    @FXML
    private VBox imageProgressBox;
    @FXML
    private Label imageStatusLabel;
    @FXML
    private Label imageProgressInfo;
    @FXML
    private ProgressBar imageProgressBar;
    @FXML
    private Button imageCancelBtn;
    @FXML
    private Button imageVerifyBtn;
    @FXML
    private Button imageActionBtn;

    /** 页面 Toast 提示器。 */
    private Toast toast;

    /** 当前操作方向。 */
    private OperationMode operationMode = OperationMode.ENCRYPT;

    /** 加密时显式选择的保护模式。 */
    private ImageCryptMode protectionMode = ImageCryptMode.PUBLIC_RECOVERY;

    /** 当前选中的输入路径。 */
    private Path selectedInput;

    /** 普通图片的有界探测结果。 */
    private ImageProbe.Result imageProbe;

    /** EGTC-IMG 产物的有界元数据。 */
    private ImageCryptMetadata encryptedMetadata;

    /** 当前输入文件大小。 */
    private long selectedInputBytes;

    /** 最近一次成功操作的结果路径。 */
    private Path resultPath;

    /** 是否正在执行加解密或校验。 */
    private boolean running;

    /** 是否正在后台探测输入。 */
    private boolean probing;

    /** 后台任务读取的取消标记。 */
    private volatile boolean cancelRequested;

    /** 选择代次，用于丢弃过期探测结果。 */
    private long selectionGeneration;

    /** 输入预览请求代次，用于丢弃过期异步解码。 */
    private long inputPreviewGeneration;

    /** 结果预览请求代次，用于丢弃过期异步解码。 */
    private long resultPreviewGeneration;

    /**
     * 初始化页面控件、交互监听和默认状态。
     */
    @FXML
    private void initialize() {
        toast = new Toast(imageRoot);
        imageEncryptTab.setOnAction(event -> switchOperation(OperationMode.ENCRYPT));
        imageDecryptTab.setOnAction(event -> switchOperation(OperationMode.DECRYPT));
        imagePublicModeBtn.setOnAction(event -> switchProtection(ImageCryptMode.PUBLIC_RECOVERY));
        imagePasswordModeBtn.setOnAction(event -> switchProtection(ImageCryptMode.PASSWORD));

        imageDropZone.setOnMouseClicked(this::onChooseFile);
        imageDropZone.setOnDragEntered(this::onDragEntered);
        imageDropZone.setOnDragExited(this::onDragExited);
        imageDropZone.setOnDragOver(this::onDragOver);
        imageDropZone.setOnDragDropped(this::onDragDropped);

        imagePasswordVisibleField.textProperty().bindBidirectional(imagePasswordField.textProperty());
        imagePasswordField.textProperty().addListener((observable, oldValue, newValue) ->
                updatePasswordFeedback());
        imageConfirmField.textProperty().addListener((observable, oldValue, newValue) ->
                updatePasswordFeedback());

        applyTexts();
        switchOperation(OperationMode.ENCRYPT);
        switchProtection(ImageCryptMode.PUBLIC_RECOVERY);
    }

    /**
     * 按当前语言刷新本页全部文案。
     */
    public void applyTexts() {
        imageEncryptTab.setText(Messages.get("imageCrypt.tab.encrypt"));
        imageDecryptTab.setText(Messages.get("imageCrypt.tab.decrypt"));
        imageDropIcon.setText(operationMode == OperationMode.ENCRYPT ? "▧" : "↶");
        imageDropHint.setText(Messages.get(operationMode == OperationMode.ENCRYPT
                ? "imageCrypt.file.encryptHint" : "imageCrypt.file.decryptHint"));
        imageDropSub.setText(Messages.get("imageCrypt.file.dropSub"));
        imageReselectFileBtn.setText(Messages.get("imageCrypt.file.reselect"));
        imageClearFileBtn.setText(Messages.get("imageCrypt.file.clearSelection"));
        imageInputPreviewCaption.setText(Messages.get("imageCrypt.preview.inputCaption"));

        imageProtectionTitle.setText(Messages.get("imageCrypt.protection.title"));
        imagePublicModeBtn.setText(Messages.get("imageCrypt.protection.public"));
        imagePasswordModeBtn.setText(Messages.get("imageCrypt.protection.password"));
        imagePasswordLabel.setText(Messages.get("password.label"));
        imagePasswordField.setPromptText(Messages.get("password.placeholder"));
        imagePasswordVisibleField.setPromptText(Messages.get("password.placeholder"));
        imageShowPasswordCheck.setText(Messages.get("password.show"));
        imageConfirmField.setPromptText(Messages.get("password.confirm.placeholder"));
        imageKdfHint.setText(Messages.get("imageCrypt.kdf.hint"));
        imageTransportTitle.setText(Messages.get("imageCrypt.transport.title"));
        imageErrorCorrectionCheck.setText(Messages.get("imageCrypt.transport.errorCorrection"));
        imageErrorCorrectionHint.setText(Messages.get("imageCrypt.transport.errorCorrection.hint"));
        imageBestEffortCheck.setText(Messages.get("imageCrypt.transport.bestEffort"));
        imageBestEffortHint.setText(Messages.get("imageCrypt.transport.bestEffort.hint"));
        imagePublicWarning.setText(Messages.get("imageCrypt.public.warning"));
        imageSendAsFileHint.setText(Messages.get("imageCrypt.sendAsFile.hint"));

        imageOutputTitle.setText(Messages.get("imageCrypt.output.directory"));
        imageOutputDirectoryField.setPromptText(Messages.get("imageCrypt.output.directoryPrompt"));
        imageOutputBrowseBtn.setText(Messages.get("file.output.browse"));
        imageOutputNameTitle.setText(Messages.get("imageCrypt.output.name"));
        imagePreviewTitle.setText(Messages.get("imageCrypt.preview.title"));
        updateResultPreviewTexts();
        imageResultTitle.setText(Messages.get("imageCrypt.result.title"));
        imageOpenDirectoryBtn.setText(Messages.get("imageCrypt.result.openDirectory"));
        imageCopyPathBtn.setText(Messages.get("imageCrypt.result.copyPath"));
        imageCancelBtn.setText(Messages.get("action.cancel"));
        imageVerifyBtn.setText(Messages.get("imageCrypt.action.verify"));
        updateActionText();
        updatePasswordFeedback();
        updateOutputName();
        refreshSelectedFileInfo();
        if (!running && !probing) {
            imageStatusLabel.setText(Messages.get("status.ready"));
        }
        updatePublicWarningVisibility();
    }

    /**
     * 切换图片加密或还原方向。
     *
     * @param mode 新操作方向
     */
    private void switchOperation(final OperationMode mode) {
        if (running || operationMode == mode && selectedInput == null) {
            operationMode = mode;
        } else if (operationMode != mode) {
            clearSelection();
            operationMode = mode;
        }
        imageEncryptTab.setSelected(mode == OperationMode.ENCRYPT);
        imageDecryptTab.setSelected(mode == OperationMode.DECRYPT);
        boolean encrypting = mode == OperationMode.ENCRYPT;
        imagePublicModeBtn.setDisable(!encrypting || running || probing);
        imagePasswordModeBtn.setDisable(!encrypting || running || probing);
        setVisible(imageErrorCorrectionCheck, encrypting);
        setVisible(imageErrorCorrectionHint, encrypting);
        setVisible(imageBestEffortCheck, !encrypting);
        setVisible(imageBestEffortHint, !encrypting);
        if (encrypting) {
            switchProtection(protectionMode);
        } else if (encryptedMetadata == null) {
            imagePublicModeBtn.setSelected(false);
            imagePasswordModeBtn.setSelected(false);
            setVisible(imagePasswordBox, false);
        }
        setVisible(imageVerifyBtn, !encrypting && selectedInput != null);
        updatePublicWarningVisibility();
        updateActionText();
        updateOutputName();
        applyTextsForOperation();
    }

    /**
     * 刷新依赖当前操作方向的少量文案。
     */
    private void applyTextsForOperation() {
        if (imageDropHint == null) {
            return;
        }
        imageDropIcon.setText(operationMode == OperationMode.ENCRYPT ? "▧" : "↶");
        imageDropHint.setText(Messages.get(operationMode == OperationMode.ENCRYPT
                ? "imageCrypt.file.encryptHint" : "imageCrypt.file.decryptHint"));
    }

    /**
     * 切换加密保护模式并刷新密码区域。
     *
     * @param mode 新保护模式
     */
    private void switchProtection(final ImageCryptMode mode) {
        if (operationMode != OperationMode.ENCRYPT || running) {
            return;
        }
        protectionMode = mode;
        imagePublicModeBtn.setSelected(mode == ImageCryptMode.PUBLIC_RECOVERY);
        imagePasswordModeBtn.setSelected(mode == ImageCryptMode.PASSWORD);
        setVisible(imagePasswordBox, mode == ImageCryptMode.PASSWORD);
        updatePublicWarningVisibility();
        updatePasswordFeedback();
    }

    /**
     * 仅在当前操作确实采用公开恢复模式时显示安全提示框。
     */
    private void updatePublicWarningVisibility() {
        if (imagePublicWarningCard == null) {
            return;
        }
        boolean publicRecovery = operationMode == OperationMode.ENCRYPT
                ? protectionMode == ImageCryptMode.PUBLIC_RECOVERY
                : encryptedMetadata != null && !encryptedMetadata.requiresPassword();
        setVisible(imagePublicWarningCard, publicRecovery);
    }

    /**
     * 打开与当前操作匹配的文件选择器。
     *
     * @param event 鼠标事件
     */
    private void onChooseFile(final MouseEvent event) {
        if (running || probing) {
            return;
        }
        chooseFile();
    }

    /**
     * 从已选文件卡重新打开文件选择器。
     */
    @FXML
    private void onReselectFile() {
        if (!running && !probing) {
            chooseFile();
        }
    }

    /**
     * 打开与当前操作匹配的文件选择器并探测所选文件。
     */
    private void chooseFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("file.choose"));
        if (operationMode == OperationMode.ENCRYPT) {
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                    Messages.get("imageCrypt.file.filter.source"),
                    "*.png", "*.apng", "*.jpg", "*.jpeg", "*.gif", "*.bmp", "*.webp"));
        } else {
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                    Messages.get("imageCrypt.file.filter.encrypted"),
                    "*.png", "*.jpg", "*.jpeg"));
        }
        File file = chooser.showOpenDialog(stage());
        if (file != null) {
            inspectInput(file.toPath());
        }
    }

    /**
     * 高亮可接收文件的拖放区域。
     *
     * @param event 拖放事件
     */
    private void onDragEntered(final DragEvent event) {
        if (!running && !probing && event.getDragboard().hasFiles()) {
            imageDropZone.getStyleClass().add("drag-over");
        }
        event.consume();
    }

    /**
     * 清除拖放区域高亮。
     *
     * @param event 拖放事件
     */
    private void onDragExited(final DragEvent event) {
        imageDropZone.getStyleClass().remove("drag-over");
        event.consume();
    }

    /**
     * 接受单文件复制拖放。
     *
     * @param event 拖放事件
     */
    private void onDragOver(final DragEvent event) {
        if (!running && !probing && event.getDragboard().hasFiles()) {
            event.acceptTransferModes(TransferMode.COPY);
        }
        event.consume();
    }

    /**
     * 取得拖入的第一个文件并启动有界探测。
     *
     * @param event 拖放事件
     */
    private void onDragDropped(final DragEvent event) {
        Dragboard dragboard = event.getDragboard();
        boolean accepted = false;
        if (!running && !probing && dragboard.hasFiles() && !dragboard.getFiles().isEmpty()) {
            inspectInput(dragboard.getFiles().get(0).toPath());
            accepted = true;
        }
        imageDropZone.getStyleClass().remove("drag-over");
        event.setDropCompleted(accepted);
        event.consume();
    }

    /**
     * 在后台执行格式护栏与有界元数据探测。
     *
     * @param input 待探测输入
     */
    private void inspectInput(final Path input) {
        clearResult();
        long generation = ++selectionGeneration;
        selectedInput = input.toAbsolutePath().normalize();
        setProbing(true);
        AtomicReference<Inspection> inspection = new AtomicReference<>();
        AtomicReference<String> rejection = new AtomicReference<>();
        taskRunner.submit(() -> {
            FileInputGuard.Feature feature = operationMode == OperationMode.ENCRYPT
                    ? FileInputGuard.Feature.IMAGE_CRYPT_ENCRYPT
                    : FileInputGuard.Feature.IMAGE_CRYPT_DECRYPT;
            FileInputGuard.GuardResult guard = FileInputGuard.check(
                    feature, FileInputGuard.Options.none(), selectedInput);
            if (guard.rejected()) {
                rejection.set(guard.message());
                return;
            }
            long fileBytes = Files.size(selectedInput);
            if (operationMode == OperationMode.ENCRYPT) {
                inspection.set(new Inspection(selectedInput, fileBytes,
                        ImageProbe.probe(selectedInput), null));
            } else {
                inspection.set(new Inspection(selectedInput, fileBytes, null,
                        codec.peekMetadata(selectedInput)));
            }
        }, () -> {
            if (generation != selectionGeneration) {
                return;
            }
            setProbing(false);
            if (rejection.get() != null) {
                toast.error(rejection.get());
                clearSelection();
                return;
            }
            applyInspection(inspection.get());
        }, error -> {
            if (generation != selectionGeneration) {
                return;
            }
            setProbing(false);
            toast.error(ExceptionMapper.friendlyMessage(error));
            clearSelection();
        });
    }

    /**
     * 把后台探测结果应用到文件卡片与输出设置。
     *
     * @param inspection 探测结果
     */
    private void applyInspection(final Inspection inspection) {
        if (inspection == null) {
            clearSelection();
            return;
        }
        selectedInput = inspection.input();
        selectedInputBytes = inspection.fileBytes();
        imageProbe = inspection.probe();
        encryptedMetadata = inspection.metadata();
        Path parent = selectedInput.getParent();
        imageOutputDirectoryField.setText(parent == null ? "" : parent.toString());
        setVisible(imageDropZone, false);
        setVisible(imageFileCard, true);
        setVisible(imageOutputCard, true);
        setVisible(imageVerifyBtn, operationMode == OperationMode.DECRYPT);
        if (encryptedMetadata != null) {
            applyMetadataProtection(encryptedMetadata);
        }
        refreshSelectedFileInfo();
        showPreview(imageInputPreview, imageInputPreviewCaption, selectedInput,
                "imageCrypt.preview.inputCaption");
        updateOutputName();
    }

    /**
     * 依据密文元数据锁定还原页的保护模式显示。
     *
     * @param metadata EGTC-IMG 元数据
     */
    private void applyMetadataProtection(final ImageCryptMetadata metadata) {
        boolean password = metadata.requiresPassword();
        imagePublicModeBtn.setSelected(!password);
        imagePasswordModeBtn.setSelected(password);
        imagePublicModeBtn.setDisable(true);
        imagePasswordModeBtn.setDisable(true);
        setVisible(imagePasswordBox, password);
        setVisible(imageConfirmField, false);
        setVisible(imageMismatchLabel, false);
        updatePublicWarningVisibility();
    }

    /**
     * 依据当前探测结果刷新文件信息卡片。
     */
    private void refreshSelectedFileInfo() {
        if (selectedInput == null || imageFileName == null) {
            return;
        }
        imageFileName.setText(selectedInput.getFileName().toString());
        if (imageProbe != null) {
            String dimensions = imageProbe.hasSizeHint()
                    ? imageProbe.width() + " × " + imageProbe.height()
                    : Messages.get("imageCrypt.meta.unknownDimensions");
            imageFileMeta.setText(Messages.format("imageCrypt.meta.source",
                    imageProbe.format().name(), dimensions, FileSizes.human(selectedInputBytes)));
            imageProtocolMeta.setText(Messages.get("imageCrypt.meta.sourceBytesPreserved"));
            imageExtensionWarning.setText(imageProbe.extensionConflict()
                    ? Messages.get("imageCrypt.meta.extensionConflict") : "");
            setVisible(imageExtensionWarning, imageProbe.extensionConflict());
            return;
        }
        if (encryptedMetadata != null) {
            String modeText = Messages.get(encryptedMetadata.requiresPassword()
                    ? "imageCrypt.protection.password" : "imageCrypt.protection.public");
            imageFileMeta.setText(Messages.format("imageCrypt.meta.encrypted",
                    encryptedMetadata.protocolVersion(), modeText,
                    FileSizes.human(selectedInputBytes)));
            imageProtocolMeta.setText(Messages.format("imageCrypt.meta.restoreEstimate",
                    formatRestoredSize(encryptedMetadata)));
            imageExtensionWarning.setText("");
            setVisible(imageExtensionWarning, false);
        }
    }

    /**
     * 格式化密文元数据给出的恢复大小区间。
     *
     * @param metadata EGTC-IMG 元数据
     * @return 人类可读大小或区间
     */
    private static String formatRestoredSize(final ImageCryptMetadata metadata) {
        long minimum = metadata.minRestoredBytes();
        long maximum = metadata.maxRestoredBytes();
        if (minimum == maximum) {
            return FileSizes.human(maximum);
        }
        return FileSizes.human(minimum) + " – " + FileSizes.human(maximum);
    }

    /**
     * 清除当前文件及其探测状态。
     */
    @FXML
    private void onClearFile() {
        if (!running) {
            clearSelection();
        }
    }

    /**
     * 清空选择并恢复初始拖放区域。
     */
    private void clearSelection() {
        selectionGeneration++;
        selectedInput = null;
        imageProbe = null;
        encryptedMetadata = null;
        selectedInputBytes = 0L;
        inputPreviewGeneration++;
        imageInputPreview.setImage(null);
        imageInputPreviewCaption.setText(Messages.get("imageCrypt.preview.inputCaption"));
        setVisible(imageFileCard, false);
        setVisible(imageOutputCard, false);
        setVisible(imageVerifyBtn, false);
        setVisible(imageDropZone, true);
        if (operationMode == OperationMode.DECRYPT) {
            imagePublicModeBtn.setSelected(false);
            imagePasswordModeBtn.setSelected(false);
            setVisible(imagePasswordBox, false);
        }
        imageOutputDirectoryField.clear();
        imageOutputName.setText("");
        clearResult();
        updatePublicWarningVisibility();
    }

    /**
     * 打开输出目录选择器。
     */
    @FXML
    private void onBrowseOutputDirectory() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle(Messages.get("imageCrypt.output.chooseDirectory"));
        Path current = parseOutputDirectory(false);
        if (current != null && Files.isDirectory(current)) {
            chooser.setInitialDirectory(current.toFile());
        }
        File directory = chooser.showDialog(stage());
        if (directory != null) {
            imageOutputDirectoryField.setText(directory.getAbsolutePath());
        }
    }

    /**
     * 显示或隐藏密码明文输入框。
     */
    @FXML
    private void onToggleShowPassword() {
        boolean show = imageShowPasswordCheck.isSelected();
        setVisible(imagePasswordVisibleField, show);
        setVisible(imagePasswordField, !show);
    }

    /**
     * 刷新密码确认不一致提示。
     */
    private void updatePasswordFeedback() {
        if (imageMismatchLabel == null) {
            return;
        }
        boolean requiresConfirmation = operationMode == OperationMode.ENCRYPT
                && protectionMode == ImageCryptMode.PASSWORD;
        String password = imagePasswordField.getText();
        boolean mismatch = requiresConfirmation && password != null && !password.isEmpty()
                && !password.equals(imageConfirmField.getText());
        imageMismatchLabel.setText(mismatch ? Messages.get("password.mismatch") : "");
        setVisible(imageMismatchLabel, mismatch);
        setVisible(imageConfirmField, requiresConfirmation);
    }

    /**
     * 启动当前方向的图片处理任务。
     */
    @FXML
    private void onAction() {
        if (running || probing || selectedInput == null) {
            if (selectedInput == null) {
                toast.error(Messages.get("toast.no.file"));
            }
            return;
        }
        if (!validatePassword()) {
            return;
        }
        Path outputDirectory = parseOutputDirectory(true);
        if (outputDirectory == null) {
            return;
        }
        if (operationMode == OperationMode.ENCRYPT) {
            startEncrypt(outputDirectory, !SettingsManager.isConfirmOverwrite());
        } else {
            startDecrypt(outputDirectory, !SettingsManager.isConfirmOverwrite());
        }
    }

    /**
     * 校验当前 EGTC-IMG 文件的完整性。
     */
    @FXML
    private void onVerifyIntegrity() {
        if (running || probing || selectedInput == null || encryptedMetadata == null) {
            return;
        }
        if (!validatePassword()) {
            return;
        }
        String password = imagePasswordField.getText();
        Path input = selectedInput;
        runCryptoTask("IMAGE_VERIFY", progress -> {
            workflow.verify(input, password, progress);
            HistoryService.record(OperationType.IMAGE_VERIFY,
                    input.getFileName().toString(), input.toString(), null);
        }, () -> finishSuccess(Messages.get("imageCrypt.status.verifySuccess"), input, false),
                this::finishError);
    }

    /**
     * 校验当前保护模式所需的密码输入。
     *
     * @return true 表示可以启动任务
     */
    private boolean validatePassword() {
        boolean passwordRequired = operationMode == OperationMode.ENCRYPT
                ? protectionMode == ImageCryptMode.PASSWORD
                : encryptedMetadata != null && encryptedMetadata.requiresPassword();
        if (!passwordRequired) {
            return true;
        }
        String password = imagePasswordField.getText();
        if (password == null || password.isEmpty()) {
            toast.error(Messages.get("imageCrypt.toast.needPassword"));
            return false;
        }
        if (operationMode == OperationMode.ENCRYPT
                && !password.equals(imageConfirmField.getText())) {
            toast.error(Messages.get("toast.no.password.confirm"));
            return false;
        }
        return true;
    }

    /**
     * 启动图片加密任务。
     *
     * @param outputDirectory   输出目录
     * @param overwriteExisting 是否覆盖已有输出
     */
    private void startEncrypt(final Path outputDirectory, final boolean overwriteExisting) {
        Path input = selectedInput;
        Path output = outputDirectory.resolve(
                OutputNaming.imageCryptOutputName(input.getFileName().toString()));
        String password = imagePasswordField.getText();
        ImageCryptMode selectedMode = protectionMode;
        boolean errorCorrection = imageErrorCorrectionCheck.isSelected();
        runCryptoTask("IMAGE_ENCRYPT", progress -> {
            workflow.encrypt(input, output, selectedMode, password, overwriteExisting,
                    errorCorrection, progress);
            HistoryService.record(OperationType.IMAGE_ENCRYPT,
                    output.getFileName().toString(), output.toString(), null);
        }, () -> finishSuccess(Messages.format("imageCrypt.status.encryptSuccess",
                output.getFileName()), output, true), error -> {
            setRunning(false);
            if (!overwriteExisting && SettingsManager.isConfirmOverwrite()
                    && ExceptionMapper.kindOf(error) == ErrorKind.FILE_EXISTS
                    && confirmOverwrite(output)) {
                startEncrypt(outputDirectory, true);
                return;
            }
            showOperationError(error);
        });
    }

    /**
     * 启动图片还原任务。
     *
     * @param outputDirectory   输出目录
     * @param overwriteExisting 是否覆盖同名恢复文件
     */
    private void startDecrypt(final Path outputDirectory, final boolean overwriteExisting) {
        Path input = selectedInput;
        String password = imagePasswordField.getText();
        boolean bestEffort = imageBestEffortCheck.isSelected();
        AtomicReference<Path> restored = new AtomicReference<>();
        runCryptoTask("IMAGE_DECRYPT", progress -> {
            Path output = workflow.decrypt(input, outputDirectory, password,
                    overwriteExisting, bestEffort, progress);
            restored.set(output);
            HistoryService.record(OperationType.IMAGE_DECRYPT,
                    output.getFileName().toString(), output.toString(), null);
        }, () -> {
            Path output = restored.get();
            finishSuccess(Messages.format("imageCrypt.status.decryptSuccess",
                    output.getFileName()), output, true);
        }, error -> {
            setRunning(false);
            if (!overwriteExisting && SettingsManager.isConfirmOverwrite()
                    && ExceptionMapper.kindOf(error) == ErrorKind.FILE_EXISTS
                    && confirmOverwrite(outputDirectory)) {
                startDecrypt(outputDirectory, true);
                return;
            }
            showOperationError(error);
        });
    }

    /**
     * 提交图片后台任务并统一连接进度、成功和失败回调。
     *
     * @param operationName 日志操作名
     * @param work          后台任务
     * @param onSuccess     成功回调
     * @param onError       失败回调
     */
    private void runCryptoTask(final String operationName, final ImageWork work,
                               final Runnable onSuccess,
                               final java.util.function.Consumer<Throwable> onError) {
        setRunning(true);
        cancelRequested = false;
        imageProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        imageProgressInfo.setText("");
        imageStatusLabel.setText(Messages.get("action.processing"));
        ImageCryptProgress progress = new FxImageCryptProgress();
        String fileName = selectedInput == null ? null : selectedInput.getFileName().toString();
        taskRunner.submit(operationName, fileName, () -> work.run(progress), onSuccess, onError);
    }

    /**
     * 完成一次成功操作并展示结果动作。
     *
     * @param message     成功文案
     * @param output      结果路径
     * @param showPreview 是否显示结果缩略图
     */
    private void finishSuccess(final String message, final Path output,
                               final boolean showPreview) {
        setRunning(false);
        imageProgressBar.setProgress(1.0);
        imageStatusLabel.setText(message);
        toast.success(message);
        resultPath = output;
        imageResultPath.setText(output.toString());
        setVisible(imageResultCard, true);
        if (showPreview) {
            showOutputPreview(output);
        } else {
            setVisible(imagePreviewCard, false);
        }
        if (SettingsManager.isAutoClearPassword()) {
            imagePasswordField.clear();
            imageConfirmField.clear();
        }
    }

    /**
     * 完成失败或取消任务并恢复页面状态。
     *
     * @param error 后台错误
     */
    private void finishError(final Throwable error) {
        setRunning(false);
        showOperationError(error);
    }

    /**
     * 按统一分类展示取消或错误信息。
     *
     * @param error 后台错误
     */
    private void showOperationError(final Throwable error) {
        if (ExceptionMapper.isCancellation(error)) {
            imageStatusLabel.setText(Messages.get("status.cancelled"));
            toast.info(Messages.get("status.cancelled"));
            return;
        }
        String message = ExceptionMapper.friendlyMessage(error);
        imageStatusLabel.setText(message);
        toast.error(message);
    }

    /**
     * 请求取消当前任务。
     */
    @FXML
    private void onCancel() {
        cancelRequested = true;
        imageStatusLabel.setText(Messages.get("imageCrypt.status.cancelRequested"));
    }

    /**
     * 用请求尺寸构造后台加载的结果缩略图。
     *
     * @param output 输出图片
     */
    private void showOutputPreview(final Path output) {
        updateResultPreviewTexts();
        showPreview(imagePreview, imagePreviewCaption, output,
                operationMode == OperationMode.ENCRYPT
                        ? "imageCrypt.preview.encryptedCaption"
                        : "imageCrypt.preview.decryptedCaption");
        setVisible(imagePreviewCard, true);
    }

    /**
     * 以固定请求尺寸异步加载输入或结果缩略图。
     *
     * @param view 图片控件
     * @param caption 预览说明控件
     * @param path 图片路径
     * @param captionKey 成功加载时的说明资源键
     */
    private void showPreview(final ImageView view, final Label caption, final Path path,
                             final String captionKey) {
        boolean inputPreview = view == imageInputPreview;
        long generation = inputPreview ? ++inputPreviewGeneration : ++resultPreviewGeneration;
        AtomicReference<BufferedImage> decoded = new AtomicReference<>();
        view.setImage(null);
        caption.setText(Messages.get("imageCrypt.preview.loading"));
        previewTaskRunner.submit(() -> decoded.set(BoundedImagePreviewLoader.readThumbnail(
                        path, (int) PREVIEW_WIDTH, (int) PREVIEW_HEIGHT)), () -> {
            long current = inputPreview ? inputPreviewGeneration : resultPreviewGeneration;
            if (generation != current) {
                BufferedImage stale = decoded.get();
                if (stale != null) {
                    stale.flush();
                }
                return;
            }
            Image preview = BoundedImagePreviewLoader.toFxImage(decoded.get());
            view.setImage(preview);
            caption.setText(Messages.get(preview == null
                    ? "imageCrypt.preview.unavailable" : captionKey));
        }, error -> {
            long current = inputPreview ? inputPreviewGeneration : resultPreviewGeneration;
            if (generation == current) {
                view.setImage(null);
                caption.setText(Messages.get("imageCrypt.preview.unavailable"));
            }
        });
    }

    /**
     * 刷新与当前操作方向匹配的结果预览标题和说明。
     */
    private void updateResultPreviewTexts() {
        if (imagePreviewTitle == null || imagePreviewCaption == null) {
            return;
        }
        imagePreviewTitle.setText(Messages.get("imageCrypt.preview.resultTitle"));
        imagePreviewCaption.setText(Messages.get(operationMode == OperationMode.ENCRYPT
                ? "imageCrypt.preview.encryptedCaption"
                : "imageCrypt.preview.decryptedCaption"));
    }

    /**
     * 清除上一项任务的结果动作和结果预览。
     */
    private void clearResult() {
        resultPath = null;
        resultPreviewGeneration++;
        imageResultPath.setText("");
        imagePreview.setImage(null);
        setVisible(imagePreviewCard, false);
        setVisible(imageResultCard, false);
    }

    /**
     * 在系统文件管理器中打开结果所在目录。
     */
    @FXML
    private void onOpenResultDirectory() {
        if (resultPath == null) {
            return;
        }
        Path directory = resultPath.getParent();
        if (directory == null) {
            return;
        }
        taskRunner.submit(() -> {
            if (!Desktop.isDesktopSupported()
                    || !Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                throw new IOException(Messages.get("imageCrypt.result.openUnsupported"));
            }
            Desktop.getDesktop().open(directory.toFile());
        }, () -> {
        }, error -> toast.error(ExceptionMapper.friendlyMessage(error)));
    }

    /**
     * 把结果绝对路径复制到系统剪贴板。
     */
    @FXML
    private void onCopyResultPath() {
        if (resultPath == null) {
            return;
        }
        ClipboardContent content = new ClipboardContent();
        content.putString(resultPath.toString());
        Clipboard.getSystemClipboard().setContent(content);
        toast.success(Messages.get("imageCrypt.result.pathCopied"));
    }

    /**
     * 解析输出目录并按需展示输入错误。
     *
     * @param showError 是否展示错误 Toast
     * @return 规范化目录；输入非法时为 {@code null}
     */
    private Path parseOutputDirectory(final boolean showError) {
        String text = imageOutputDirectoryField.getText();
        if (text == null || text.isBlank()) {
            if (showError) {
                toast.error(Messages.get("imageCrypt.toast.outputRequired"));
            }
            return null;
        }
        try {
            return Path.of(text).toAbsolutePath().normalize();
        } catch (InvalidPathException error) {
            if (showError) {
                toast.error(Messages.get("imageCrypt.toast.invalidOutput"));
            }
            return null;
        }
    }

    /**
     * 请求用户确认覆盖目标。
     *
     * @param target 已存在的目标或包含冲突文件的目录
     * @return true 表示允许覆盖
     */
    private boolean confirmOverwrite(final Path target) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.initOwner(stage());
        alert.setTitle(Messages.get("imageCrypt.overwrite.title"));
        alert.setHeaderText(Messages.get("imageCrypt.overwrite.header"));
        alert.setContentText(Messages.format("imageCrypt.overwrite.content", target));
        return alert.showAndWait().filter(ButtonType.OK::equals).isPresent();
    }

    /**
     * 刷新输出文件名提示。
     */
    private void updateOutputName() {
        if (imageOutputName == null) {
            return;
        }
        if (selectedInput == null) {
            imageOutputName.setText("");
        } else if (operationMode == OperationMode.ENCRYPT) {
            imageOutputName.setText(OutputNaming.imageCryptOutputName(
                    selectedInput.getFileName().toString()));
        } else {
            imageOutputName.setText(Messages.get("imageCrypt.output.restoredNamePending"));
        }
    }

    /**
     * 刷新主操作按钮文案。
     */
    private void updateActionText() {
        if (imageActionBtn != null) {
            imageActionBtn.setText(Messages.get(operationMode == OperationMode.ENCRYPT
                    ? "imageCrypt.action.encrypt" : "imageCrypt.action.decrypt"));
        }
    }

    /**
     * 切换输入探测状态。
     *
     * @param value true 表示正在探测
     */
    private void setProbing(final boolean value) {
        probing = value;
        imageActionBtn.setDisable(value || running);
        imageEncryptTab.setDisable(value || running);
        imageDecryptTab.setDisable(value || running);
        imageReselectFileBtn.setDisable(value || running);
        imageClearFileBtn.setDisable(value || running);
        imageStatusLabel.setText(value
                ? Messages.get("imageCrypt.status.probing") : Messages.get("status.ready"));
        setVisible(imageProgressBox, value || running);
        if (value) {
            imageProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
            imageProgressInfo.setText("");
        }
    }

    /**
     * 切换长任务运行状态。
     *
     * @param value true 表示正在运行
     */
    private void setRunning(final boolean value) {
        running = value;
        imageActionBtn.setDisable(value || probing);
        imageEncryptTab.setDisable(value || probing);
        imageDecryptTab.setDisable(value || probing);
        imagePublicModeBtn.setDisable(value || probing || operationMode == OperationMode.DECRYPT);
        imagePasswordModeBtn.setDisable(value || probing || operationMode == OperationMode.DECRYPT);
        imageErrorCorrectionCheck.setDisable(value || probing);
        imageBestEffortCheck.setDisable(value || probing);
        imageReselectFileBtn.setDisable(value);
        imageClearFileBtn.setDisable(value);
        imageOutputBrowseBtn.setDisable(value);
        imageOutputDirectoryField.setDisable(value);
        imageVerifyBtn.setDisable(value);
        setVisible(imageProgressBox, value || probing);
        setVisible(imageCancelBtn, value);
    }

    /**
     * 显示或隐藏节点，并同步其布局占位。
     *
     * @param node    目标节点
     * @param visible 是否显示
     */
    private static void setVisible(final Node node, final boolean visible) {
        if (node != null) {
            node.setVisible(visible);
            node.setManaged(visible);
        }
    }

    /**
     * 返回当前页面所属舞台。
     *
     * @return JavaFX 舞台
     */
    private Stage stage() {
        return (Stage) imageRoot.getScene().getWindow();
    }

    /**
     * 应用退出时取消任务并关闭页面线程池。
     */
    public void shutdown() {
        cancelRequested = true;
        taskRunner.shutdown();
        previewTaskRunner.shutdown();
    }

    /** 图片页面操作方向。 */
    private enum OperationMode {
        /** 加密普通图片。 */
        ENCRYPT,
        /** 还原 EGTC-IMG PNG。 */
        DECRYPT
    }

    /**
     * 后台输入探测结果。
     *
     * @param input     输入路径
     * @param fileBytes 文件大小
     * @param probe     普通图片探测结果
     * @param metadata  EGTC-IMG 元数据
     */
    private record Inspection(Path input, long fileBytes, ImageProbe.Result probe,
                              ImageCryptMetadata metadata) {
    }

    /**
     * 可抛出受检异常的图片任务。
     */
    @FunctionalInterface
    private interface ImageWork {

        /**
         * 执行图片任务。
         *
         * @param progress 进度与取消回调
         * @throws Exception 图片处理失败
         */
        void run(ImageCryptProgress progress) throws Exception;
    }

    /**
     * 把共享核心进度节流后切回 JavaFX 线程。
     */
    private final class FxImageCryptProgress implements ImageCryptProgress {

        /** 任务开始时间。 */
        private final long startedNanos = System.nanoTime();

        /** 最近一次界面刷新时间。 */
        private long lastRefreshNanos;

        /**
         * 创建当前任务的 JavaFX 进度桥接器。
         */
        private FxImageCryptProgress() {
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void onPhase(final ImageCryptPhase phase) {
            Platform.runLater(() -> {
                imageStatusLabel.setText(Messages.get(phase.i18nKey()));
                if (phase == ImageCryptPhase.KDF || phase == ImageCryptPhase.PROBE
                        || phase == ImageCryptPhase.COMMITTING) {
                    imageProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
                }
            });
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void onBytes(final long processed, final long total) {
            long now = System.nanoTime();
            if (processed < total && now - lastRefreshNanos < PROGRESS_REFRESH_NANOS) {
                return;
            }
            lastRefreshNanos = now;
            double fraction = total <= 0L ? ProgressBar.INDETERMINATE_PROGRESS
                    : Math.min(1.0, (double) processed / (double) total);
            double elapsedSeconds = Math.max(0.001,
                    (now - startedNanos) / 1_000_000_000.0);
            long bytesPerSecond = Math.max(0L, Math.round(processed / elapsedSeconds));
            String eta = formatEta(processed, total, bytesPerSecond);
            String information = Messages.format("imageCrypt.progress.info",
                    FileSizes.human(processed), FileSizes.human(Math.max(total, 0L)),
                    FileSizes.human(bytesPerSecond), eta);
            Platform.runLater(() -> {
                imageProgressBar.setProgress(fraction);
                imageProgressInfo.setText(information);
            });
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void onKdfPass(final int completedPasses, final int totalPasses) {
            String information = Messages.format("imageCrypt.progress.kdf",
                    completedPasses, totalPasses);
            Platform.runLater(() -> {
                imageProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
                imageProgressInfo.setText(information);
            });
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isCancelled() {
            return cancelRequested;
        }

        /**
         * 格式化剩余时间估算。
         *
         * @param processed      已处理字节
         * @param total          总字节
         * @param bytesPerSecond 当前吞吐
         * @return 本地化剩余时间文本
         */
        private String formatEta(final long processed, final long total,
                                 final long bytesPerSecond) {
            if (total <= 0L || bytesPerSecond <= 0L || processed >= total) {
                return Messages.get("imageCrypt.progress.etaPending");
            }
            long seconds = Math.max(1L, (total - processed) / bytesPerSecond);
            if (seconds < 60L) {
                return Messages.format("imageCrypt.progress.seconds", seconds);
            }
            long minutes = seconds / 60L;
            long remainingSeconds = seconds % 60L;
            return String.format(Locale.ROOT, "%d:%02d", minutes, remainingSeconds);
        }
    }
}
