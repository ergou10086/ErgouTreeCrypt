package hbnu.project.ergoutreecrypt.ui;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptCodec;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptOptions;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptProfile;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaFormat;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaProgress;
import hbnu.project.ergoutreecrypt.ui.support.FileSizes;
import hbnu.project.ergoutreecrypt.ui.support.TaskRunner;
import hbnu.project.ergoutreecrypt.ui.support.Toast;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.control.ToggleGroup;
import javafx.scene.input.Dragboard;
import javafx.scene.input.DragEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

/**
 * 音视频加密标签页控制器：对 MP3 / MP4 / WAV 做"格式保持加密"（加密后仍是合法可播放的媒体，但内容为噪声）。
 *
 * <p>本控制器独立于文件加密主控制器 {@link MainController}，仅依赖 {@code mediacrypt} 子系统与 {@code i18n}，
 * 符合 UI 不直接触碰密码学原语的分层约束。
 *
 * <p>解密模式提供"<b>噪音文件解密</b>"开关：
 * <ul>
 *   <li>开关关闭（默认）：按文件扩展名识别（仍是 .mp3/.mp4/.wav），直接走对应格式解密；</li>
 *   <li>开关开启：明确告诉程序"这是一个被本工具加密过、表面看是正常媒体但内容是噪声的文件"，
 *       用于用户不确定来源、想强调走"加密媒体还原"路径的场景。两者底层都按容器内的加密元数据还原，
 *       开关主要影响 UI 提示与校验严格度。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public class MediaCryptController {

    private final MediaCryptCodec codec = new MediaCryptCodec();
    private final TaskRunner taskRunner = new TaskRunner();

    // ---- 模式切换 ----
    @FXML
    private ToggleGroup avModeGroup;
    @FXML
    private ToggleButton avEncryptTab;
    @FXML
    private ToggleButton avDecryptTab;

    // ---- 文件区 ----
    @FXML
    private VBox avDropZone;
    @FXML
    private Label avDropHint;
    @FXML
    private Label avDropSub;
    @FXML
    private VBox avFileCard;
    @FXML
    private Label avFileName;
    @FXML
    private Label avFileMeta;
    @FXML
    private Button avClearFileBtn;

    // ---- 输出路径 ----
    @FXML
    private VBox avOutputCard;
    @FXML
    private Label avOutputLabel;
    @FXML
    private TextField avOutputFileField;
    @FXML
    private Button avOutputBrowseBtn;
    private boolean outputPathUserEdited = false;

    // ---- 密码区 ----
    @FXML
    private Label avPasswordTitle;
    @FXML
    private PasswordField avPasswordField;
    @FXML
    private TextField avPasswordVisibleField;
    @FXML
    private CheckBox avShowPasswordCheck;
    @FXML
    private VBox avConfirmBox;
    @FXML
    private PasswordField avConfirmField;
    @FXML
    private Label avMismatchLabel;

    // ---- 加密选项 ----
    @FXML
    private VBox avEncryptOptions;
    @FXML
    private Label avProfileLabel;
    @FXML
    private Label avProfileInfo;
    @FXML
    private ComboBox<ProfileItem> avProfileCombo;
    @FXML
    private CheckBox avParanoidCheck;
    @FXML
    private Label avParanoidInfo;
    @FXML
    private CheckBox avIntegrityCheck;
    @FXML
    private Label avIntegrityInfo;
    @FXML
    private CheckBox avCompressAfterCheck;
    @FXML
    private Label avCompressAfterInfo;
    @FXML
    private ComboBox<String> avCompressFormatCombo;
    @FXML
    private PasswordField avArchivePasswordField;

    // ---- 解密选项 ----
    @FXML
    private VBox avDecryptOptions;
    @FXML
    private CheckBox avNoiseDecryptCheck;
    @FXML
    private Label avNoiseDecryptInfo;
    @FXML
    private Label avNoiseDecryptHint;
    @FXML
    private CheckBox avDecompressAfterCheck;
    @FXML
    private Label avDecompressAfterInfo;
    @FXML
    private PasswordField avDecompressPasswordField;

    // ---- 底部 ----
    @FXML
    private StackPane avRoot;
    @FXML
    private VBox avProgressBox;
    @FXML
    private Label avStatusLabel;
    @FXML
    private Label avProgressInfo;
    @FXML
    private ProgressBar avProgressBar;
    @FXML
    private Button avCancelBtn;
    @FXML
    private Button avVerifyBtn;
    @FXML
    private Button avActionBtn;

    private Toast toast;
    private Mode mode = Mode.ENCRYPT;
    private File selectedFile;
    private boolean running = false;
    private volatile boolean cancelRequested = false;

    private static void setVisible(Region node, boolean visible) {
        if (node == null) {
            return;
        }
        node.setVisible(visible);
        node.setManaged(visible);
    }

    @FXML
    private void initialize() {
        toast = new Toast(avRoot);

        avEncryptTab.setOnAction(e -> switchMode(Mode.ENCRYPT));
        avDecryptTab.setOnAction(e -> switchMode(Mode.DECRYPT));

        avDropZone.setOnMouseClicked(this::onChooseFile);
        avDropZone.setOnDragOver(this::onDragOver);
        avDropZone.setOnDragDropped(this::onDragDropped);
        avDropZone.setOnDragEntered(this::onDragEntered);
        avDropZone.setOnDragExited(this::onDragExited);

        avPasswordVisibleField.textProperty().bindBidirectional(avPasswordField.textProperty());
        avPasswordField.textProperty().addListener((o, a, b) -> updatePasswordFeedback());
        avConfirmField.textProperty().addListener((o, a, b) -> updatePasswordFeedback());

        // 加密后压缩：格式下拉绑定
        avCompressFormatCombo.getItems().setAll("ZIP", "GZ", "TAR.GZ");
        avCompressFormatCombo.managedProperty().bind(avCompressAfterCheck.selectedProperty());
        avCompressFormatCombo.visibleProperty().bind(avCompressAfterCheck.selectedProperty());
        avArchivePasswordField.managedProperty().bind(avCompressAfterCheck.selectedProperty());
        avArchivePasswordField.visibleProperty().bind(avCompressAfterCheck.selectedProperty());

        // 解密时解压后解密：密码字段绑定
        avDecompressPasswordField.managedProperty().bind(avDecompressAfterCheck.selectedProperty());
        avDecompressPasswordField.visibleProperty().bind(avDecompressAfterCheck.selectedProperty());

        // 输出路径：检测用户手动编辑
        avOutputFileField.textProperty().addListener((o, a, b) -> {
            if (b != null && !b.equals(a)) {
                outputPathUserEdited = true;
            }
        });

        applyTexts();
        switchMode(Mode.ENCRYPT);
    }

    /**
     * 语言切换时由主控制器调用，刷新本页文案。
     */
    public void applyTexts() {
        avEncryptTab.setText(Messages.get("av.tab.encrypt"));
        avDecryptTab.setText(Messages.get("av.tab.decrypt"));

        avDropHint.setText(Messages.get("av.file.drop.hint"));
        avDropSub.setText(Messages.get("av.file.drop.sub"));
        avClearFileBtn.setText(Messages.get("file.clear"));

        avOutputLabel.setText(Messages.get("file.output.label"));
        avOutputBrowseBtn.setText(Messages.get("file.output.browse"));

        avPasswordTitle.setText(Messages.get("password.label"));
        avPasswordField.setPromptText(Messages.get("password.placeholder"));
        avPasswordVisibleField.setPromptText(Messages.get("password.placeholder"));
        avShowPasswordCheck.setText(Messages.get("password.show"));
        avConfirmField.setPromptText(Messages.get("password.confirm.placeholder"));

        avProfileLabel.setText(Messages.get("av.profile.label"));
        avParanoidCheck.setText(Messages.get("options.paranoid"));
        avIntegrityCheck.setText(Messages.get("av.option.integrity"));

        avNoiseDecryptCheck.setText(Messages.get("av.option.noiseDecrypt"));
        avNoiseDecryptHint.setText(Messages.get("av.option.noiseDecrypt.hint"));

        avDecompressAfterCheck.setText(Messages.get("av.option.decompressAfter"));
        avDecompressPasswordField.setPromptText(Messages.get("av.decompress.password"));

        avCompressAfterCheck.setText(Messages.get("options.compressAfter"));
        avCompressFormatCombo.setValue(SettingsManager.getDefaultCompressFormat());

        setupInfoTooltips();

        avCancelBtn.setText(Messages.get("action.cancel"));
        avVerifyBtn.setText(Messages.get("av.action.verify"));
        rebuildProfileItems();
        updateActionButtonText();
        if (!running) {
            avStatusLabel.setText(Messages.get("status.ready"));
        }
        if (selectedFile != null) {
            showFileInfo();
        }
    }

    private void rebuildProfileItems() {
        ProfileItem current = avProfileCombo.getValue();
        avProfileCombo.getItems().setAll(
                new ProfileItem(null, Messages.get("av.profile.auto")),
                new ProfileItem(MediaCryptProfile.W_FULL, "WAV · " + Messages.get("av.profile.wFull")),
                new ProfileItem(MediaCryptProfile.W_SEL, "WAV · " + Messages.get("av.profile.wSel")),
                new ProfileItem(MediaCryptProfile.M_BODY, "MP3 · " + Messages.get("av.profile.mBody")),
                new ProfileItem(MediaCryptProfile.M_SAFE, "MP3 · " + Messages.get("av.profile.mSafe")),
                new ProfileItem(MediaCryptProfile.V_MDAT, "MP4 · " + Messages.get("av.profile.vMdat")));
        avProfileCombo.setValue(current == null ? avProfileCombo.getItems().get(0) : current);
    }

    private void switchMode(Mode m) {
        this.mode = m;
        avEncryptTab.setSelected(m == Mode.ENCRYPT);
        avDecryptTab.setSelected(m == Mode.DECRYPT);
        boolean encrypting = m == Mode.ENCRYPT;
        setVisible(avEncryptOptions, encrypting);
        setVisible(avDecryptOptions, !encrypting);
        setVisible(avConfirmBox, encrypting);
        setVisible(avVerifyBtn, !encrypting && selectedFile != null);
        updateActionButtonText();
        updatePasswordFeedback();
    }

    private void updateActionButtonText() {
        avActionBtn.setText(mode == Mode.ENCRYPT
                ? Messages.get("av.action.encrypt") : Messages.get("av.action.decrypt"));
    }

    // ---- 文件选择 / 拖拽 ----

    private void onChooseFile(MouseEvent e) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("file.choose"));
        // 解密模式且勾选解压后解密时，也允许选择该工具支持的压缩包
        if (mode == Mode.DECRYPT && avDecompressAfterCheck.isSelected()) {
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                    Messages.get("av.file.filter.all"),
                    "*.mp3", "*.mp4", "*.m4a", "*.m4v", "*.mov", "*.wav",
                    "*.zip", "*.gz", "*.tar.gz"));
        } else {
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                    Messages.get("av.file.filter"),
                    "*.mp3", "*.mp4", "*.m4a", "*.m4v", "*.mov", "*.wav"));
        }
        File f = chooser.showOpenDialog(stage());
        if (f != null) {
            setSelectedFile(f);
        }
    }

    private void onDragEntered(DragEvent e) {
        if (e.getDragboard().hasFiles()) {
            avDropZone.getStyleClass().add("drag-over");
        }
        e.consume();
    }

    private void onDragExited(DragEvent e) {
        avDropZone.getStyleClass().remove("drag-over");
        e.consume();
    }

    private void onDragOver(DragEvent e) {
        if (e.getDragboard().hasFiles()) {
            e.acceptTransferModes(TransferMode.COPY);
        }
        e.consume();
    }

    private void onDragDropped(DragEvent e) {
        Dragboard db = e.getDragboard();
        boolean ok = false;
        if (db.hasFiles() && !db.getFiles().isEmpty()) {
            setSelectedFile(db.getFiles().get(0));
            ok = true;
        }
        avDropZone.getStyleClass().remove("drag-over");
        e.setDropCompleted(ok);
        e.consume();
    }

    private void setSelectedFile(File f) {
        this.selectedFile = f;
        showFileInfo();
    }

    private void showFileInfo() {
        avFileName.setText(selectedFile.getName());
        String fmtName;
        if (ArchiveExtractor.isArchive(selectedFile.toPath())) {
            fmtName = Messages.get("av.format.archive");
        } else {
            MediaFormat fmt = MediaFormat.fromExtension(selectedFile.toPath());
            fmtName = fmt == null ? Messages.get("av.format.unknown") : fmt.name();
        }
        avFileMeta.setText(fmtName + " · " + FileSizes.human(selectedFile.length()));
        setVisible(avFileCard, true);
        setVisible(avDropZone, false);
        setVisible(avOutputCard, true);
        setVisible(avVerifyBtn, mode == Mode.DECRYPT);
        if (!outputPathUserEdited) {
            avOutputFileField.setText(computeDefaultOutput());
        }
    }

    private String computeDefaultOutput() {
        if (selectedFile == null) return "";
        String fullName = selectedFile.getName();
        String parent = selectedFile.getParent();

        // 解密模式：若勾选解压后解密且输入为压缩包，先剥掉压缩包扩展名再计算解密输出
        if (mode == Mode.DECRYPT
                && avDecompressAfterCheck.isSelected()
                && ArchiveExtractor.isArchive(selectedFile.toPath())) {
            String innerName = fullName;
            // 剥掉压缩包扩展名（支持 .tar.gz 双扩展名）
            if (innerName.toLowerCase().endsWith(".tar.gz")) {
                innerName = innerName.substring(0, innerName.length() - ".tar.gz".length());
            } else {
                int dot = innerName.lastIndexOf('.');
                innerName = dot > 0 ? innerName.substring(0, dot) : innerName;
            }
            // 剥掉 .enc 标记得到原始文件名
            return parent + File.separator + stripEncMarker(innerName);
        }

        int idx = fullName.lastIndexOf('.');
        String ext = idx >= 0 ? fullName.substring(idx) : "";
        String base = idx >= 0 ? fullName.substring(0, idx) : fullName;
        if (mode == Mode.ENCRYPT) {
            return parent + File.separator + base + ".enc" + ext;
        } else {
            if (base.endsWith(".enc")) {
                return parent + File.separator
                        + base.substring(0, base.length() - 4) + ".dec" + ext;
            }
            return parent + File.separator + base + ".dec" + ext;
        }
    }

    /**
     * 去掉文件名中的 .enc 标记。
     * 例如 {@code song.enc.mp4 → song.mp4}，{@code song.enc → song}。
     */
    private static String stripEncMarker(String name) {
        // 找到 .enc 的位置（最后一个 .ext 之前如果是 .enc 则去掉）
        int lastDot = name.lastIndexOf('.');
        if (lastDot > 0) {
            String base = name.substring(0, lastDot);
            if (base.toLowerCase().endsWith(".enc")) {
                return base.substring(0, base.length() - ".enc".length())
                        + name.substring(lastDot);
            }
        }
        // 无扩展名但以 .enc 结尾
        if (name.toLowerCase().endsWith(".enc")) {
            return name.substring(0, name.length() - ".enc".length());
        }
        return name;
    }

    @FXML
    private void onClearFile() {
        selectedFile = null;
        outputPathUserEdited = false;
        setVisible(avFileCard, false);
        setVisible(avOutputCard, false);
        setVisible(avVerifyBtn, false);
        setVisible(avDropZone, true);
    }

    @FXML
    private void onBrowseOutput() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("file.output.choose"));
        File cur = new File(avOutputFileField.getText());
        if (cur.getParentFile() != null && cur.getParentFile().exists()) {
            chooser.setInitialDirectory(cur.getParentFile());
        }
        chooser.setInitialFileName(cur.getName());
        File f = chooser.showSaveDialog(stage());
        if (f != null) {
            avOutputFileField.setText(f.getAbsolutePath());
            outputPathUserEdited = true;
        }
    }

    // ---- 密码 ----

    @FXML
    private void onToggleShowPassword() {
        boolean show = avShowPasswordCheck.isSelected();
        setVisible(avPasswordVisibleField, show);
        setVisible(avPasswordField, !show);
    }

    private void updatePasswordFeedback() {
        String pwd = avPasswordField.getText();
        boolean mismatch = mode == Mode.ENCRYPT
                && pwd != null && !pwd.isEmpty()
                && !pwd.equals(avConfirmField.getText());
        avMismatchLabel.setText(mismatch ? Messages.get("password.mismatch") : "");
        setVisible(avMismatchLabel, mismatch);
    }

    // ---- 执行 ----

    @FXML
    private void onAction() {
        if (running) {
            return;
        }
        if (selectedFile == null) {
            toast.error(Messages.get("toast.no.file"));
            return;
        }
        String pwd = avPasswordField.getText();
        if (pwd == null || pwd.isEmpty()) {
            toast.error(Messages.get("av.toast.needPassword"));
            return;
        }
        if (mode == Mode.ENCRYPT && !pwd.equals(avConfirmField.getText())) {
            toast.error(Messages.get("toast.no.password.confirm"));
            return;
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
        String pwd = avPasswordField.getText();
        if (pwd == null || pwd.isEmpty()) {
            toast.error(Messages.get("av.toast.needPassword"));
            return;
        }
        startMediaVerify(pwd);
    }

    /**
     * 启动音视频文件的完整性校验（只读，不保留解密输出）。
     *
     * @param pwd 密码
     */
    private void startMediaVerify(String pwd) {
        Path input = selectedFile.toPath();

        // 格式校验
        if (MediaFormat.fromExtension(input) == null) {
            toast.error(Messages.get("av.toast.unsupported"));
            return;
        }

        byte[] pwdBytes = pwd.getBytes(StandardCharsets.UTF_8);
        runTask(progress -> {
            boolean ok = codec.verifyIntegrity(input, pwdBytes, progress);
            if (!ok) {
                throw new hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException(
                        Messages.get("av.status.failed.verify.noIntegrity"));
            }
        }, Messages.get("av.status.success.verify"));
    }

    private void startEncrypt(String pwd) {
        Path input = selectedFile.toPath();
        if (MediaFormat.fromExtension(input) == null) {
            toast.error(Messages.get("av.toast.unsupported"));
            return;
        }
        String outPath = avOutputFileField.getText();
        if (outPath == null || outPath.isEmpty()) {
            outPath = computeDefaultOutput();
        }
        Path output = Path.of(outPath);

        ProfileItem item = avProfileCombo.getValue();
        MediaCryptOptions.Builder builder = MediaCryptOptions.builder()
                .paranoid(avParanoidCheck.isSelected())
                .storeIntegrity(avIntegrityCheck.isSelected());
        if (item != null && item.profile != null) {
            // 仅当所选档位与文件格式匹配时才采用，否则回退默认。
            MediaFormat fmt = MediaFormat.fromExtension(input);
            if (item.profile.format() == fmt) {
                builder.profile(item.profile);
            }
        }
        MediaCryptOptions options = builder.build();

        byte[] pwdBytes = pwd.getBytes(StandardCharsets.UTF_8);
        // 是否加密后归档
        boolean doArchive = avCompressAfterCheck.isSelected() && avCompressFormatCombo.getValue() != null;
        Path finalOutput = output;
        if (doArchive) {
            ArchivePacker.Format fmt = ArchivePacker.Format.valueOf(
                    avCompressFormatCombo.getValue().replace(".", "_"));
            String ext = switch (fmt) {
                case ZIP -> ".zip";
                case GZ -> ".gz";
                case TAR_GZ -> ".tar.gz";
            };
            finalOutput = Path.of(output.toString() + ext);
        }
        Path archivePath = finalOutput;
        runTask(progress -> {
            codec.encrypt(input, output, pwdBytes, options, progress);
            if (doArchive) {
                Platform.runLater(() -> avStatusLabel.setText(Messages.get("status.archiving")));
                String archPwd = avArchivePasswordField.getText();
                ArchivePacker.pack(archivePath, output, ArchivePacker.Format.valueOf(
                        avCompressFormatCombo.getValue().replace(".", "_")),
                        archPwd == null || archPwd.isEmpty() ? null : archPwd);
                java.nio.file.Files.deleteIfExists(output);
            }
        }, Messages.format("av.status.success.encrypt", finalOutput.getFileName()));
    }

    private void startDecrypt(String pwd) {
        Path input = selectedFile.toPath();
        boolean decompressFirst = avDecompressAfterCheck.isSelected();
        boolean isArchive = ArchiveExtractor.isArchive(input);

        // 若未勾选解压后解密且输入不是支持的媒体格式，报错
        if (!decompressFirst || !isArchive) {
            if (MediaFormat.fromExtension(input) == null) {
                toast.error(Messages.get("av.toast.unsupported"));
                return;
            }
        }

        String outPath = avOutputFileField.getText();
        if (outPath == null || outPath.isEmpty()) {
            outPath = computeDefaultOutput();
        }
        Path output = Path.of(outPath);

        byte[] pwdBytes = pwd.getBytes(StandardCharsets.UTF_8);
        boolean noiseMode = avNoiseDecryptCheck.isSelected();
        runTask(progress -> {
            Path actualInput = input;
            Path tempDir = null;
            try {
                // 解压后解密：先将压缩包解压到临时目录，找出其中的加密媒体文件
                if (decompressFirst && isArchive) {
                    // 阶段 1：解压（进度条置为轻微进度表示正在工作）
                    Platform.runLater(() -> {
                        avStatusLabel.setText(Messages.get("status.extracting"));
                        avProgressBar.setProgress(0.02);
                        avProgressInfo.setText("");
                    });
                    tempDir = Files.createTempDirectory("ergou-av-extract-");
                    String archPwd = avDecompressPasswordField.getText();
                    String effectiveArchPwd = (archPwd == null || archPwd.isEmpty())
                            ? null : archPwd;
                    try {
                        ArchiveExtractor.extractPreserving(input, tempDir,
                                effectiveArchPwd);
                    } catch (ArchiveExtractor.PasswordNeededException pne) {
                        // 需要归档密码：弹窗询问后重试
                        java.util.concurrent.CompletableFuture<String> future =
                                new java.util.concurrent.CompletableFuture<>();
                        Platform.runLater(() ->
                                future.complete(showMediaArchivePasswordDialog()));
                        String retryPwd;
                        try {
                            retryPwd = future.get();
                        } catch (Exception ignored) {
                            throw new IOException(
                                    Messages.get("archivePassword.title")
                                    + ": " + Messages.get("status.cancelled"),
                                    pne);
                        }
                        if (retryPwd == null || retryPwd.isEmpty()) {
                            throw new IOException(
                                    Messages.get("archivePassword.title")
                                    + ": " + Messages.get("av.toast.needPassword"),
                                    pne);
                        }
                        // 告知用户正在用新密码重试解压
                        Platform.runLater(() ->
                                avStatusLabel.setText(Messages.get("status.extracting")));
                        ArchiveExtractor.extractPreserving(input, tempDir,
                                retryPwd);
                    }

                    // 在解压结果中寻找第一个支持的媒体文件
                    try (Stream<Path> walk = Files.walk(tempDir)) {
                        actualInput = walk.filter(Files::isRegularFile)
                                .filter(p -> MediaFormat.fromExtension(p) != null)
                                .findFirst()
                                .orElseThrow(() -> new IOException(
                                        Messages.get("av.error.notEncrypted")));
                    }

                    // 阶段 2：解密解压得到的媒体文件
                    Platform.runLater(() ->
                            avStatusLabel.setText(Messages.get("status.decrypting")));
                }

                // 格式校验
                if (MediaFormat.fromExtension(actualInput) == null) {
                    throw new IOException(Messages.get("av.toast.unsupported"));
                }

                // 噪音文件解密校验
                if (noiseMode && !codec.isEncrypted(actualInput)) {
                    throw new hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException(
                            Messages.get("av.error.notEncrypted"));
                }

                // 阶段 3：真正的媒体解密（progress 回调由 codec 通过 MediaProgress 驱动）
                codec.decrypt(actualInput, output, pwdBytes, progress);
            } finally {
                if (tempDir != null) {
                    deleteRecursively(tempDir);
                }
            }
        }, Messages.format("av.status.success.decrypt", output.getFileName()));
    }

    /**
     * 弹出归档密码输入对话框，供解压后解密流程使用。
     *
     * @return 用户输入的密码，取消则返回空字符串
     */
    private String showMediaArchivePasswordDialog() {
        javafx.scene.control.TextInputDialog dlg =
                new javafx.scene.control.TextInputDialog();
        dlg.initOwner(stage());
        dlg.setTitle(Messages.get("archivePassword.title"));
        dlg.setHeaderText(Messages.get("archivePassword.prompt"));
        dlg.setContentText(Messages.get("archivePassword.label"));
        return dlg.showAndWait().orElse("");
    }

    /** 递归删除目录。 */
    private static void deleteRecursively(Path dir) {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }

    private void runTask(MediaWork work, String successMsg) {
        setRunning(true);
        cancelRequested = false;
        avProgressBar.setProgress(0);
        avStatusLabel.setText(Messages.get("action.processing"));

        MediaProgress progress = new MediaProgress() {
            @Override
            public void onProgress(long processed, long total) {
                double frac = total <= 0 ? 0 : (double) processed / total;
                String info = FileSizes.human(processed) + " / " + FileSizes.human(total);
                Platform.runLater(() -> {
                    avProgressBar.setProgress(frac);
                    avProgressInfo.setText(info);
                });
            }

            @Override
            public boolean isCancelled() {
                return cancelRequested;
            }
        };

        taskRunner.submit(() -> work.run(progress),
                () -> {
                    avProgressBar.setProgress(1);
                    avStatusLabel.setText(successMsg);
                    toast.success(successMsg);
                    setRunning(false);
                },
                err -> {
                    boolean cancelled = err instanceof
                            hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptCancelledException
                            || err instanceof InterruptedException;
                    if (cancelled) {
                        avStatusLabel.setText(Messages.get("status.cancelled"));
                        toast.info(Messages.get("status.cancelled"));
                    } else {
                        String msg = err.getMessage() == null ? err.toString() : err.getMessage();
                        avStatusLabel.setText(Messages.format("status.failed", msg));
                        toast.error(Messages.format("status.failed", msg));
                    }
                    setRunning(false);
                });
    }

    @FXML
    private void onCancel() {
        cancelRequested = true;
        avStatusLabel.setText(Messages.get("status.cancelled"));
    }

    private void setRunning(boolean r) {
        this.running = r;
        avActionBtn.setDisable(r);
        setVisible(avProgressBox, r);
        setVisible(avCancelBtn, r);
        avEncryptTab.setDisable(r);
        avDecryptTab.setDisable(r);
        avVerifyBtn.setDisable(r);
    }

    /**
     * 应用退出时释放线程池。
     */
    public void shutdown() {
        taskRunner.shutdown();
    }

    private Stage stage() {
        return (Stage) avRoot.getScene().getWindow();
    }

    // ---- Info-icon tooltip helpers ----

    private static void setTip(Label label, String text) {
        if (label == null) return;
        javafx.scene.control.Tooltip tip = new javafx.scene.control.Tooltip(text);
        tip.getStyleClass().add("info-tooltip");
        tip.setShowDelay(javafx.util.Duration.millis(120));
        tip.setShowDuration(javafx.util.Duration.seconds(20));
        tip.setHideDelay(javafx.util.Duration.millis(120));
        tip.setWrapText(true);
        tip.setMaxWidth(300);
        javafx.scene.control.Tooltip.install(label, tip);
        label.setTooltip(tip);
    }

    private void setupInfoTooltips() {
        setTip(avProfileInfo, Messages.get("av.profile.tip"));
        setTip(avParanoidInfo, Messages.get("options.paranoid.tip"));
        setTip(avIntegrityInfo, Messages.get("av.option.integrity.tip"));
        setTip(avNoiseDecryptInfo, Messages.get("av.option.noiseDecrypt.tip"));
        setTip(avDecompressAfterInfo, Messages.get("av.option.decompressAfter.tip"));
        setTip(avCompressAfterInfo, Messages.get("options.compressAfter.tip"));
    }

    private enum Mode {ENCRYPT, DECRYPT}

    /**
     * 后台工作：接收进度回调。
     */
    @FunctionalInterface
    private interface MediaWork {
        void run(MediaProgress progress) throws Exception;
    }

    /**
     * 档位下拉项。{@code profile==null} 表示"按格式自动选择默认安全档"。
     */
    private record ProfileItem(MediaCryptProfile profile, String label) {
        @Override
        public String toString() {
            return label;
        }
    }
}
