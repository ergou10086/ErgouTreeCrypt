package hbnu.project.ergoutreecrypt.ui;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.stego.ImageStegoCodec;
import hbnu.project.ergoutreecrypt.stego.ImageStegoException;
import hbnu.project.ergoutreecrypt.stego.StegoOptions;
import hbnu.project.ergoutreecrypt.ui.support.Toast;
import hbnu.project.ergoutreecrypt.ui.support.TaskRunner;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.DragEvent;
import javafx.scene.input.Dragboard;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 图像隐写标签页控制器。
 *
 * <p>支持两种隐写方案：
 * <ul>
 *   <li><b>LSB像素</b>：当前已实现的像素域 LSB 嵌入，容量受限于图像像素数</li>
 *   <li><b>Chunk结构</b>：未来实现的块域隐写，不依赖像素容量</li>
 * </ul>
 *
 * @author ErgouTree
 */
public class ImageStegoController {

    // ---- 依赖 ----
    private final ImageStegoCodec codec = new ImageStegoCodec();
    private final TaskRunner taskRunner = new TaskRunner();
    private Toast toast;

    // ---- 子方案切换 ----
    @FXML
    private ToggleButton stegoPixelTab;
    @FXML
    private ToggleButton stegoChunkTab;
    @FXML
    private ToggleGroup stegoSubGroup;
    @FXML
    private VBox stegoPixelContent;
    @FXML
    private VBox stegoChunkContent;

    // ---- 模式（Pixel LSB 隐藏/提取）----
    @FXML
    private ToggleButton stegoHideTab;
    @FXML
    private ToggleButton stegoExtractTab;
    @FXML
    private ToggleGroup stegoModeGroup;

    // ---- Chunk 结构 UI 控件 ----
    @FXML private ToggleButton stegoChunkHideTab;
    @FXML private ToggleButton stegoChunkExtractTab;
    @FXML private ToggleGroup stegoChunkModeGroup;
    @FXML private Label stegoChunkImageLabel;
    @FXML private StackPane stegoChunkImageStack;
    @FXML private ImageView stegoChunkImageView;
    @FXML private Label stegoChunkImagePlaceholder;
    @FXML private Label stegoChunkImageInfo;
    @FXML private Button stegoChunkImageBtn;
    @FXML private Button stegoChunkClearImageBtn;
    @FXML private VBox stegoChunkFileCard;
    @FXML private Label stegoChunkFileLabel;
    @FXML private Label stegoChunkFileName;
    @FXML private Label stegoChunkFileSize;
    @FXML private Button stegoChunkFileBtn;
    @FXML private Button stegoChunkClearFileBtn;
    @FXML private Label stegoChunkPasswordLabel;
    @FXML private PasswordField stegoChunkPasswordField;
    @FXML private TextField stegoChunkPasswordVisibleField;
    @FXML private CheckBox stegoChunkShowPasswordCheck;
    @FXML private Label stegoChunkOptionsLabel;
    @FXML private CheckBox stegoChunkParanoidCheck;
    @FXML private Label stegoChunkParanoidLabel;
    @FXML private CheckBox stegoChunkIntegrityCheck;
    @FXML private Label stegoChunkIntegrityLabel;

    // ---- Chunk 结构状态 ----
    private File chunkImageFile;
    private File chunkSecretFile;
    private boolean isChunkHideMode = true;

    // ---- 根 ----
    @FXML
    private StackPane stegoRoot;

    // ---- 图片区 ----
    @FXML
    private Label stegoImageLabel;
    @FXML
    private StackPane stegoImageStack;
    @FXML
    private ImageView stegoImageView;
    @FXML
    private Label stegoImagePlaceholder;
    @FXML
    private Label stegoImageInfo;
    @FXML
    private Button stegoImageBtn;
    @FXML
    private Button stegoClearImageBtn;

    // ---- 文件区 ----
    @FXML
    private VBox stegoFileCard;
    @FXML
    private Label stegoFileLabel;
    @FXML
    private Label stegoFileName;
    @FXML
    private Label stegoFileSize;
    @FXML
    private Button stegoFileBtn;
    @FXML
    private Button stegoClearFileBtn;

    // ---- 密码区 ----
    @FXML
    private Label stegoPasswordLabel;
    @FXML
    private PasswordField stegoPasswordField;
    @FXML
    private TextField stegoPasswordVisibleField;
    @FXML
    private CheckBox stegoShowPasswordCheck;

    // ---- 选项区 ----
    @FXML
    private Label stegoOptionsLabel;
    @FXML
    private Label stegoLsbDepthLabel;
    @FXML
    private ComboBox<Integer> stegoLsbDepthCombo;
    @FXML
    private CheckBox stegoParanoidCheck;
    @FXML
    private Label stegoParanoidLabel;
    @FXML
    private CheckBox stegoIntegrityCheck;
    @FXML
    private Label stegoIntegrityLabel;

    // ---- 容量 ----
    @FXML
    private VBox stegoCapacityCard;
    @FXML
    private Label stegoCapacityLabel;
    @FXML
    private ProgressBar stegoCapacityBar;
    @FXML
    private Label stegoCapacityText;

    // ---- 底部 ----
    @FXML
    private VBox stegoProgressBox;
    @FXML
    private Label stegoStatusLabel;
    @FXML
    private Label stegoProgressInfo;
    @FXML
    private ProgressBar stegoProgressBar;
    @FXML
    private Button stegoCancelBtn;
    @FXML
    private Button stegoActionBtn;

    // ---- 状态 ----
    private File selectedImageFile;
    private File selectedSecretFile;
    private boolean isHideMode = true;

    /**
     * FXML 加载完成后由 FXMLLoader 调用。
     */
    @FXML
    private void initialize() {
        toast = new Toast(stegoRoot);
        stegoLsbDepthCombo.getItems().addAll(1, 2, 3, 4);
        stegoLsbDepthCombo.getSelectionModel().select(0);
        // ImageView 宽度跟随父容器自适应
        stegoImageView.fitWidthProperty().bind(stegoImageStack.widthProperty().subtract(20));
        stegoChunkImageView.fitWidthProperty().bind(stegoChunkImageStack.widthProperty().subtract(20));
        stegoSubGroup.selectedToggleProperty().addListener((obs, old, val) -> onSubChanged());
        stegoModeGroup.selectedToggleProperty().addListener((obs, old, val) -> onModeChanged());
        stegoChunkModeGroup.selectedToggleProperty().addListener((obs, old, val) -> onChunkModeChanged());
        setupDragDrop();
        applyTexts();
        updateSubUI();
        updateModeUI();
        updateChunkModeUI();
    }

    // ---- 子方案切换 ----

    private void onSubChanged() {
        updateSubUI();
    }

    private void updateSubUI() {
        boolean isPixel = stegoPixelTab.isSelected();
        setVisibility(stegoPixelContent, isPixel);
        setVisibility(stegoChunkContent, !isPixel);
        // 根据当前方案切换底部按钮行为
        stegoActionBtn.setOnAction(e -> {
            if (stegoPixelTab.isSelected()) {
                onAction();
            } else {
                onChunkAction();
            }
        });
    }

    // ---- 模式切换（隐藏/提取）----

    private void onModeChanged() {
        isHideMode = stegoHideTab.isSelected();
        updateModeUI();
    }

    private void updateModeUI() {
        setVisibility(stegoFileCard, isHideMode);
        setVisibility(stegoCapacityCard, isHideMode);
        stegoActionBtn.setText(isHideMode
                ? Messages.get("stego.btn.hide")
                : Messages.get("stego.btn.extract"));
    }

    // ---- 图片选择 ----

    @FXML
    private void onChooseImage() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("stego.choose.image"));
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                "PNG images", "*.png"));
        File f = chooser.showOpenDialog(stegoRoot.getScene().getWindow());
        if (f != null) {
            setImageFile(f);
        }
    }

    @FXML
    private void onClearImage() {
        selectedImageFile = null;
        stegoImageView.setImage(null);
        stegoImagePlaceholder.setVisible(true);
        stegoImageInfo.setText("");
        stegoClearImageBtn.setVisible(false);
        stegoClearImageBtn.setManaged(false);
        updateCapacityDisplay();
    }

    private void setImageFile(final File file) {
        selectedImageFile = file;
        // 预览
        try {
            Image img = new Image(file.toURI().toString(), 660, 240, true, true, true);
            stegoImageView.setImage(img);
            stegoImagePlaceholder.setVisible(false);
        } catch (Exception e) {
            stegoImagePlaceholder.setVisible(true);
        }
        // 信息
        try {
            java.awt.image.BufferedImage bi = javax.imageio.ImageIO.read(file);
            if (bi != null) {
                stegoImageInfo.setText(String.format("%s | %d×%d | %s",
                        file.getName(), bi.getWidth(), bi.getHeight(),
                        isHideMode ? Messages.get("stego.capacity.calculating") : ""));
            }
        } catch (IOException ignored) {
            stegoImageInfo.setText(file.getName());
        }
        stegoClearImageBtn.setVisible(true);
        stegoClearImageBtn.setManaged(true);
        updateCapacityDisplay();
    }

    // ---- 文件选择 ----

    @FXML
    private void onChooseFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("stego.choose.file"));
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                Messages.get("stego.file.filter"), "*.*"));
        File f = chooser.showOpenDialog(stegoRoot.getScene().getWindow());
        if (f != null) {
            setSecretFile(f);
        }
    }

    @FXML
    private void onClearFile() {
        selectedSecretFile = null;
        stegoFileName.setText("");
        stegoFileSize.setText("");
        stegoClearFileBtn.setVisible(false);
        stegoClearFileBtn.setManaged(false);
        updateCapacityDisplay();
    }

    private void setSecretFile(final File file) {
        selectedSecretFile = file;
        stegoFileName.setText(file.getName());
        stegoFileSize.setText(formatSize(file.length()));
        stegoClearFileBtn.setVisible(true);
        stegoClearFileBtn.setManaged(true);
        updateCapacityDisplay();
    }

    // ---- 密码 ----

    @FXML
    private void onToggleShowPassword() {
        boolean show = stegoShowPasswordCheck.isSelected();
        if (show) {
            stegoPasswordVisibleField.setText(stegoPasswordField.getText());
            stegoPasswordVisibleField.setVisible(true);
            stegoPasswordVisibleField.setManaged(true);
            stegoPasswordField.setVisible(false);
            stegoPasswordField.setManaged(false);
        } else {
            stegoPasswordField.setText(stegoPasswordVisibleField.getText());
            stegoPasswordField.setVisible(true);
            stegoPasswordField.setManaged(true);
            stegoPasswordVisibleField.setVisible(false);
            stegoPasswordVisibleField.setManaged(false);
        }
    }

    private byte[] getPasswordBytes() {
        String pwd = stegoPasswordField.isVisible()
                ? stegoPasswordField.getText()
                : stegoPasswordVisibleField.getText();
        if (pwd == null || pwd.isEmpty()) {
            return new byte[0];
        }
        return pwd.getBytes(StandardCharsets.UTF_8);
    }

    // ---- Chunk 模式切换 ----

    private void onChunkModeChanged() {
        isChunkHideMode = stegoChunkHideTab.isSelected();
        updateChunkModeUI();
    }

    private void updateChunkModeUI() {
        setVisibility(stegoChunkFileCard, isChunkHideMode);
        stegoActionBtn.setText(isChunkHideMode
                ? Messages.get("stego.btn.hide")
                : Messages.get("stego.btn.extract"));
    }

    // ---- Chunk 图片选择 ----

    @FXML
    private void onChooseChunkImage() {
        File f = choosePngFile(Messages.get("stego.choose.image"));
        if (f != null) setChunkImageFile(f);
    }

    @FXML
    private void onClearChunkImage() {
        chunkImageFile = null;
        stegoChunkImageView.setImage(null);
        stegoChunkImagePlaceholder.setVisible(true);
        stegoChunkImageInfo.setText("");
        stegoChunkClearImageBtn.setVisible(false);
        stegoChunkClearImageBtn.setManaged(false);
    }

    private void setChunkImageFile(final File file) {
        chunkImageFile = file;
        try {
            Image img = new Image(file.toURI().toString(), 440, 180, true, true, true);
            stegoChunkImageView.setImage(img);
            stegoChunkImagePlaceholder.setVisible(false);
        } catch (Exception e) {
            stegoChunkImagePlaceholder.setVisible(true);
        }
        stegoChunkImageInfo.setText(file.getName() + " | " + formatSize(file.length()));
        stegoChunkClearImageBtn.setVisible(true);
        stegoChunkClearImageBtn.setManaged(true);
    }

    // ---- Chunk 文件选择 ----

    @FXML
    private void onChooseChunkFile() {
        File f = chooseAnyFile(Messages.get("stego.choose.file"));
        if (f != null) setChunkSecretFile(f);
    }

    @FXML
    private void onClearChunkFile() {
        chunkSecretFile = null;
        stegoChunkFileName.setText("");
        stegoChunkFileSize.setText("");
        stegoChunkClearFileBtn.setVisible(false);
        stegoChunkClearFileBtn.setManaged(false);
    }

    private void setChunkSecretFile(final File file) {
        chunkSecretFile = file;
        stegoChunkFileName.setText(file.getName());
        stegoChunkFileSize.setText(formatSize(file.length()));
        stegoChunkClearFileBtn.setVisible(true);
        stegoChunkClearFileBtn.setManaged(true);
    }

    // ---- Chunk 密码 ----

    @FXML
    private void onToggleChunkShowPassword() {
        boolean show = stegoChunkShowPasswordCheck.isSelected();
        if (show) {
            stegoChunkPasswordVisibleField.setText(stegoChunkPasswordField.getText());
            stegoChunkPasswordVisibleField.setVisible(true);
            stegoChunkPasswordVisibleField.setManaged(true);
            stegoChunkPasswordField.setVisible(false);
            stegoChunkPasswordField.setManaged(false);
        } else {
            stegoChunkPasswordField.setText(stegoChunkPasswordVisibleField.getText());
            stegoChunkPasswordField.setVisible(true);
            stegoChunkPasswordField.setManaged(true);
            stegoChunkPasswordVisibleField.setVisible(false);
            stegoChunkPasswordVisibleField.setManaged(false);
        }
    }

    private byte[] getChunkPasswordBytes() {
        String pwd = stegoChunkPasswordField.isVisible()
                ? stegoChunkPasswordField.getText()
                : stegoChunkPasswordVisibleField.getText();
        return (pwd == null || pwd.isEmpty()) ? new byte[0]
                : pwd.getBytes(StandardCharsets.UTF_8);
    }

    // ---- Chunk 操作 ----

    @FXML
    private void onChunkAction() {
        if (isChunkHideMode) {
            doChunkHide();
        } else {
            doChunkExtract();
        }
    }

    private void doChunkHide() {
        if (chunkImageFile == null) {
            toast.info(Messages.get("stego.toast.no.image"));
            return;
        }
        if (chunkSecretFile == null) {
            toast.info(Messages.get("stego.toast.no.file"));
            return;
        }
        File outFile = chooseSavePng(Messages.get("stego.save.stego"),
                "stego_" + chunkImageFile.getName());
        if (outFile == null) return;

        StegoOptions opts = StegoOptions.builder()
                .paranoid(stegoChunkParanoidCheck.isSelected())
                .storeMac(stegoChunkIntegrityCheck.isSelected())
                .build();
        byte[] pwd = getChunkPasswordBytes();
        Path outputPath = outFile.toPath();

        showProgress(true);
        taskRunner.submit(() -> {
            codec.hideChunk(chunkImageFile.toPath(), chunkSecretFile.toPath(),
                    outputPath, pwd, opts);
            Platform.runLater(() -> {
                showProgress(false);
                toast.success(Messages.format("stego.status.success.hide",
                        outputPath.getFileName()));
            });
        }, () -> {}, ex -> {
            Platform.runLater(() -> {
                showProgress(false);
                toast.info(Messages.format("stego.toast.error", ex.getMessage()));
                tryDelete(outputPath);
            });
        });
    }

    private void doChunkExtract() {
        if (chunkImageFile == null) {
            toast.info(Messages.get("stego.toast.no.image"));
            return;
        }
        File outDir = chooseDirectory(Messages.get("stego.choose.output.dir"));
        if (outDir == null) return;

        byte[] pwd = getChunkPasswordBytes();
        showProgress(true);
        taskRunner.submit(() -> {
            Path extracted = codec.extractChunk(chunkImageFile.toPath(),
                    outDir.toPath(), pwd);
            Platform.runLater(() -> {
                showProgress(false);
                toast.success(Messages.format("stego.status.success.extract",
                        extracted.getFileName()));
            });
        }, () -> {}, ex -> {
            Platform.runLater(() -> {
                showProgress(false);
                toast.info(Messages.format("stego.toast.error", ex.getMessage()));
            });
        });
    }

    // ---- 文件选择器工具 ----

    private File choosePngFile(final String title) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(title);
        chooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("PNG images", "*.png"));
        return chooser.showOpenDialog(stegoRoot.getScene().getWindow());
    }

    private File chooseAnyFile(final String title) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(title);
        chooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter(Messages.get("stego.file.filter"), "*.*"));
        return chooser.showOpenDialog(stegoRoot.getScene().getWindow());
    }

    private File chooseSavePng(final String title, final String initialName) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(title);
        chooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("PNG", "*.png"));
        chooser.setInitialFileName(initialName);
        return chooser.showSaveDialog(stegoRoot.getScene().getWindow());
    }

    private File chooseDirectory(final String title) {
        javafx.stage.DirectoryChooser chooser = new javafx.stage.DirectoryChooser();
        chooser.setTitle(title);
        return chooser.showDialog(stegoRoot.getScene().getWindow());
    }

    // ---- 操作（LSB像素）----

    @FXML
    private void onAction() {
        if (isHideMode) {
            doHide();
        } else {
            doExtract();
        }
    }

    private void doHide() {
        if (selectedImageFile == null) {
            toast.info(Messages.get("stego.toast.no.image"));
            return;
        }
        if (selectedSecretFile == null) {
            toast.info(Messages.get("stego.toast.no.file"));
            return;
        }
        Path imagePath = selectedImageFile.toPath();
        Path secretPath = selectedSecretFile.toPath();

        FileChooser chooser = new FileChooser();
        chooser.setTitle(Messages.get("stego.save.stego"));
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PNG", "*.png"));
        chooser.setInitialFileName("stego_" + selectedImageFile.getName());
        File outFile = chooser.showSaveDialog(stegoRoot.getScene().getWindow());
        if (outFile == null) {
            return;
        }

        StegoOptions options = StegoOptions.builder()
                .lsbDepth(stegoLsbDepthCombo.getValue())
                .paranoid(stegoParanoidCheck.isSelected())
                .storeMac(stegoIntegrityCheck.isSelected())
                .build();
        byte[] pwd = getPasswordBytes();
        Path outputPath = outFile.toPath();

        showProgress(true);
        taskRunner.submit(() -> {
            codec.hide(imagePath, secretPath, outputPath, pwd, options);
        }, () -> {
            showProgress(false);
            toast.success(Messages.format("stego.status.success.hide",
                    outputPath.getFileName()));
        }, ex -> {
            showProgress(false);
            toast.info(Messages.format("stego.toast.error", ex.getMessage()));
            tryDelete(outputPath);
        });
    }

    private void doExtract() {
        if (selectedImageFile == null) {
            toast.info(Messages.get("stego.toast.no.image"));
            return;
        }
        Path imagePath = selectedImageFile.toPath();
        byte[] pwd = getPasswordBytes();

        File outDir = chooseDirectory(Messages.get("stego.choose.output.dir"));
        if (outDir == null) {
            return;
        }

        showProgress(true);
        taskRunner.submit(() -> {
            Path extracted = codec.extract(imagePath, outDir.toPath(), pwd);
            Platform.runLater(() -> {
                showProgress(false);
                toast.success(Messages.format("stego.status.success.extract",
                        extracted.getFileName()));
            });
        }, () -> {
            // onSuccess 回调由 CheckedRunnable 内部的 Platform.runLater 处理
        }, ex -> {
            Platform.runLater(() -> {
                showProgress(false);
                toast.info(Messages.format("stego.toast.error", ex.getMessage()));
            });
        });
    }

    @FXML
    private void onCancel() {
        taskRunner.shutdown();
        showProgress(false);
    }

    // ---- 容量计算 ----

    private void updateCapacityDisplay() {
        if (!isHideMode || selectedImageFile == null || selectedSecretFile == null) {
            stegoCapacityBar.setProgress(0);
            stegoCapacityText.setText("");
            return;
        }
        try {
            StegoOptions opts = StegoOptions.builder()
                    .lsbDepth(stegoLsbDepthCombo.getValue())
                    .storeMac(stegoIntegrityCheck.isSelected())
                    .build();
            long capacity = codec.availableCapacity(selectedImageFile.toPath(), opts,
                    selectedSecretFile.getName());
            long needed = selectedSecretFile.length();
            double ratio = capacity > 0 ? (double) needed / capacity : 1.0;
            stegoCapacityBar.setProgress(Math.min(ratio, 1.0));
            stegoCapacityText.setText(Messages.format("stego.capacity.text",
                    formatSize(needed), formatSize(capacity)));
            if (needed > capacity) {
                stegoCapacityBar.setStyle("-fx-accent: #e74c3c;");
            } else {
                stegoCapacityBar.setStyle("-fx-accent: #2ecc71;");
            }
        } catch (Exception e) {
            stegoCapacityText.setText("");
        }
    }

    // ---- 拖拽 ----

    private void setupDragDrop() {
        stegoImageStack.setOnDragOver(this::onDragOver);
        stegoImageStack.setOnDragDropped(this::onImageDragDropped);
        stegoImageStack.setOnDragEntered(this::onDragEntered);
        stegoImageStack.setOnDragExited(this::onDragExited);
    }

    private void onDragEntered(final DragEvent e) {
        if (e.getDragboard().hasFiles()) {
            stegoImageStack.setStyle("-fx-background-color: #d0e4f7; -fx-background-radius: 6;");
        }
    }

    private void onDragExited(final DragEvent e) {
        stegoImageStack.setStyle("-fx-background-color: #e8e8e8; -fx-background-radius: 6;");
    }

    private void onDragOver(final DragEvent e) {
        if (e.getDragboard().hasFiles()) {
            e.acceptTransferModes(javafx.scene.input.TransferMode.COPY);
        }
    }

    private void onImageDragDropped(final DragEvent e) {
        stegoImageStack.setStyle("-fx-background-color: #e8e8e8; -fx-background-radius: 6;");
        Dragboard db = e.getDragboard();
        if (db.hasFiles() && !db.getFiles().isEmpty()) {
            setImageFile(db.getFiles().get(0));
        }
        e.setDropCompleted(true);
    }

    // ---- 进度 ----

    private void showProgress(final boolean show) {
        setVisibility(stegoProgressBox, show);
        stegoCancelBtn.setVisible(show);
        stegoCancelBtn.setManaged(show);
        stegoActionBtn.setDisable(show);
    }

    // ---- 工具 ----

    private static void setVisibility(final javafx.scene.Node node, final boolean visible) {
        node.setVisible(visible);
        node.setManaged(visible);
    }

    private static String formatSize(final long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        }
        return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }

    private static void tryDelete(final Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
        }
    }

    /**
     * 刷新所有 UI 文案（语言切换时调用）。
     */
    public void applyTexts() {
        if (stegoPixelTab == null) {
            return;
        }
        stegoPixelTab.setText(Messages.get("stego.sub.pixel"));
        stegoChunkTab.setText(Messages.get("stego.sub.chunk"));
        stegoHideTab.setText(Messages.get("stego.mode.hide"));
        stegoExtractTab.setText(Messages.get("stego.mode.extract"));
        stegoChunkHideTab.setText(Messages.get("stego.mode.hide"));
        stegoChunkExtractTab.setText(Messages.get("stego.mode.extract"));
        // LSB 控件
        stegoImageLabel.setText(Messages.get("stego.image.label"));
        stegoImageBtn.setText(Messages.get("stego.image.choose"));
        stegoClearImageBtn.setText(Messages.get("stego.image.clear"));
        stegoFileLabel.setText(Messages.get("stego.file.label"));
        stegoFileBtn.setText(Messages.get("stego.file.choose"));
        stegoClearFileBtn.setText(Messages.get("stego.file.clear"));
        stegoPasswordLabel.setText(Messages.get("password.label"));
        stegoShowPasswordCheck.setText(Messages.get("password.show"));
        stegoOptionsLabel.setText(Messages.get("stego.options.label"));
        stegoLsbDepthLabel.setText(Messages.get("stego.option.lsbDepth"));
        stegoParanoidLabel.setText(Messages.get("options.paranoid"));
        stegoIntegrityLabel.setText(Messages.get("stego.option.integrity"));
        stegoCapacityLabel.setText(Messages.get("stego.capacity.label"));
        // Chunk 控件
        stegoChunkImageLabel.setText(Messages.get("stego.image.label"));
        stegoChunkImageBtn.setText(Messages.get("stego.image.choose"));
        stegoChunkClearImageBtn.setText(Messages.get("stego.image.clear"));
        stegoChunkFileLabel.setText(Messages.get("stego.file.label"));
        stegoChunkFileBtn.setText(Messages.get("stego.file.choose"));
        stegoChunkClearFileBtn.setText(Messages.get("stego.file.clear"));
        stegoChunkPasswordLabel.setText(Messages.get("password.label"));
        stegoChunkShowPasswordCheck.setText(Messages.get("password.show"));
        stegoChunkOptionsLabel.setText(Messages.get("stego.options.label"));
        stegoChunkParanoidLabel.setText(Messages.get("options.paranoid"));
        stegoChunkIntegrityLabel.setText(Messages.get("stego.option.integrity"));
        stegoImageLabel.setText(Messages.get("stego.image.label"));
        stegoImageBtn.setText(Messages.get("stego.image.choose"));
        stegoClearImageBtn.setText(Messages.get("stego.image.clear"));
        stegoFileLabel.setText(Messages.get("stego.file.label"));
        stegoFileBtn.setText(Messages.get("stego.file.choose"));
        stegoClearFileBtn.setText(Messages.get("stego.file.clear"));
        stegoPasswordLabel.setText(Messages.get("password.label"));
        stegoShowPasswordCheck.setText(Messages.get("password.show"));
        stegoOptionsLabel.setText(Messages.get("stego.options.label"));
        stegoLsbDepthLabel.setText(Messages.get("stego.option.lsbDepth"));
        stegoParanoidLabel.setText(Messages.get("options.paranoid"));
        stegoIntegrityLabel.setText(Messages.get("stego.option.integrity"));
        stegoCapacityLabel.setText(Messages.get("stego.capacity.label"));
        stegoCancelBtn.setText(Messages.get("action.cancel"));
        stegoActionBtn.setText(isHideMode
                ? Messages.get("stego.btn.hide")
                : Messages.get("stego.btn.extract"));
    }

    /**
     * 关闭时释放资源。
     */
    public void shutdown() {
        taskRunner.shutdown();
    }
}
