package hbnu.project.ergoutreecrypt.ui;

import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.stego.ImageStegoCodec;
import hbnu.project.ergoutreecrypt.stego.ImageStegoException;
import hbnu.project.ergoutreecrypt.stego.StegoOptions;
import hbnu.project.ergoutreecrypt.ui.support.Toast;
import hbnu.project.ergoutreecrypt.ui.support.TaskRunner;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.DragEvent;
import javafx.scene.input.Dragboard;
import javafx.scene.layout.HBox;
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
 * 图像隐写标签页控制器（v1.9.6）。
 *
 * <p>支持 LSB 像素 和 Chunk 结构两种隐写方案，以及：
 * <ul>
 *   <li>Paranoid 模式（Serpent + XChaCha20 双层加密）</li>
 *   <li>隐蔽模式（HMAC 派生魔数，避免固定魔数检测）</li>
 *   <li>文件大小混淆（追加随机填充）</li>
 *   <li>防暴力破解（BruteForceGuard）</li>
 * </ul>
 *
 * @author ErgouTree
 */
public class ImageStegoController {

    private final ImageStegoCodec codec = new ImageStegoCodec();
    private final TaskRunner taskRunner = new TaskRunner();
    private Toast toast;

    // ---- 子方案切换 ----
    @FXML private ToggleButton stegoPixelTab;
    @FXML private ToggleButton stegoChunkTab;
    @FXML private ToggleGroup stegoSubGroup;
    @FXML private VBox stegoPixelContent;
    @FXML private VBox stegoChunkContent;

    // ---- LSB 模式 ----
    @FXML private ToggleButton stegoHideTab;
    @FXML private ToggleButton stegoExtractTab;
    @FXML private ToggleGroup stegoModeGroup;

    // ---- Chunk 模式 ----
    @FXML private ToggleButton stegoChunkHideTab;
    @FXML private ToggleButton stegoChunkExtractTab;
    @FXML private ToggleGroup stegoChunkModeGroup;

    // ---- LSB 控件 ----
    @FXML private Label stegoImageLabel;
    @FXML private StackPane stegoImageStack;
    @FXML private ImageView stegoImageView;
    @FXML private Label stegoImagePlaceholder;
    @FXML private Label stegoImageInfo;
    @FXML private Button stegoImageBtn;
    @FXML private Button stegoClearImageBtn;
    @FXML private VBox stegoFileCard;
    @FXML private Label stegoFileLabel;
    @FXML private Label stegoFileName;
    @FXML private Label stegoFileSize;
    @FXML private Button stegoFileBtn;
    @FXML private Button stegoClearFileBtn;
    @FXML private Label stegoPasswordLabel;
    @FXML private PasswordField stegoPasswordField;
    @FXML private TextField stegoPasswordVisibleField;
    @FXML private CheckBox stegoShowPasswordCheck;
    @FXML private Label stegoOptionsLabel;
    // 选项行容器（控制整行显示/隐藏）
    @FXML private HBox stegoLsbDepthRow;
    @FXML private Label stegoLsbDepthLabel;
    @FXML private ComboBox<Integer> stegoLsbDepthCombo;
    @FXML private Label stegoLsbDepthInfo;
    @FXML private HBox stegoParanoidRow;
    @FXML private CheckBox stegoParanoidCheck;
    @FXML private Label stegoParanoidLabel;
    @FXML private Label stegoParanoidInfo;
    @FXML private HBox stegoIntegrityRow;
    @FXML private CheckBox stegoIntegrityCheck;
    @FXML private Label stegoIntegrityLabel;
    @FXML private Label stegoIntegrityInfo;
    @FXML private HBox stegoStealthRow;
    @FXML private CheckBox stegoStealthCheck;
    @FXML private Label stegoStealthLabel;
    @FXML private Label stegoStealthInfo;
    @FXML private HBox stegoObfuscateRow;
    @FXML private CheckBox stegoObfuscateCheck;
    @FXML private Label stegoObfuscateLabel;
    @FXML private Label stegoObfuscateInfo;
    @FXML private HBox stegoObfuscateSizeRow;
    @FXML private Label stegoObfuscateSizeLabel;
    @FXML private TextField stegoObfuscateSizeField;
    @FXML private HBox stegoBruteForceRow;
    @FXML private CheckBox stegoBruteForceCheck;
    @FXML private Label stegoBruteForceLabel;
    @FXML private Label stegoBruteForceInfo;
    @FXML private VBox stegoCapacityCard;
    @FXML private Label stegoCapacityLabel;
    @FXML private ProgressBar stegoCapacityBar;
    @FXML private Label stegoCapacityText;

    // ---- Chunk 控件 ----
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
    @FXML private HBox stegoChunkParanoidRow;
    @FXML private CheckBox stegoChunkParanoidCheck;
    @FXML private Label stegoChunkParanoidLabel;
    @FXML private Label stegoChunkParanoidInfo;
    @FXML private HBox stegoChunkIntegrityRow;
    @FXML private CheckBox stegoChunkIntegrityCheck;
    @FXML private Label stegoChunkIntegrityLabel;
    @FXML private Label stegoChunkIntegrityInfo;
    @FXML private HBox stegoChunkStealthRow;
    @FXML private CheckBox stegoChunkStealthCheck;
    @FXML private Label stegoChunkStealthLabel;
    @FXML private Label stegoChunkStealthInfo;
    @FXML private HBox stegoChunkObfuscateRow;
    @FXML private CheckBox stegoChunkObfuscateCheck;
    @FXML private Label stegoChunkObfuscateLabel;
    @FXML private Label stegoChunkObfuscateInfo;
    @FXML private HBox stegoChunkObfuscateSizeRow;
    @FXML private Label stegoChunkObfuscateSizeLabel;
    @FXML private TextField stegoChunkObfuscateSizeField;
    @FXML private HBox stegoChunkBruteForceRow;
    @FXML private CheckBox stegoChunkBruteForceCheck;
    @FXML private Label stegoChunkBruteForceLabel;
    @FXML private Label stegoChunkBruteForceInfo;

    // ---- 底部 ----
    @FXML private StackPane stegoRoot;
    @FXML private VBox stegoProgressBox;
    @FXML private Label stegoStatusLabel;
    @FXML private Label stegoProgressInfo;
    @FXML private ProgressBar stegoProgressBar;
    @FXML private Button stegoCancelBtn;
    @FXML private Button stegoActionBtn;

    // ---- 状态 ----
    private File selectedImageFile;
    private File selectedSecretFile;
    private boolean isHideMode = true;
    private File chunkImageFile;
    private File chunkSecretFile;
    private boolean isChunkHideMode = true;

    /** 密码变更监听器（用于联动选项可用性）。 */
    private final ChangeListener<String> lsbPasswordListener = (obs, old, val) -> updateOptionLinkage();
    private final ChangeListener<String> chunkPasswordListener = (obs, old, val) -> updateChunkOptionLinkage();

    @FXML
    private void initialize() {
        toast = new Toast(stegoRoot);
        stegoLsbDepthCombo.getItems().addAll(1, 2, 3, 4);
        stegoLsbDepthCombo.getSelectionModel().select(0);
        stegoImageView.fitWidthProperty().bind(stegoImageStack.widthProperty().subtract(20));
        stegoChunkImageView.fitWidthProperty().bind(stegoChunkImageStack.widthProperty().subtract(20));

        // 子方案切换
        stegoSubGroup.selectedToggleProperty().addListener((obs, old, val) -> onSubChanged());
        stegoModeGroup.selectedToggleProperty().addListener((obs, old, val) -> onModeChanged());
        stegoChunkModeGroup.selectedToggleProperty().addListener((obs, old, val) -> onChunkModeChanged());

        // 密码联动
        stegoPasswordField.textProperty().addListener(lsbPasswordListener);
        stegoPasswordVisibleField.textProperty().addListener(lsbPasswordListener);
        stegoChunkPasswordField.textProperty().addListener(chunkPasswordListener);
        stegoChunkPasswordVisibleField.textProperty().addListener(chunkPasswordListener);

        // 混淆大小联动：勾选时显示目标大小输入行
        stegoObfuscateCheck.selectedProperty().addListener((obs, old, val) -> {
            setVisibility(stegoObfuscateSizeRow, val);
        });
        stegoChunkObfuscateCheck.selectedProperty().addListener((obs, old, val) -> {
            setVisibility(stegoChunkObfuscateSizeRow, val);
        });

        // 隐蔽模式联动
        stegoStealthCheck.selectedProperty().addListener((obs, old, val) -> updateOptionLinkage());
        stegoChunkStealthCheck.selectedProperty().addListener((obs, old, val) -> updateChunkOptionLinkage());

        setupDragDrop();
        applyTexts();
        updateSubUI();
        updateModeUI();
        updateChunkModeUI();
        updateOptionLinkage();
        updateChunkOptionLinkage();
    }

    // ---- 密码联动：无密码时禁用隐蔽模式 ----

    /**
     * 获取 LSB 标签页当前密码长度。
     */
    private int getLsbPasswordLength() {
        String pwd = stegoPasswordField.isVisible()
                ? stegoPasswordField.getText()
                : stegoPasswordVisibleField.getText();
        return (pwd == null) ? 0 : pwd.length();
    }

    /**
     * 获取 Chunk 标签页当前密码长度。
     */
    private int getChunkPasswordLength() {
        String pwd = stegoChunkPasswordField.isVisible()
                ? stegoChunkPasswordField.getText()
                : stegoChunkPasswordVisibleField.getText();
        return (pwd == null) ? 0 : pwd.length();
    }

    /**
     * 更新 LSB 标签页选项联动：
     * - 隐蔽模式：需要密码
     * - 防暴力破解：需要密码（无密码时无法区分正确/错误）
     */
    private void updateOptionLinkage() {
        boolean hasPassword = getLsbPasswordLength() > 0;
        // 隐蔽模式需要密码（嵌入时由密码派生魔数）
        if (!hasPassword && stegoStealthCheck.isSelected()) {
            stegoStealthCheck.setSelected(false);
        }
        stegoStealthCheck.setDisable(!hasPassword);
        // 防暴力破解始终可点击（提取时用户可能后续输入密码）
    }

    private void updateChunkOptionLinkage() {
        boolean hasPassword = getChunkPasswordLength() > 0;
        if (!hasPassword && stegoChunkStealthCheck.isSelected()) {
            stegoChunkStealthCheck.setSelected(false);
        }
        stegoChunkStealthCheck.setDisable(!hasPassword);
    }

    // ---- 子方案切换 ----

    private void onSubChanged() { updateSubUI(); }

    private void updateSubUI() {
        boolean isPixel = stegoPixelTab.isSelected();
        setVisibility(stegoPixelContent, isPixel);
        setVisibility(stegoChunkContent, !isPixel);
        stegoActionBtn.setOnAction(e -> {
            if (stegoPixelTab.isSelected()) onAction(); else onChunkAction();
        });
    }

    // ---- LSB 模式切换 ----

    private void onModeChanged() {
        isHideMode = stegoHideTab.isSelected();
        updateModeUI();
    }

    private void updateModeUI() {
        setVisibility(stegoFileCard, isHideMode);
        setVisibility(stegoCapacityCard, isHideMode);
        // 隐藏模式显示嵌入选项行，提取模式显示防暴力破解行
        setVisibility(stegoLsbDepthRow, isHideMode);
        setVisibility(stegoParanoidRow, isHideMode);
        setVisibility(stegoIntegrityRow, isHideMode);
        setVisibility(stegoStealthRow, isHideMode);
        setVisibility(stegoObfuscateRow, isHideMode);
        setVisibility(stegoObfuscateSizeRow, isHideMode && stegoObfuscateCheck.isSelected());
        setVisibility(stegoBruteForceRow, !isHideMode);
        stegoActionBtn.setText(isHideMode
                ? Messages.get("stego.btn.hide")
                : Messages.get("stego.btn.extract"));
    }

    // ---- Chunk 模式切换 ----

    private void onChunkModeChanged() {
        isChunkHideMode = stegoChunkHideTab.isSelected();
        updateChunkModeUI();
    }

    private void updateChunkModeUI() {
        setVisibility(stegoChunkFileCard, isChunkHideMode);
        setVisibility(stegoChunkParanoidRow, isChunkHideMode);
        setVisibility(stegoChunkIntegrityRow, isChunkHideMode);
        setVisibility(stegoChunkStealthRow, isChunkHideMode);
        setVisibility(stegoChunkObfuscateRow, isChunkHideMode);
        setVisibility(stegoChunkObfuscateSizeRow, isChunkHideMode && stegoChunkObfuscateCheck.isSelected());
        setVisibility(stegoChunkBruteForceRow, !isChunkHideMode);
        stegoActionBtn.setText(isChunkHideMode
                ? Messages.get("stego.btn.hide")
                : Messages.get("stego.btn.extract"));
    }

    // ---- LSB 图片 ----

    @FXML private void onChooseImage() {
        File f = choosePngFile(Messages.get("stego.choose.image"));
        if (f != null) setImageFile(f);
    }

    @FXML private void onClearImage() {
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
        try {
            Image img = new Image(file.toURI().toString(), 660, 240, true, true, true);
            stegoImageView.setImage(img);
            stegoImagePlaceholder.setVisible(false);
        } catch (Exception e) {
            stegoImagePlaceholder.setVisible(true);
        }
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

    // ---- LSB 文件 ----

    @FXML private void onChooseFile() {
        File f = chooseAnyFile(Messages.get("stego.choose.file"));
        if (f != null) setSecretFile(f);
    }

    @FXML private void onClearFile() {
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

    // ---- LSB 密码 ----

    @FXML private void onToggleShowPassword() {
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
        return (pwd == null || pwd.isEmpty()) ? new byte[0]
                : pwd.getBytes(StandardCharsets.UTF_8);
    }

    // ---- Chunk 图片 ----

    @FXML private void onChooseChunkImage() {
        File f = choosePngFile(Messages.get("stego.choose.image"));
        if (f != null) setChunkImageFile(f);
    }

    @FXML private void onClearChunkImage() {
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

    // ---- Chunk 文件 ----

    @FXML private void onChooseChunkFile() {
        File f = chooseAnyFile(Messages.get("stego.choose.file"));
        if (f != null) setChunkSecretFile(f);
    }

    @FXML private void onClearChunkFile() {
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

    @FXML private void onToggleChunkShowPassword() {
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

    // ---- LSB 操作 ----

    @FXML private void onAction() {
        if (isHideMode) doHide(); else doExtract();
    }

    private void doHide() {
        if (selectedImageFile == null) {
            toast.info(Messages.get("stego.toast.no.image")); return;
        }
        if (selectedSecretFile == null) {
            toast.info(Messages.get("stego.toast.no.file")); return;
        }
        File outFile = chooseSavePng(Messages.get("stego.save.stego"),
                "stego_" + selectedImageFile.getName());
        if (outFile == null) return;

        // 解析目标大小
        long targetSizeBytes = 0;
        if (stegoObfuscateCheck.isSelected()) {
            targetSizeBytes = parseTargetSize(stegoObfuscateSizeField.getText());
            if (targetSizeBytes <= 0) {
                toast.info(Messages.get("stego.toast.invalid.size")); return;
            }
        }

        StegoOptions options = StegoOptions.builder()
                .lsbDepth(stegoLsbDepthCombo.getValue())
                .paranoid(stegoParanoidCheck.isSelected())
                .storeMac(stegoIntegrityCheck.isSelected())
                .stealth(stegoStealthCheck.isSelected() && getLsbPasswordLength() > 0)
                .obfuscateSize(stegoObfuscateCheck.isSelected())
                .targetSizeBytes(targetSizeBytes)
                .bruteForceGuard(stegoBruteForceCheck.isSelected())
                .build();
        byte[] pwd = getPasswordBytes();
        Path outputPath = outFile.toPath();

        showProgress(true);
        taskRunner.submit(() -> {
            codec.hide(selectedImageFile.toPath(), selectedSecretFile.toPath(),
                    outputPath, pwd, options);
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

    private void doExtract() {
        if (selectedImageFile == null) {
            toast.info(Messages.get("stego.toast.no.image")); return;
        }
        File outDir = chooseDirectory(Messages.get("stego.choose.output.dir"));
        if (outDir == null) return;

        byte[] pwd = getPasswordBytes();
        showProgress(true);
        taskRunner.submit(() -> {
            Path extracted = codec.extract(selectedImageFile.toPath(), outDir.toPath(), pwd);
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

    // ---- Chunk 操作 ----

    @FXML private void onChunkAction() {
        if (isChunkHideMode) doChunkHide(); else doChunkExtract();
    }

    private void doChunkHide() {
        if (chunkImageFile == null) {
            toast.info(Messages.get("stego.toast.no.image")); return;
        }
        if (chunkSecretFile == null) {
            toast.info(Messages.get("stego.toast.no.file")); return;
        }
        File outFile = chooseSavePng(Messages.get("stego.save.stego"),
                "stego_" + chunkImageFile.getName());
        if (outFile == null) return;

        long targetSizeBytes = 0;
        if (stegoChunkObfuscateCheck.isSelected()) {
            targetSizeBytes = parseTargetSize(stegoChunkObfuscateSizeField.getText());
            if (targetSizeBytes <= 0) {
                toast.info(Messages.get("stego.toast.invalid.size")); return;
            }
        }

        StegoOptions opts = StegoOptions.builder()
                .paranoid(stegoChunkParanoidCheck.isSelected())
                .storeMac(stegoChunkIntegrityCheck.isSelected())
                .stealth(stegoChunkStealthCheck.isSelected() && getChunkPasswordLength() > 0)
                .obfuscateSize(stegoChunkObfuscateCheck.isSelected())
                .targetSizeBytes(targetSizeBytes)
                .bruteForceGuard(stegoChunkBruteForceCheck.isSelected())
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
            toast.info(Messages.get("stego.toast.no.image")); return;
        }
        File outDir = chooseDirectory(Messages.get("stego.choose.output.dir"));
        if (outDir == null) return;

        byte[] pwd = getChunkPasswordBytes();
        showProgress(true);
        taskRunner.submit(() -> {
            Path extracted = codec.extractChunk(chunkImageFile.toPath(), outDir.toPath(), pwd);
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
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PNG images", "*.png"));
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
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PNG", "*.png"));
        chooser.setInitialFileName(initialName);
        return chooser.showSaveDialog(stegoRoot.getScene().getWindow());
    }

    private File chooseDirectory(final String title) {
        javafx.stage.DirectoryChooser chooser = new javafx.stage.DirectoryChooser();
        chooser.setTitle(title);
        return chooser.showDialog(stegoRoot.getScene().getWindow());
    }

    // ---- 容量 ----

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
                    .paranoid(stegoParanoidCheck.isSelected())
                    .stealth(stegoStealthCheck.isSelected() && getLsbPasswordLength() > 0)
                    .build();
            long capacity = codec.availableCapacity(selectedImageFile.toPath(), opts,
                    selectedSecretFile.getName());
            long needed = selectedSecretFile.length();
            double ratio = capacity > 0 ? (double) needed / capacity : 1.0;
            stegoCapacityBar.setProgress(Math.min(ratio, 1.0));
            stegoCapacityText.setText(Messages.format("stego.capacity.text",
                    formatSize(needed), formatSize(capacity)));
            stegoCapacityBar.setStyle(needed > capacity
                    ? "-fx-accent: #e74c3c;" : "-fx-accent: #2ecc71;");
        } catch (Exception e) {
            stegoCapacityText.setText("");
        }
    }

    // ---- 拖拽（LSB + Chunk 两个图片区都支持）----

    private void setupDragDrop() {
        // LSB 图片区
        stegoImageStack.setOnDragOver(this::onDragOver);
        stegoImageStack.setOnDragDropped(this::onImageDragDropped);
        stegoImageStack.setOnDragEntered(e -> onDragEntered(e, stegoImageStack));
        stegoImageStack.setOnDragExited(e -> onDragExited(e, stegoImageStack));
        // Chunk 图片区
        stegoChunkImageStack.setOnDragOver(this::onChunkDragOver);
        stegoChunkImageStack.setOnDragDropped(this::onChunkImageDragDropped);
        stegoChunkImageStack.setOnDragEntered(e -> onDragEntered(e, stegoChunkImageStack));
        stegoChunkImageStack.setOnDragExited(e -> onDragExited(e, stegoChunkImageStack));
    }

    private void onDragEntered(final DragEvent e, final StackPane zone) {
        if (e.getDragboard().hasFiles())
            zone.setStyle("-fx-background-color: #d0e4f7; -fx-background-radius: 6;");
    }

    private void onDragExited(final DragEvent e, final StackPane zone) {
        zone.setStyle("-fx-background-color: #e8e8e8; -fx-background-radius: 6;");
    }

    private void onDragOver(final DragEvent e) {
        if (e.getDragboard().hasFiles())
            e.acceptTransferModes(javafx.scene.input.TransferMode.COPY);
    }

    private void onChunkDragOver(final DragEvent e) {
        if (e.getDragboard().hasFiles())
            e.acceptTransferModes(javafx.scene.input.TransferMode.COPY);
    }

    private void onImageDragDropped(final DragEvent e) {
        stegoImageStack.setStyle("-fx-background-color: #e8e8e8; -fx-background-radius: 6;");
        Dragboard db = e.getDragboard();
        if (db.hasFiles() && !db.getFiles().isEmpty())
            setImageFile(db.getFiles().get(0));
        e.setDropCompleted(true);
    }

    private void onChunkImageDragDropped(final DragEvent e) {
        stegoChunkImageStack.setStyle("-fx-background-color: #e8e8e8; -fx-background-radius: 6;");
        Dragboard db = e.getDragboard();
        if (db.hasFiles() && !db.getFiles().isEmpty())
            setChunkImageFile(db.getFiles().get(0));
        e.setDropCompleted(true);
    }

    // ---- 进度 ----

    private void showProgress(final boolean show) {
        setVisibility(stegoProgressBox, show);
        stegoCancelBtn.setVisible(show);
        stegoCancelBtn.setManaged(show);
        stegoActionBtn.setDisable(show);
    }

    @FXML private void onCancel() {
        taskRunner.shutdown();
        showProgress(false);
    }

    // ---- 工具 ----

    private static void setVisibility(final javafx.scene.Node node, final boolean visible) {
        if (node != null) {
            node.setVisible(visible);
            node.setManaged(visible);
        }
    }

    private static String formatSize(final long bytes) {
        if (bytes < 1024) return bytes + " B";
        else if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        else if (bytes < 1024 * 1024 * 1024)
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }

    /**
     * 解析目标大小字符串（支持 "500"=500KB, "1.5"=1.5MB, "200KB", "3MB"）。
     */
    private static long parseTargetSize(final String text) {
        if (text == null || text.isBlank()) return 0;
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
                // 纯数字，默认 KB
                return (long) (Double.parseDouble(t) * 1024);
            }
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static void tryDelete(final Path path) {
        try { Files.deleteIfExists(path); } catch (IOException ignored) {}
    }

    /** 安装带样式的提示气泡到 info-icon 标签上。 */
    private static void setTip(final Label label, final String text) {
        if (label == null) return;
        javafx.scene.control.Tooltip tip = new javafx.scene.control.Tooltip(text);
        tip.getStyleClass().add("info-tooltip");
        tip.setShowDuration(javafx.util.Duration.seconds(20));
        tip.setHideDelay(javafx.util.Duration.millis(120));
        tip.setWrapText(true);
        tip.setMaxWidth(300);
        javafx.scene.control.Tooltip.install(label, tip);
        label.setTooltip(tip);
    }

    // ---- 国际化 ----

    public void applyTexts() {
        if (stegoPixelTab == null) return;
        stegoPixelTab.setText(Messages.get("stego.sub.pixel"));
        stegoChunkTab.setText(Messages.get("stego.sub.chunk"));
        stegoHideTab.setText(Messages.get("stego.mode.hide"));
        stegoExtractTab.setText(Messages.get("stego.mode.extract"));
        stegoChunkHideTab.setText(Messages.get("stego.mode.hide"));
        stegoChunkExtractTab.setText(Messages.get("stego.mode.extract"));
        // LSB
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
        stegoStealthLabel.setText(Messages.get("stego.option.stealth"));
        stegoObfuscateLabel.setText(Messages.get("stego.option.obfuscate"));
        stegoObfuscateSizeLabel.setText(Messages.get("stego.option.obfuscateSize"));
        stegoBruteForceLabel.setText(Messages.get("stego.option.bruteForce"));
        stegoCapacityLabel.setText(Messages.get("stego.capacity.label"));
        // Chunk
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
        stegoChunkStealthLabel.setText(Messages.get("stego.option.stealth"));
        stegoChunkObfuscateLabel.setText(Messages.get("stego.option.obfuscate"));
        stegoChunkObfuscateSizeLabel.setText(Messages.get("stego.option.obfuscateSize"));
        stegoChunkBruteForceLabel.setText(Messages.get("stego.option.bruteForce"));
        stegoCancelBtn.setText(Messages.get("action.cancel"));
        stegoActionBtn.setText(isHideMode
                ? Messages.get("stego.btn.hide") : Messages.get("stego.btn.extract"));
        // 提示气泡
        setTip(stegoLsbDepthInfo, Messages.get("stego.option.lsbDepth.tip"));
        setTip(stegoParanoidInfo, Messages.get("options.paranoid.tip"));
        setTip(stegoIntegrityInfo, Messages.get("stego.option.integrity.tip"));
        setTip(stegoStealthInfo, Messages.get("stego.option.stealth.tip"));
        setTip(stegoObfuscateInfo, Messages.get("stego.option.obfuscate.tip"));
        setTip(stegoBruteForceInfo, Messages.get("stego.option.bruteForce.tip"));
        setTip(stegoChunkParanoidInfo, Messages.get("options.paranoid.tip"));
        setTip(stegoChunkIntegrityInfo, Messages.get("stego.option.integrity.tip"));
        setTip(stegoChunkStealthInfo, Messages.get("stego.option.stealth.tip"));
        setTip(stegoChunkObfuscateInfo, Messages.get("stego.option.obfuscate.tip"));
        setTip(stegoChunkBruteForceInfo, Messages.get("stego.option.bruteForce.tip"));
    }

    public void shutdown() { taskRunner.shutdown(); }
}
