package hbnu.project.ergoutreecrypt.ui;

import hbnu.project.ergoutreecrypt.classical.CipherInfo;
import hbnu.project.ergoutreecrypt.classical.CipherRegistry;
import hbnu.project.ergoutreecrypt.classical.ClassicalCipher;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.ui.support.Toast;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 古典密码明密文转换页签控制器。
 *
 * <p>负责算法选择、参数字段的动态显示/隐藏、明文与密文的双向转换操作。
 * 支持所有通过 {@link CipherRegistry} 注册的古典密码算法。
 *
 * @author ErgouTree
 */
public class ClassicalCryptController {

    // ---- 根 ----
    @FXML
    private StackPane ccRoot;

    // ---- 算法选择 ----
    @FXML
    private Label ccAlgorithmLabel;
    @FXML
    private ComboBox<CipherItem> ccAlgorithmCombo;

    // ---- 参数卡片及子控件 ----
    @FXML
    private VBox ccParamCard;
    @FXML
    private VBox ccShiftBox;
    @FXML
    private Label ccShiftLabel;
    @FXML
    private TextField ccShiftField;
    @FXML
    private VBox ccKeywordBox;
    @FXML
    private Label ccKeywordLabel;
    @FXML
    private TextField ccKeywordField;
    @FXML
    private VBox ccRailsBox;
    @FXML
    private Label ccRailsLabel;
    @FXML
    private TextField ccRailsField;
    @FXML
    private VBox ccKeyBox;
    @FXML
    private Label ccKeyLabel;
    @FXML
    private TextField ccKeyField;

    // ---- 文本区域 ----
    @FXML
    private Label ccPlaintextLabel;
    @FXML
    private TextArea ccPlaintextArea;
    @FXML
    private Label ccCiphertextLabel;
    @FXML
    private TextArea ccCiphertextArea;

    // ---- 按钮 ----
    @FXML
    private Button ccEncryptBtn;
    @FXML
    private Button ccDecryptBtn;
    @FXML
    private Button ccSwapBtn;
    @FXML
    private Button ccCopyBtn;
    @FXML
    private Button ccClearBtn;

    /**
     * 当前选中的算法实例。
     */
    private ClassicalCipher currentCipher;

    /**
     * Toast 通知组件。
     */
    private Toast toast;

    /**
     * FXML 加载完成后由 FXMLLoader 调用的初始化方法。
     */
    @FXML
    private void initialize() {
        toast = new Toast(ccRoot);
        currentCipher = CipherRegistry.getDefault();
        populateAlgorithmCombo();
        ccAlgorithmCombo.getSelectionModel().selectFirst();
        ccAlgorithmCombo.setOnAction(e -> onAlgorithmChanged());
        showParamsFor(currentCipher.getInfo());
        applyTexts();
    }

    /**
     * 填充算法下拉列表。
     */
    private void populateAlgorithmCombo() {
        List<CipherInfo> infos = CipherRegistry.getAll();
        List<CipherItem> items = infos.stream()
                .map(CipherItem::new)
                .toList();
        ccAlgorithmCombo.setItems(FXCollections.observableArrayList(items));
    }

    /**
     * 算法选择变更时的处理逻辑。
     */
    private void onAlgorithmChanged() {
        CipherItem selected = ccAlgorithmCombo.getSelectionModel().getSelectedItem();
        if (selected == null) {
            return;
        }
        currentCipher = CipherRegistry.get(selected.info().id());
        if (currentCipher == null) {
            currentCipher = CipherRegistry.getDefault();
        }
        showParamsFor(currentCipher.getInfo());
    }

    /**
     * 根据算法信息显示/隐藏对应的参数字段，并设置默认值。
     *
     * @param info 算法元数据
     */
    private void showParamsFor(final CipherInfo info) {
        hideAllParams();
        if (info.params().isEmpty()) {
            setVisibility(ccParamCard, false);
            return;
        }
        setVisibility(ccParamCard, true);
        for (CipherInfo.ParamDef param : info.params()) {
            switch (param.key()) {
                case "shift" -> {
                    setVisibility(ccShiftBox, true);
                    ccShiftField.setText(param.defaultValue());
                }
                case "keyword" -> {
                    setVisibility(ccKeywordBox, true);
                    ccKeywordField.setText(param.defaultValue());
                }
                case "rails" -> {
                    setVisibility(ccRailsBox, true);
                    ccRailsField.setText(param.defaultValue());
                }
                case "key" -> {
                    setVisibility(ccKeyBox, true);
                    ccKeyField.setText(param.defaultValue());
                }
                default -> {
                    // 未知参数类型，忽略
                }
            }
        }
    }

    /**
     * 隐藏所有参数字段。
     */
    private void hideAllParams() {
        setVisibility(ccShiftBox, false);
        setVisibility(ccKeywordBox, false);
        setVisibility(ccRailsBox, false);
        setVisibility(ccKeyBox, false);
    }

    /**
     * 加密操作：读取左侧明文，生成密文写入右侧。
     */
    @FXML
    private void onEncrypt() {
        String plaintext = ccPlaintextArea.getText();
        if (plaintext == null || plaintext.isEmpty()) {
            toast.info(Messages.get("cc.toast.empty.input"));
            return;
        }
        Map<String, String> params = collectParams();
        try {
            String ciphertext = currentCipher.encrypt(plaintext, params);
            ccCiphertextArea.setText(ciphertext);
        } catch (Exception e) {
            toast.info(Messages.format("cc.toast.error", e.getMessage()));
        }
    }

    /**
     * 解密操作：读取右侧密文，还原明文写入左侧。
     */
    @FXML
    private void onDecrypt() {
        String ciphertext = ccCiphertextArea.getText();
        if (ciphertext == null || ciphertext.isEmpty()) {
            toast.info(Messages.get("cc.toast.empty.input"));
            return;
        }
        Map<String, String> params = collectParams();
        try {
            String plaintext = currentCipher.decrypt(ciphertext, params);
            ccPlaintextArea.setText(plaintext);
        } catch (Exception e) {
            toast.info(Messages.format("cc.toast.error", e.getMessage()));
        }
    }

    /**
     * 交换左右两侧文本区域的内容。
     */
    @FXML
    private void onSwap() {
        String left = ccPlaintextArea.getText();
        String right = ccCiphertextArea.getText();
        ccPlaintextArea.setText(right);
        ccCiphertextArea.setText(left);
    }

    /**
     * 复制密文区域的内容到系统剪贴板。
     */
    @FXML
    private void onCopy() {
        String text = ccCiphertextArea.getText();
        if (text == null || text.isEmpty()) {
            toast.info(Messages.get("cc.toast.empty.copy"));
            return;
        }
        ClipboardContent content = new ClipboardContent();
        content.putString(text);
        Clipboard.getSystemClipboard().setContent(content);
        toast.success(Messages.get("toast.copied"));
    }

    /**
     * 清空左右两侧文本区域。
     */
    @FXML
    private void onClear() {
        ccPlaintextArea.clear();
        ccCiphertextArea.clear();
    }

    /**
     * 收集当前显示参数的值。
     *
     * @return 参数键值对
     */
    private Map<String, String> collectParams() {
        Map<String, String> params = new HashMap<>();
        if (ccShiftBox.isVisible()) {
            params.put("shift", ccShiftField.getText());
        }
        if (ccKeywordBox.isVisible()) {
            params.put("keyword", ccKeywordField.getText());
        }
        if (ccRailsBox.isVisible()) {
            params.put("rails", ccRailsField.getText());
        }
        if (ccKeyBox.isVisible()) {
            params.put("key", ccKeyField.getText());
        }
        return params;
    }

    /**
     * 设置节点的可见性和管理状态。
     *
     * @param node    目标节点
     * @param visible 是否可见
     */
    private static void setVisibility(final javafx.scene.Node node, final boolean visible) {
        node.setVisible(visible);
        node.setManaged(visible);
    }

    /**
     * 根据当前语言环境刷新所有 UI 文案。
     */
    public void applyTexts() {
        if (ccAlgorithmLabel == null) {
            return;
        }
        ccAlgorithmLabel.setText(Messages.get("cc.algorithm.label"));
        ccShiftLabel.setText(Messages.get("cc.param.shift"));
        ccKeywordLabel.setText(Messages.get("cc.param.keyword"));
        ccRailsLabel.setText(Messages.get("cc.param.rails"));
        ccKeyLabel.setText(Messages.get("cc.param.key"));
        ccPlaintextLabel.setText(Messages.get("cc.plaintext"));
        ccCiphertextLabel.setText(Messages.get("cc.ciphertext"));
        ccEncryptBtn.setText(Messages.get("cc.btn.encrypt"));
        ccDecryptBtn.setText(Messages.get("cc.btn.decrypt"));
        ccSwapBtn.setText(Messages.get("cc.btn.swap"));
        ccCopyBtn.setText(Messages.get("cc.btn.copy"));
        ccClearBtn.setText(Messages.get("cc.btn.clear"));
        // 刷新下拉列表中的算法名称
        if (ccAlgorithmCombo != null) {
            ccAlgorithmCombo.getItems().forEach(CipherItem::refreshLabel);
            // 强制刷新下拉列表显示
            CipherItem selected = ccAlgorithmCombo.getSelectionModel().getSelectedItem();
            if (selected != null) {
                int idx = ccAlgorithmCombo.getSelectionModel().getSelectedIndex();
                ccAlgorithmCombo.getSelectionModel().clearSelection();
                ccAlgorithmCombo.getSelectionModel().select(idx);
            }
        }
    }

    /**
     * 关闭时释放资源。
     */
    public void shutdown() {
        // 当前无需释放额外资源
    }

    /**
     * 算法下拉列表项，封装 CipherInfo 并提供可刷新的显示标签。
     */
    private static final class CipherItem {

        /**
         * 算法元数据。
         */
        private final CipherInfo info;

        /**
         * @param info 算法元数据
         */
        CipherItem(final CipherInfo info) {
            this.info = info;
        }

        /**
         * @return 算法元数据
         */
        CipherInfo info() {
            return info;
        }

        /**
         * 根据当前语言刷新显示标签。
         */
        void refreshLabel() {
            // toString 在下一次调用时自动反映当前语言
        }

        @Override
        public String toString() {
            return Messages.get(info.nameKey());
        }
    }
}
