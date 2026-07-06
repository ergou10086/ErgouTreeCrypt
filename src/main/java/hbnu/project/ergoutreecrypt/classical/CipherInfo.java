package hbnu.project.ergoutreecrypt.classical;

import java.util.List;

/**
 * 古典密码算法的元数据描述。
 *
 * <p>包含算法标识、i18n 键值及参数定义，供 UI 动态渲染算法选择与参数输入控件。
 *
 * @param id      算法唯一标识，如 "caesar"、"vigenere"
 * @param nameKey i18n 资源文件中算法名称的 key
 * @param descKey i18n 资源文件中算法描述的 key
 * @param params  该算法需要的参数定义列表
 * @author ErgouTree
 */
public record CipherInfo(String id, String nameKey, String descKey, List<ParamDef> params) {

    /**
     * 单个参数的定义。
     *
     * @param key         参数键名，用于参数 Map
     * @param labelKey    i18n 资源文件中参数标签的 key
     * @param type        参数输入控件类型：{@code "text"}、{@code "number"}
     * @param defaultValue 默认值
     */
    public record ParamDef(String key, String labelKey, String type, String defaultValue) {
    }
}
