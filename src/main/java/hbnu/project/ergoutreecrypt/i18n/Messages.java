package hbnu.project.ergoutreecrypt.i18n;

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * 国际化文案封装。
 * 基于 {@link ResourceBundle} 加载 {@code i18n/messages_*.properties}，支持运行期在中文 / 英文之间切换。
 *
 * <p>线程不可变状态仅为 {@code locale} 与 {@code bundle}，切换语言后由 UI 层重建界面文案。
 *
 * @author ErgouTree
 */
public final class Messages {

    private static final String BASE = "hbnu.project.ergoutreecrypt.i18n.messages";

    private static Locale currentLocale = Locale.SIMPLIFIED_CHINESE;
    private static ResourceBundle bundle = load(currentLocale);

    private Messages() {
    }

    private static ResourceBundle load(Locale locale) {
        return ResourceBundle.getBundle(BASE, locale);
    }

    /** 当前语言。 */
    public static Locale getLocale() {
        return currentLocale;
    }

    /** 是否为中文环境。 */
    public static boolean isChinese() {
        return "zh".equals(currentLocale.getLanguage());
    }

    /** 设置语言并重新加载资源包。 */
    public static void setLocale(Locale locale) {
        currentLocale = locale;
        bundle = load(locale);
    }

    /** 在中文 / 英文之间切换。 */
    public static void toggleLocale() {
        setLocale(isChinese() ? Locale.ENGLISH : Locale.SIMPLIFIED_CHINESE);
    }

    /** 取文案；缺失时回退为 {@code !key!}，避免抛异常中断 UI。 */
    public static String get(String key) {
        try {
            return bundle.getString(key);
        } catch (MissingResourceException e) {
            return "!" + key + "!";
        }
    }

    /** 取格式化文案（{@link String#format}）。 */
    public static String format(String key, Object... args) {
        return String.format(get(key), args);
    }
}
