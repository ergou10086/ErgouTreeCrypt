package hbnu.project.ergoutreecrypt.i18n;

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * 国际化文案封装。
 *
 * <p>基于 {@link ResourceBundle} 加载 {@code messages_*.properties} 资源文件，
 * 支持运行时在中文与英文之间切换。缺失 key 时回退为 {@code !key!}，避免抛异常中断 UI。
 *
 * @author ErgouTree
 */
public final class Messages {

    /**
     * 资源包的基础名称。
     */
    private static final String BASE = "hbnu.project.ergoutreecrypt.i18n.messages";

    /**
     * 当前语言环境，默认为简体中文。
     */
    private static Locale currentLocale = Locale.SIMPLIFIED_CHINESE;

    /**
     * 当前已加载的资源包。
     */
    private static ResourceBundle bundle = load(currentLocale);

    private Messages() {
    }

    /**
     * 按语言环境加载资源包。
     */
    private static ResourceBundle load(Locale locale) {
        return ResourceBundle.getBundle(BASE, locale);
    }

    /**
     * 返回当前语言环境。
     */
    public static Locale getLocale() {
        return currentLocale;
    }

    /**
     * 设置语言环境并重新加载对应资源包。
     */
    public static void setLocale(Locale locale) {
        currentLocale = locale;
        bundle = load(locale);
    }

    /**
     * 当前是否为中文环境。
     */
    public static boolean isChinese() {
        return "zh".equals(currentLocale.getLanguage());
    }

    /**
     * 在中文与英文之间切换。
     */
    public static void toggleLocale() {
        setLocale(isChinese() ? Locale.ENGLISH : Locale.SIMPLIFIED_CHINESE);
    }

    /**
     * 取指定 key 的文案。缺失时回退为 {@code !key!}。
     *
     * @param key 文案 key
     * @return 对应语言的文案字符串
     */
    public static String get(String key) {
        try {
            return bundle.getString(key);
        } catch (MissingResourceException e) {
            return "!" + key + "!";
        }
    }

    /**
     * 取格式化文案（通过 {@link String#format}）。
     *
     * @param key  文案 key
     * @param args 格式化参数
     * @return 格式化后的文案字符串
     */
    public static String format(String key, Object... args) {
        return String.format(get(key), args);
    }
}
