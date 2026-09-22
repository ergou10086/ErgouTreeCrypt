package hbnu.project.ergoutreecrypt.passwordbook;

import java.util.Objects;

/**
 * 密码本中的一条名称与密码记录。
 *
 * @author ErgouTree
 * @since 2026/9/22
 */
public final class PasswordBookEntry {

    private final String name;
    private final String password;

    /**
     * 创建密码记录。
     *
     * @param name     用于识别密码的名称
     * @param password 实际密码
     */
    public PasswordBookEntry(String name, String password) {
        this.name = Objects.requireNonNullElse(name, "");
        this.password = Objects.requireNonNullElse(password, "");
    }

    /**
     * 获取记录名称。
     *
     * @return 记录名称
     */
    public String getName() {
        return name;
    }

    /**
     * 获取实际密码。
     *
     * @return 实际密码
     */
    public String getPassword() {
        return password;
    }

    /**
     * 比较两条密码记录的内容。
     *
     * @param other 待比较对象
     * @return 名称和密码均相同时返回 true
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof PasswordBookEntry entry)) {
            return false;
        }
        return name.equals(entry.name) && password.equals(entry.password);
    }

    /**
     * 计算记录内容的哈希值。
     *
     * @return 内容哈希值
     */
    @Override
    public int hashCode() {
        return Objects.hash(name, password);
    }

    /**
     * 返回不包含明文密码的调试文本。
     *
     * @return 安全的记录描述
     */
    @Override
    public String toString() {
        return "PasswordBookEntry{name='" + name + "', password=<hidden>}";
    }
}
