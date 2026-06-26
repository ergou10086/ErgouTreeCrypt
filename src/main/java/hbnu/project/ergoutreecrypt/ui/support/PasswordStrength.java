package hbnu.project.ergoutreecrypt.ui.support;

/**
 * 简易密码强度评估
 * 仅用于 UI 反馈，不参与任何密码学计算
 *
 * @author ErgouTree
 */
public final class PasswordStrength {

    private PasswordStrength() {
    }

    /**
     * 根据长度与字符多样性给出一个 0..1 的分数与等级。
     */
    public static Level evaluate(String pwd) {
        if (pwd == null || pwd.isEmpty()) {
            return Level.EMPTY;
        }
        int score = 0;
        if (pwd.length() >= 8) {
            score++;
        }
        if (pwd.length() >= 14) {
            score++;
        }
        boolean lower = false, upper = false, digit = false, symbol = false;
        for (int i = 0; i < pwd.length(); i++) {
            char c = pwd.charAt(i);
            if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else {
                symbol = true;
            }
        }
        int variety = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
        score += variety >= 3 ? 2 : (variety == 2 ? 1 : 0);

        if (score >= 4) {
            return Level.STRONG;
        }
        if (score >= 2) {
            return Level.MEDIUM;
        }
        return Level.WEAK;
    }

    /**
     * 生成强随机密码（字母 + 数字 + 符号）。
     */
    public static String generate(int length) {
        final String chars =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
        java.security.SecureRandom rng = new java.security.SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(rng.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * 强度等级。
     */
    public enum Level {EMPTY, WEAK, MEDIUM, STRONG}
}
