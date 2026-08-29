package hbnu.project.ergoutreecrypt.fileops;

import java.nio.file.Path;

/**
 * 归档密码提供者：当解压遇到受密码保护的归档但当前没有可用密码时，
 * 由调用方（桌面 / 移动端）提供密码，通常通过弹窗询问用户。
 *
 * <p>核心层不感知具体 UI，仅通过该回调获取密码；返回 null 或空表示放弃
 * （跳过该归档或终止解压），由调用方决定后续行为。
 *
 * @author ErgouTree
 */
@FunctionalInterface
public interface ArchivePasswordProvider {

    /**
     * 提供用于解压指定归档的密码。
     *
     * @param archive 需要密码的归档路径
     * @param retry   是否为重试：上一次提供的密码被判定为错误（或解压失败），
     *                提示文案应据此调整为「密码错误，请重新输入」
     * @return 归档密码；返回 null 或空字符串表示放弃 / 跳过
     */
    String providePassword(Path archive, boolean retry);
}
