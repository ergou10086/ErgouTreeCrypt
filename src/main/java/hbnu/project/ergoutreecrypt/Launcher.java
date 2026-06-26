package hbnu.project.ergoutreecrypt;

import javafx.application.Application;

/**
 * 绕过 Java 启动器对 JavaFX 模块的预检查。
 *
 * <p>Java 启动器会检查 main 类是否继承 {@link javafx.application.Application}，
 * 若 JRE 中未包含 JavaFX 模块则直接拒绝启动。通过一个不继承 Application 的中间类
 * 来调用 {@link Application#launch(Class, String...)}，可以绕过此检查，
 * 使 JavaFX 从 classpath 加载。
 *
 * @author ErgouTree
 */
public final class Launcher {

    private Launcher() {
    }

    /**
     * 程序入口，将启动委托给 {@link PicocryptApplication}。
     *
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        Application.launch(PicocryptApplication.class, args);
    }
}
