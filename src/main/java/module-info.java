module hbnu.project.ergoutreecrypt {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires org.kordamp.ikonli.javafx;
    requires org.kordamp.bootstrapfx.core;

    requires org.bouncycastle.provider;

    requires org.apache.commons.compress;
    // commons-compress 对 xz 仅声明 requires static（运行时可选），若本模块不强依赖，
    // 解析 7z 时 Coders 静态初始化引用 org.tukaani.xz.FilterOptions 会抛 NoClassDefFoundError。
    // 显式 require 以强制 JPMS 解析 xz 模块。
    requires org.tukaani.xz;
    requires zip4j;
    requires com.github.luben.zstd_jni;
    requires java.prefs;
    requires java.desktop;
    requires jdk.unsupported;
    requires org.slf4j;
    requires ch.qos.logback.classic;
    requires ch.qos.logback.core;

    opens hbnu.project.ergoutreecrypt to javafx.fxml;
    opens hbnu.project.ergoutreecrypt.ui to javafx.fxml;

    exports hbnu.project.ergoutreecrypt;
    exports hbnu.project.ergoutreecrypt.i18n;
    exports hbnu.project.ergoutreecrypt.ui;
    exports hbnu.project.ergoutreecrypt.ui.support;
    exports hbnu.project.ergoutreecrypt.crypto;
    exports hbnu.project.ergoutreecrypt.compress;
    exports hbnu.project.ergoutreecrypt.encoding;
    exports hbnu.project.ergoutreecrypt.fileops;
    exports hbnu.project.ergoutreecrypt.header;
    exports hbnu.project.ergoutreecrypt.keyfile;
    exports hbnu.project.ergoutreecrypt.password;
    exports hbnu.project.ergoutreecrypt.settings;
    exports hbnu.project.ergoutreecrypt.history;
    exports hbnu.project.ergoutreecrypt.log;
    exports hbnu.project.ergoutreecrypt.volume;
    exports hbnu.project.ergoutreecrypt.mediacrypt;
    exports hbnu.project.ergoutreecrypt.mediacrypt.wav;
    exports hbnu.project.ergoutreecrypt.mediacrypt.mp3;
    exports hbnu.project.ergoutreecrypt.mediacrypt.mp4;
    exports hbnu.project.ergoutreecrypt.stego;
    exports hbnu.project.ergoutreecrypt.filestego;
    exports hbnu.project.ergoutreecrypt.filestego.api;
    exports hbnu.project.ergoutreecrypt.filestego.codec;
    exports hbnu.project.ergoutreecrypt.filestego.carrier.spi;
    exports hbnu.project.ergoutreecrypt.filestego.carrier.png;
    exports hbnu.project.ergoutreecrypt.filestego.carrier.zip;
    exports hbnu.project.ergoutreecrypt.filestego.carrier.pdf;
    exports hbnu.project.ergoutreecrypt.filestego.carrier.wav;
    exports hbnu.project.ergoutreecrypt.filestego.carrier.flac;
    exports hbnu.project.ergoutreecrypt.filestego.carrier.mp4;
}
