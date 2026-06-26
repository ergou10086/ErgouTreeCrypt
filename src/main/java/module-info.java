module hbnu.project.ergoutreecrypt {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires org.kordamp.ikonli.javafx;
    requires org.kordamp.bootstrapfx.core;

    requires org.bouncycastle.provider;

    requires org.apache.commons.compress;
    requires java.prefs;

    opens hbnu.project.ergoutreecrypt to javafx.fxml;
    opens hbnu.project.ergoutreecrypt.ui to javafx.fxml;

    exports hbnu.project.ergoutreecrypt;
    exports hbnu.project.ergoutreecrypt.i18n;
    exports hbnu.project.ergoutreecrypt.ui;
    exports hbnu.project.ergoutreecrypt.ui.support;
    exports hbnu.project.ergoutreecrypt.crypto;
    exports hbnu.project.ergoutreecrypt.encoding;
    exports hbnu.project.ergoutreecrypt.fileops;
    exports hbnu.project.ergoutreecrypt.header;
    exports hbnu.project.ergoutreecrypt.keyfile;
    exports hbnu.project.ergoutreecrypt.password;
    exports hbnu.project.ergoutreecrypt.settings;
    exports hbnu.project.ergoutreecrypt.volume;
    exports hbnu.project.ergoutreecrypt.mediacrypt;
    exports hbnu.project.ergoutreecrypt.mediacrypt.wav;
    exports hbnu.project.ergoutreecrypt.mediacrypt.mp3;
    exports hbnu.project.ergoutreecrypt.mediacrypt.mp4;
}
