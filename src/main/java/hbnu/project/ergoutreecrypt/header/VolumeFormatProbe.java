package hbnu.project.ergoutreecrypt.header;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** 每项任务独立探测魔数，FAST 解析失败不降级重试旧格式。 */
public final class VolumeFormatProbe {
    /** 禁止实例化工具类。 */
    private VolumeFormatProbe() {}

    /**
     * 只读取八字节，不依据扩展名、密码或用户高级选项猜测。
     *
     * @param input 普通密文文件
     * @return 是否为 FAST 外头
     * @throws IOException 文件读取失败
     */
    public static boolean isFast(Path input) throws IOException {
        try (var stream = Files.newInputStream(input)) {
            return FastHeaderReaderWriter.hasMagic(stream.readNBytes(8));
        }
    }
}
