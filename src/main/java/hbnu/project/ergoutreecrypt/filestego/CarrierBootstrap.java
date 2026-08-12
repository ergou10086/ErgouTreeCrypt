package hbnu.project.ergoutreecrypt.filestego;

import hbnu.project.ergoutreecrypt.filestego.carrier.flac.FlacCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.mp4.Mp4CarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.pdf.PdfCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.png.PngCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierRegistry;
import hbnu.project.ergoutreecrypt.filestego.carrier.wav.WavCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.zip.ZipCarrierAdapter;

/**
 * 内置载体适配器引导注册器。
 *
 * <p>将项目内建的各格式 {@link hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierAdapter}
 * 实现集中注册到 {@link CarrierRegistry}。{@link FileStegoCodec} 在类加载时会自动调用
 * {@link #ensureRegistered()}，因此调用方通常无需手动触发。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class CarrierBootstrap {

    /** 是否已完成注册，保证幂等。 */
    private static volatile boolean registered;

    private CarrierBootstrap() {
    }

    /**
     * 确保所有内置适配器已注册（幂等，线程安全）。
     */
    public static synchronized void ensureRegistered() {
        if (registered) {
            return;
        }
        CarrierRegistry.register(new PngCarrierAdapter());
        CarrierRegistry.register(new ZipCarrierAdapter());
        CarrierRegistry.register(new PdfCarrierAdapter());
        CarrierRegistry.register(new WavCarrierAdapter());
        CarrierRegistry.register(new FlacCarrierAdapter());
        CarrierRegistry.register(new Mp4CarrierAdapter());
        registered = true;
    }
}
