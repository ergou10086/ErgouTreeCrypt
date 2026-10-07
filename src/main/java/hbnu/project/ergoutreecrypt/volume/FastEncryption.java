package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.fast.FastKdfPolicy;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.filetypes.OutputNaming;
import hbnu.project.ergoutreecrypt.i18n.Messages;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** FAST 请求编排；独立归档复用现有库，不混入密码格式或修改旧流水线。 */
final class FastEncryption {
    /** 禁止实例化工具类。 */
    private FastEncryption() {}

    /**
     * 验证请求并在私有中间文件内执行可选前归档、FAST 和可选后归档。
     *
     * @param request FAST 请求
     * @throws Exception 选项、归档、认证加密、取消或提交失败
     */
    static void encrypt(EncryptRequest request) throws Exception {
        FastCapabilities.validateEncryption(request);
        SecureZero.zero(FastKdfPolicy.encodePassword(request.getPassword()));
        var progress = new FastProgress(request.getReporter(), request.getKdfProgress());
        progress.checkCancelled();
        List<String> requested = request.getInputFiles();
        List<Path> inputs =
                requested != null && !requested.isEmpty()
                        ? requested.stream().map(Path::of).toList()
                        : List.of(Path.of(request.getInputFile()));
        for (Path input : inputs)
            if (!Files.isRegularFile(input)) throw new IOException("FAST 输入必须为普通文件：" + input);
        boolean before = FastCapabilities.enabled(request.getPreArchiveFormat());
        boolean after = FastCapabilities.enabled(request.getArchiveFormat());
        ArchivePacker.Format preFormat =
                before
                        ? ArchivePacker.effectiveFormat(
                                ArchivePacker.parseFormat(request.getPreArchiveFormat()),
                                inputs.size())
                        : null;
        ArchivePacker.Format postFormat =
                after ? ArchivePacker.parseFormat(request.getArchiveFormat()) : null;
        Path rawOutput =
                Path.of(
                        before
                                ? OutputNaming.preArchiveEncryptOutputName(
                                        request.getOutputFile(), preFormat.name())
                                : request.getOutputFile());
        Path finalOutput = after ? Path.of(rawOutput + ArchivePacker.extOf(postFormat)) : rawOutput;
        try (var finalStage = FastOutput.create(finalOutput);
                var preStage = before ? FastOutput.temporary(finalStage.path().getParent()) : null;
                var cipherStage =
                        after ? FastOutput.temporary(finalStage.path().getParent()) : null) {
            if (before) {
                archiveStatus(request, progress, "status.compressing");
                ArchivePacker.packEntries(
                        preStage.path(),
                        null,
                        inputs,
                        ArchivePacker.uniqueEntryNames(null, inputs),
                        preFormat,
                        ArchivePacker.resolveArchivePassword(
                                request.getPreArchivePassword(), null, preFormat),
                        request.getReporter());
            }
            progress.checkCancelled();
            Path source = before ? preStage.path() : inputs.getFirst().toRealPath();
            Path encrypted = after ? cipherStage.path() : finalStage.path();
            FastVolumeCodec.writeEncrypted(source, encrypted, request.getPassword(), progress);
            if (after) {
                archiveStatus(request, progress, "status.archiving");
                ArchivePacker.packEntries(
                        finalStage.path(),
                        null,
                        List.of(encrypted),
                        List.of(rawOutput.getFileName().toString()),
                        postFormat,
                        ArchivePacker.resolveArchivePassword(
                                request.getArchivePassword(), request.getPassword(), postFormat),
                        request.getReporter());
            }
            progress.finish();
            finalStage.commit();
            request.setOutputFile(finalOutput.toString());
        }
    }

    /**
     * 归档继续使用独立进度阶段。
     *
     * @param request 原请求
     * @param progress 取消快照
     * @param key 本地化状态键
     * @throws Exception 已取消或回调失败
     */
    private static void archiveStatus(EncryptRequest request, FastProgress progress, String key)
            throws Exception {
        progress.checkCancelled();
        if (request.getReporter() != null)
            request.getReporter().setStatus(Messages.get(key), ProgressPhase.ARCHIVE);
        progress.checkCancelled();
    }
}
