package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.volume.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** 分卷缺失、清单、异常文件、取消与输出保护的回归测试。 */
class SplitCompletenessTest {
    @TempDir Path dir;

    /** @return 空文件、精确边界和 long 上限的分卷往返。 */
    @TestFactory Stream<DynamicTest> boundaries() {
        return Stream.of(0,1,1023,1024,1025,2048,2049).flatMap(size -> Stream.of(1024L,Long.MAX_VALUE)
            .map(chunk -> DynamicTest.dynamicTest(size+"/"+chunk, () -> {
                Path base = Files.write(dir.resolve(size+"-"+chunk+".ergou"), data(size));
                Splitter.split(base,chunk);
                var info = Splitter.inspect(base);
                assertTrue(info.totalKnown());
                assertEquals(Math.max(1,1+(size-1L)/chunk),info.expectedCount());
                info.requireComplete();
                Path merged = dir.resolve("merged-"+size+"-"+chunk);
                Splitter.recombine(merged,base.toString());
                assertArrayEquals(data(size),Files.readAllBytes(merged));
            })));
    }

    /** @return 缺首卷、中间卷、末卷、所有卷均准确报告且保留输出。 */
    @TestFactory Stream<DynamicTest> missingVolumes() {
        return Stream.of(List.of(0),List.of(1),List.of(2),List.of(0,1,2)).map(indices ->
            DynamicTest.dynamicTest("missing="+indices, () -> {
                Path base = Files.write(dir.resolve("missing"+indices+".ergou"),data(2050));
                Splitter.split(base,1024);
                for(int i:indices) Files.delete(Path.of(base+"."+i));
                var info=Splitter.inspect(base);
                assertEquals(3,info.expectedCount());
                assertEquals(indices,info.missing());
                Path out=Files.writeString(dir.resolve("out"+indices),"keep");
                IOException error=assertThrows(IOException.class,()->Splitter.recombine(out,base.toString()));
                for(int i:indices) assertTrue(error.getMessage().contains("."+i));
                assertEquals("keep",Files.readString(out));
                assertFalse(Files.exists(Path.of(out+".incomplete")));
            }));
    }

    /** @return 截断、增大、目录冒充碎片均在合并前拒绝。 */
    @TestFactory Stream<DynamicTest> wrongSizesAndDirectories() {
        return Stream.of("short","long","directory").map(kind -> DynamicTest.dynamicTest(kind,()->{
            Path base=Files.write(dir.resolve(kind+".pcv"),data(2050)); Splitter.split(base,1024);
            Path chunk=Path.of(base+".1"); Files.delete(chunk);
            if(kind.equals("directory")) Files.createDirectory(chunk);
            else Files.write(chunk,new byte[kind.equals("short")?1023:1025]);
            assertEquals(List.of(1),Splitter.inspect(base).damaged());
            assertThrows(IOException.class,()->Splitter.recombine(dir.resolve("bad"),base.toString()));
            assertFalse(Files.exists(dir.resolve("bad")));
        }));
    }

    /** @return 恶意或损坏清单拒绝，避免整数溢出和巨量分配。 */
    @TestFactory Stream<DynamicTest> invalidManifests() {
        return Stream.of("", "format=other\n", "format=EGTC-SPLIT-1\ncount=2147483647\nbytes=1\nchunkSize=1\n",
            "format=EGTC-SPLIT-1\ncount=1\nbytes=-1\nchunkSize=1\n",
            "format=EGTC-SPLIT-1\ncount=1\nbytes=1\nchunkSize=0\n", "x".repeat(4097))
            .map(text -> DynamicTest.dynamicTest("manifest length="+text.length(),()->{
                Path base=Files.write(dir.resolve("invalid-"+text.hashCode()+".ergou"),data(4)); Splitter.split(base,2);
                Files.writeString(Splitter.manifestPath(base),text);
                assertThrows(IOException.class,()->Splitter.inspect(base));
            }));
    }

    /** 多余卷、别名编号和极大编号不能混入合法分卷。 */
    @Test void unexpectedAndInvalidIndices() throws Exception {
        Path base=Files.write(dir.resolve("extra.ergou"),data(4)); Splitter.split(base,2);
        Files.write(Path.of(base+".2"),data(2)); assertEquals(List.of(2),Splitter.inspect(base).unexpected());
        assertThrows(IOException.class,()->Splitter.recombine(dir.resolve("out"),base.toString()));
        Files.delete(Path.of(base+".2"));
        for(String suffix:List.of("01","2147483647","9999999999999999999999")) {
            Path extra=Files.write(Path.of(base+"."+suffix),data(2));
            assertThrows(IOException.class,()->Splitter.inspect(base)); Files.delete(extra);
        }
    }

    /** 无清单的旧分卷保持兼容，明确提示无法确定总卷数。 */
    @Test void legacyAndActualChunkList() throws Exception {
        Path base=Files.write(dir.resolve("legacy.pcv"),data(2050)); Splitter.split(base,1024);
        Files.delete(Splitter.manifestPath(base)); assertFalse(Splitter.inspect(base).totalKnown());
        Path out=dir.resolve("out"); Splitter.recombine(out,base.toString()); assertArrayEquals(data(2050),Files.readAllBytes(out));
        Files.delete(Path.of(base+".1")); assertEquals(2,Splitter.listChunks(base).size());
        assertEquals(List.of(1),Splitter.inspect(base).missing());
    }

    /** 重新分卷不会残留旧的末卷，也不删除同名前缀的其他文件。 */
    @Test void resplitAndInvalidSizesPreserveArtifacts() throws Exception {
        Path base=Files.write(dir.resolve("repeat.ergou"),data(2050)); Splitter.split(base,1024);
        Path note=Files.writeString(Path.of(base+".notes"),"keep");
        assertThrows(IllegalArgumentException.class,()->Splitter.split(base,0));
        assertThrows(IllegalArgumentException.class,()->Splitter.split(base,-1));
        assertEquals(3,Splitter.inspect(base).expectedCount());
        Files.write(base,data(10)); Splitter.split(base,1024);
        assertEquals(1,Splitter.inspect(base).expectedCount()); assertFalse(Files.exists(Path.of(base+".2")));
        assertEquals("keep",Files.readString(note));
    }

    /** 相对路径、中文目录、整体移动与重命名都保持清单有效。 */
    @Test void moveRenameAndRelativePath() throws Exception {
        Path original=Files.createDirectories(dir.resolve("中文 空格/emoji-🔑")).resolve("same.bin.ergou");
        Files.write(original,data(2001)); Splitter.split(original,500);
        Path relocated=Files.createDirectories(dir.resolve("moved")).resolve("renamed.pcv");
        for(Path p:Splitter.artifacts(original)) {
            String suffix=p.getFileName().toString().substring(original.getFileName().toString().length());
            Files.move(p,Path.of(relocated+suffix));
        }
        Path out=dir.resolve("out"); Splitter.recombine(out,relocated.toString()); assertArrayEquals(data(2001),Files.readAllBytes(out));
        Path relativeDir=Files.createTempDirectory(Path.of("."),"split-relative-");
        try {
            Path relative=Files.write(relativeDir.resolve("x.pcv"),data(2001));
            assertFalse(relative.isAbsolute());Splitter.split(relative,500);
            assertEquals(5,Splitter.inspect(relative).expectedCount());
        } finally {
            try(var walk=Files.walk(relativeDir)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}
        }
    }

    /** 合并不得覆盖任何分卷或清单，取消时保留原输出并清理暂存。 */
    @Test void overwriteProtectionAndCancellation() throws Exception {
        Path base=Files.write(dir.resolve("cancel.ergou"),data(2050)); Splitter.split(base,1024);
        for(Path artifact:Splitter.artifacts(base)) assertThrows(IOException.class,()->Splitter.recombine(artifact,base.toString()));
        Path out=Files.writeString(dir.resolve("out"),"keep");
        final CancelReporter reporter=new CancelReporter();
        assertThrows(CancellationException.class,()->Splitter.recombine(out,base.toString(),reporter));
        assertEquals("keep",Files.readString(out));
        try(var files=Files.list(dir)){assertFalse(files.anyMatch(p->p.toString().endsWith(".incomplete")));}
        final CancelReporter splitReporter=new CancelReporter();
        assertThrows(CancellationException.class,()->Splitter.split(base,1024,splitReporter));
        assertFalse(Files.exists(Splitter.manifestPath(base)));
        try(var files=Files.list(dir)){assertFalse(files.anyMatch(p->p.toString().endsWith(".incomplete")));}
    }

    /** 解密和校验不得修改输入路径或覆盖同名完整文件，可复用请求。 */
    @Test void decryptAndVerifyKeepSourceAndReusableRequests() throws Exception {
        Path source=Files.write(dir.resolve("source"),data(2000));
        Path base=dir.resolve("input.ergou"); EncryptRequest e=request(source,base); Encryptor.encrypt(e); Splitter.split(base,700);
        byte[] cipher=Files.readAllBytes(base); Path chunk=Path.of(base+".2");
        DecryptRequest d=new DecryptRequest();d.setInputFile(chunk.toString());d.setOutputFile(dir.resolve("out").toString());d.setPassword("pw");d.setRsCodecs(new RsCodecs());d.setRecombine(true);
        Decryptor.decrypt(d); Decryptor.decrypt(d); assertEquals(chunk.toString(),d.getInputFile());
        assertArrayEquals(data(2000),Files.readAllBytes(dir.resolve("out"))); assertArrayEquals(cipher,Files.readAllBytes(base));
        VerifyRequest v=new VerifyRequest();v.setInputFile(Splitter.manifestPath(base).toString());v.setPassword("pw");v.setRsCodecs(new RsCodecs());v.setRecombine(false);
        assertTrue(Verifier.verify(v)); assertArrayEquals(cipher,Files.readAllBytes(base));
        Files.delete(Path.of(base+".0")); assertThrows(IOException.class,()->Verifier.verify(v));
    }

    /** 独立输入有缺卷时继续解密其他组，并在批报告中保留缺卷详情。 */
    @Test void mixedBatchContinuesAfterMissingVolumes() throws Exception {
        Path source=Files.write(dir.resolve("source"),data(2000));
        for(String name:List.of("bad","good")) {Path base=dir.resolve(name+".ergou");Encryptor.encrypt(request(source,base));Splitter.split(base,700);Files.delete(base);}
        Files.delete(dir.resolve("bad.ergou.0"));
        FolderCrypt.DecryptOptions opts=new FolderCrypt.DecryptOptions();opts.password="pw";opts.rsCodecs=new RsCodecs();
        FolderCrypt.decryptFiles(List.of(dir.resolve("bad.ergou.1"),dir.resolve("good.ergou.1"),dir.resolve("good.ergou.volumes")),dir.resolve("out"),opts);
        assertArrayEquals(data(2000),Files.readAllBytes(dir.resolve("out/good")));assertEquals(1,opts.batchResult.succeededCount());assertEquals(1,opts.batchResult.failedCount());
    }

    /** 任意命名的分卷子文件夹保持路径；多选同名分卷分别恢复。 */
    @Test void renamedFoldersAndSameNamedBatchDoNotOverwrite() throws Exception {
        Path root=Files.createDirectories(dir.resolve("mixed"));
        for(int i=0;i<2;i++) {
            Path folder=Files.createDirectories(root.resolve("group-"+i));Path source=Files.write(dir.resolve("source-"+i),data(2000+i));
            Path base=folder.resolve("same.bin.ergou");Encryptor.encrypt(request(source,base));Splitter.split(base,700);Files.delete(base);
        }
        FolderCrypt.DecryptOptions opts=new FolderCrypt.DecryptOptions();opts.password="pw";opts.rsCodecs=new RsCodecs();opts.threadCount=2;
        FolderCrypt.decryptAuto(root,dir.resolve("directory-out"),opts);
        for(int i=0;i<2;i++)assertArrayEquals(data(2000+i),Files.readAllBytes(dir.resolve("directory-out/mixed/group-"+i+"/same.bin")));
        FolderCrypt.decryptFiles(List.of(root.resolve("group-0/same.bin.ergou.0"),root.resolve("group-1/same.bin.ergou.1")),dir.resolve("batch-out"),opts);
        assertArrayEquals(data(2000),Files.readAllBytes(dir.resolve("batch-out/same.bin")));
        assertArrayEquals(data(2001),Files.readAllBytes(dir.resolve("batch-out/same (2).bin")));
    }

    /** 同大小损坏通过密文认证拒绝；RS 模式可以修复少量错误。 */
    @Test void ciphertextCorruptionAndRsRecovery() throws Exception {
        Path source=Files.write(dir.resolve("source"),data(4096));
        for(boolean rs:List.of(false,true)) {
            Path base=dir.resolve("damage-"+rs+".ergou");EncryptRequest e=request(source,base);e.setReedSolomon(rs);
            Encryptor.encrypt(e);Splitter.split(base,700);Files.delete(base);
            Path changed=Path.of(base+".4");byte[] bytes=Files.readAllBytes(changed);bytes[50]^=1;Files.write(changed,bytes);
            Splitter.inspect(base).requireComplete();
            VerifyRequest v=new VerifyRequest();v.setInputFile(Path.of(base+".0").toString());v.setPassword("pw");v.setRsCodecs(new RsCodecs());
            DecryptRequest d=new DecryptRequest();d.setInputFile(Path.of(base+".0").toString());d.setOutputFile(dir.resolve("out-"+rs).toString());d.setPassword("pw");d.setRsCodecs(new RsCodecs());
            if(rs){assertTrue(Verifier.verify(v));Decryptor.decrypt(d);assertEquals(-1,Files.mismatch(source,Path.of(d.getOutputFile())));}
            else {assertThrows(Exception.class,()->Verifier.verify(v));assertThrows(Exception.class,()->Decryptor.decrypt(d));assertFalse(Files.exists(Path.of(d.getOutputFile())));}
            assertFalse(Files.exists(Path.of(d.getOutputFile()+".incomplete")));
        }
    }

    /** 错误密码、丢失密钥文件和顺序颠倒不能生成明文。 */
    @Test void passwordAndKeyfileFailures() throws Exception {
        Path source=Files.write(dir.resolve("source"),data(2000)),a=Files.writeString(dir.resolve("key-a"),"one"),b=Files.writeString(dir.resolve("key-b"),"two");
        Path base=dir.resolve("protected.ergou");EncryptRequest e=request(source,base);e.setKeyfiles(List.of(a.toString(),b.toString()));e.setKeyfileOrdered(true);
        Encryptor.encrypt(e);Splitter.split(base,700);Files.delete(base);
        for(int variant=0;variant<3;variant++) {
            DecryptRequest d=new DecryptRequest();d.setInputFile(Path.of(base+".1").toString());d.setOutputFile(dir.resolve("out"+variant).toString());d.setPassword(variant==0?"wrong":"pw");d.setRsCodecs(new RsCodecs());
            d.setKeyfiles(variant==1?List.of():variant==2?List.of(b.toString(),a.toString()):List.of(a.toString(),b.toString()));
            assertThrows(Exception.class,()->Decryptor.decrypt(d));assertFalse(Files.exists(Path.of(d.getOutputFile())));
        }
    }

    /** 选择包含多层分卷目录的根目录时，预览也显示深处的缺卷。 */
    @Test void nestedFolderPreviewReportsMissingVolumes() throws Exception {
        Path root=Files.createDirectories(dir.resolve("nested"));
        Path base=Files.createDirectories(root.resolve("A/中文/B")).resolve("data.ergou");
        Files.write(base,data(2050));Splitter.split(base,1024);Files.delete(base);Files.delete(Path.of(base+".2"));
        String summary=Splitter.describeInput(root);
        assertTrue(summary.contains("data.ergou"));assertTrue(summary.contains(".2"));assertTrue(summary.contains("3"));
        assertEquals(summary,Splitter.describeInputs(List.of(root,Path.of(base+".0"))));
    }

    /** 解密明文也不能覆盖所选分卷组内的其他碎片或清单。 */
    @Test void plaintextOutputCannotOverwriteSplitArtifacts() throws Exception {
        Path source=Files.write(dir.resolve("source"),data(2000)),base=dir.resolve("protected.ergou");
        Encryptor.encrypt(request(source,base));Splitter.split(base,700);Files.delete(base);
        for(Path artifact:Splitter.artifacts(base)) {
            byte[] before=Files.readAllBytes(artifact);
            DecryptRequest d=new DecryptRequest();d.setInputFile(Path.of(base+".0").toString());d.setOutputFile(artifact.toString());d.setPassword("pw");d.setRsCodecs(new RsCodecs());
            assertThrows(IOException.class,()->Decryptor.decrypt(d));assertArrayEquals(before,Files.readAllBytes(artifact));
        }
        Splitter.inspect(base).requireComplete();
    }

    /** @param source 明文 @param out 密文 @return 小内存测试请求。 */
    private static EncryptRequest request(Path source,Path out) {
        EncryptRequest e=new EncryptRequest();e.setInputFile(source.toString());e.setOutputFile(out.toString());e.setPassword("pw");e.setRsCodecs(new RsCodecs());e.setArgon2MemoryKib(32);e.setArgon2Passes(1);e.setArgon2Threads(1);return e;
    }
    /** @param size 长度 @return 可复现随机字节。 */
    private static byte[] data(int size){byte[] b=new byte[size];new Random(size).nextBytes(b);return b;}
    /** 在第一卷完成后取消，覆盖中途清理。 */
    private static class CancelReporter implements ProgressReporter {
        boolean cancel;
        /** @param text 状态。 */ public void setStatus(String text) { }
        /** @param fraction 进度 @param info 信息。 */ public void setProgress(float fraction,String info){cancel=true;}
        /** @param can 可否取消。 */ public void setCanCancel(boolean can) { }
        /** @return 是否取消。 */ public boolean isCancelled(){return cancel;}
    }
}