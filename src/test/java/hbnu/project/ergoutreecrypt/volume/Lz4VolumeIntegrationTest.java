package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.fileops.*;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class Lz4VolumeIntegrationTest {
    @TempDir Path dir;
    boolean custom, fallback;
    @BeforeEach void setup() { custom=SettingsManager.isArchiveCustomEncryption(); fallback=SettingsManager.isArchivePasswordFallback(); SettingsManager.setArchiveCustomEncryption(true); SettingsManager.setArchivePasswordFallback(false); }
    @AfterEach void restore() { SettingsManager.setArchiveCustomEncryption(custom); SettingsManager.setArchivePasswordFallback(fallback); }
    EncryptRequest request(Path source, Path dest) {
        EncryptRequest req = new EncryptRequest(); req.setInputFile(source.toString()); req.setOutputFile(dest.toString());
        req.setPassword("volume"); req.setArgon2MemoryKib(32); req.setArgon2Passes(1); req.setArgon2Threads(1); req.setRsCodecs(new RsCodecs()); return req;
    }
    void decrypt(Path enc, Path output) throws Exception {
        DecryptRequest req = new DecryptRequest(); req.setInputFile(enc.toString()); req.setOutputFile(output.toString()); req.setPassword("volume"); req.setRsCodecs(new RsCodecs()); Decryptor.decrypt(req);
    }
    @TestFactory Stream<DynamicTest> preArchiveMultipleInputsWithAndWithoutZstdAndEncryption() {
        return Stream.of("ZIP","GZ","LZ4","TAR.LZ4").flatMap(fmt -> Stream.of(false,true).map(zstd -> DynamicTest.dynamicTest(fmt + "/zstd="+zstd, () -> {
            Path root = Files.createDirectories(dir.resolve(fmt+zstd));
            Path a=Files.writeString(root.resolve("a.txt"),"first"), b=Files.writeString(root.resolve("b.txt"),"second");
            EncryptRequest req=request(a,root.resolve("data.ergou")); req.setInputFiles(List.of(a.toString(),b.toString()));
            req.setPreArchiveFormat(fmt); req.setPreArchivePassword("archive"); req.setCompress(zstd); Encryptor.encrypt(req);
            var effective=ArchivePacker.effectiveFormat(ArchivePacker.parseFormat(fmt),2);
            assertTrue(req.getOutputFile().endsWith(ArchivePacker.extOf(effective)+".ergou"));
            Path archive=root.resolve("restored"+ArchivePacker.extOf(effective)); decrypt(Path.of(req.getOutputFile()),archive);
            Path out=root.resolve("files"); assertEquals(2,ArchiveExtractor.extract(archive,out,"archive").size());
            assertEquals("first",Files.readString(out.resolve("a.txt"))); assertEquals("second",Files.readString(out.resolve("b.txt")));
        })));
    }
    @Test void preArchiveHonorsCustomEncryptionOff() throws Exception {
        SettingsManager.setArchiveCustomEncryption(false);
        Path source=Files.writeString(dir.resolve("source.txt"),"plain");
        EncryptRequest req=request(source,dir.resolve("off.ergou")); req.setPreArchiveFormat("LZ4"); req.setPreArchivePassword("ignored"); Encryptor.encrypt(req);
        Path archive=dir.resolve("off.lz4"); decrypt(Path.of(req.getOutputFile()),archive);
        assertFalse(ArchiveExtractor.isEncryptedFile(archive)); assertEquals("plain",Files.readString(ArchiveExtractor.extract(archive,dir.resolve("out"),null).getFirst()));
    }
    @TestFactory Stream<DynamicTest> singleAndMultipleSplitChunksUseTarLz4() {
        return Stream.of(100,1024*1024+4096).map(size -> DynamicTest.dynamicTest("split-size="+size, () -> {
            Path root=Files.createDirectories(dir.resolve("split"+size)); byte[] data=new byte[size]; new Random(size).nextBytes(data);
            Path source=Files.write(root.resolve("source.bin"),data); Path enc=Files.createDirectories(root.resolve("enc"));
            EncryptRequest req=request(source,enc.resolve("source.bin.ergou")); req.setSplit(true); req.setChunkSize(1); req.setArchiveFormat("LZ4"); req.setArchivePassword("archive"); Encryptor.encrypt(req);
            Path archive=enc.resolve("source.bin.tar.lz4"); assertTrue(Files.isRegularFile(archive));
            List<Path> chunks=ArchiveExtractor.extract(archive,root.resolve("chunks"),"archive"); assertEquals(size>1024*1024?2:1,chunks.size());
            assertFalse(chunks.stream().anyMatch(p -> Splitter.isManifestPath(p.toString())));
            assertTrue(Splitter.inspect(Path.of(Splitter.splitChunkBase(chunks.getFirst().toString()))).totalKnown());
            Path restored=root.resolve("out"); Files.createDirectories(restored);
            FolderCrypt.DecryptOptions opts=new FolderCrypt.DecryptOptions(); opts.password="volume";opts.archivePassword="archive";opts.rsCodecs=new RsCodecs();
            FolderCrypt.decryptAuto(archive,restored,opts);
            try(var walk=Files.walk(restored)) { assertTrue(walk.filter(Files::isRegularFile).anyMatch(p -> {try{return Files.mismatch(source,p)==-1;}catch(Exception e){return false;}})); }
        }));
    }
    @TestFactory Stream<DynamicTest> folderPreAndPostArchivePreservesTreeAndSource() {
        return Stream.of(false,true).map(pre -> DynamicTest.dynamicTest(pre?"folder-pre":"folder-post", () -> {
            Path root=Files.createDirectories(dir.resolve("folder"+pre));Path input=Files.createDirectories(root.resolve("input/sub"));
            Path a=Files.writeString(input.resolve("a.txt"),"tree"),b=Files.writeString(input.resolve("b.txt"),"branch");
            FolderCrypt.EncryptOptions opts=new FolderCrypt.EncryptOptions();opts.password="volume";opts.rsCodecs=new RsCodecs();opts.threadCount=1;opts.argon2MemoryKib=32;opts.argon2Passes=1;opts.argon2Threads=1;
            if(pre){opts.preArchiveFormat="LZ4";opts.preArchivePassword="archive";}else{opts.archiveFormat="LZ4";opts.archivePassword="archive";}
            FolderCrypt.encryptFolder(root.resolve("input"),root,opts);
            assertEquals("tree",Files.readString(a));assertEquals("branch",Files.readString(b));
            Path produced=root.resolve("input.tar.lz4"+(pre?".ergou":""));assertTrue(Files.exists(produced));
            Path out=Files.createDirectories(root.resolve("out"));
            FolderCrypt.DecryptOptions dop=new FolderCrypt.DecryptOptions();dop.password="volume";dop.archivePassword="archive";dop.rsCodecs=new RsCodecs();dop.decryptThenExtract=true;
            FolderCrypt.decryptAuto(produced,out,dop);
            try(var walk=Files.walk(out)){List<Path> files=walk.filter(Files::isRegularFile).toList(); assertTrue(files.stream().anyMatch(p->{try{return Files.mismatch(a,p)==-1;}catch(Exception e){return false;}}));assertTrue(files.stream().anyMatch(p->{try{return Files.mismatch(b,p)==-1;}catch(Exception e){return false;}}));}
        }));
    }
}
