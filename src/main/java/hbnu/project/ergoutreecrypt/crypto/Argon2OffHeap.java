package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.util.Pack;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.LongBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * 离堆（native 内存）Argon2id v1.3 实现。
 *
 * <p>BouncyCastle 的 {@code Argon2BytesGenerator} 将整块 Argon2 内存分配在
 * Java 堆内；Android 应用堆上限（largeHeap 下通常约 512 MiB）因此无法派生
 * 1 GiB 参数的密钥——即使设备物理内存有 16 GB。本实现把 Argon2 内存块放在
 * native 内存中，绕开 Java 堆上限，使桌面端/高内存档位创建的文件也能在移动
 * 端完成密钥派生。
 *
 * <p>内存分配优先使用 {@code sun.misc.Unsafe.allocateMemory}（纯 native
 * malloc，不受堆上限与 direct-buffer 预算约束；Android ART 与桌面 JVM 均
 * 可用）；Unsafe 不可用时回退 {@link ByteBuffer#allocateDirect}（受堆预算
 * 约束，可能提前 OOM）。
 *
 * <p>输出与 BouncyCastle 实现逐字节一致（由 {@code Argon2OffHeapTest} 交叉
 * 验证）。填充按 lane 并行（切片间加屏障），与参考实现的执行顺序一致。
 *
 * <p>注意：离堆路径速度慢于 BC 堆内实现（1 GiB/4 passes 在移动端可能需要
 * 数分钟），仅作为堆内存不足时的回退路径，由 {@link Argon2Kdf} 自动选择。
 *
 * @author ErgouTree
 * @since 2026/8/15
 */
public final class Argon2OffHeap {

    /** Argon2id 类型常量 */
    public static final int TYPE_ARGON2_ID = 2;

    /** Argon2 版本号（1.3） */
    private static final int ARGON2_VERSION = 0x13;

    /** 同步点数（切片数） */
    private static final int SYNC_POINTS = 4;

    /** 每块 64 位字数（1024 字节） */
    private static final int BLOCK_LONGS = 128;

    /** 块字节数 */
    private static final int BLOCK_BYTES = 1024;

    /** 初始哈希 H0 的字节数 */
    private static final int H0_BYTES = 64;

    /** 首块种子字节数（H0 + 块索引 + lane 索引） */
    private static final int SEED_BYTES = 72;

    /** Unsafe 桥接（反射 + MethodHandle 获取，不可用时为 null） */
    private static final UnsafeBridge UNSAFE_BRIDGE = UnsafeBridge.tryCreate();

    private Argon2OffHeap() {
    }

    /**
     * 离堆派生 Argon2id 密钥。
     *
     * @param password    密码字节
     * @param salt        Argon2 盐（至少 8 字节）
     * @param memoryKiB   内存参数（KiB），须 ≥ 2×parallelism
     * @param passes      迭代次数，须 ≥ 1
     * @param parallelism 并行 lane 数，须 ≥ 1
     * @param outputLen   输出字节数（≥ 4）
     * @return 派生密钥
     * @throws IllegalArgumentException 参数非法
     * @throws OutOfMemoryError         native 内存分配失败
     */
    public static byte[] deriveKey(final byte[] password, final byte[] salt,
                                   final int memoryKiB, final int passes,
                                   final int parallelism, final int outputLen) {
        return deriveKey(password, salt, memoryKiB, passes, parallelism, outputLen, null);
    }

    /**
     * 离堆派生 Argon2id 密钥（支持进度/取消回调）。
     *
     * <p>{@code progress} 为 null 时行为与 6 参重载一致（桌面端）。移动端传回调
     * 以在长派生期间回传 pass 粒度进度并响应取消。
     *
     * @param password    密码字节
     * @param salt        Argon2 盐（至少 8 字节）
     * @param memoryKiB   内存参数（KiB），须 ≥ 2×parallelism
     * @param passes      迭代次数，须 ≥ 1
     * @param parallelism 并行 lane 数，须 ≥ 1
     * @param outputLen   输出字节数（≥ 4）
     * @param progress    进度/取消回调，可为 null
     * @return 派生密钥
     * @throws IllegalArgumentException 参数非法
     * @throws OutOfMemoryError         native 内存分配失败
     */
    public static byte[] deriveKey(final byte[] password, final byte[] salt,
                                   final int memoryKiB, final int passes,
                                   final int parallelism, final int outputLen,
                                   final KdfProgress progress) {
        if (parallelism < 1) {
            throw new IllegalArgumentException("lanes must be greater than 1");
        }
        if (memoryKiB < 2 * parallelism) {
            throw new IllegalArgumentException("memory is less than: " + (2 * parallelism) + " KiB");
        }
        if (passes < 1) {
            throw new IllegalArgumentException("iterations is less than: 1");
        }
        if (outputLen < 4) {
            throw new IllegalArgumentException("output length less than 4");
        }

        int segmentLength = memoryKiB / (parallelism * SYNC_POINTS);
        int laneLength = segmentLength * SYNC_POINTS;
        int memoryBlocks = laneLength * parallelism;
        if (memoryBlocks <= 0) {
            throw new IllegalArgumentException("memory is too small for " + parallelism + " lanes");
        }
        long memoryBytes = (long) memoryBlocks * BLOCK_BYTES;
        if (memoryBytes > Integer.MAX_VALUE - 8) {
            throw new IllegalArgumentException("memory is too large: " + memoryBytes + " bytes");
        }

        byte[] h0 = initialHash(password, salt, parallelism, outputLen, memoryKiB, passes);

        // 离堆内存：优先 Unsafe 纯 native 分配（不受 direct-buffer 预算约束）
        OffHeapMemory memory = allocate(memoryBytes);
        byte[] seed = new byte[SEED_BYTES];
        byte[] hashBytes = new byte[BLOCK_BYTES];
        try {
            System.arraycopy(h0, 0, seed, 0, H0_BYTES);
            fillFirstBlocks(memory, seed, hashBytes, parallelism, laneLength);
            SecureZero.zero(h0);

            fillMemory(memory, parallelism, passes, segmentLength, laneLength, memoryBlocks, progress);

            long[] finalBlock = new long[BLOCK_LONGS];
            for (int lane = 0; lane < parallelism; lane++) {
                int lastBlockLong = (lane * laneLength + laneLength - 1) * BLOCK_LONGS;
                for (int k = 0; k < BLOCK_LONGS; k++) {
                    finalBlock[k] ^= memory.get(lastBlockLong + k);
                }
            }
            byte[] finalBytes = new byte[BLOCK_BYTES];
            Pack.longToLittleEndian(finalBlock, finalBytes, 0);
            byte[] out = new byte[outputLen];
            variableLengthHash(finalBytes, out);
            return out;
        } finally {
            // 清空离堆缓冲与临时数组，避免密钥材料残留
            memory.zero();
            memory.release();
            java.util.Arrays.fill(seed, (byte) 0);
            java.util.Arrays.fill(hashBytes, (byte) 0);
            SecureZero.zero(h0);
        }
    }

    /**
     * 分配离堆内存：优先 Unsafe（绕过 direct-buffer 预算），回退直接缓冲区。
     *
     * @param memoryBytes 所需字节数
     * @return 离堆内存访问器
     */
    private static OffHeapMemory allocate(final long memoryBytes) {
        if (UNSAFE_BRIDGE != null) {
            long address = UNSAFE_BRIDGE.allocateMemory(memoryBytes);
            return new UnsafeMemory(address, memoryBytes);
        }
        ByteBuffer raw = ByteBuffer.allocateDirect((int) memoryBytes);
        return new DirectBufferMemory(raw.order(ByteOrder.LITTLE_ENDIAN).asLongBuffer());
    }

    /**
     * 计算初始哈希 H0 = Blake2b-64(LE32 参数序列)。
     */
    static byte[] initialHash(final byte[] password, final byte[] salt,
                              final int lanes, final int outputLen,
                              final int memoryKiB, final int passes) {
        Blake2bDigest digest = new Blake2bDigest(512);
        byte[] le = new byte[4];
        updateLe32(digest, le, lanes);
        updateLe32(digest, le, outputLen);
        updateLe32(digest, le, memoryKiB);
        updateLe32(digest, le, passes);
        updateLe32(digest, le, ARGON2_VERSION);
        updateLe32(digest, le, TYPE_ARGON2_ID);
        addByteString(digest, le, password);
        addByteString(digest, le, salt);
        addByteString(digest, le, null);
        addByteString(digest, le, null);
        byte[] h0 = new byte[H0_BYTES];
        digest.doFinal(h0, 0);
        return h0;
    }

    /**
     * 追加"长度 + 数据"字段；数据为 null 时仅追加 LE32(0)。
     */
    private static void addByteString(final Blake2bDigest digest, final byte[] leBuf,
                                      final byte[] data) {
        if (data == null) {
            updateLe32(digest, leBuf, 0);
            return;
        }
        updateLe32(digest, leBuf, data.length);
        digest.update(data, 0, data.length);
    }

    /**
     * 追加一个 LE32 值。
     */
    private static void updateLe32(final Blake2bDigest digest, final byte[] buf, final int value) {
        Pack.intToLittleEndian(value, buf, 0);
        digest.update(buf, 0, 4);
    }

    /**
     * 填充各 lane 的前两个块：B[i][0] = H'(1024, H0||LE32(0)||i)，
     * B[i][1] = H'(1024, H0||LE32(1)||i)。
     */
    static void fillFirstBlocks(final OffHeapMemory mem, final byte[] seed,
                                final byte[] hashBytes, final int lanes,
                                final int laneLength) {
        for (int lane = 0; lane < lanes; lane++) {
            Pack.intToLittleEndian(lane, seed, 68);
            for (int blockIndex = 0; blockIndex < 2; blockIndex++) {
                seed[64] = (byte) blockIndex;
                variableLengthHash(seed, hashBytes);
                int longOffset = (lane * laneLength + blockIndex) * BLOCK_LONGS;
                for (int k = 0; k < BLOCK_LONGS; k++) {
                    mem.put(longOffset + k, Pack.littleEndianToLong(hashBytes, k * 8));
                }
            }
        }
    }

    /**
     * 变长哈希 H'：T ≤ 64 时为 Blake2b-T(LE32(T) || in)；
     * T &gt; 64 时迭代 Blake2b-64 逐块产出（每块取前 32 字节，末块截断）。
     */
    static void variableLengthHash(final byte[] input, final byte[] out) {
        int outLen = out.length;
        byte[] le = new byte[4];
        Pack.intToLittleEndian(outLen, le, 0);
        if (outLen <= 64) {
            Blake2bDigest digest = new Blake2bDigest(outLen * 8);
            digest.update(le, 0, 4);
            digest.update(input, 0, input.length);
            digest.doFinal(out, 0);
            return;
        }
        Blake2bDigest digest = new Blake2bDigest(512);
        digest.update(le, 0, 4);
        digest.update(input, 0, input.length);
        byte[] v = new byte[64];
        digest.doFinal(v, 0);
        int offset = 0;
        System.arraycopy(v, 0, out, offset, 32);
        offset += 32;
        int count = (outLen + 31) / 32 - 2;
        for (int i = 2; i <= count; i++) {
            digest.reset();
            digest.update(v, 0, 64);
            digest.doFinal(v, 0);
            System.arraycopy(v, 0, out, offset, 32);
            offset += 32;
        }
        int remaining = outLen - 32 * count;
        if (remaining > 0) {
            Blake2bDigest finalDigest = new Blake2bDigest(remaining * 8);
            finalDigest.update(v, 0, 64);
            finalDigest.doFinal(out, offset);
        }
    }

    /**
     * 按 pass → slice → lane（lane 并行、切片间屏障）填充内存。
     *
     * <p>与参考实现一致的执行顺序保证：同一切片内各 lane 的引用块要么来自
     * 上一 pass，要么来自本 pass 的早期切片，互不依赖，可安全并行。
     */
    static void fillMemory(final OffHeapMemory mem, final int lanes, final int passes,
                           final int segmentLength, final int laneLength,
                           final int memoryBlocks, final KdfProgress progress) {
        ExecutorService pool = Executors.newFixedThreadPool(lanes);
        try {
            for (int pass = 0; pass < passes; pass++) {
                if (Thread.currentThread().isInterrupted()
                        || (progress != null && progress.isCancelled())) {
                    throw new IllegalStateException("Argon2 密钥派生已被取消");
                }
                if (progress != null) {
                    progress.onProgress(pass + 1, passes);
                }
                for (int slice = 0; slice < SYNC_POINTS; slice++) {
                    final int p = pass;
                    final int s = slice;
                    List<Future<?>> futures = new ArrayList<>(lanes);
                    for (int lane = 0; lane < lanes; lane++) {
                        final int l = lane;
                        futures.add(pool.submit(() -> fillSegment(mem, l, p, s,
                                segmentLength, laneLength, lanes, memoryBlocks, passes)));
                    }
                    for (Future<?> future : futures) {
                        future.get();
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Argon2 密钥派生已被取消", e);
        } catch (ExecutionException e) {
            throw new IllegalStateException("Argon2 离堆填充失败", e.getCause());
        } finally {
            pool.shutdownNow();
        }
    }

    /**
     * 填充单个 lane 的单个切片。
     */
    private static void fillSegment(final OffHeapMemory mem, final int lane, final int pass,
                                    final int slice, final int segmentLength,
                                    final int laneLength, final int lanes,
                                    final int memoryBlocks, final int passes) {
        // Argon2id：仅 pass 0 的前两个切片使用数据独立寻址
        boolean dataIndependent = pass == 0 && slice < SYNC_POINTS / 2;
        int startingIndex = (pass == 0 && slice == 0) ? 2 : 0;

        long[] inputBlock = null;
        long[] addressBlock = null;
        if (dataIndependent) {
            inputBlock = new long[BLOCK_LONGS];
            inputBlock[0] = pass;
            inputBlock[1] = lane;
            inputBlock[2] = slice;
            inputBlock[3] = memoryBlocks;
            inputBlock[4] = passes;
            inputBlock[5] = TYPE_ARGON2_ID;
            addressBlock = new long[BLOCK_LONGS];
            if (startingIndex == 2) {
                nextAddresses(addressBlock, inputBlock);
            }
        }

        int currOffset = lane * laneLength + slice * segmentLength + startingIndex;
        int prevOffset = (currOffset % laneLength == 0)
                ? currOffset + laneLength - 1
                : currOffset - 1;
        boolean withXor = pass != 0;

        long[] r = new long[BLOCK_LONGS];
        long[] z = new long[BLOCK_LONGS];

        for (int i = startingIndex; i < segmentLength; i++, currOffset++, prevOffset++) {
            if (currOffset % laneLength == 1) {
                prevOffset = currOffset - 1;
            }

            long pseudoRand;
            if (dataIndependent) {
                if (i % BLOCK_LONGS == 0) {
                    nextAddresses(addressBlock, inputBlock);
                }
                pseudoRand = addressBlock[i % BLOCK_LONGS];
            } else {
                pseudoRand = mem.get(prevOffset * BLOCK_LONGS);
            }

            int refLane = (int) ((pseudoRand >>> 32) % lanes);
            if (pass == 0 && slice == 0) {
                refLane = lane;
            }
            int refIndex = refColumn(pass, slice, i, pseudoRand,
                    segmentLength, laneLength, refLane == lane);
            int prevLong = prevOffset * BLOCK_LONGS;
            int refLong = (refLane * laneLength + refIndex) * BLOCK_LONGS;
            int currLong = currOffset * BLOCK_LONGS;

            // R = prev XOR ref；Z = compress(R)
            for (int k = 0; k < BLOCK_LONGS; k++) {
                r[k] = mem.get(prevLong + k) ^ mem.get(refLong + k);
            }
            System.arraycopy(r, 0, z, 0, BLOCK_LONGS);
            compressBlock(z);
            // next = (pass ≥ 1 ? 旧值 : 0) XOR R XOR Z
            for (int k = 0; k < BLOCK_LONGS; k++) {
                long old = withXor ? mem.get(currLong + k) : 0L;
                mem.put(currLong + k, old ^ r[k] ^ z[k]);
            }
        }
    }

    /**
     * 生成下一个地址块：inputBlock.v[6] 自增后，
     * address = input XOR compress(input)，再 address = address XOR compress(address)。
     */
    private static void nextAddresses(final long[] addressBlock, final long[] inputBlock) {
        inputBlock[6]++;
        long[] temp = new long[BLOCK_LONGS];
        System.arraycopy(inputBlock, 0, addressBlock, 0, BLOCK_LONGS);
        System.arraycopy(addressBlock, 0, temp, 0, BLOCK_LONGS);
        compressBlock(temp);
        for (int k = 0; k < BLOCK_LONGS; k++) {
            addressBlock[k] ^= temp[k];
        }
        System.arraycopy(addressBlock, 0, temp, 0, BLOCK_LONGS);
        compressBlock(temp);
        for (int k = 0; k < BLOCK_LONGS; k++) {
            addressBlock[k] ^= temp[k];
        }
    }

    /**
     * 计算引用块在 lane 内的列索引（index_alpha 映射）。
     */
    private static int refColumn(final int pass, final int slice, final int index,
                                 final long pseudoRand, final int segmentLength,
                                 final int laneLength, final boolean sameLane) {
        int referenceArea;
        int startPosition;
        if (pass == 0) {
            startPosition = 0;
            if (sameLane) {
                referenceArea = slice * segmentLength + index - 1;
            } else {
                referenceArea = slice * segmentLength + (index == 0 ? -1 : 0);
            }
        } else {
            startPosition = ((slice + 1) * segmentLength) % laneLength;
            if (sameLane) {
                referenceArea = laneLength - segmentLength + index - 1;
            } else {
                referenceArea = laneLength - segmentLength + (index == 0 ? -1 : 0);
            }
        }
        long x = pseudoRand & 0xFFFFFFFFL;
        x = (x * x) >>> 32;
        x = referenceArea - 1 - ((referenceArea * x) >>> 32);
        return (startPosition + (int) x) % laneLength;
    }

    /**
     * 块压缩：先按列（16i..16i+15）再按行（2i 模式）应用 BLAKE2 轮函数。
     */
    private static void compressBlock(final long[] v) {
        for (int i = 0; i < 8; i++) {
            int b = 16 * i;
            roundFunction(v, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                    b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
        }
        for (int i = 0; i < 8; i++) {
            int b = 2 * i;
            roundFunction(v, b, b + 1, b + 16, b + 17, b + 32, b + 33,
                    b + 48, b + 49, b + 64, b + 65, b + 80, b + 81,
                    b + 96, b + 97, b + 112, b + 113);
        }
    }

    /**
     * BLAKE2_ROUND_NOMSG：8 次 G（列顺序 + 对角顺序）。
     */
    private static void roundFunction(final long[] v, final int v0, final int v1,
                                      final int v2, final int v3, final int v4,
                                      final int v5, final int v6, final int v7,
                                      final int v8, final int v9, final int v10,
                                      final int v11, final int v12, final int v13,
                                      final int v14, final int v15) {
        g(v, v0, v4, v8, v12);
        g(v, v1, v5, v9, v13);
        g(v, v2, v6, v10, v14);
        g(v, v3, v7, v11, v15);
        g(v, v0, v5, v10, v15);
        g(v, v1, v6, v11, v12);
        g(v, v2, v7, v8, v13);
        g(v, v3, v4, v9, v14);
    }

    /**
     * Argon2 的 G 函数（带 fBlaMka 的 BLAKE2b 四分之一轮）。
     */
    private static void g(final long[] v, final int a, final int b, final int c, final int d) {
        quarterRound(v, a, b, d, 32);
        quarterRound(v, c, d, b, 24);
        quarterRound(v, a, b, d, 16);
        quarterRound(v, c, d, b, 63);
    }

    /**
     * 单次四分之一轮：a = fBlaMka(a, b)，d = rotr(d XOR a, rot)。
     */
    private static void quarterRound(final long[] v, final int a, final int b,
                                     final int d, final int rot) {
        long va = fBlaMka(v[a], v[b]);
        v[a] = va;
        v[d] = (v[d] ^ va) >>> rot | (v[d] ^ va) << (64 - rot);
    }

    /**
     * fBlaMka(x, y) = x + y + 2 × lo32(x) × lo32(y)。
     */
    private static long fBlaMka(final long x, final long y) {
        return x + y + 2 * ((x & 0xFFFFFFFFL) * (y & 0xFFFFFFFFL));
    }

    /**
     * 离堆内存访问抽象——屏蔽 Unsafe 地址与直接缓冲区的差异。
     */
    interface OffHeapMemory {

        /**
         * 读取第 longIndex 个 64 位字（小端）。
         *
         * @param longIndex 64 位字索引（非字节偏移）
         * @return 对应字的值
         */
        long get(int longIndex);

        /**
         * 写入第 longIndex 个 64 位字（小端）。
         *
         * @param longIndex 64 位字索引（非字节偏移）
         * @param value     写入值
         */
        void put(int longIndex, long value);

        /** 将整个内存区域清零。 */
        void zero();

        /** 释放底层内存。 */
        void release();
    }

    /**
     * 基于 Unsafe 地址的离堆内存（纯 native malloc，绕过 direct-buffer 预算）。
     */
    private static final class UnsafeMemory implements OffHeapMemory {

        /** native 内存起始地址 */
        private final long address;

        /** 内存区域字节数 */
        private final long byteSize;

        /**
         * 创建 Unsafe 内存访问器。
         *
         * @param address  native 内存起始地址
         * @param byteSize 内存区域字节数
         */
        UnsafeMemory(final long address, final long byteSize) {
            this.address = address;
            this.byteSize = byteSize;
        }

        @Override
        public long get(final int longIndex) {
            return UNSAFE_BRIDGE.getLong(address + (long) longIndex * 8);
        }

        @Override
        public void put(final int longIndex, final long value) {
            UNSAFE_BRIDGE.putLong(address + (long) longIndex * 8, value);
        }

        @Override
        public void zero() {
            UNSAFE_BRIDGE.setMemory(address, byteSize);
        }

        @Override
        public void release() {
            UNSAFE_BRIDGE.freeMemory(address);
        }
    }

    /**
     * {@code sun.misc.Unsafe} 反射桥接。
     *
     * <p>通过 {@code Class.forName + theUnsafe 字段反射} 获取实例、{@code MethodHandle}
     * 绑定方法，避免编译期依赖 {@code sun.misc} 包（Android SDK 编译类路径不含该包，
     * 但桌面 JVM 与 Android ART 运行时均提供该类）。MethodHandle 的
     * {@code invokeExact} 可被 JIT 内联，性能接近直接调用。
     *
     * <p>桌面 JVM 需模块声明 {@code requires jdk.unsupported}；Android 上
     * 若被隐藏 API 策略拦截则获取失败，调用方回退直接缓冲区。
     */
    private static final class UnsafeBridge {

        /** Unsafe 实例（Object 类型，避免编译期 sun.misc 依赖） */
        private final Object unsafe;

        /** allocateMemory(long)long */
        private final MethodHandle allocateMemory;

        /** freeMemory(long)void */
        private final MethodHandle freeMemory;

        /** setMemory(long,long,byte)void */
        private final MethodHandle setMemory;

        /** getLong(long)long */
        private final MethodHandle getLong;

        /** putLong(long,long)void */
        private final MethodHandle putLong;

        /**
         * 创建桥接实例。
         *
         * @param unsafe Unsafe 实例
         * @param handles 五个方法句柄（按上述顺序）
         */
        private UnsafeBridge(final Object unsafe, final MethodHandle[] handles) {
            this.unsafe = unsafe;
            this.allocateMemory = handles[0];
            this.freeMemory = handles[1];
            this.setMemory = handles[2];
            this.getLong = handles[3];
            this.putLong = handles[4];
        }

        /**
         * 尝试创建桥接；任何一步失败（类不存在、字段被拦截等）返回 null。
         *
         * @return 桥接实例或 null
         */
        static UnsafeBridge tryCreate() {
            try {
                Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
                Field field = unsafeClass.getDeclaredField("theUnsafe");
                field.setAccessible(true);
                Object unsafe = field.get(null);
                if (unsafe == null) {
                    return null;
                }
                MethodHandles.Lookup lookup = MethodHandles.lookup();
                MethodHandle[] handles = {
                        lookup.findVirtual(unsafeClass, "allocateMemory",
                                MethodType.methodType(long.class, long.class)).bindTo(unsafe),
                        lookup.findVirtual(unsafeClass, "freeMemory",
                                MethodType.methodType(void.class, long.class)).bindTo(unsafe),
                        lookup.findVirtual(unsafeClass, "setMemory",
                                MethodType.methodType(void.class, long.class, long.class, byte.class))
                                .bindTo(unsafe),
                        lookup.findVirtual(unsafeClass, "getLong",
                                MethodType.methodType(long.class, long.class)).bindTo(unsafe),
                        lookup.findVirtual(unsafeClass, "putLong",
                                MethodType.methodType(void.class, long.class, long.class)).bindTo(unsafe),
                };
                return new UnsafeBridge(unsafe, handles);
            } catch (Throwable t) {
                return null;
            }
        }

        /**
         * 分配 native 内存。
         *
         * @param bytes 字节数
         * @return 内存起始地址
         */
        long allocateMemory(final long bytes) {
            try {
                return (long) allocateMemory.invokeExact(bytes);
            } catch (Throwable t) {
                throw new OutOfMemoryError("离堆内存分配失败: " + t);
            }
        }

        /**
         * 释放 native 内存。
         *
         * @param address 内存起始地址
         */
        void freeMemory(final long address) {
            try {
                freeMemory.invokeExact(address);
            } catch (Throwable t) {
                // 释放失败不影响密钥派生结果，忽略
            }
        }

        /**
         * 将内存区域清零。
         *
         * @param address 内存起始地址
         * @param bytes   字节数
         */
        void setMemory(final long address, final long bytes) {
            try {
                setMemory.invokeExact(address, bytes, (byte) 0);
            } catch (Throwable t) {
                // 清零失败时按 long 逐个清除，保证密钥材料不残留
                for (long off = 0; off < bytes; off += 8) {
                    putLong(address + off, 0L);
                }
            }
        }

        /**
         * 读取指定地址的 64 位值。
         *
         * @param address 内存地址
         * @return 64 位值
         */
        long getLong(final long address) {
            try {
                return (long) getLong.invokeExact(address);
            } catch (Throwable t) {
                throw new IllegalStateException("读取离堆内存失败", t);
            }
        }

        /**
         * 写入指定地址的 64 位值。
         *
         * @param address 内存地址
         * @param value   写入值
         */
        void putLong(final long address, final long value) {
            try {
                putLong.invokeExact(address, value);
            } catch (Throwable t) {
                throw new IllegalStateException("写入离堆内存失败", t);
            }
        }
    }

    /**
     * 基于直接缓冲区的离堆内存（Unsafe 不可用时的回退，受堆预算约束）。
     */
    private static final class DirectBufferMemory implements OffHeapMemory {

        /** 小端 long 视图 */
        private final LongBuffer buffer;

        /**
         * 创建直接缓冲区访问器。
         *
         * @param buffer 小端 long 视图
         */
        DirectBufferMemory(final LongBuffer buffer) {
            this.buffer = buffer;
        }

        @Override
        public long get(final int longIndex) {
            return buffer.get(longIndex);
        }

        @Override
        public void put(final int longIndex, final long value) {
            buffer.put(longIndex, value);
        }

        @Override
        public void zero() {
            buffer.clear();
            while (buffer.hasRemaining()) {
                buffer.put(0L);
            }
        }

        @Override
        public void release() {
            // 直接缓冲区由 GC 回收，无需显式释放
        }
    }
}
