package hbnu.project.ergoutreecrypt.android.viewmodel

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.atomic.AtomicReference

/**
 * 全局加解密操作忙标记协调器。
 *
 * <p>ViewModel 提升到 Activity 作用域后，用户可以在不同 Tab 间切换并
 * 各自启动操作。加解密为 CPU/内存密集型任务，且前台 Service 通知同一时刻
 * 只应存在一个，因此通过进程级忙标记阻止并发启动：
 * 各 ViewModel 在 {@code startXxx} 时置忙，操作结束或取消时凭令牌释放；
 * 页面据此禁用启动按钮。
 *
 * <p>释放采用令牌校验：旧任务被取消后延迟退出（共享核心周期性轮询取消标记）
 * 时，其过期的 {@code release(token)} 不会误清新任务的忙标记。
 *
 * @author ErgouTree
 * @since 2026/8/25
 */
object OperationCoordinator {

    /** 当前占用操作权的任务令牌；null 表示空闲。 */
    private val currentToken = AtomicReference<Long?>(null)

    /** 令牌发号器（进程内单调递增即可）。 */
    private val tokenGenerator = AtomicReference(0L)

    /** Compose 可收集的忙标记（与令牌保持同步，供 UI 禁用启动按钮）。 */
    private val _busy = MutableStateFlow(false)

    /** 是否有加解密/隐写操作正在运行。 */
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    /**
     * 尝试占用操作权。
     *
     * @return 成功时返回本次操作的释放令牌；已有操作在运行时返回 null
     */
    fun tryAcquire(): Long? {
        val token = tokenGenerator.updateAndGet { it + 1 }
        val acquired = currentToken.compareAndSet(null, token)
        if (acquired) {
            _busy.value = true
            return token
        }
        return null
    }

    /**
     * 释放操作权（操作结束、失败或取消时调用）。
     *
     * <p>仅当令牌与当前持有者一致时才释放，防止过期任务误清。
     *
     * @param token 由 {@link #tryAcquire()} 返回的令牌
     */
    fun release(token: Long?) {
        if (token != null && currentToken.compareAndSet(token, null)) {
            _busy.value = false
        }
    }
}
