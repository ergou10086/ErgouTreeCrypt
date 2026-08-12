package hbnu.project.ergoutreecrypt.android.viewmodel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * EncryptViewModel 单元测试。
 *
 * <p>验证进度状态流的初始状态和状态转换逻辑。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class EncryptViewModelTest {

    /**
     * ViewModel 创建后进度状态应为 IDLE。
     */
    @Test
    fun initialState_isIdle() {
        val viewModel = EncryptViewModel()
        val state = viewModel.progress.value
        assertEquals(ProgressState.State.IDLE, state.state)
        assertEquals(0f, state.progress)
    }

    /**
     * 取消操作应正确设置状态为 CANCELLED。
     */
    @Test
    fun cancel_setsCancelledState() {
        val viewModel = EncryptViewModel()
        viewModel.cancel()
        val state = viewModel.progress.value
        assertEquals(ProgressState.State.CANCELLED, state.state)
    }

    /**
     * 进度状态流默认应可被收集。
     */
    @Test
    fun progressStateFlow_isNotNull() {
        val viewModel = EncryptViewModel()
        assertNotNull(viewModel.progress)
    }

    /**
     * 初始状态下 canCancel 应为 false。
     */
    @Test
    fun initialState_canCancelIsFalse() {
        val viewModel = EncryptViewModel()
        assertFalse(viewModel.progress.value.canCancel)
    }

    /**
     * ProgressState 默认构造。
     */
    @Test
    fun progressState_defaults() {
        val state = ProgressState()
        assertEquals("", state.statusText)
        assertEquals(0f, state.progress)
        assertEquals("", state.info)
        assertEquals(false, state.canCancel)
        assertEquals(ProgressState.State.IDLE, state.state)
    }
}
