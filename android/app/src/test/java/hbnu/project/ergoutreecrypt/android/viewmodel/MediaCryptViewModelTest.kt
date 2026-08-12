package hbnu.project.ergoutreecrypt.android.viewmodel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * MediaCryptViewModel 单元测试。
 *
 * <p>验证进度状态流的初始状态和状态转换。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class MediaCryptViewModelTest {

    /**
     * ViewModel 创建后进度状态应为 IDLE。
     */
    @Test
    fun initialState_isIdle() {
        val viewModel = MediaCryptViewModel()
        val state = viewModel.progress.value
        assertEquals(ProgressState.State.IDLE, state.state)
        assertEquals(0f, state.progress)
    }

    /**
     * 取消操作应正确设置状态为 CANCELLED。
     */
    @Test
    fun cancel_setsCancelledState() {
        val viewModel = MediaCryptViewModel()
        viewModel.cancel()
        val state = viewModel.progress.value
        assertEquals(ProgressState.State.CANCELLED, state.state)
    }

    /**
     * 进度状态流默认应可被收集。
     */
    @Test
    fun progressStateFlow_isNotNull() {
        val viewModel = MediaCryptViewModel()
        assertNotNull(viewModel.progress)
    }

    /**
     * 重置后状态恢复为 IDLE。
     */
    @Test
    fun reset_returnsToIdle() {
        val viewModel = MediaCryptViewModel()
        viewModel.cancel()
        viewModel.reset()
        val state = viewModel.progress.value
        assertEquals(ProgressState.State.IDLE, state.state)
        assertEquals(0f, state.progress)
    }

    /**
     * 初始错误信息为 null。
     */
    @Test
    fun initialState_errorIsNull() {
        val viewModel = MediaCryptViewModel()
        assertEquals(null, viewModel.progress.value.error)
    }
}
