package hbnu.project.ergoutreecrypt.android.viewmodel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * DecryptViewModel 单元测试。
 *
 * <p>验证进度状态流的初始状态和状态转换。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class DecryptViewModelTest {

    /**
     * ViewModel 创建后进度状态应为 IDLE。
     */
    @Test
    fun initialState_isIdle() {
        val viewModel = DecryptViewModel()
        val state = viewModel.progress.value
        assertEquals(ProgressState.State.IDLE, state.state)
        assertEquals(0f, state.progress)
    }

    /**
     * 取消操作应正确设置状态为 CANCELLED。
     */
    @Test
    fun cancel_setsCancelledState() {
        val viewModel = DecryptViewModel()
        viewModel.cancel()
        val state = viewModel.progress.value
        assertEquals(ProgressState.State.CANCELLED, state.state)
    }

    /**
     * 进度状态流默认应可被收集。
     */
    @Test
    fun progressStateFlow_isNotNull() {
        val viewModel = DecryptViewModel()
        assertNotNull(viewModel.progress)
    }

    /**
     * 初始状态下错误信息应为 null。
     */
    @Test
    fun initialState_errorIsNull() {
        val viewModel = DecryptViewModel()
        val error = viewModel.progress.value.error
        assertEquals(null, error)
    }

    /**
     * 初始状态下 statusText 为空。
     */
    @Test
    fun initialState_statusTextEmpty() {
        val viewModel = DecryptViewModel()
        assertEquals("", viewModel.progress.value.statusText)
    }
}
