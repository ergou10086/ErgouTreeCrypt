package hbnu.project.ergoutreecrypt.volume;

import org.junit.jupiter.api.Test;

/** P0 官方依赖与完整流行为的桌面验证。 */
final class FastPrototypeTest {
    /** @throws Exception 依赖或协议行为不符合预期 */
    @Test
    void officialStreamingPrimitiveWorks() throws Exception { FastPrototypeSupport.smoke(); }
}
