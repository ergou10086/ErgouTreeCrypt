package hbnu.project.ergoutreecrypt.volume;

import org.junit.jupiter.api.Test;

/** 独立黄金向量的桌面入口。 */
final class FastGoldenVectorTest {
    /** @throws Exception 中间值或完整流不一致 */
    @Test
    void independentVectorIsAccepted() throws Exception {
        try (var input = getClass().getResourceAsStream("/fast/v1/golden.properties")) {
            if (input == null) throw new AssertionError("缺少正式黄金向量");
            FastGoldenSupport.verify(input);
        }
    }
}
