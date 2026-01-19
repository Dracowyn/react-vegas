package cc.coopersoft.keycloak.phone.providers.rest.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 重发时间查询响应模型
 * 用于返回验证码重发限制时间
 *
 * @author Dracowyn
 * @since 2026-01-15
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResendExpiresResponse {
    /**
     * 允许重新发送的时间（毫秒时间戳）
     */
    private Long resendExpire;

    /**
     * 创建响应
     *
     * @param resendExpire 重发时间
     * @return ResendExpiresResponse实例
     */
    public static ResendExpiresResponse of(Long resendExpire) {
        return ResendExpiresResponse.builder()
                .resendExpire(resendExpire)
                .build();
    }
}
