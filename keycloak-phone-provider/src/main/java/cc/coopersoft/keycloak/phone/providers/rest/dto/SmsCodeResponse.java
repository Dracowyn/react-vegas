package cc.coopersoft.keycloak.phone.providers.rest.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 短信验证码响应模型
 * 用于返回验证码发送结果
 *
 * @author Dracowyn
 * @since 2026-01-15
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SmsCodeResponse {
    /**
     * 验证码过期时间（毫秒时间戳）
     */
    private Long expiresIn;

    /**
     * 允许重新发送的时间（毫秒时间戳）
     */
    private Long resendExpires;

    /**
     * 创建成功响应
     *
     * @param expiresIn     过期时间
     * @param resendExpires 重发时间
     * @return SmsCodeResponse实例
     */
    public static SmsCodeResponse success(Long expiresIn, Long resendExpires) {
        return SmsCodeResponse.builder()
                .expiresIn(expiresIn)
                .resendExpires(resendExpires)
                .build();
    }
}
