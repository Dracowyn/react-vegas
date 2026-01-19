package cc.coopersoft.keycloak.phone.providers.rest.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * 验证码配置响应模型
 * 用于返回人机验证配置信息
 *
 * @author Dracowyn
 * @since 2026-01-15
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CaptchaConfigResponse {
    /**
     * 验证码类型（geetest/tencent/recaptcha）
     */
    private String type;

    /**
     * 验证码应用ID（前端初始化用）
     */
    private String captchaAppId;

    /**
     * 极验ID（仅geetest使用）
     */
    private String geetestId;

    /**
     * 其他配置参数
     */
    private Map<String, Object> config;

    /**
     * 是否成功（兼容旧版本）
     */
    @Deprecated
    private Integer success;
}
