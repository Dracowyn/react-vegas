package cc.coopersoft.keycloak.phone.providers.rest.dto;

import cc.coopersoft.keycloak.phone.providers.constants.ErrorCode;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

/**
 * API错误响应模型
 * 用于统一的错误信息返回
 *
 * @author Dracowyn
 * @since 2026-01-15
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiError {
    /**
     * 错误码
     */
    private String code;

    /**
     * 错误消息
     */
    private String message;

    /**
     * 错误详情（可选）
     */
    private Map<String, Object> details;

    /**
     * 时间戳
     */
    @Builder.Default
    private String timestamp = Instant.now().toString();

    /**
     * 从ErrorCode枚举创建ApiError
     *
     * @param errorCode 错误码枚举
     * @return ApiError实例
     */
    public static ApiError from(ErrorCode errorCode) {
        return ApiError.builder()
                .code(errorCode.getCode())
                .message(errorCode.getMessage())
                .build();
    }

    /**
     * 从ErrorCode枚举创建ApiError，带自定义消息
     *
     * @param errorCode 错误码枚举
     * @param message   自定义消息
     * @return ApiError实例
     */
    public static ApiError from(ErrorCode errorCode, String message) {
        return ApiError.builder()
                .code(errorCode.getCode())
                .message(message)
                .build();
    }

    /**
     * 从ErrorCode枚举创建ApiError，带详情
     *
     * @param errorCode 错误码枚举
     * @param details   错误详情
     * @return ApiError实例
     */
    public static ApiError from(ErrorCode errorCode, Map<String, Object> details) {
        return ApiError.builder()
                .code(errorCode.getCode())
                .message(errorCode.getMessage())
                .details(details)
                .build();
    }
}
