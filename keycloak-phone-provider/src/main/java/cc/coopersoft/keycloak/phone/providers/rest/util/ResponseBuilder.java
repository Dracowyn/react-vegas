package cc.coopersoft.keycloak.phone.providers.rest.util;

import cc.coopersoft.keycloak.phone.providers.constants.ErrorCode;
import cc.coopersoft.keycloak.phone.providers.rest.dto.ApiError;
import jakarta.ws.rs.core.CacheControl;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * 响应构建工具类
 * 提供统一的Response构建方法
 *
 * @author Dracowyn
 * @since 2026-01-15
 */
public class ResponseBuilder {

    private static final CacheControl NO_CACHE;

    static {
        NO_CACHE = new CacheControl();
        NO_CACHE.setNoCache(true);
    }

    /**
     * 构建成功响应
     *
     * @param data 响应数据
     * @return Response
     */
    public static Response ok(Object data) {
        return Response.ok(data, MediaType.APPLICATION_JSON_TYPE)
                .cacheControl(NO_CACHE)
                .build();
    }

    /**
     * 构建无内容成功响应
     *
     * @return Response
     */
    public static Response noContent() {
        return Response.noContent()
                .cacheControl(NO_CACHE)
                .build();
    }

    /**
     * 构建错误响应
     *
     * @param errorCode 错误码枚举
     * @return Response
     */
    public static Response error(ErrorCode errorCode) {
        ApiError error = ApiError.from(errorCode);
        return Response.status(errorCode.getHttpStatus())
                .entity(error)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .cacheControl(NO_CACHE)
                .build();
    }

    /**
     * 构建错误响应，带自定义消息
     *
     * @param errorCode 错误码枚举
     * @param message   自定义消息
     * @return Response
     */
    public static Response error(ErrorCode errorCode, String message) {
        ApiError error = ApiError.from(errorCode, message);
        return Response.status(errorCode.getHttpStatus())
                .entity(error)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .cacheControl(NO_CACHE)
                .build();
    }

    /**
     * 构建错误响应，使用ApiError对象
     *
     * @param httpStatus HTTP状态码
     * @param error      错误对象
     * @return Response
     */
    public static Response error(int httpStatus, ApiError error) {
        return Response.status(httpStatus)
                .entity(error)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .cacheControl(NO_CACHE)
                .build();
    }

    /**
     * 构建服务器错误响应
     *
     * @return Response
     */
    public static Response serverError() {
        return error(ErrorCode.INTERNAL_ERROR);
    }

    /**
     * 构建服务器错误响应，带消息
     *
     * @param message 错误消息
     * @return Response
     */
    public static Response serverError(String message) {
        return error(ErrorCode.INTERNAL_ERROR, message);
    }
}
