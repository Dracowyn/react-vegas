package cc.coopersoft.keycloak.phone.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

/**
 * JSON工具类
 *
 * <p>{@link ObjectMapper} 在完成配置后是线程安全的，因此这里复用一个共享的静态实例，
 * 避免每次调用都创建新的 mapper，也不再使用此前那个错误的“单例”实现。</p>
 */
public final class JsonUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonUtils() {
    }

    /**
     * 将Map对象转换为JSON字符串
     *
     * @param map 要转换为JSON的Map对象
     * @return 转换后的JSON字符串
     * @throws JsonProcessingException JSON转换过程异常时抛出
     */
    public static String encode(Map<String, Object> map) throws JsonProcessingException {
        return MAPPER.writeValueAsString(map);
    }

    /**
     * 将JSON字符串转换为Map对象
     */
    public static Map<String, Object> decode(String json) throws JsonProcessingException {
        return MAPPER.readValue(json, new TypeReference<>() {
        });
    }
}
