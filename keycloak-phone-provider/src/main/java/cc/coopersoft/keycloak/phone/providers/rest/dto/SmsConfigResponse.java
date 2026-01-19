package cc.coopersoft.keycloak.phone.providers.rest.dto;

import cc.coopersoft.keycloak.phone.providers.spi.AreaCodeService;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 短信配置响应模型
 * 用于返回短信服务配置信息
 *
 * @author Dracowyn
 * @since 2026-01-15
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SmsConfigResponse {
    /**
     * 验证码有效期（秒）
     */
    private Integer tokenExpires;

    /**
     * 默认区号
     */
    private String defaultAreaCode;

    /**
     * 是否锁定区号（不允许修改）
     */
    private Boolean areaLocked;

    /**
     * 是否允许取消绑定手机号
     */
    private Boolean allowUnset;

    /**
     * 区号列表
     */
    private List<AreaCodeService.AreaCodeData> areaCodeList;
}
