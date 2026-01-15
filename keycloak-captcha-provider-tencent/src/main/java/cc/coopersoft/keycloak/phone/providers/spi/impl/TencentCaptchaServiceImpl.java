package cc.coopersoft.keycloak.phone.providers.spi.impl;

import cc.coopersoft.keycloak.phone.providers.spi.CaptchaService;
import com.tencentcloudapi.captcha.v20190722.CaptchaClient;
import com.tencentcloudapi.captcha.v20190722.models.DescribeCaptchaResultRequest;
import com.tencentcloudapi.captcha.v20190722.models.DescribeCaptchaResultResponse;
import com.tencentcloudapi.common.Credential;
import com.tencentcloudapi.common.exception.TencentCloudSDKException;
import com.tencentcloudapi.common.profile.ClientProfile;
import com.tencentcloudapi.common.profile.HttpProfile;
import lombok.Setter;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AuthenticationManager;

import jakarta.ws.rs.core.MultivaluedMap;
import java.util.Optional;

/**
 * 腾讯云验证码服务实现
 * 支持腾讯云验证码的验证和前端密钥获取
 */
public class TencentCaptchaServiceImpl implements CaptchaService {
    private static final Logger log = Logger.getLogger(TencentCaptchaServiceImpl.class);
    
    // 默认值
    private static final String DEFAULT_USER_ID = "guest";
    private static final String UNKNOWN_USER = "unknown";
    private static final String DEFAULT_ENDPOINT = "captcha.tencentcloudapi.com";
    
    // 表单参数名
    private static final String PARAM_TICKET = "ticket";
    private static final String PARAM_RANDSTR = "randstr";

    private final KeycloakSession session;
    
    @Setter
    private Config.Scope config;

    public TencentCaptchaServiceImpl(KeycloakSession session) {
        this.session = session;
    }

    /**
     * 根据认证结果获取用户ID
     *
     * @param user 认证结果
     * @return 用户ID，如果为空则返回默认用户ID
     */
    private String getUserIdByAuthResult(AuthenticationManager.AuthResult user) {
        return user != null ? user.getUser().getId() : DEFAULT_USER_ID;
    }

    @Override
    public boolean verify(final MultivaluedMap<String, String> formParams, AuthenticationManager.AuthResult user) {
        return verify(formParams, getUserIdByAuthResult(user));
    }

    @Override
    public boolean verify(final MultivaluedMap<String, String> formParams, String user) {
        // 确保用户ID不为空
        user = Optional.ofNullable(user).orElse(UNKNOWN_USER);

        // 获取腾讯云配置
        String secretId = config.get("secretId");
        String secretKey = config.get("secretKey");
        String captchaAppId = config.get("captchaAppId");
        String appSecretKey = config.get("appSecretKey");
        long captchaType = 9;

        if (secretId == null || secretKey == null || captchaAppId == null || appSecretKey == null) {
            log.warn("腾讯云验证码配置不完整，跳过验证");
            return true;
        }

        // 从表单参数获取票据和随机字符串
        String ticket = formParams.getFirst(PARAM_TICKET);
        String randstr = formParams.getFirst(PARAM_RANDSTR);

        if (ticket == null || randstr == null) {
            log.warn("表单提交中缺少必要的腾讯云验证码参数（ticket或randstr）");
            return false;
        }

        // 获取用户IP地址
        String userIp = session.getContext().getConnection().getRemoteAddr();

        try {
            // 创建腾讯云API凭证
            Credential cred = new Credential(secretId, secretKey);
            
            // 配置HTTP选项
            HttpProfile httpProfile = new HttpProfile();
            httpProfile.setEndpoint(Optional.ofNullable(config.get("endpoint"))
                    .orElse(DEFAULT_ENDPOINT));
            
            ClientProfile clientProfile = new ClientProfile();
            clientProfile.setHttpProfile(httpProfile);

            // 创建验证码客户端
            CaptchaClient client = new CaptchaClient(cred, "", clientProfile);

            // 构建请求
            DescribeCaptchaResultRequest request = new DescribeCaptchaResultRequest();
            // CaptchaType是可选的，腾讯云会根据CaptchaAppId自动识别验证码类型
            // 如果需要明确指定类型，可以配置captchaType参数
            String captchaTypeStr = config.get("captchaType");
            if (captchaTypeStr != null) {
                request.setCaptchaType(Long.parseLong(captchaTypeStr));
            }
            request.setTicket(ticket);
            request.setRandstr(randstr);
            request.setUserIp(userIp);
            request.setCaptchaAppId(Long.parseLong(captchaAppId));
            request.setAppSecretKey(appSecretKey);
            request.setCaptchaType(captchaType);

            // 发送请求并获取响应
            DescribeCaptchaResultResponse response = client.DescribeCaptchaResult(request);

            // 判断验证结果
            // CaptchaCode为1表示验证成功
            Long captchaCode = response.getCaptchaCode();
            boolean success = captchaCode != null && captchaCode == 1L;

            if (!success) {
                log.warnf("腾讯云验证码验证失败: CaptchaCode=%d, CaptchaMsg=%s", 
                        captchaCode, response.getCaptchaMsg());
            } else {
                log.debugf("腾讯云验证码验证成功: user=%s, ip=%s", user, userIp);
            }

            return success;

        } catch (TencentCloudSDKException e) {
            log.error("调用腾讯云验证码API时出错: " + e.getMessage(), e);
            
            // 根据配置决定在API错误时是否通过验证
            boolean fallbackOnError = Optional.ofNullable(config.getBoolean("fallbackOnError"))
                    .orElse(false);
            
            if (fallbackOnError) {
                log.warn("由于API错误且配置了fallbackOnError=true，验证通过");
            }
            
            return fallbackOnError;
        } catch (NumberFormatException e) {
            log.error("配置参数格式错误: " + e.getMessage(), e);
            return false;
        }
    }

    @Override
    public String getFrontendKey(AuthenticationManager.AuthResult user) {
        return getFrontendKey(getUserIdByAuthResult(user));
    }

    @Override
    public String getFrontendKey(String user) {
        // 确保用户ID不为空
        user = Optional.ofNullable(user).orElse(UNKNOWN_USER);

        // 获取腾讯云配置
        String captchaAppId = config.get("captchaAppId");

        if (captchaAppId == null) {
            log.error("必须配置腾讯云验证码应用ID（captchaAppId）");
            return "{\"success\":0,\"message\":\"腾讯云验证码应用ID未配置\"}";
        }

        // 返回前端需要的配置信息
        // 前端会使用这个AppId初始化验证码组件
        return String.format("{\"success\":1,\"captchaAppId\":\"%s\"}", captchaAppId);
    }

    @Override
    public void close() {
        // 无需清理资源
    }
}
