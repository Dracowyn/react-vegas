package cc.coopersoft.keycloak.phone.providers.rest;

import cc.coopersoft.keycloak.phone.providers.constants.ErrorCode;
import cc.coopersoft.keycloak.phone.providers.constants.MessageSendResult;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.rest.dto.ResendExpiresResponse;
import cc.coopersoft.keycloak.phone.providers.rest.dto.SmsCodeResponse;
import cc.coopersoft.keycloak.phone.providers.rest.util.ResponseBuilder;
import cc.coopersoft.keycloak.phone.providers.spi.AreaCodeService;
import cc.coopersoft.keycloak.phone.providers.spi.CaptchaService;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneMessageService;
import cc.coopersoft.keycloak.phone.providers.spi.TokenCodeService;
import cc.coopersoft.keycloak.phone.utils.PhoneConstants;
import cc.coopersoft.keycloak.phone.utils.PhoneNumber;
import cc.coopersoft.keycloak.phone.utils.UserUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.io.IOException;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

import static jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

/**
 * TokenCodeResource
 * 发送TokenCode的RESTful接口
 *
 * @author cooper
 * @since 2020/10/30
 */
public class TokenCodeResource {

    /**
     * 日志记录器
     */
    private static final Logger logger = Logger.getLogger(TokenCodeResource.class);

    /**
     * Keycloak会话
     */
    protected final KeycloakSession session;

    /**
     * TokenCode类型
     */
    protected final TokenCodeType tokenCodeType;

    /**
     * 认证结果
     */
    private final AuthenticationManager.AuthResult auth;

    /**
     * TokenCodeResource构造函数
     *
     * @param session       Keycloak会话
     * @param tokenCodeType TokenCode类型
     */
    TokenCodeResource(KeycloakSession session, TokenCodeType tokenCodeType) {
        this.session = session;
        this.tokenCodeType = tokenCodeType;
        this.auth = new AppAuthManager().authenticateIdentityCookie(session, session.getContext().getRealm());
    }

    /**
     * 发送TokenCode的POST请求（JSON格式）
     *
     * @param reqBody 请求体
     * @return 响应
     */
    @POST
    @Path("")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    public Response sendTokenCodeJson(String reqBody) {
        try {
            JsonNode jsonObject = new ObjectMapper().readTree(reqBody);
            MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
            for (Iterator<Map.Entry<String, JsonNode>> it = jsonObject.fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> node = it.next();
                formData.addAll(node.getKey(), node.getValue().asText());
            }
            return this.sendTokenCode(formData);
        } catch (IOException e) {
            logger.error("解析JSON请求体失败", e);
            return ResponseBuilder.serverError("请求格式错误");
        }
    }

    /**
     * 发送TokenCode的POST请求（表单格式）
     *
     * @param formData 表单数据
     * @return 响应
     */
    @POST
    @Path("")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_FORM_URLENCODED)
    public Response sendTokenCode(MultivaluedMap<String, String> formData) {
        PhoneNumber phoneNumber = new PhoneNumber(formData);

        // 验证手机号
        if (phoneNumber.isEmpty()) {
            return ResponseBuilder.error(ErrorCode.PHONE_NUMBER_REQUIRED);
        }

        // 验证人机验证码
        if (!session.getProvider(CaptchaService.class).verify(formData, this.auth) &&
                !isTrustedClient(formData.getFirst("client_id"), formData.getFirst("client_secret"))) {
            return ResponseBuilder.error(ErrorCode.CAPTCHA_REQUIRED);
        }

        // 验证区号
        AreaCodeService areaCodeService = session.getProvider(AreaCodeService.class);
        if (!areaCodeService.isAreaCodeAllowed(phoneNumber.getAreaCodeInt())) {
            return ResponseBuilder.error(ErrorCode.AREA_NOT_SUPPORTED);
        }

        // 检查用户是否存在（非注册和验证类型需要）
        if (tokenCodeType != TokenCodeType.REGISTRATION && tokenCodeType != TokenCodeType.VERIFY) {
            UserModel user = UserUtils.findUserByPhone(session.users(), session.getContext().getRealm(), phoneNumber);
            if (user == null) {
                return ResponseBuilder.error(ErrorCode.USER_NOT_FOUND);
            }
        }

        logger.info(String.format("请求发送 %s 验证码到 %s", tokenCodeType.name(), phoneNumber.getFullPhoneNumber()));

        // 创建事件构建器来记录短信发送事件
        EventBuilder eventBuilder = new EventBuilder(session.getContext().getRealm(), session, session.getContext().getConnection())
                .event(EventType.CUSTOM_REQUIRED_ACTION)
                .detail("phone_number", phoneNumber.getFullPhoneNumber())
                .detail("token_code_type", tokenCodeType.name())
                .detail("area_code", phoneNumber.getAreaCode());

        // 如果有已认证的用户，记录用户信息
        if (auth != null && auth.getUser() != null) {
            eventBuilder.user(auth.getUser());
        } else {
            // 对于注册和验证类型，尝试根据手机号查找用户
            UserModel user = UserUtils.findUserByPhone(session.users(), session.getContext().getRealm(), phoneNumber);
            if (user != null) {
                eventBuilder.user(user);
            }
        }

        // 发送短信验证码
        MessageSendResult result = session.getProvider(PhoneMessageService.class).sendTokenCode(phoneNumber, tokenCodeType);

        if (result.ok()) {
            // 记录成功事件
            eventBuilder.detail("result", "success")
                    .detail("expires_in", String.valueOf(result.getExpiresTime()))
                    .detail("resend_expires", String.valueOf(result.getResendExpiresTime()))
                    .success();

            // 返回成功响应
            SmsCodeResponse response = SmsCodeResponse.success(
                    result.getExpiresTime(),
                    result.getResendExpiresTime()
            );
            return ResponseBuilder.ok(response);
        } else {
            // 记录失败事件
            eventBuilder.detail("result", "failure")
                    .detail("error_code", result.getErrorCode())
                    .detail("error_message", result.getErrorMessage())
                    .error("SMS_SEND_FAILED");

            // 返回错误响应
            return ResponseBuilder.error(ErrorCode.SMS_SEND_FAILED, result.getErrorMessage());
        }
    }

    /**
     * 获取Resend Expires的JSON响应
     *
     * @param reqBody 请求体
     * @return 响应
     */
    @POST
    @Path("/resend-expires")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    public Response getResendExpireJson(String reqBody) {
        try {
            JsonNode jsonObject = new ObjectMapper().readTree(reqBody);
            return this.getResendExpire(jsonObject.get(PhoneConstants.FIELD_AREA_CODE).asText(),
                    jsonObject.get(PhoneConstants.FIELD_PHONE_NUMBER).asText());
        } catch (IOException e) {
            logger.error("解析JSON请求体失败", e);
            return ResponseBuilder.serverError("请求格式错误");
        }
    }

    /**
     * 获取Resend Expires的POST请求
     *
     * @param areaCode    区号
     * @param phoneNumber 电话号码
     * @return 响应
     */
    @POST
    @Path("/resend-expires")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_FORM_URLENCODED)
    public Response getResendExpirePost(@FormParam(PhoneConstants.FIELD_AREA_CODE) String areaCode,
                                        @FormParam(PhoneConstants.FIELD_PHONE_NUMBER) String phoneNumber) {
        return this.getResendExpire(areaCode, phoneNumber);
    }

    /**
     * 获取Resend Expires的GET请求
     *
     * @param areaCode       区号
     * @param phoneNumberStr 电话号码
     * @return 响应
     */
    @GET
    @Path("/resend-expires")
    @Produces(APPLICATION_JSON)
    public Response getResendExpire(@QueryParam(PhoneConstants.FIELD_AREA_CODE) String areaCode,
                                    @QueryParam(PhoneConstants.FIELD_PHONE_NUMBER) String phoneNumberStr) {
        PhoneNumber phoneNumber = new PhoneNumber(areaCode + phoneNumberStr);
        
        if (phoneNumber.isEmpty()) {
            return ResponseBuilder.error(ErrorCode.PHONE_NUMBER_REQUIRED);
        }

        TokenCodeService tokenCodeService = session.getProvider(TokenCodeService.class);
        try {
            Date resendExpireDate = tokenCodeService.getResendExpires(phoneNumber, tokenCodeType);
            long resendExpire = resendExpireDate.getTime();

            ResendExpiresResponse response = ResendExpiresResponse.of(resendExpire);
            return ResponseBuilder.ok(response);
        } catch (BadRequestException e) {
            logger.error("获取重发时间失败", e);
            return ResponseBuilder.error(ErrorCode.TOKEN_NOT_FOUND, e.getMessage());
        }
    }

    /**
     * 判断是否为受信任的客户端
     *
     * @param id     客户端ID
     * @param secret 客户端 secret
     * @return true: 是信任的客户端; false: 不是信任的客户端
     */
    private boolean isTrustedClient(String id, String secret) {
        if (id == null || secret == null) {
            return false;
        }
        ClientModel client = this.session.getContext().getRealm().getClientByClientId(id);
        return client != null && client.validateSecret(secret);
    }
}
