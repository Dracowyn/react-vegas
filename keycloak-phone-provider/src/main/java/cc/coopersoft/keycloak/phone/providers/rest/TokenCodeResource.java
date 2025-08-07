package cc.coopersoft.keycloak.phone.providers.rest;

import cc.coopersoft.keycloak.phone.providers.constants.MessageSendResult;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.spi.AreaCodeService;
import cc.coopersoft.keycloak.phone.providers.spi.CaptchaService;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneMessageService;
import cc.coopersoft.keycloak.phone.providers.spi.TokenCodeService;
import cc.coopersoft.keycloak.phone.utils.PhoneConstants;
import cc.coopersoft.keycloak.phone.utils.PhoneNumber;
import cc.coopersoft.keycloak.phone.utils.UserUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.CacheControl;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import static jakarta.ws.rs.core.MediaType.*;

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
     * 发送TokenCode的POST请求
     *
     * @param reqBody 请求体
     * @return 响应
     */
    @POST
    @Path("")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    public Response sendTokenCodeJson(String reqBody) {
        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);
        try {
            JsonNode jsonObject = new ObjectMapper().readTree(reqBody);
            MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
            for (Iterator<Map.Entry<String, JsonNode>> it = jsonObject.fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> node = it.next();
                formData.addAll(node.getKey(), node.getValue().asText());
            }
            return this.sendTokenCode(formData);
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        return Response.serverError().cacheControl(cacheControl).build();
    }

    /**
     * 发送TokenCode的POST请求
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
        HashMap<String, Object> retData = new HashMap<>();
        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);

        if (phoneNumber.isEmpty()) {
            retData.put("status", 0);
            retData.put("error", "Must inform a cellphone number.");
            retData.put("errormsg", "phoneNumberCannotBeEmpty");
            return Response.ok(retData, APPLICATION_JSON_TYPE).cacheControl(cacheControl).build();
        }

        // 验证码
        if (!session.getProvider(CaptchaService.class).verify(formData, this.auth) &&
                !isTrustedClient(formData.getFirst("client_id"), formData.getFirst("client_secret"))) {
            retData.put("status", -1);
            retData.put("error", "Captcha not completed.");
            retData.put("errormsg", "captchaNotCompleted");
            return Response.ok(retData, APPLICATION_JSON_TYPE).cacheControl(cacheControl).build();
        }

        // 区号
        AreaCodeService areaCodeService = session.getProvider(AreaCodeService.class);
        if (!areaCodeService.isAreaCodeAllowed(phoneNumber.getAreaCodeInt())) {
            retData.put("status", -2);
            retData.put("error", "This area is not supported");
            retData.put("errormsg", "areaNotSupported");
            return Response.ok(retData, APPLICATION_JSON_TYPE).cacheControl(cacheControl).build();
        }

        if (tokenCodeType != TokenCodeType.REGISTRATION && tokenCodeType != TokenCodeType.VERIFY) {
            // 需要检测用户是否存在
            UserModel user = UserUtils.findUserByPhone(session.users(), session.getContext().getRealm(), phoneNumber);
            if (user == null) {
                retData.put("status", 0);
                retData.put("error", "This user not exists");
                retData.put("errormsg", "userNotExists");
                return Response.ok(retData, APPLICATION_JSON_TYPE).cacheControl(cacheControl).build();
            }
        }

        logger.info(String.format("Requested %s code to %s", tokenCodeType.name(), phoneNumber.getFullPhoneNumber()));

        // 创建事件构建器来记录短信发送事件
        EventBuilder eventBuilder = new EventBuilder(session.getContext().getRealm(), session, session.getContext().getConnection())
                .event(EventType.CUSTOM_REQUIRED_ACTION)
                .detail("phone_number", phoneNumber.getFullPhoneNumber())
                .detail("token_code_type", tokenCodeType.name())
                .detail("area_code", phoneNumber.getAreaCode())
                .detail("phone_number", phoneNumber.getPhoneNumber());

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

        MessageSendResult result = session.getProvider(PhoneMessageService.class).sendTokenCode(phoneNumber, tokenCodeType);

        if (result.ok()) {
            // 记录成功事件
            eventBuilder.detail("result", "success")
                    .detail("expires_in", String.valueOf(result.getExpiresTime()))
                    .detail("resend_expires", String.valueOf(result.getResendExpiresTime()))
                    .success();

            retData.put("status", 1);
            retData.put("expires_in", result.getExpiresTime());
            retData.put("resend_expires", result.getResendExpiresTime());
        } else {
            // 记录失败事件
            eventBuilder.detail("result", "failure")
                    .detail("error_code", result.getErrorCode())
                    .detail("error_message", result.getErrorMessage())
                    .error("SMS_SEND_FAILED");

            // 不知道为什么这里当时为什么要写成固定的 @Author Dracowyn
            retData.put("status", result.ok() ? 1 : 0);
            retData.put("error", result.getErrorMessage());
            retData.put("errormsg", result.getErrorMessage());
        }
        return Response.ok(retData, APPLICATION_JSON_TYPE).cacheControl(cacheControl).build();
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
        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);
        try {
            JsonNode jsonObject = new ObjectMapper().readTree(reqBody);
            return this.getResendExpire(jsonObject.get(PhoneConstants.FIELD_AREA_CODE).asText(),
                    jsonObject.get(PhoneConstants.FIELD_PHONE_NUMBER).asText());
        } catch (IOException e) {
            logger.error(e);
        }
        return Response.serverError().cacheControl(cacheControl).build();
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
        HashMap<String, Object> retData = new HashMap<>();
        PhoneNumber phoneNumber = new PhoneNumber(areaCode + phoneNumberStr);
        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);
        if (phoneNumber.isEmpty()) {
            retData.put("status", 0);
            retData.put("error", "Must inform a phone number.");
            retData.put("errormsg", "phoneNumberCannotBeEmpty");
            return Response.ok(retData, APPLICATION_JSON_TYPE).cacheControl(cacheControl).build();
        }

        TokenCodeService tokenCodeService = session.getProvider(TokenCodeService.class);
        try {
            Date resendExpireDate = tokenCodeService.getResendExpires(phoneNumber, tokenCodeType);
            long resendExpire = resendExpireDate.getTime();

            retData.put("status", 1);
            retData.put("resend_expire", resendExpire);
            return Response.ok(retData, APPLICATION_JSON_TYPE).cacheControl(cacheControl).build();
        } catch (BadRequestException e) {
            retData.put("status", 0);
            retData.put("error", e.getMessage());
            retData.put("errormsg", "serverError");
            return Response.ok(retData, APPLICATION_JSON_TYPE).cacheControl(cacheControl).build();
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
