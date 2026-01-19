package cc.coopersoft.keycloak.phone.providers.rest;

import cc.coopersoft.keycloak.phone.providers.constants.ErrorCode;
import cc.coopersoft.keycloak.phone.providers.rest.util.ResponseBuilder;
import cc.coopersoft.keycloak.phone.providers.spi.ConfigService;
import cc.coopersoft.keycloak.phone.providers.spi.TokenCodeService;
import cc.coopersoft.keycloak.phone.utils.PhoneConstants;
import cc.coopersoft.keycloak.phone.utils.PhoneNumber;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

import java.io.IOException;

import static jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

/**
 * 验证码验证资源
 * 提供验证码验证和手机号绑定接口
 *
 * @author cooper
 * @since 2020/10/30
 */
public class VerificationCodeResource {

    private static final Logger logger = Logger.getLogger(VerificationCodeResource.class);

    private final KeycloakSession session;
    private final AuthResult auth;

    VerificationCodeResource(KeycloakSession session) {
        this.session = session;
        this.auth = new AppAuthManager().authenticateIdentityCookie(session, session.getContext().getRealm());
    }

    private TokenCodeService getTokenCodeService() {
        return session.getProvider(TokenCodeService.class);
    }

    /**
     * 设置用户手机号（JSON格式）
     *
     * @param reqBody 请求体
     * @return 响应
     */
    @POST
    @Path("")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    public Response setUserPhoneNumberJson(String reqBody) {
        try {
            JsonNode jsonObject = new ObjectMapper().readTree(reqBody);

            return this.setUserPhoneNumber(jsonObject.get(PhoneConstants.FIELD_AREA_CODE).asText(),
                    jsonObject.get(PhoneConstants.FIELD_PHONE_NUMBER).asText(),
                    jsonObject.get(PhoneConstants.FIELD_VERIFICATION_CODE).asText());
        } catch (IOException e) {
            logger.error("解析JSON请求体失败", e);
            return ResponseBuilder.serverError("请求格式错误");
        }
    }

    /**
     * 设置用户手机号（表单格式）
     *
     * @param areaCode     区号
     * @param phoneNumberStr 手机号
     * @param code         验证码
     * @return 响应
     */
    @POST
    @Path("")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_FORM_URLENCODED)
    public Response setUserPhoneNumber(@FormParam(PhoneConstants.FIELD_AREA_CODE) String areaCode,
                                       @FormParam(PhoneConstants.FIELD_PHONE_NUMBER) String phoneNumberStr,
                                       @FormParam(PhoneConstants.FIELD_VERIFICATION_CODE) String code) {

        // 验证用户是否登录
        if (auth == null) {
            return ResponseBuilder.error(ErrorCode.AUTHENTICATION_REQUIRED);
        }

        PhoneNumber phoneNumber = new PhoneNumber(areaCode, phoneNumberStr);
        
        // 验证手机号
        if (phoneNumber.isEmpty()) {
            return ResponseBuilder.error(ErrorCode.PHONE_NUMBER_REQUIRED);
        }
        
        // 验证验证码
        if (code == null || code.trim().isEmpty()) {
            return ResponseBuilder.error(ErrorCode.VERIFICATION_CODE_REQUIRED);
        }

        try {
            UserModel user = auth.getUser();
            getTokenCodeService().setUserPhoneNumberByCode(user, phoneNumber, code);
            return ResponseBuilder.noContent();
        } catch (BadRequestException e) {
            logger.error("设置用户手机号失败", e);
            return ResponseBuilder.error(ErrorCode.VERIFICATION_CODE_INVALID, e.getMessage());
        }
    }

    /**
     * 取消绑定用户手机号
     *
     * @return 响应
     */
    @POST
    @Path("/unset")
    @Produces(APPLICATION_JSON)
    @Consumes({APPLICATION_JSON, APPLICATION_FORM_URLENCODED})
    public Response unsetUserPhoneNumber() {
        ConfigService config = session.getProvider(ConfigService.class);
        
        // 检查是否允许取消绑定
        if (!config.isAllowUnset()) {
            return ResponseBuilder.error(ErrorCode.PHONE_UNSET_NOT_ALLOWED);
        }
        
        // 验证用户是否登录
        if (auth == null) {
            return ResponseBuilder.error(ErrorCode.AUTHENTICATION_REQUIRED);
        }

        UserModel user = auth.getUser();
        
        // 检查邮箱是否已验证
        if (!user.isEmailVerified()) {
            return ResponseBuilder.error(ErrorCode.EMAIL_NOT_VERIFIED, "取消绑定手机号前需要先验证邮箱");
        }
        
        // 移除手机号属性
        user.removeAttribute("phoneNumber");
        return ResponseBuilder.noContent();
    }
}