package cc.coopersoft.keycloak.phone.providers.representations;

import cc.coopersoft.keycloak.phone.utils.PhoneNumber;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenCodeRepresentation {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private String id;
    private String areaCode;
    private String phoneNumber;
    private String code;
    private String type;
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
    private LocalDateTime resendExpiresAt;
    private Boolean confirmed;

    public static TokenCodeRepresentation forPhoneNumber(PhoneNumber phoneNumber) {
        TokenCodeRepresentation tokenCode = new TokenCodeRepresentation();

        tokenCode.id = KeycloakModelUtils.generateId();
        tokenCode.areaCode = phoneNumber.getAreaCode();
        tokenCode.phoneNumber = phoneNumber.getPhoneNumber();
        tokenCode.code = generateTokenCode();
        tokenCode.confirmed = false;

        return tokenCode;
    }

    private static String generateTokenCode() {
        int code = SECURE_RANDOM.nextInt(1_000_000);
        return String.format("%06d", code);
    }
}
