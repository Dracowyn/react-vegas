package cc.coopersoft.keycloak.phone.providers.representations;

import cc.coopersoft.keycloak.phone.utils.PhoneNumber;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure logic tests for {@link TokenCodeRepresentation#forPhoneNumber(PhoneNumber)}.
 */
class TokenCodeRepresentationTest {

    @Test
    @DisplayName("forPhoneNumber_generatesSixDigitNumericCode_overManyIterations")
    void forPhoneNumber_generatesSixDigitNumericCode_overManyIterations() {
        PhoneNumber phoneNumber = new PhoneNumber("86", "13800000000");

        for (int i = 0; i < 500; i++) {
            TokenCodeRepresentation tokenCode = TokenCodeRepresentation.forPhoneNumber(phoneNumber);
            assertThat(tokenCode.getCode())
                    .as("iteration %d code must always be a zero-padded 6 digit string", i)
                    .matches("\\d{6}");
        }
    }

    @Test
    @DisplayName("forPhoneNumber_setsIdConfirmedAndTransfersAreaCodeAndPhoneNumber")
    void forPhoneNumber_setsIdConfirmedAndTransfersAreaCodeAndPhoneNumber() {
        PhoneNumber phoneNumber = new PhoneNumber("86", "13800000000");

        TokenCodeRepresentation tokenCode = TokenCodeRepresentation.forPhoneNumber(phoneNumber);

        assertThat(tokenCode.getId()).isNotBlank();
        assertThat(tokenCode.getConfirmed()).isFalse();
        assertThat(tokenCode.getAreaCode()).isEqualTo("86");
        assertThat(tokenCode.getPhoneNumber()).isEqualTo("13800000000");
    }
}
