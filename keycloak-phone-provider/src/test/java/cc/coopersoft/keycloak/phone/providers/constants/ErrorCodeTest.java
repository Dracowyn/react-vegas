package cc.coopersoft.keycloak.phone.providers.constants;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the HTTP status code contract for error codes added/enabled in this round of fixes.
 */
class ErrorCodeTest {

    static Stream<Arguments> httpStatusContract() {
        return Stream.of(
                Arguments.of(ErrorCode.INVALID_REQUEST, 400),
                Arguments.of(ErrorCode.SMS_SEND_LIMIT_EXCEEDED, 429),
                Arguments.of(ErrorCode.RESEND_TOO_SOON, 429),
                Arguments.of(ErrorCode.ILLEGAL_PHONE_NUMBER, 403),
                Arguments.of(ErrorCode.VERIFICATION_CODE_EXPIRED, 400)
        );
    }

    @ParameterizedTest(name = "{0}.getHttpStatus() == {1}")
    @MethodSource("httpStatusContract")
    @DisplayName("getHttpStatus_regressionErrorCodes_matchesExpectedContract")
    void getHttpStatus_regressionErrorCodes_matchesExpectedContract(ErrorCode errorCode, int expectedStatus) {
        assertThat(errorCode.getHttpStatus()).isEqualTo(expectedStatus);
    }

    @Test
    @DisplayName("getCode_everyEnumConstant_equalsEnumName")
    void getCode_everyEnumConstant_equalsEnumName() {
        for (ErrorCode errorCode : ErrorCode.values()) {
            assertThat(errorCode.getCode()).isEqualTo(errorCode.name());
        }
    }
}
