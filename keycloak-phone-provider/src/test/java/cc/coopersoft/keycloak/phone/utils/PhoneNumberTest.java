package cc.coopersoft.keycloak.phone.utils;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure logic tests for {@link PhoneNumber}.
 */
class PhoneNumberTest {

    @Nested
    @DisplayName("isEmpty")
    class IsEmpty {

        @Test
        @DisplayName("isEmpty_nullAreaCodeAndPhoneNumber_returnsTrue")
        void isEmpty_nullAreaCodeAndPhoneNumber_returnsTrue() {
            PhoneNumber phoneNumber = new PhoneNumber(null, null);
            assertThat(phoneNumber.isEmpty()).isTrue();
        }

        @Test
        @DisplayName("isEmpty_emptyStringPhoneNumber_returnsTrue")
        void isEmpty_emptyStringPhoneNumber_returnsTrue() {
            PhoneNumber phoneNumber = new PhoneNumber("86", "");
            assertThat(phoneNumber.isEmpty()).isTrue();
        }

        @Test
        @DisplayName("isEmpty_emptyStringAreaCode_returnsTrue")
        void isEmpty_emptyStringAreaCode_returnsTrue() {
            PhoneNumber phoneNumber = new PhoneNumber("", "13800000000");
            assertThat(phoneNumber.isEmpty()).isTrue();
        }

        @Test
        @DisplayName("isEmpty_whitespacePhoneNumber_returnsTrue")
        void isEmpty_whitespacePhoneNumber_returnsTrue() {
            PhoneNumber phoneNumber = new PhoneNumber("86", "   ");
            assertThat(phoneNumber.isEmpty()).isTrue();
        }

        @Test
        @DisplayName("isEmpty_bothPresent_returnsFalse")
        void isEmpty_bothPresent_returnsFalse() {
            PhoneNumber phoneNumber = new PhoneNumber("86", "13800000000");
            assertThat(phoneNumber.isEmpty()).isFalse();
        }
    }

    @Nested
    @DisplayName("getFullPhoneNumber")
    class GetFullPhoneNumber {

        @Test
        @DisplayName("getFullPhoneNumber_noArg_returnsPlusAreaCodeSpacePhoneNumber")
        void getFullPhoneNumber_noArg_returnsPlusAreaCodeSpacePhoneNumber() {
            PhoneNumber phoneNumber = new PhoneNumber("86", "13800000000");
            assertThat(phoneNumber.getFullPhoneNumber()).isEqualTo("+86 13800000000");
        }

        @Test
        @DisplayName("getFullPhoneNumber_noSpaceTrue_returnsPlusAreaCodePhoneNumberWithoutSpace")
        void getFullPhoneNumber_noSpaceTrue_returnsPlusAreaCodePhoneNumberWithoutSpace() {
            PhoneNumber phoneNumber = new PhoneNumber("86", "13800000000");
            assertThat(phoneNumber.getFullPhoneNumber(true)).isEqualTo("+8613800000000");
        }

        @Test
        @DisplayName("getFullPhoneNumber_noSpaceFalse_sameAsNoArgVariant")
        void getFullPhoneNumber_noSpaceFalse_sameAsNoArgVariant() {
            PhoneNumber phoneNumber = new PhoneNumber("86", "13800000000");
            assertThat(phoneNumber.getFullPhoneNumber(false)).isEqualTo(phoneNumber.getFullPhoneNumber());
        }
    }

    @Nested
    @DisplayName("setFullPhoneNumber")
    class SetFullPhoneNumber {

        @Test
        @DisplayName("setFullPhoneNumber_validInput_parsesAreaCodeAndPhoneNumberAndReturnsTrue")
        void setFullPhoneNumber_validInput_parsesAreaCodeAndPhoneNumberAndReturnsTrue() {
            PhoneNumber phoneNumber = new PhoneNumber("+86 13800000000");

            assertThat(phoneNumber.getAreaCode()).isEqualTo("86");
            assertThat(phoneNumber.getPhoneNumber()).isEqualTo("13800000000");
        }

        @Test
        @DisplayName("setFullPhoneNumber_validInput_returnsTrueViaDirectCall")
        void setFullPhoneNumber_validInput_returnsTrueViaDirectCall() {
            PhoneNumber phoneNumber = new PhoneNumber("86", "13800000000");
            boolean result = phoneNumber.setFullPhoneNumber("+1 5551234567");

            assertThat(result).isTrue();
            assertThat(phoneNumber.getAreaCode()).isEqualTo("1");
            assertThat(phoneNumber.getPhoneNumber()).isEqualTo("5551234567");
        }

        @Test
        @DisplayName("setFullPhoneNumber_missingSpace_returnsFalseAndLeavesStateUnchanged")
        void setFullPhoneNumber_missingSpace_returnsFalseAndLeavesStateUnchanged() {
            PhoneNumber phoneNumber = new PhoneNumber("86", "13800000000");
            boolean result = phoneNumber.setFullPhoneNumber("8613800000000");

            assertThat(result).isFalse();
            assertThat(phoneNumber.getAreaCode()).isEqualTo("86");
            assertThat(phoneNumber.getPhoneNumber()).isEqualTo("13800000000");
        }

        @Test
        @DisplayName("setFullPhoneNumber_tooManySegments_returnsFalseAndLeavesStateUnchanged")
        void setFullPhoneNumber_tooManySegments_returnsFalseAndLeavesStateUnchanged() {
            PhoneNumber phoneNumber = new PhoneNumber("86", "13800000000");
            boolean result = phoneNumber.setFullPhoneNumber("+86 138 00000");

            assertThat(result).isFalse();
            assertThat(phoneNumber.getAreaCode()).isEqualTo("86");
            assertThat(phoneNumber.getPhoneNumber()).isEqualTo("13800000000");
        }
    }

    @Nested
    @DisplayName("MultivaluedMap constructor")
    class MultivaluedMapConstructor {

        @Test
        @DisplayName("constructor_newFieldNamesOnly_parsesFromNewFieldNames")
        void constructor_newFieldNamesOnly_parsesFromNewFieldNames() {
            MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
            formData.putSingle(PhoneConstants.FIELD_AREA_CODE, "86");
            formData.putSingle(PhoneConstants.FIELD_PHONE_NUMBER, "13800000000");

            PhoneNumber phoneNumber = new PhoneNumber(formData);

            assertThat(phoneNumber.getAreaCode()).isEqualTo("86");
            assertThat(phoneNumber.getPhoneNumber()).isEqualTo("13800000000");
        }

        @Test
        @DisplayName("constructor_legacyFieldNamesOnly_fallsBackToLegacyFieldNames")
        void constructor_legacyFieldNamesOnly_fallsBackToLegacyFieldNames() {
            MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
            formData.putSingle(PhoneConstants.LEGACY_FIELD_AREA_CODE, "1");
            formData.putSingle(PhoneConstants.LEGACY_FIELD_PHONE_NUMBER, "5551234567");

            PhoneNumber phoneNumber = new PhoneNumber(formData);

            assertThat(phoneNumber.getAreaCode()).isEqualTo("1");
            assertThat(phoneNumber.getPhoneNumber()).isEqualTo("5551234567");
        }

        @Test
        @DisplayName("constructor_bothNewAndLegacyFieldNamesPresent_newFieldNamesTakePriority")
        void constructor_bothNewAndLegacyFieldNamesPresent_newFieldNamesTakePriority() {
            MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
            formData.putSingle(PhoneConstants.FIELD_AREA_CODE, "86");
            formData.putSingle(PhoneConstants.FIELD_PHONE_NUMBER, "13800000000");
            formData.putSingle(PhoneConstants.LEGACY_FIELD_AREA_CODE, "1");
            formData.putSingle(PhoneConstants.LEGACY_FIELD_PHONE_NUMBER, "5551234567");

            PhoneNumber phoneNumber = new PhoneNumber(formData);

            assertThat(phoneNumber.getAreaCode()).isEqualTo("86");
            assertThat(phoneNumber.getPhoneNumber()).isEqualTo("13800000000");
        }
    }
}
