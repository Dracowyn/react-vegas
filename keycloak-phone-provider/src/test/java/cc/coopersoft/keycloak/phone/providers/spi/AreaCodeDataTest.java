package cc.coopersoft.keycloak.phone.providers.spi;

import cc.coopersoft.keycloak.phone.providers.spi.AreaCodeService.AreaCodeData;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure logic tests for {@link AreaCodeData#getCountryName(String)}.
 * This round of fixes corrected an off-by-one bug in the substring() call used
 * to derive the base language code (e.g. "zh" from "zh-CN") - see
 * {@link AreaCodeData#getCountryName(String)} in src/main for the current implementation.
 */
class AreaCodeDataTest {

    private AreaCodeData newData(HashMap<String, String> names) {
        return new AreaCodeData(86, "CN", names);
    }

    @Test
    @DisplayName("getCountryName_exactLanguageKey_returnsMappedName")
    void getCountryName_exactLanguageKey_returnsMappedName() {
        HashMap<String, String> names = new HashMap<>();
        names.put("zh", "中国");
        names.put("en", "China");
        AreaCodeData data = newData(names);

        assertThat(data.getCountryName("zh")).isEqualTo("中国");
        assertThat(data.getCountryName("en")).isEqualTo("China");
    }

    @Test
    @DisplayName("getCountryName_regionVariantWithBaseLanguagePresent_fallsBackToBaseLanguage")
    void getCountryName_regionVariantWithBaseLanguagePresent_fallsBackToBaseLanguage() {
        // Regression test for the substring off-by-one fix: "zh-CN" must fall back to "zh",
        // not "z" (off-by-one) nor throw/lose a character.
        HashMap<String, String> names = new HashMap<>();
        names.put("zh", "中国");
        AreaCodeData data = newData(names);

        assertThat(data.getCountryName("zh-CN")).isEqualTo("中国");
    }

    @Test
    @DisplayName("getCountryName_noMatchAtAll_fallsBackToEnglish")
    void getCountryName_noMatchAtAll_fallsBackToEnglish() {
        HashMap<String, String> names = new HashMap<>();
        names.put("en", "China");
        AreaCodeData data = newData(names);

        // Neither "fr-fr" nor its base language "fr" exist in the map -> falls back to "en".
        assertThat(data.getCountryName("fr-FR")).isEqualTo("China");
    }

    @Test
    @DisplayName("getCountryName_noMatchAndNoEnglish_returnsCountryCode")
    void getCountryName_noMatchAndNoEnglish_returnsCountryCode() {
        HashMap<String, String> names = new HashMap<>();
        names.put("ja", "中国（日本語）");
        AreaCodeData data = newData(names);

        // No exact match, no base-language match, and no "en" entry -> falls back to countryCode.
        assertThat(data.getCountryName("de")).isEqualTo("CN");
        assertThat(data.getCountryName("fr-FR")).isEqualTo("CN");
    }
}
