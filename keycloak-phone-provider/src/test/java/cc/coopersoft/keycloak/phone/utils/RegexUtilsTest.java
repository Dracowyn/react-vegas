package cc.coopersoft.keycloak.phone.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure logic tests for {@link RegexUtils}.
 */
class RegexUtilsTest {

    @Test
    @DisplayName("matchGlob_exactPattern_matchesOnlySameString")
    void matchGlob_exactPattern_matchesOnlySameString() {
        assertThat(RegexUtils.matchGlob("https://app.example.com", "https://app.example.com")).isTrue();
        assertThat(RegexUtils.matchGlob("https://evil.com", "https://app.example.com")).isFalse();
        assertThat(RegexUtils.matchGlob("abc", "completely-different-pattern")).isFalse();
        assertThat(RegexUtils.matchGlob("abc", "")).isFalse();
    }

    @Test
    @DisplayName("matchGlob_wildcardPattern_matchesGlobSemantics")
    void matchGlob_wildcardPattern_matchesGlobSemantics() {
        assertThat(RegexUtils.matchGlob("https://app.example.com", "https://*.example.com")).isTrue();
        assertThat(RegexUtils.matchGlob("https://a.b.example.com", "https://*.example.com")).isTrue();
        assertThat(RegexUtils.matchGlob("https://example.org", "https://*.example.com")).isFalse();
        // 通配符不匹配字面点号前缀之外的域（evil.com 结尾不同）
        assertThat(RegexUtils.matchGlob("https://app.example.com.evil.com", "https://*.example.com")).isFalse();
        // 单独 * 匹配任意字符串
        assertThat(RegexUtils.matchGlob("anything-at-all", "*")).isTrue();
        assertThat(RegexUtils.matchGlob("", "*")).isTrue();
    }

    @Test
    @DisplayName("matchGlob_nullArguments_returnFalse")
    void matchGlob_nullArguments_returnFalse() {
        assertThat(RegexUtils.matchGlob(null, "*")).isFalse();
        assertThat(RegexUtils.matchGlob("abc", null)).isFalse();
        assertThat(RegexUtils.matchGlob(null, null)).isFalse();
    }

    @Test
    @DisplayName("buildExprFromGlob_wildcard_becomesNonGreedyRegex")
    void buildExprFromGlob_wildcard_becomesNonGreedyRegex() {
        assertThat(RegexUtils.buildExprFromGlob("https://*.example.com"))
                .isEqualTo("^https://.*?\\.example\\.com$");
        assertThat(RegexUtils.buildExprFromGlob("*")).isEqualTo("^.*?$");
    }

    @Test
    @DisplayName("buildExprFromGlob_escapesRegexMetacharactersInInput")
    void buildExprFromGlob_escapesRegexMetacharactersInInput() {
        assertThat(RegexUtils.buildExprFromGlob("a.b")).isEqualTo("^a\\.b$");
        assertThat(RegexUtils.buildExprFromGlob("plain")).isEqualTo("^plain$");
    }

    @Test
    @DisplayName("escapeExprSpecialWord_blankInput_returnsInputUnchanged")
    void escapeExprSpecialWord_blankInput_returnsInputUnchanged() {
        assertThat(RegexUtils.escapeExprSpecialWord(null)).isNull();
        assertThat(RegexUtils.escapeExprSpecialWord("")).isEqualTo("");
    }

    @Test
    @DisplayName("escapeExprSpecialWord_specialCharacters_areBackslashEscaped")
    void escapeExprSpecialWord_specialCharacters_areBackslashEscaped() {
        assertThat(RegexUtils.escapeExprSpecialWord("a.b")).isEqualTo("a\\.b");
        assertThat(RegexUtils.escapeExprSpecialWord("(a)[b]{c}")).isEqualTo("\\(a\\)\\[b\\]\\{c\\}");
        assertThat(RegexUtils.escapeExprSpecialWord("no-special-chars")).isEqualTo("no-special-chars");
    }
}
