package cc.coopersoft.keycloak.phone.utils;

import org.apache.commons.lang3.StringUtils;

import java.util.regex.Pattern;

public class RegexUtils {
    /**
     * 转义正则特殊字符 （$()*+.[]?\^{},|）
     *
     * @param keyword
     * @return
     */
    public static String escapeExprSpecialWord(String keyword) {
        if (StringUtils.isNotBlank(keyword)) {
            String[] fbsArr = { "\\", "$", "(", ")", "+", ".", "[", "]", "?", "^", "{", "}", "|" };
            for (String key : fbsArr) {
                if (keyword.contains(key)) {
                    keyword = keyword.replace(key, "\\" + key);
                }
            }
        }
        return keyword;
    }

    /**
     * 把 glob 模式（* 为通配符）转换为正则表达式。
     * 按 * 切分后对每段做正则转义，再用 .*? 连接，保证通配符生效且其余字符按字面匹配。
     *
     * @param glob glob 模式，如 https://*.example.com
     * @return 对应的正则表达式
     */
    public static String buildExprFromGlob(String glob){
        String[] parts = glob.split("\\*", -1);
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                regex.append(".*?");
            }
            regex.append(escapeExprSpecialWord(parts[i]));
        }
        regex.append("$");
        return regex.toString();
    }

    /**
     * 判断字符串是否匹配 glob 模式（正则由 match 参数构建）。
     * 任一参数为 null 时返回 false（如请求缺少 Origin 头的场景）。
     *
     * @param str   待匹配的字符串（如请求的 Origin）
     * @param match glob 模式（如客户端配置的 Web Origin）
     * @return 是否匹配
     */
    public static boolean matchGlob(String str, String match){
        if (str == null || match == null) {
            return false;
        }
        return Pattern.matches(buildExprFromGlob(match), str);
    }
}
