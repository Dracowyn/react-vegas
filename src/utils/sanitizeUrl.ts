/**
 * 转义 CSS url() 中的特殊字符，防止 CSS 注入
 */
export const sanitizeCssUrl = (url: string): string => {
	return `url("${url.replace(/[\\"'()]/g, "\\$&")}")`;
};
