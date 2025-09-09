export default {
	stories: [
		'../stories/**/*.mdx',
		'../stories/**/*.stories.@(js|jsx|mjs|ts|tsx)',
	],
	addons: ['storybook-addon-rslib', '@storybook/addon-docs'],
	framework: 'storybook-react-rsbuild',
};
