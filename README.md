# React Vegas 幻灯片组件

参考 [Vegas Background SlideShow](https://github.com/jaysalvat/vegas) 实现的React组件，提供强大灵活的幻灯片展示功能，支持图片和视频，具有平滑过渡效果和可定制化功能。

简体中文 | [English](./README.EN.md)

## 功能特性

- 🖼️ 支持图片和视频
- 🎬 多种过渡效果
- 🔄 可配置间隔时间的自动播放
- 🎯 自定义对齐方式
- 🔀 随机播放模式
- ⚡ 预加载功能
- 📱 响应式设计
- 🎨 可定制的遮罩层和进度条
- 🎮 手动控制功能
- 🎯 TypeScript 支持

## 安装说明

npm

```bash
npm install react-vegas
```

yarn

```bash
yarn add react-vegas
```

pnpm

```bash
pnpm add react-vegas
```

## 基础用法

```tsx
import { Vegas } from "react-vegas";

const App = () => {
	const slides = [
		{
			src: '/images/slide1.jpg',
			transition: 'fade'
		},
		{
			src: '/images/slide2.jpg',
			transition: 'slideLeft'
		}
	];

	return (
		<Vegas
			slides={slides}
			delay={5000}
			autoplay={true}
		/>
	);
};
```

## 高级用法

```tsx
const slides = [
	{
		src: '/images/slide1.jpg',
		align: 'center',                        // 水平对齐
		valign: 'center',                       // 垂直对齐
		transition: 'fade',                     // 过渡效果
		transitionDuration: 2000,               // 过渡时长
		delay: 5000                             // 本页停留时间
	},
	{
		src: '/videos/video1.mp4',
		video: {
			src: [                                // 多格式支持
				'/videos/video1.mp4',
				'/videos/video1.webm'
			],
			muted: true,                          // 静音播放
			loop: false                           // 是否循环
		},
		transition: 'zoomIn'                    // 缩放进入效果
	}
];

<Vegas
	slides={slides}
	autoplay={true}                           // 启用自动播放
	overlay={true}                            // 启用遮罩层
	timer={false}                             // 隐藏进度条
	delay={7000}                              // 全局停留时间
	shuffle={true}                            // 随机播放
	preload={true}                            // 启用预加载
	preloadImage={true}                       // 启用预加载图片
	transitionDuration={3000}                 // 全局过渡时长
	firstTransitionDuration={5000}            // 初始过渡时长
	defaultBackground="/images/loading.jpg"   // 加载背景图
	defaultBackgroundDuration={2000}          // 加载背景显示时间
	debug={false}                             // 调试模式
	color="#000"                              // 背景色
/>
```

## 组件属性

### 基础属性

| 属性       | 类型      | 默认值   | 说明          |
|----------|---------|-------|-------------|
| slides   | Array   | 必填    | 幻灯片对象数组     |
| slide    | number  | 0     | 初始幻灯片索引     |
| delay    | number  | 5000  | 幻灯片切换间隔(毫秒) |
| autoplay | boolean | true  | 启用自动播放      |
| loop     | boolean | true  | 循环播放        |
| shuffle  | boolean | false | 随机播放顺序      |
| debug    | boolean | false | 启用调试日志      |

### 过渡效果

| 属性                      | 类型     | 默认值    | 说明         |
|-------------------------|--------|--------|------------|
| transition              | string | 'fade' | 过渡效果类型     |
| transitionDuration      | number | 1000   | 过渡时长(毫秒)   |
| firstTransitionDuration | number | 3000   | 初始过渡时长(毫秒) |

### 视觉属性

| 属性      | 类型      | 默认值    | 说明     |
|---------|---------|--------|--------|
| overlay | boolean | false  | 显示遮罩层  |
| timer   | boolean | false  | 显示进度条  |
| color   | string  | null   | 背景颜色   |
| cover   | boolean | true   | 图片覆盖模式 |
| align   | string  | center | 水平对齐方式 |
| valign  | string  | center | 垂直对齐方式 |

### 加载配置

| 属性                        | 类型      | 默认值       | 说明        |
|---------------------------|---------|-----------|-----------|
| preload                   | boolean | false     | 启用资源预加载   |
| preloadImage              | boolean | false     | 预加载图片     |
| preloadImageBatch         | number  | 3         | 批量预加载图片数量 |
| preLoadImageBatch         | number  | 3         | 旧属性名，建议改用 preloadImageBatch |
| preloadVideo              | boolean | false     | 预加载视频     |
| showLoading               | boolean | false     | 显示加载指示器   |
| defaultBackground         | string  | undefined | 加载背景图     |
| defaultBackgroundDuration | number  | 3000      | 加载背景显示时长  |

### 回调函数

| 属性      | 类型         | 说明       |
|---------|------------|----------|
| onInit  | () => void | 初始化完成时触发 |
| onPlay  | () => void | 播放开始时触发  |
| onPause | () => void | 暂停时触发    |
| onWalk  | () => void | 幻灯片切换时触发 |

## 幻灯片对象属性

```typescript
interface Slide {
	src: string;                            // 资源路径
	color?: string;                         // 背景色
	delay?: number;                         // 单独设置停留时间
	align?: 'left' | 'center' | 'right';    // 水平对齐
	valign?: 'top' | 'center' | 'bottom';   // 垂直对齐
	transition?: string;                    // 单独过渡效果
	transitionDuration?: number;            // 单独过渡时长
	cover?: boolean;                        // 是否覆盖模式
	video?: {                               // 视频配置
		src: string[];                      // 多格式源
		muted?: boolean;                    // 静音
		loop?: boolean;                     // 循环
	};
}
```

## 可用过渡效果

- `fade`: 淡入淡出
- `slideLeft`: 左滑进入
- `slideRight`: 右滑进入
- `zoomIn`: 放大进入
- `zoomOut`: 缩小退出
- `zoomInOut`: 组合缩放

## 组件方法

通过ref可调用以下方法：

```tsx
const vegasRef = useRef();

// 可用方法
vegasRef.current.play();        // 开始播放
vegasRef.current.pause();       // 暂停播放
vegasRef.current.next();        // 下一张
vegasRef.current.previous();    // 上一张
```

## 浏览器支持

- Chrome (最新版)
- Firefox (最新版)
- Safari (最新版)
- Edge (最新版)

## 性能优化建议

1. 使用前优化图片体积
2. 选择合适的视频格式和分辨率
3. 启用预加载提升性能
4. 推荐使用WebP格式图片
5. 适当压缩视频文件

## 已知问题

- 部分浏览器需用户交互后才允许视频自动播放
- Safari对某些视频格式支持有限

## 致谢

本组件灵感来源于Jay Salvat开发的[jQuery版Vegas背景轮播插件](https://github.com/jaysalvat/vegas)
，使用React和TypeScript进行了现代化重构。
