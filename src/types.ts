// Vegas组件的Props类型定义
export interface VegasProps {
	slide?: number;                   // 初始幻灯片索引
	delay?: number;                   // 切换延迟时间(毫秒)
	loop?: boolean;                   // 是否循环播放
	preload?: boolean;                // 是否预加载资源
	preloadImage?: boolean;           // 是否预加载图片
	preloadImageBatch?: number;       // 批量预加载图片数量
	/** @deprecated 使用 `preloadImageBatch` 代替 */
	preLoadImageBatch?: number;       // 批量预加载图片数量
	preloadVideo?: boolean;           // 是否预加载视频
	showLoading?: boolean;            // 是否显示加载指示器
	timer?: boolean;                  // 是否显示计时器
	overlay?: boolean;                // 是否显示遮罩层
	autoplay?: boolean;               // 是否自动播放
	shuffle?: boolean;                // 是否随机播放
	cover?: boolean;                  // 是否覆盖整个容器
	color?: string | null;            // 背景颜色
	align?: "left" | "center" | "right"; // 水平对齐方式
	valign?: "top" | "center" | "bottom"; // 垂直对齐方式
	firstTransition?: string | null;      // 第一次切换动画
	firstTransitionDuration?: number;     // 第一次切换动画持续时间
	transition?: string;                  // 切换动画类型
	transitionDuration?: number;          // 切换动画持续时间
	defaultBackground?: string;           // 默认背景图
	defaultBackgroundDuration?: number;   // 默认背景图与第一张幻灯片间隔时间
	loadingText?: string;                 // 加载中文案，默认 "Loading..."
	overlayColor?: string;                // 遮罩层颜色，默认 "rgba(0,0,0,0.3)"
	debug?: boolean;                      // 是否启用日志
	slides: Array<SlideProps>;
	onInit?: () => void;                  // 初始化回调
	onPlay?: () => void;                  // 播放回调
	onPause?: () => void;                 // 暂停回调
	onWalk?: () => void;                  // 切换回调
}

export interface SlideProps {
	src: string;                      // 图片/视频源地址
	color?: string | null;            // 幻灯片背景色
	delay?: number | null;            // 当前幻灯片延迟时间
	align?: "left" | "center" | "right"; // 当前幻灯片水平对齐
	valign?: "top" | "center" | "bottom"; // 当前幻灯片垂直对齐
	transition?: string | null;        // 当前幻灯片切换动画
	transitionDuration?: number | null; // 当前幻灯片切换动画持续时间
	cover?: boolean;                   // 当前幻灯片是否覆盖
	video?: {
		src: string[];                 // 视频源地址数组
		muted?: boolean;               // 是否静音
		loop?: boolean;                // 是否循环播放
	};
}

export interface VegasHandle {
	previous: () => void;
	next: () => void;
	play: () => void;
	pause: () => void;
}

export type Logger = (message: string, ...args: unknown[]) => void;

export type VegasPhase =
	| "idle"
	| "preloading"
	| "showingDefaultBackground"
	| "firstSlide"
	| "playing"
	| "paused";
