import {useEffect, useRef, useState, useCallback, useImperativeHandle, forwardRef} from "react";
import {VegasProps} from "./types";
import {VegasLoader} from "./components/VegasLoader";
import {VegasTimer} from "./components/VegasTimer";
import {VegasOverlay} from "./components/VegasOverlay";
import {VegasDefaultBackground} from "./components/VegasDefaultBackground";
import {VegasSlideRenderer} from "./components/VegasSlideRenderer";
import {VegasSlide} from "./components/VegasSlide";
import {useLogger} from "./hooks/useLogger";
import {usePreload} from "./hooks/usePreload";
import {useAnimationVariants} from "./hooks/useAnimationVariants";
import {useVegasState} from "./hooks/useVegasState";
import {useAutoplay} from "./hooks/useAutoplay";
import {useVisibilityChange} from "./hooks/useVisibilityChange";


// Vegas主组件
export const Vegas = forwardRef<{
	previous: () => void;
	next: () => void;
	play: () => void;
	pause: () => void;
} | null, VegasProps>((props, ref) => {
	const {
		slide = 0,
		delay = 5000,
		loop = true,
		preload = false,
		preloadImage = false,
		preloadImageBatch,
		preLoadImageBatch,
		preloadVideo = false,
		showLoading = false,
		timer = false,
		overlay = false,
		autoplay = true,
		shuffle = false,
		cover = true,
		color = null,
		align = "center",
		valign = "center",
		firstTransition = null,
		firstTransitionDuration = 3000,
		transition = "fade",
		transitionDuration = 1000,
		defaultBackground,
		defaultBackgroundDuration = 3000,
		debug = false,
		slides,
		onInit,
		onPlay,
		onPause,
		onWalk
	} = props;

	// 状态管理
	const [isTransitioning, setIsTransitioning] = useState(false);
	const [showDefaultBg, setShowDefaultBg] = useState(true);
	const defaultBackgroundTimerRef = useRef<number | null>(null);
	const hideDefaultBackgroundTimerRef = useRef<number | null>(null);

	// 日志函数
	const {log, logWarn, logError} = useLogger(debug);
	const containerRef = useRef<HTMLDivElement>(null);
	const effectivePreloadImageBatch = preloadImageBatch ?? preLoadImageBatch ?? 3;

	// 预加载资源
	const {loading, loadProgress, loadedImages, batchPreloadImages} =
		usePreload(slides, preloadImage, preloadVideo, effectivePreloadImageBatch, log, logWarn, logError);

	// 动画变体配置
	const {variants} = useAnimationVariants(transitionDuration);

	// 幻灯片状态管理
	const vegasState = useVegasState(
		slide,
		slides,
		loop,
		shuffle,
		isTransitioning,
		log,
		onWalk
	);

	const {
		currentSlide,
		isPlaying,
		setIsPlaying,
		visibleSlides,
		isFirstTransition,
		setIsFirstTransition,
		play: statePlay,
		pause: statePause,
		next: stateNext,
		previous: statePrevious,
	} = vegasState;

	const startTransition = useCallback((transitionStarted: boolean) => {
		if (transitionStarted) {
			setIsTransitioning(true);
		}

		return transitionStarted;
	}, []);

	const next = useCallback(() => startTransition(stateNext()), [startTransition, stateNext]);
	const previous = useCallback(() => startTransition(statePrevious()), [startTransition, statePrevious]);

	// 播放控制函
	const play = useCallback(() => {
		statePlay();

		if (isFirstTransition && showDefaultBg) {
			logWarn("默认背景显示中，等待动画完成");
			if (hideDefaultBackgroundTimerRef.current !== null) {
				clearTimeout(hideDefaultBackgroundTimerRef.current);
			}

			hideDefaultBackgroundTimerRef.current = window.setTimeout(() => {
				setShowDefaultBg(false);
				log("默认背景隐藏");
			}, transitionDuration);
			setIsFirstTransition(false);
		}

		onPlay?.();
	}, [isFirstTransition, log, logWarn, onPlay, showDefaultBg, statePlay, transitionDuration]);

	// 暂停控制函数
	const pause = useCallback(() => {
		statePause();
		onPause?.();
	}, [statePause, onPause]);

	// 自动播放逻辑
	useAutoplay(isPlaying, isTransitioning, currentSlide, slides, delay, next, log);

	// 页面可见性变化处理
	useVisibilityChange(isPlaying, play, pause, log);

	useEffect(() => {
		setShowDefaultBg(Boolean(defaultBackground));
	}, [defaultBackground]);

	// 初始化
	useEffect(() => {
		log("Vegas组件开始初始化");
		onInit?.();
	}, [log, onInit]);

	useEffect(() => {
		let disposed = false;

		if (defaultBackgroundTimerRef.current !== null) {
			clearTimeout(defaultBackgroundTimerRef.current);
			defaultBackgroundTimerRef.current = null;
		}

		if (!preload) {
			setIsPlaying(false);
			if (defaultBackground) {
				log(`存在默认背景，关闭自动播放`);
				log(`设置默认背景: ${defaultBackground}`);
				log(`设置默认背景显示定时器，延迟: ${defaultBackgroundDuration}ms`);
				defaultBackgroundTimerRef.current = window.setTimeout(() => {
					if (!disposed && autoplay) {
						log("默认背景显示完成，开始自动播放");
						play();
					}
				}, defaultBackgroundDuration);
			} else if (autoplay) {
				play();
			}

			return () => {
				disposed = true;
				if (defaultBackgroundTimerRef.current !== null) {
					clearTimeout(defaultBackgroundTimerRef.current);
					defaultBackgroundTimerRef.current = null;
				}
			};
		}

		log("开始预加载资源");
		setIsPlaying(false);
		batchPreloadImages().then(() => {
			if (disposed) {
				return;
			}

			if (defaultBackground) {
				log(`存在默认背景，关闭自动播放`);
				log(`设置默认背景: ${defaultBackground}`);
				log(`设置默认背景显示定时器，延迟: ${defaultBackgroundDuration}ms`);
				defaultBackgroundTimerRef.current = window.setTimeout(() => {
					if (!disposed && autoplay) {
						log("默认背景显示完成，开始自动播放");
						play();
					}
				}, defaultBackgroundDuration);
			} else if (autoplay) {
				play();
			}
		});

		return () => {
			disposed = true;
			if (defaultBackgroundTimerRef.current !== null) {
				clearTimeout(defaultBackgroundTimerRef.current);
				defaultBackgroundTimerRef.current = null;
			}
		};
	}, [autoplay, batchPreloadImages, defaultBackground, defaultBackgroundDuration, log, pause, play, preload, setIsPlaying]);

	useEffect(() => {
		return () => {
			log("Vegas组件卸载");
			pause();

			if (defaultBackgroundTimerRef.current !== null) {
				clearTimeout(defaultBackgroundTimerRef.current);
			}

			if (hideDefaultBackgroundTimerRef.current !== null) {
				clearTimeout(hideDefaultBackgroundTimerRef.current);
			}
		};
	}, [log, pause]);

	// 动画结束处理
	useEffect(() => {
		if (isTransitioning) {
			const timer = setTimeout(() => {
				setIsTransitioning(false);
				log("幻灯片切换动画完成");
			}, transitionDuration);
			return () => clearTimeout(timer);
		}
	}, [isTransitioning, transitionDuration]);

	// 渲染幻灯片
	const renderSlide = useCallback((index: number) => {
		try {
			const slide = slides[index];
			if (!slide) {
				logError(`幻灯片索引 ${index} 不存在`);
				return null;
			}

			return (
				<VegasSlideRenderer
					slide={slide}
					index={index}
					isFirstTransition={isFirstTransition}
					firstTransition={firstTransition}
					firstTransitionDuration={firstTransitionDuration}
					transitionDuration={transitionDuration}
					transition={transition}
					cover={cover}
					align={align}
					valign={valign}
					color={color}
					variants={variants}
					preloadImage={preloadImage}
					loadedImages={loadedImages}
					next={next}
					log={log}
					logError={logError}
				/>
			);
		} catch (error) {
			logError("渲染幻灯片时发生错误:", error);
			return null;
		}
	}, [align, color, cover, firstTransition, firstTransitionDuration, isFirstTransition,
		loadedImages, log, logError, next, preloadImage, slides, transition, transitionDuration, valign, variants]);


	// 暴露组件实例方法
	useImperativeHandle(ref, () => ({
		previous,
		next,
		play,
		pause
	}));

	// Props 验证
	if (slides.length === 0) {
		logError("幻灯片数组不能为空");
		return null;
	}

	if (transitionDuration <= 0) {
		logWarn("transitionDuration 应该大于 0");
	}

	// 渲染组件
	return (
		<div
			ref={containerRef}
			style={{
				position: "relative",
				width: "100%",
				height: "100%",
				overflow: "hidden",
				backgroundColor: color || undefined
			}}
		>
			{/* 默认背景图层 */}
			{defaultBackground && showDefaultBg && (
				<VegasDefaultBackground
					backgroundUrl={defaultBackground.toString()}
				/>
			)}

			{/* 渲染幻灯片 */}
			{isPlaying && (
				<VegasSlide
					visibleSlides={visibleSlides}
					renderSlide={renderSlide}
				/>
			)}

			{/* 遮罩层 */}
			{overlay && (
				<VegasOverlay/>
			)}

			{/* 进度条 */}
			{timer && isPlaying && (
				<VegasTimer
					currentOrderIndex={vegasState.currentOrderIndex} totalSlides={slides.length}
				/>
			)}

			{/* 加载指示器 */}
			{showLoading && loading && (
				<VegasLoader loadProgress={loadProgress}/>
			)}
		</div>
	);
});

Vegas.displayName = "Vegas";
