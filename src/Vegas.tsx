import {useEffect, useRef, useState, useCallback, useImperativeHandle, forwardRef} from "react";
import {VegasHandle, VegasProps} from "./types";
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
import {useVegasLifecycle} from "./hooks/useVegasLifecycle";
import {useVisibilityChange} from "./hooks/useVisibilityChange";


// Vegas主组件
export const Vegas = forwardRef<VegasHandle | null, VegasProps>((props, ref) => {
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
		loadingText,
		overlayColor,
		debug = false,
		slides,
		onInit,
		onPlay,
		onPause,
		onWalk
	} = props;

	const [isTransitioning, setIsTransitioning] = useState(false);

	const {log, logWarn, logError} = useLogger(debug);
	const previousPhaseRef = useRef<string | null>(null);
	const effectivePreloadImageBatch = preloadImageBatch ?? preLoadImageBatch ?? 3;

	const {loading, loadProgress, loadedImages, preloadResources} =
		usePreload(slides, preloadImage, preloadVideo, effectivePreloadImageBatch, log, logWarn, logError);

	const {variants} = useAnimationVariants(transitionDuration);

	const {
		phase,
		isPlaying,
		isFirstTransition,
		shouldRenderSlides,
		showDefaultBackground,
		play: startPlayback,
		pause: stopPlayback
	} = useVegasLifecycle(
		preload,
		autoplay,
		Boolean(defaultBackground),
		defaultBackgroundDuration,
		firstTransitionDuration,
		preloadResources,
		log
	);

	const vegasState = useVegasState(
		slide,
		slides,
		loop,
		shuffle,
		isTransitioning,
		log,
		onWalk,
		stopPlayback
	);

	const {
		currentSlide,
		currentOrderIndex,
		visibleSlides,
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

	const play = useCallback(() => {
		log("开始播放幻灯片");
		startPlayback();
	}, [log, startPlayback]);

	const pause = useCallback(() => {
		log("暂停播放幻灯片");
		stopPlayback();
	}, [log, stopPlayback]);

	useAutoplay(isPlaying, isTransitioning, currentSlide, slides, delay, next, log);
	useVisibilityChange(isPlaying, play, pause, log);

	useEffect(() => {
		log("Vegas组件开始初始化");
		onInit?.();
	}, [log, onInit]);

	useEffect(() => {
		const previousPhase = previousPhaseRef.current;

		if (previousPhase !== phase) {
			if (phase === "playing") {
				onPlay?.();
			}

			if (phase === "paused" && previousPhase === "playing") {
				onPause?.();
			}

			previousPhaseRef.current = phase;
		}
	}, [onPause, onPlay, phase]);

	useEffect(() => {
		return () => {
			log("Vegas组件卸载");
		};
	}, [log]);

	useEffect(() => {
		if (isTransitioning) {
			const timer = setTimeout(() => {
				setIsTransitioning(false);
				log("幻灯片切换动画完成");
			}, transitionDuration);
			return () => clearTimeout(timer);
		}
	}, [isTransitioning, log, transitionDuration]);

	const renderSlide = useCallback((index: number) => {
		try {
			const slide = slides[index];
			if (!slide) {
				logError(`幻灯片索引 ${index} 不存在`);
				return null;
			}

			return (
				<VegasSlideRenderer
					key={slide.src}
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
					isMediaPlaying={phase !== "paused"}
					canAdvance={phase === "playing"}
					next={next}
					log={log}
					logWarn={logWarn}
					logError={logError}
				/>
			);
		} catch (error) {
			logError("渲染幻灯片时发生错误:", error);
			return null;
		}
	}, [align, color, cover, firstTransition, firstTransitionDuration, isFirstTransition,
		loadedImages, log, logError, logWarn, next, phase, preloadImage, slides, transition, transitionDuration, valign, variants]);

	useImperativeHandle(ref, () => ({
		previous,
		next,
		play,
		pause
	}));

	if (slides.length === 0) {
		logError("幻灯片数组不能为空");
		return null;
	}

	if (transitionDuration <= 0) {
		logWarn("transitionDuration 应该大于 0");
	}

	return (
		<div
			style={{
				position: "relative",
				width: "100%",
				height: "100%",
				overflow: "hidden",
				backgroundColor: color || undefined
			}}
		>
			{/* 默认背景图层 */}
			{defaultBackground && showDefaultBackground && (
				<VegasDefaultBackground
					backgroundUrl={defaultBackground}
				/>
			)}

			{shouldRenderSlides && (
				<VegasSlide
					visibleSlides={visibleSlides}
					renderSlide={renderSlide}
				/>
			)}

			{/* 遮罩层 */}
			{overlay && (
				<VegasOverlay overlayColor={overlayColor}/>
			)}

			{/* 进度条 */}
			{timer && shouldRenderSlides && (
				<VegasTimer
					currentOrderIndex={currentOrderIndex}
					totalSlides={slides.length}
				/>
			)}

			{/* 加载指示器 */}
			{showLoading && loading && (
				<VegasLoader loadProgress={loadProgress} loadingText={loadingText}/>
			)}
		</div>
	);
});

Vegas.displayName = "Vegas";
