import { type MutableRefObject, useCallback, useEffect, useRef, useState } from "react";
import { Logger, VegasPhase } from "../types";

/**
 * Vegas 生命周期状态机：
 * idle -> preloading -> showingDefaultBackground -> firstSlide -> playing/paused
 */
export const useVegasLifecycle = (
	preload: boolean,
	autoplay: boolean,
	hasDefaultBackground: boolean,
	defaultBackgroundDuration: number,
	firstTransitionDuration: number,
	preloadResources: () => Promise<void>,
	log: Logger
) => {
	const [phase, setPhase] = useState<VegasPhase>("idle");
	const backgroundTimerRef = useRef<number | null>(null);
	const firstSlideTimerRef = useRef<number | null>(null);
	const lifecycleIdRef = useRef(0);

	const clearTimer = (timerRef: MutableRefObject<number | null>) => {
		if (timerRef.current !== null) {
			clearTimeout(timerRef.current);
			timerRef.current = null;
		}
	};

	const clearTimers = useCallback(() => {
		clearTimer(backgroundTimerRef);
		clearTimer(firstSlideTimerRef);
	}, []);

	const enterPlaybackPhase = useCallback((targetPhase: "playing" | "paused") => {
		clearTimer(firstSlideTimerRef);
		setPhase(targetPhase);
	}, []);

	const play = useCallback(() => {
		setPhase(currentPhase => {
			if (currentPhase === "paused" || currentPhase === "firstSlide") {
				clearTimer(firstSlideTimerRef);
				return "playing";
			}

			return currentPhase;
		});
	}, []);

	const pause = useCallback(() => {
		setPhase(currentPhase => {
			if (currentPhase === "playing" || currentPhase === "firstSlide") {
				clearTimer(firstSlideTimerRef);
				return "paused";
			}

			return currentPhase;
		});
	}, []);

	useEffect(() => {
		const lifecycleId = lifecycleIdRef.current + 1;
		lifecycleIdRef.current = lifecycleId;
		clearTimers();
		setPhase("idle");

		const runLifecycle = async () => {
			if (preload) {
				log("进入预加载阶段");
				setPhase("preloading");
				await preloadResources();
				if (lifecycleIdRef.current !== lifecycleId) {
					return;
				}
			}

			if (hasDefaultBackground) {
				log(`进入默认背景阶段，持续 ${defaultBackgroundDuration}ms`);
				setPhase("showingDefaultBackground");

				await new Promise<void>(resolve => {
					backgroundTimerRef.current = window.setTimeout(resolve, defaultBackgroundDuration);
				});

				if (lifecycleIdRef.current !== lifecycleId) {
					return;
				}
			}

			log("进入首帧阶段");
			setPhase("firstSlide");

			if (firstTransitionDuration <= 0) {
				enterPlaybackPhase(autoplay ? "playing" : "paused");
				return;
			}

			firstSlideTimerRef.current = window.setTimeout(() => {
				if (lifecycleIdRef.current !== lifecycleId) {
					return;
				}

				enterPlaybackPhase(autoplay ? "playing" : "paused");
			}, firstTransitionDuration);
		};

		void runLifecycle();

		return () => {
			lifecycleIdRef.current += 1;
			clearTimers();
		};
	}, [
		autoplay,
		clearTimers,
		defaultBackgroundDuration,
		enterPlaybackPhase,
		firstTransitionDuration,
		hasDefaultBackground,
		log,
		preload,
		preloadResources
	]);

	return {
		phase,
		isPlaying: phase === "playing",
		isFirstTransition: phase === "firstSlide",
		shouldRenderSlides: phase === "firstSlide" || phase === "playing" || phase === "paused",
		showDefaultBackground: phase === "showingDefaultBackground",
		play,
		pause
	};
};
