import { useEffect } from 'react';
import { SlideProps, Logger } from "../types";

/**
 * 自动播放钩子
 * @param isPlaying
 * @param isTransitioning
 * @param currentSlide
 * @param slides
 * @param delay
 * @param next
 * @param log
 */
export const useAutoplay = (
	isPlaying: boolean,
	isTransitioning: boolean,
	currentSlide: number,
	slides: SlideProps[],
	delay: number,
	next: () => void,
	log: Logger
) => {
	useEffect(() => {
		if (!isPlaying || isTransitioning || !slides[currentSlide]) {
			return;
		}

		const currentDelay = slides[currentSlide].delay || delay;
		log(`设置自动播放定时器,延迟: ${currentDelay}ms`);
		const timer = window.setTimeout(() => {
			next();
		}, currentDelay);

		return () => {
			log("清理自动播放定时器");
			clearTimeout(timer);
		};
	}, [currentSlide, delay, isPlaying, isTransitioning, log, next, slides]);
};
