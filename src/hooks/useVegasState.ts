import { useState, useCallback, useEffect } from "react";
import { SlideProps, Logger } from "../types";

const buildSlideOrder = (length: number, shuffle: boolean) => {
	const order = Array.from({length}, (_, index) => index);

	if (shuffle) {
		for (let index = order.length - 1; index > 0; index--) {
			const randomIndex = Math.floor(Math.random() * (index + 1));
			[order[index], order[randomIndex]] = [order[randomIndex], order[index]];
		}
	}

	return order;
};

const clampSlideIndex = (index: number, length: number) => {
	if (length === 0) {
		return 0;
	}

	return Math.min(Math.max(index, 0), length - 1);
};

/**
 * Vegas核心状态管理钩子
 * @param initialSlide
 * @param slides
 * @param loop
 * @param shuffle
 * @param isTransitioning
 * @param log
 * @param onWalk
 */
export const useVegasState = (
	initialSlide: number,
	slides: SlideProps[],
	loop: boolean,
	shuffle: boolean,
	isTransitioning: boolean,
	log: Logger,
	onWalk?: () => void,
	stopPlayback?: () => void
) => {
	const [currentSlide, setCurrentSlide] = useState(initialSlide);
	const [slideOrder, setSlideOrder] = useState<number[]>([]);
	const [currentOrderIndex, setCurrentOrderIndex] = useState(0);
	const [visibleSlides, setVisibleSlides] = useState([initialSlide]);

	// 初始化或同步顺序
	useEffect(() => {
		if (slides.length === 0) {
			setSlideOrder([]);
			setCurrentOrderIndex(0);
			setVisibleSlides([]);
			return;
		}

		const order = buildSlideOrder(slides.length, shuffle);
		const normalizedInitialSlide = clampSlideIndex(initialSlide, slides.length);
		const initialOrderIndex = shuffle ? order.indexOf(normalizedInitialSlide) : normalizedInitialSlide;
		const nextOrderIndex = initialOrderIndex >= 0 ? initialOrderIndex : 0;
		const nextSlideIndex = order[nextOrderIndex] ?? normalizedInitialSlide;

		if (shuffle) {
			log("幻灯片随机排序完成:", order);
		}

		setSlideOrder(order);
		setCurrentOrderIndex(nextOrderIndex);
		setCurrentSlide(nextSlideIndex);
		setVisibleSlides([nextSlideIndex]);
	}, [initialSlide, shuffle, slides.length, log]);

	// 切换到指定幻灯片
	const goTo = useCallback((index: number) => {
		if (index < 0 || index >= slides.length || isTransitioning || index === currentSlide) {
			return false;
		}

		log(`切换到幻灯片: ${index}`);
		setVisibleSlides([index]);
		setCurrentSlide(index);

		const nextOrderIndex = slideOrder.indexOf(index);
		if (nextOrderIndex >= 0) {
			setCurrentOrderIndex(nextOrderIndex);
		}

		onWalk?.();

		return true;
	}, [currentSlide, isTransitioning, log, onWalk, slideOrder, slides.length]);

	// 下一页逻辑
	const next = useCallback(() => {
		if (isTransitioning) {
			log("正在切换中,跳过本次切换");
			return false;
		}

		if (slideOrder.length === 0) {
			return false;
		}

		let nextOrderIndex = currentOrderIndex + 1;
		if (nextOrderIndex >= slideOrder.length) {
			if (loop) {
				nextOrderIndex = 0;
				log("到达最后一张,循环回到第一张");
			} else {
				log("到达最后一张,停止播放");
				stopPlayback?.();
				return false;
			}
		}

		const nextSlideIndex = slideOrder[nextOrderIndex];
		return goTo(nextSlideIndex);
	}, [currentOrderIndex, slideOrder, isTransitioning, loop, goTo, log, stopPlayback]);

	// 上一页逻辑
	const previous = useCallback(() => {
		if (isTransitioning) {
			log("正在切换中,跳过本次切换");
			return false;
		}

		if (slideOrder.length === 0) {
			return false;
		}

		let prevOrderIndex = currentOrderIndex - 1;
		if (prevOrderIndex < 0) {
			if (loop) {
				prevOrderIndex = slideOrder.length - 1;
				log("到达第一张,循环到最后一张");
			} else {
				log("到达第一张,停止播放");
				stopPlayback?.();
				return false;
			}
		}

		const prevSlideIndex = slideOrder[prevOrderIndex];
		return goTo(prevSlideIndex);
	}, [currentOrderIndex, slideOrder, isTransitioning, loop, goTo, log, stopPlayback]);

	return {
		currentSlide,
		slideOrder,
		currentOrderIndex,
		visibleSlides,
		next,
		previous,
		goTo
	};
};
