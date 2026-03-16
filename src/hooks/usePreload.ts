import { useState, useCallback, useEffect, useRef } from "react";
import { SlideProps, Logger } from "../types";

/**
 * 预加载资源的自定义钩子
 * @param slides
 * @param preloadImage
 * @param preloadVideo
 * @param preLoadImageBatch
 * @param log
 * @param logWarn
 * @param logError
 */
export const usePreload = (
	slides: SlideProps[],
	preloadImage: boolean,
	preloadVideo: boolean,
	preLoadImageBatch: number,
	log: Logger,
	logWarn: Logger,
	logError: Logger
) => {
	const [loading, setLoading] = useState(false);
	const [loadProgress, setLoadProgress] = useState(0);
	const [loadedImages, setLoadedImages] = useState<Record<string, boolean>>({});
	const preloadLinksRef = useRef<HTMLLinkElement[]>([]);

	useEffect(() => {
		return () => {
			preloadLinksRef.current.forEach(link => {
				link.remove();
			});
			preloadLinksRef.current = [];
		};
	}, []);

	// 批量预加载图片
	const batchPreloadImages = useCallback(async () => {
		if (!preloadImage) return;

		setLoading(true);
		setLoadProgress(0);
		const batchSize = preLoadImageBatch;
		const imageSlides = slides.filter(slide => !slide.video);

		if (imageSlides.length === 0) {
			setLoadProgress(100);
			setLoading(false);
			return;
		}

		try {
			for (let i = 0; i < imageSlides.length; i += batchSize) {
				const batch = imageSlides.slice(i, i + batchSize);
				const promises = batch.map(slide => {
					return new Promise<void>((resolve) => {
						const img = new Image();
						img.onload = () => {
							setLoadedImages(prev => ({...prev, [slide.src]: true}));
							resolve();
						};
						img.onerror = () => {
							logWarn(`图片加载失败: ${slide.src}`);
							resolve();
						};
						img.src = slide.src;
					});
				});

				await Promise.all(promises);
				setLoadProgress(Math.min(100, Math.floor(((i + batch.length) / imageSlides.length) * 100)));
			}
		} catch (error) {
			logError("预加载图片时发生错误:", error);
		} finally {
			setLoading(false);
		}
	}, [slides, preloadImage, preLoadImageBatch, log, logWarn, logError]);

	// 预加载视频资源
	const preloadVideoResources = useCallback(() => {
		if (!preloadVideo) return;

		log("开始预加载视频资源");
		preloadLinksRef.current.forEach(link => {
			link.remove();
		});
		preloadLinksRef.current = [];

		slides.forEach(slide => {
			if (slide.video) {
				slide.video.src.forEach(src => {
					const link = document.createElement("link");
					link.rel = "preload";
					link.as = "video";
					link.href = src;
					document.head.appendChild(link);
					preloadLinksRef.current.push(link);
					log(`预加载视频: ${src}`);
				});
			}
		});
	}, [slides, preloadVideo, log]);

	// 执行所有预加载操作
	const preloadResources = useCallback(async () => {
		log("开始预加载资源");
		setLoading(true);

		const preloadPromises: Promise<void>[] = [];

		if (preloadImage) {
			preloadPromises.push(batchPreloadImages());
		}

		if (preloadVideo) {
			preloadVideoResources();
		}

		try {
			await Promise.all(preloadPromises);
			log("所有资源预加载完成");
		} catch (error) {
			logError("预加载资源时发生错误:", error);
		} finally {
			setLoading(false);
		}
	}, [batchPreloadImages, preloadVideoResources, preloadImage, preloadVideo, log, logError]);

	return {
		loading,
		loadProgress,
		loadedImages,
		preloadResources,
		batchPreloadImages,
		preloadVideoResources
	};
};
