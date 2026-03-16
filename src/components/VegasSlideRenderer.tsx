import React, {CSSProperties, FC} from "react";
import {motion} from "motion/react";
import {SlideProps, Logger} from "../types";

interface VegasSlideRendererProps {
	slide: SlideProps;
	index: number;
	isFirstTransition: boolean;
	firstTransition: string | null;
	firstTransitionDuration: number;
	transitionDuration: number;
	transition: string;
	cover: boolean;
	align: string;
	valign: string;
	color: string | null;
	variants: any;
	preloadImage: boolean;
	loadedImages: Record<string, boolean>;
	next: () => void;
	log: Logger;
	logError: Logger;
}

/**
 * 幻灯片渲染器组件
 * @param slide
 * @param index
 * @param isFirstTransition
 * @param firstTransitionDuration
 * @param transitionDuration
 * @param transition
 * @param cover
 * @param align
 * @param valign
 * @param color
 * @param variants
 * @param preloadImage
 * @param loadedImages
 * @param next
 * @param log
 * @param logError
 * @constructor
 */
export const VegasSlideRenderer: FC<VegasSlideRendererProps> = ({
	                                                                      slide,
	                                                                      index,
	                                                                      isFirstTransition,
	                                                                      firstTransition,
	                                                                      firstTransitionDuration,
	                                                                      transitionDuration,
	                                                                      transition,
	                                                                      cover,
	                                                                      align,
	                                                                      valign,
	                                                                      color,
	                                                                      variants,
	                                                                      preloadImage,
	                                                                      loadedImages,
	                                                                      next,
	                                                                      log,
	                                                                      logError
                                                                      }) => {
	const mediaFit = slide.cover ?? cover ? "cover" : "contain";
	const mediaPosition = `${slide.align || align} ${slide.valign || valign}`;
	const currentTransition = isFirstTransition && firstTransition ? firstTransition : slide.transition || transition;
	const surfaceStyle: CSSProperties = {
		position: "absolute",
		top: 0,
		left: 0,
		width: "100%",
		height: "100%",
		backgroundColor: slide.color || color || undefined
	};
	const videoStyle: CSSProperties = {
		...surfaceStyle,
		objectFit: mediaFit,
		objectPosition: mediaPosition
	};

	const currentTransitionDurationValue = isFirstTransition
		? firstTransitionDuration
		: slide.transitionDuration || transitionDuration;

	const isImagePreloaded = preloadImage && loadedImages[slide.src];

	const content = slide.video ? (
		<video
			key={index}
			style={videoStyle}
			autoPlay
			muted={slide.video.muted}
			loop={slide.video.loop}
			onEnded={() => {
				if (!slide.video?.loop) {
					log("视频播放结束,切换到下一张");
					next();
				}
			}}
		>
			{slide.video.src.map((src, i) => (
				<source key={i} src={src}/>
			))}
		</video>
	) : (
		<div
			key={index}
			style={{
				...surfaceStyle,
				backgroundImage: `url(${slide.src})`,
				backgroundSize: mediaFit,
				backgroundPosition: mediaPosition,
				backgroundRepeat: "no-repeat"
			}}
			aria-hidden={!isImagePreloaded}
			onError={() => {
				logError(`图片加载失败: ${slide.src}`);
			}}
		/>
	);

	const variant = variants[currentTransition as keyof typeof variants] || variants.fade;

	log(`渲染幻灯片: ${slide.src}, 动画: ${currentTransition}, 持续时间: ${currentTransitionDurationValue}ms`);

	return (
		<motion.div
			key={slide.src}
			initial="exit"
			animate="enter"
			exit="exit"
			variants={
				currentTransition in variants
					? variant({duration: currentTransitionDurationValue / 1000})
					: variant({duration: transitionDuration / 1000})
			}
			style={{
				position: "absolute",
				width: "100%",
				height: "100%"
			}}
		>
			{content}
		</motion.div>
	);
};
