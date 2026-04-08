import {CSSProperties, FC, useEffect, useRef} from "react";
import {motion} from "motion/react";
import {SlideProps, Logger} from "../types";
import {VegasVariants} from "../hooks/useAnimationVariants";
import {sanitizeCssUrl} from "../utils/sanitizeUrl";

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
	variants: VegasVariants;
	preloadImage: boolean;
	loadedImages: Record<string, boolean>;
	isMediaPlaying: boolean;
	canAdvance: boolean;
	next: () => void;
	log: Logger;
	logWarn: Logger;
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
	isMediaPlaying,
	canAdvance,
	next,
	log,
	logWarn,
	logError
                                                                      }) => {
	const videoRef = useRef<HTMLVideoElement>(null);
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

	useEffect(() => {
		if (!slide.video || !videoRef.current) {
			return;
		}

		if (!isMediaPlaying) {
			videoRef.current.pause();
			return;
		}

		const playPromise = videoRef.current.play();
		if (playPromise) {
			playPromise.catch(error => {
				logWarn(`视频播放被浏览器阻止: ${slide.src}`, error);
			});
		}
	}, [isMediaPlaying, logWarn, slide.src, slide.video]);

	const content = slide.video ? (
		<video
			ref={videoRef}
			key={index}
			style={videoStyle}
			autoPlay={isMediaPlaying}
			muted={slide.video.muted}
			loop={slide.video.loop}
			onEnded={() => {
				if (!slide.video?.loop && canAdvance) {
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
		<img
			key={index}
			src={slide.src}
			alt=""
			style={{
				...surfaceStyle,
				objectFit: mediaFit,
				objectPosition: mediaPosition,
			}}
			aria-hidden={!isImagePreloaded}
			onError={() => {
				logError(`图片加载失败: ${slide.src}`);
			}}
		/>
	);

	const variant = variants[currentTransition] || variants.fade;

	return (
		<motion.div
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
