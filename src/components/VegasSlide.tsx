import {FC, ReactNode} from "react";
import {AnimatePresence} from "motion/react";

interface VegasSlideProps {
	visibleSlides: number[];
	renderSlide: (index: number) => ReactNode;
}

/**
 * 动画幻灯片组件
 * @param visibleSlides
 * @param renderSlide
 * @constructor
 */
export const VegasSlide: FC<VegasSlideProps> = ({
	                                                visibleSlides,
	                                                renderSlide
                                                }) => {
	return (
		<AnimatePresence mode="sync" presenceAffectsLayout={false}>
			{visibleSlides.map(index => renderSlide(index))}
		</AnimatePresence>
	);
};
