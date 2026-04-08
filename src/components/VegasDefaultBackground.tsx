import {FC} from "react";
import {motion} from "motion/react";
import {sanitizeCssUrl} from "../utils/sanitizeUrl";

interface VegasDefaultBackgroundProps {
	backgroundUrl: string;
}

/**
 * 默认背景组件
 * @param backgroundUrl
 * @constructor
 */
export const VegasDefaultBackground: FC<VegasDefaultBackgroundProps> = ({
	                                                                        backgroundUrl
                                                                        }) => {
	return (
		<motion.div
			initial={{opacity: 1}}
			style={{
				position: "absolute",
				top: 0,
				left: 0,
				width: "100%",
				height: "100%",
				backgroundImage: sanitizeCssUrl(backgroundUrl),
				backgroundSize: "cover",
				backgroundPosition: "center",
				zIndex: 0
			}}
		/>
	);
};
