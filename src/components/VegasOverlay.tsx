import {FC} from "react";

interface VegasOverlayProps {
	overlayColor?: string;
}

/**
 * 遮罩层组件
 * @param overlayColor
 * @constructor
 */
export const VegasOverlay: FC<VegasOverlayProps> = ({
	                                                     overlayColor = "rgba(0,0,0,0.3)"
                                                     }) => {
	return (
		<div
			style={{
				position: "absolute",
				top: 0,
				left: 0,
				width: "100%",
				height: "100%",
				background: overlayColor
			}}
		/>
	);
};
