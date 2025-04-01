import {FC} from "react";

interface VegasLoaderProps {
	loadProgress: number;
}

/**
 * 加载指示器组件
 * @param loadProgress
 * @constructor
 */
export const VegasLoader: FC<VegasLoaderProps> = ({
	                                                  loadProgress
                                                  }) => {
	return (
		<div style={{
			position: "absolute",
			top: "50%",
			left: "50%",
			transform: "translate(-50%, -50%)",
			textAlign: "center",
			color: "#fff",
			zIndex: 10,
			backgroundColor: "rgba(0,0,0,0.5)",
			padding: "20px",
			borderRadius: "8px"
		}}>
			<div>加载中... {loadProgress}%</div>
			<div style={{
				width: "200px",
				height: "5px",
				backgroundColor: "rgba(255,255,255,0.3)",
				marginTop: "10px"
			}}>
				<div style={{
					width: `${loadProgress}%`,
					height: "100%",
					backgroundColor: "#fff",
					transition: "width 0.3s"
				}}></div>
			</div>
		</div>
	);
};
