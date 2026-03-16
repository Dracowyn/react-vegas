import { useEffect, useRef } from 'react';
import { Logger } from "../types";

/**
 * 页面可见性变化钩子
 * @param play
 * @param pause
 * @param log
 */
export const useVisibilityChange = (
	isPlaying: boolean,
	play: () => void,
	pause: () => void,
	log: Logger
) => {
	const shouldResumeRef = useRef(false);

	useEffect(() => {
		shouldResumeRef.current = isPlaying;
	}, [isPlaying]);

	useEffect(() => {
		const handleVisibilityChange = () => {
			if (document.hidden) {
				shouldResumeRef.current = isPlaying;
				log("页面隐藏，暂停播放幻灯片");
				pause();
			} else if (shouldResumeRef.current) {
				log("页面可见，继续播放幻灯片");
				play();
			}
		};

		document.addEventListener("visibilitychange", handleVisibilityChange);
		return () => {
			document.removeEventListener("visibilitychange", handleVisibilityChange);
		};
	}, [isPlaying, log, pause, play]);
};
