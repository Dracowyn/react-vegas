import { useEffect, useRef } from 'react';
import { Logger } from "../types";

/**
 * 页面可见性变化钩子
 * @param isPlaying
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
	const isPlayingRef = useRef(isPlaying);
	const shouldResumeRef = useRef(false);
	const playRef = useRef(play);
	const pauseRef = useRef(pause);
	const logRef = useRef(log);

	useEffect(() => {
		isPlayingRef.current = isPlaying;
	}, [isPlaying]);

	useEffect(() => {
		playRef.current = play;
		pauseRef.current = pause;
		logRef.current = log;
	}, [play, pause, log]);

	useEffect(() => {
		const handleVisibilityChange = () => {
			if (document.hidden) {
				shouldResumeRef.current = isPlayingRef.current;
				logRef.current("页面隐藏，暂停播放幻灯片");
				pauseRef.current();
			} else if (shouldResumeRef.current) {
				logRef.current("页面可见，继续播放幻灯片");
				playRef.current();
			}
		};

		document.addEventListener("visibilitychange", handleVisibilityChange);
		return () => {
			document.removeEventListener("visibilitychange", handleVisibilityChange);
		};
	}, []);
};
