import {useMemo} from "react";
import {Logger} from "../types";

const noopLogger: Logger = () => {
};

/**
 * 自定义日志钩子
 * @param debug
 */
export const useLogger = (debug: boolean) => {
	return useMemo(() => {
		if (!debug) {
			return {
				log: noopLogger,
				logError: noopLogger,
				logWarn: noopLogger
			};
		}

		return {
			log: console.log.bind(console) as Logger,
			logError: console.error.bind(console) as Logger,
			logWarn: console.warn.bind(console) as Logger
		};
	}, [debug]);
};
