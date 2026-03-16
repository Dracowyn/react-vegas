import type { ReactNode } from "react";
import { cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";

vi.mock("motion/react", async () => {
	const React = await import("react");
	type MockMotionProps = {
		children?: ReactNode;
	} & Record<string, unknown>;

	const createMotionComponent = (tagName: string) =>
		React.forwardRef<HTMLElement, MockMotionProps>(({children, ...props}, ref) =>
			React.createElement(tagName, {...props, ref}, children as ReactNode)
		);

	return {
		motion: new Proxy({}, {
			get: (_, tagName) => createMotionComponent(String(tagName))
		}),
		AnimatePresence: ({children}: {children: React.ReactNode}) =>
			React.createElement(React.Fragment, null, children)
	};
});

Object.defineProperty(HTMLMediaElement.prototype, "play", {
	configurable: true,
	value: vi.fn().mockResolvedValue(undefined)
});

Object.defineProperty(HTMLMediaElement.prototype, "pause", {
	configurable: true,
	value: vi.fn()
});

afterEach(() => {
	cleanup();
	document.head.innerHTML = "";
	document.body.innerHTML = "";
	vi.clearAllMocks();
});
