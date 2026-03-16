import { act, render, waitFor } from "@testing-library/react";
import { createRef } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Vegas } from "../src";

type VegasRefHandle = {
	previous: () => void;
	next: () => void;
	play: () => void;
	pause: () => void;
};

const slides = [
	{src: "/slide-1.jpg"},
	{src: "/slide-2.jpg"}
];

const findSlideBySource = (container: HTMLElement, source: string) =>
	Array.from(container.querySelectorAll("div")).find(node =>
		(node as HTMLDivElement).style.backgroundImage.includes(source)
	);

const advanceTimers = async (duration: number) => {
	await act(async () => {
		vi.advanceTimersByTime(duration);
	});
};

const flushEffects = async () => {
	await act(async () => {
		await Promise.resolve();
	});
};

describe("Vegas", () => {
	afterEach(() => {
		if (vi.isFakeTimers()) {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("renders the first slide even when autoplay is disabled", async () => {
		const {container} = render(
			<Vegas
				slides={[slides[0]]}
				autoplay={false}
				firstTransitionDuration={0}
			/>
		);

		await flushEffects();

		await waitFor(() => {
			expect(findSlideBySource(container, slides[0].src)).toBeTruthy();
		});
	});

	it("keeps the current slide mounted when pause is called", async () => {
		const ref = createRef<VegasRefHandle>();
		const {container} = render(
			<Vegas
				ref={ref}
				slides={[slides[0]]}
				autoplay
				firstTransitionDuration={0}
			/>
		);

		await flushEffects();

		await waitFor(() => {
			expect(findSlideBySource(container, slides[0].src)).toBeTruthy();
		});

		act(() => {
			ref.current?.pause();
		});

		expect(findSlideBySource(container, slides[0].src)).toBeTruthy();
	});

	it("honors the default background and first transition before autoplay advances", async () => {
		vi.useFakeTimers();

		const {container} = render(
			<Vegas
				slides={slides}
				autoplay
				delay={500}
				transitionDuration={1}
				firstTransitionDuration={1500}
				defaultBackground="/loading.jpg"
				defaultBackgroundDuration={1000}
			/>
		);

		await flushEffects();
		expect(findSlideBySource(container, "/loading.jpg")).toBeTruthy();

		await advanceTimers(1000);
		await flushEffects();

		expect(findSlideBySource(container, slides[0].src)).toBeTruthy();
		expect(findSlideBySource(container, slides[1].src)).toBeFalsy();

		await advanceTimers(1000);
		await flushEffects();
		expect(findSlideBySource(container, slides[1].src)).toBeFalsy();

		await advanceTimers(500);
		await flushEffects();

		expect(findSlideBySource(container, slides[1].src)).toBeFalsy();

		await advanceTimers(500);
		await flushEffects();
		expect(findSlideBySource(container, slides[1].src)).toBeTruthy();
	});

	it("preloads video sources during the preload phase and cleans them up on unmount", async () => {
		const {unmount} = render(
			<Vegas
				slides={[{
					src: "/poster.jpg",
					video: {
						src: ["/intro.mp4", "/intro.webm"],
						muted: true
					}
				}]}
				autoplay={false}
				preload
				preloadVideo
				firstTransitionDuration={0}
			/>
		);

		await flushEffects();

		await waitFor(() => {
			const preloadLinks = Array.from(document.head.querySelectorAll('link[rel="preload"]'));
			const preloadSources = preloadLinks.map(link => link.getAttribute("href"));

			expect(preloadSources).toEqual(["/intro.mp4", "/intro.webm"]);
		});

		unmount();

		expect(document.head.querySelectorAll('link[rel="preload"]')).toHaveLength(0);
	});
});
