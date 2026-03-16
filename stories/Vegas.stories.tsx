import {useRef} from "react";
import type {ComponentType, ReactElement} from "react";
import {Vegas} from "../src";
import type {SlideProps, VegasProps} from "../src/types";

type TransitionName = "fade" | "slideLeft" | "slideRight" | "zoomIn" | "zoomOut" | "zoomInOut";

type VegasRefHandle = {
	previous: () => void;
	next: () => void;
	play: () => void;
	pause: () => void;
};

const imageSources = [
	"https://images.unsplash.com/photo-1506744038136-46273834b3fb",
	"https://images.unsplash.com/photo-1741986947217-d1a0ecc39149",
	"https://cdn.pixabay.com/photo/2023/12/24/16/43/autumn-8467482_1280.jpg",
	"https://cdn.pixabay.com/photo/2024/05/21/21/46/bird-8779199_1280.jpg",
	"https://cdn.pixabay.com/photo/2021/03/13/21/54/planet-6092940_1280.jpg",
	"https://cdn.pixabay.com/photo/2023/08/31/14/40/mountain-8225287_1280.jpg"
] as const;

const background = "https://images.unsplash.com/photo-1742560897614-69c3f47771be";
const videoPoster = "https://images.unsplash.com/photo-1493246507139-91e8fad9978e";

const baseArgs: VegasProps = {
	autoplay: true,
	delay: 3500,
	transitionDuration: 1200,
	firstTransition: "fade",
	firstTransitionDuration: 1800,
	color: "#000",
	cover: true,
	loop: true,
	preload: true,
	preloadImage: true,
	preloadImageBatch: 3,
	preloadVideo: false,
	timer: true,
	overlay: false,
	showLoading: true,
	debug: false,
	slides: []
};

const buildSlides = (transitionName: TransitionName): SlideProps[] =>
	imageSources.map((src, index) => ({
		src,
		transition: transitionName,
		delay: 2500 + index * 250
	}));

const mixedSlides: SlideProps[] = [
	{src: imageSources[0], transition: "fade"},
	{src: imageSources[1], transition: "slideLeft"},
	{src: imageSources[2], transition: "slideRight"},
	{src: imageSources[3], transition: "zoomIn"},
	{src: imageSources[4], transition: "zoomOut"},
	{src: imageSources[5], transition: "zoomInOut"}
];

const videoSlides: SlideProps[] = [
	{src: imageSources[0], transition: "fade"},
	{
		src: videoPoster,
		transition: "zoomIn",
		video: {
			src: [
				"https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
				"https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.webm"
			],
			muted: true,
			loop: true
		}
	},
	{src: imageSources[3], transition: "fade"}
];

type StoryDefinition = {
	name?: string;
	args?: VegasProps;
	render?: (args: VegasProps) => ReactElement;
};

const meta = {
	title: "Vegas Slides",
	component: Vegas,
	decorators: [
		(Story: ComponentType) => (
			<div style={{height: "100vh"}}>
				<Story/>
			</div>
		)
	],
	parameters: {
		layout: "fullscreen",
		docs: {
			description: {
				component: "用于验证 react-vegas 过渡效果、默认背景、视频与手动控制的 Storybook 场景集合。"
			}
		}
	},
	argTypes: {
		transition: {
			control: "select",
			options: ["fade", "slideLeft", "slideRight", "zoomIn", "zoomOut", "zoomInOut"]
		},
		align: {
			control: "inline-radio",
			options: ["left", "center", "right"]
		},
		valign: {
			control: "inline-radio",
			options: ["top", "center", "bottom"]
		}
	}
};

export default meta;

export const Default: StoryDefinition = {
	args: {
		...baseArgs,
		slides: mixedSlides,
		shuffle: true,
		overlay: true,
		defaultBackground: background,
		defaultBackgroundDuration: 2200
	}
};

export const FadeEffect: StoryDefinition = {
	name: "Effect/Fade",
	args: {
		...baseArgs,
		slides: buildSlides("fade")
	}
};

export const SlideLeftEffect: StoryDefinition = {
	name: "Effect/Slide Left",
	args: {
		...baseArgs,
		slides: buildSlides("slideLeft")
	}
};

export const SlideRightEffect: StoryDefinition = {
	name: "Effect/Slide Right",
	args: {
		...baseArgs,
		slides: buildSlides("slideRight")
	}
};

export const ZoomInEffect: StoryDefinition = {
	name: "Effect/Zoom In",
	args: {
		...baseArgs,
		slides: buildSlides("zoomIn")
	}
};

export const ZoomOutEffect: StoryDefinition = {
	name: "Effect/Zoom Out",
	args: {
		...baseArgs,
		slides: buildSlides("zoomOut")
	}
};

export const ZoomInOutEffect: StoryDefinition = {
	name: "Effect/Zoom In Out",
	args: {
		...baseArgs,
		slides: buildSlides("zoomInOut")
	}
};

export const DefaultBackgroundFlow: StoryDefinition = {
	name: "Scenario/Default Background",
	args: {
		...baseArgs,
		slides: buildSlides("fade"),
		defaultBackground: background,
		defaultBackgroundDuration: 3000,
		firstTransition: "zoomIn"
	}
};

export const ShuffleAndOverlay: StoryDefinition = {
	name: "Scenario/Shuffle And Overlay",
	args: {
		...baseArgs,
		slides: mixedSlides,
		shuffle: true,
		overlay: true,
		timer: true
	}
};

export const VideoSlide: StoryDefinition = {
	name: "Scenario/Video Slide",
	args: {
		...baseArgs,
		slides: videoSlides,
		preloadVideo: true,
		showLoading: false,
		transitionDuration: 1500
	}
};

export const ManualControls: StoryDefinition = {
	name: "Scenario/Manual Controls",
	render: (args) => {
		const vegasRef = useRef<VegasRefHandle | null>(null);

		return (
			<div style={{height: "100%", position: "relative"}}>
				<Vegas ref={vegasRef} {...args} />
				<div style={{
					position: "absolute",
					left: 24,
					bottom: 24,
					display: "flex",
					gap: 12,
					zIndex: 20
				}}>
					<button onClick={() => vegasRef.current?.previous()} type="button">Previous</button>
					<button onClick={() => vegasRef.current?.play()} type="button">Play</button>
					<button onClick={() => vegasRef.current?.pause()} type="button">Pause</button>
					<button onClick={() => vegasRef.current?.next()} type="button">Next</button>
				</div>
			</div>
		);
	},
	args: {
		...baseArgs,
		slides: mixedSlides,
		autoplay: false,
		showLoading: false,
		timer: false
	}
};