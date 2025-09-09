# React Vegas Slideshow

A React implementation of the [Vegas Background SlideShow](https://github.com/jaysalvat/vegas), providing a powerful and
flexible slide

```typescript
interface Slide {
	src: string;                       // Resource path
	color?: string;                    // Background color
	delay?: number;                    // Individual slide delay
	align?: 'left' | 'center' | 'right';  // Horizontal alignment
	valign?: 'top' | 'center' | 'bottom'; // Vertical alignment
	transition?: string;               // Individual transition
	transitionDuration?: number;       // Individual transition duration
	cover?: boolean;                  // Cover mode
	video?: {                        // Video specific options
		src: string[];               // Multiple format sources
		muted?: boolean;               // Mute video
		loop?: boolean;                // Loop video
	};
}

```
at supports images and videos with smooth transitions and customizable effects.

English | [简体中文](./README.md)

## Features

- 🖼️ Support for both images and videos
- 🎬 Multiple transition effects
- 🔄 Auto-play with configurable delays
- 🎯 Custom alignment options
- 🔀 Random/shuffle play mode
- ⚡ Preloading capabilities
- 📱 Responsive design
- 🎨 Customizable overlay and timer
- 🎮 Manual control options
- 🎯 TypeScript support

## Installation

npm

```
bash
npm
install
react - vegas
```

yarn

```bash
yarn add react-vegas
```

pnpm

```bash
pnpm add react-vegas
```

## Basic Usage

```tsx
import { Vegas } from "react-vegas";

const App = () => {
	const slides = [
		{
			src: '/images/slide1.jpg',
			transition: 'fade'
		},
		{
			src: '/images/slide2.jpg',
			transition: 'slideLeft'
		}
	];

	return (
		<Vegas
			slides={slides}
			delay={5000}
			autoplay={true}
		/>
	);
};
```

## Advanced Usage

```tsx
const slides = [
	{
		src: '/images/slide1.jpg',
		align: 'center',
		valign: 'center',
		transition: 'fade',
		transitionDuration: 2000,
		delay: 5000
	},
	{
		src: '/videos/video1.mp4',
		video: {
			src: [
				'/videos/video1.mp4',
				'/videos/video1.webm'
			],
			muted: true,
			loop: false
		},
		transition: 'zoomIn'
	}
];

<Vegas
	slides={slides}
	overlay={true}
	timer={false}
	delay={7000}
	shuffle={true}
	transitionDuration={3000}
	firstTransitionDuration={5000}
	defaultBackground="/images/loading.jpg"
	defaultBackgroundDuration={2000}
	debug={true}
	color="#000"
/>
```

## Props

### Basic Props

| Prop     | Type    | Default  | Description               |
|----------|---------|----------|---------------------------|
| slides   | Array   | Required | Array of slide objects    |
| slide    | number  | 0        | Initial slide index       |
| delay    | number  | 5000     | Delay between slides (ms) |
| autoplay | boolean | true     | Enable automatic playback |
| loop     | boolean | true     | Enable continuous loop    |
| shuffle  | boolean | false    | Randomize slide order     |
| debug    | boolean | false    | Enable debug logging      |

### Transition Props

| Prop                    | Type   | Default | Description                    |
|-------------------------|--------|---------|--------------------------------|
| transition              | string | 'fade'  | Transition effect type         |
| transitionDuration      | number | 1000    | Transition duration (ms)       |
| firstTransitionDuration | number | 3000    | First transition duration (ms) |

### Visual Props

| Prop    | Type    | Default | Description           |
|---------|---------|---------|-----------------------|
| overlay | boolean | false   | Show overlay layer    |
| timer   | boolean | false   | Show progress timer   |
| color   | string  | null    | Background color      |
| cover   | boolean | true    | Cover mode for images |
| align   | string  | center  | Horizontal alignment  |
| valign  | string  | center  | Vertical alignment    |

### Loading Props

| Prop                      | Type    | Default   | Description                 |
|---------------------------|---------|-----------|-----------------------------|
| preload                   | boolean | false     | Enable resource preloading  |
| preloadImage              | boolean | false     | Preload images              |
| preloadImageBatch         | number  | 3         | Batch preload image count   |
| preloadVideo              | boolean | false     | Preload videos              |
| showLoading               | boolean | false     | Show loading indicator      |
| defaultBackground         | string  | undefined | Loading background image    |
| defaultBackgroundDuration | number  | 3000      | Loading background duration |

### Callback Props

| Prop    | Type       | Description                  |
|---------|------------|------------------------------|
| onInit  | () => void | Called after initialization  |
| onPlay  | () => void | Called when slideshow starts |
| onPause | () => void | Called when slideshow pauses |
| onWalk  | () => void | Called on slide change       |

## Slide Object Properties

```typescript
interface Slide {
	src: string;                      // Image/video source URL
	color?: string;                   // Slide background color
	delay?: number;                   // Individual slide delay
	align?: 'left' | 'center' | 'right';  // Horizontal alignment
	valign?: 'top' | 'center' | 'bottom'; // Vertical alignment
	transition?: string;              // Individual transition
	transitionDuration?: number;      // Individual transition duration
	cover?: boolean;                  // Cover mode
	video?: {                        // Video specific options
		src: string[];                 // Multiple format sources
		muted?: boolean;               // Mute video
		loop?: boolean;                // Loop video
	};
}
```

## Available Transitions

- `fade`: Fade in/out
- `slideLeft`: Slide from left
- `slideRight`: Slide from right
- `zoomIn`: Zoom in effect
- `zoomOut`: Zoom out effect
- `zoomInOut`: Combined zoom effect

## Component Methods

You can access the following methods using a ref:

```tsx
const vegasRef = useRef();

// Available methods
vegasRef.current.play();    // Start slideshow
vegasRef.current.pause();   // Pause slideshow
vegasRef.current.next();    // Go to next slide
vegasRef.current.previous(); // Go to previous slide
```

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Performance Tips

1. Optimize your images before use
2. Use appropriate video formats and resolutions
3. Enable preloading for better performance
4. Consider using WebP format for images
5. Compress videos appropriately

## Known Issues

- Video autoplay might be blocked in some browsers without user interaction
- Safari has limited support for some video formats

## Credits

This component is inspired by [Vegas Background SlideShow](https://github.com/jaysalvat/vegas) jQuery plugin by Jay
Salvat. It has been reimplemented in React with TypeScript support and modern web features.
