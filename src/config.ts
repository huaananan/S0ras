import type {
	AnalyticsConfig,
	CookieConsentConfig,
	DeployConfig,
	ExpressiveCodeConfig,
	FooterConfig,
	GiscusConfig,
	GitHubEditConfig,
	ImageFallbackConfig,
	LicenseConfig,
	NavBarConfig,
	NoticeConfig,
	PostActionsConfig,
	ProfileConfig,
	SiteAssetsConfig,
	SiteConfig,
	UmamiConfig,
} from "./types/config";
import { LinkPreset } from "./types/config";

export const noticeConfig: NoticeConfig = {
	enable: true,
	level: "info",
	content:
		"<strong>\u6B22\u8FCE\u6765\u5230\u6211\u7684\u535A\u5BA2\u3002</strong> \u8FD9\u91CC\u4E3B\u8981\u8BB0\u5F55\u5F00\u53D1\u3001\u5B89\u5168\u548C CTF \u5B66\u4E60\u3002",
};

export const deployConfig: DeployConfig = {
	site: "https://huaananan.github.io",
	base: "/S0ras",
	trailingSlash: "always",
};

export const siteConfig: SiteConfig = {
	title: "S0ras",
	subtitle: "\u5F00\u53D1\u4E0E\u5B89\u5168\u5B66\u4E60",
	description:
		"\u805A\u7126\u5F00\u53D1\u3001\u7F51\u7EDC\u5B89\u5168\u3001CTF \u4E0E\u65E5\u5E38\u6280\u672F\u8BB0\u5F55\u3002",
	keywords: [
		"S0ras",
		"S0ra",
		"Astro",
		"Blog",
		"CTF",
		"Security",
		"\u6280\u672F\u535A\u5BA2",
		"\u7F51\u7EDC\u5B89\u5168",
		"\u5F00\u53D1",
	],
	lang: "zh_CN",
	themeColor: {
		hue: 361,
		fixed: false,
		forceDarkMode: false,
	},
	banner: {
		enable: false,
		src: "/xinghui.avif",
		position: "center",
		credit: {
			enable: true,
			text: "Pixiv @chokei",
			url: "https://www.pixiv.net/artworks/122782209",
		},
	},
	background: {
		enable: true,
		src: "/random/h",
		position: "center",
		size: "cover",
		repeat: "no-repeat",
		attachment: "fixed",
		opacity: 1,
	},
	toc: {
		enable: true,
		depth: 2,
	},
	favicon: [
		{
			src: "/sora.png?v=2",
		},
	],
};

export const navBarConfig: NavBarConfig = {
	links: [
		LinkPreset.Home,
		LinkPreset.Archive,
		{
			name: "\u53CB\u94FE",
			url: "/friends/",
			external: false,
		},
	],
};

export const profileConfig: ProfileConfig = {
	avatar: "/sora.png",
	name: "S0ra",
	bio: "Protect What You Love.",
	links: [
		{
			name: "GitHub",
			icon: "github",
			url: "https://github.com/huaananan/",
		},
	],
};

export const footerConfig: FooterConfig = {
	startYear: 2024,
	links: [
		{
			label: "RSS",
			url: "/rss.xml",
		},
		{
			label: "\u7F51\u7AD9\u5730\u56FE",
			url: "/sitemap-index.xml",
		},
	],
	poweredBy: [
		{
			label: "Astro",
			url: "https://astro.build",
			external: true,
		},
		{
			label: "Fuwari",
			url: "https://github.com/saicaca/fuwari",
			external: true,
		},
	],
};

export const licenseConfig: LicenseConfig = {
	enable: true,
	name: "CC BY-NC-SA 4.0",
	url: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
};

export const imageFallbackConfig: ImageFallbackConfig = {
	enable: false,
	originalDomain: "",
	fallbackDomain: "",
};

export const umamiConfig: UmamiConfig = {
	enable: true,
	baseUrl: "https://umami.acofork.com",
	websiteId: "5d710dbd-3a2e-43e3-a553-97b415090c63",
	shareId: "CdkXbGgZr6ECKOyK",
	timezone: "Asia/Shanghai",
};

export const siteAssetsConfig: SiteAssetsConfig = {
	preconnect: ["https://pic1.acofork.com", "https://umami.acofork.com"],
	backgroundScriptUrl: "https://pic1.acofork.com/random.js",
};

export const cookieConsentConfig: CookieConsentConfig = {
	enable: true,
	scriptUrl:
		"https://www.termsfeed.com/public/cookie-consent/4.2.0/cookie-consent.js",
	noticeBannerType: "simple",
	consentType: "express",
	language: "en",
	pageLoadConsentLevels: ["strictly-necessary"],
	showRejectButton: true,
	showPreferencesCloseButton: true,
	pageRefreshConfirmationButtons: false,
	websiteName: "S0ras",
};

export const analyticsConfig: AnalyticsConfig = {
	googleAnalytics: {
		enable: true,
		consentLevel: "tracking",
		measurementId: "G-YG02LLPGWC",
	},
	clarity: {
		enable: true,
		consentLevel: "tracking",
		projectId: "v94yrasi99",
	},
	adsense: {
		enable: true,
		consentLevel: "targeting",
		clientId: "ca-pub-1683686345039700",
	},
};

export const expressiveCodeConfig: ExpressiveCodeConfig = {
	theme: "github-dark",
};

export const giscusConfig: GiscusConfig = {
	enable: true,
	repo: "afoim/giscus-fuwari",
	repoId: "R_kgDOOi8quw",
	category: "Announcements",
	categoryId: "DIC_kwDOOi8qu84CprDV",
	mapping: "pathname",
	strict: "1",
	reactionsEnabled: "1",
	emitMetadata: "0",
	inputPosition: "top",
	lang: "zh-CN",
	loading: "lazy",
};

export const postActionsConfig: PostActionsConfig = {
	contact: {
		label: "\u8054\u7CFB",
		url: "https://github.com/huaananan/",
		icon: "material-symbols:contact-mail-outline",
		external: true,
		variant: "secondary",
	},
	sponsor: {
		label: "\u8D5E\u52A9",
		url: "/sponsors/",
		icon: "material-symbols:favorite-outline",
		external: false,
		variant: "primary",
	},
};

export const gitHubEditConfig: GitHubEditConfig = {
	enable: true,
	baseUrl: "https://github.com/huaananan/my-blog/edit/main/src/content/posts",
};
