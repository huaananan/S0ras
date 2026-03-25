import { getImage } from "astro:assets";
import { siteConfig } from "@/config";
import { getSortedPosts } from "@/utils/content-utils";
import { url } from "@/utils/url-utils";
import rss from "@astrojs/rss";
import type { RSSFeedItem } from "@astrojs/rss";
import type { APIContext, ImageMetadata } from "astro";
import MarkdownIt from "markdown-it";
import { parse as htmlParser } from "node-html-parser";
import sanitizeHtml from "sanitize-html";

const markdownParser = new MarkdownIt();

const imagesGlob = import.meta.glob<{ default: ImageMetadata }>(
	"/src/content/**/*.{jpeg,jpg,png,gif,webp}",
);

export async function GET(context: APIContext) {
	if (!context.site) {
		throw Error("site not set");
	}

	const siteUrl = new URL(import.meta.env.BASE_URL, context.site);
	const posts = await getSortedPosts();
	const feed: RSSFeedItem[] = [];

	for (const post of posts) {
		const body = markdownParser.render(post.body || "");
		const html = htmlParser.parse(body);
		const images = html.querySelectorAll("img");

		for (const img of images) {
			const src = img.getAttribute("src");
			if (!src) continue;

			if (src.startsWith("./") || src.startsWith("../")) {
				let importPath: string | null = null;

				if (src.startsWith("./")) {
					importPath = `/src/content/posts/${src.slice(2)}`;
				} else {
					importPath = `/src/content/${src.replace(/^\.\.\//, "")}`;
				}

				const imageMod = await imagesGlob[importPath]?.()?.then(
					(res) => res.default,
				);
				if (imageMod) {
					const optimizedImg = await getImage({ src: imageMod });
					img.setAttribute("src", new URL(optimizedImg.src, siteUrl).href);
				}
			} else if (src.startsWith("/")) {
				img.setAttribute("src", new URL(url(src), context.site).href);
			}
		}

		feed.push({
			title: post.data.title,
			description: post.data.description,
			pubDate: post.data.published,
			link: url(`/posts/${post.slug}/`),
			content: sanitizeHtml(html.toString(), {
				allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img"]),
			}),
		});
	}

	return rss({
		title: siteConfig.title,
		description: siteConfig.subtitle || "No description",
		site: siteUrl,
		items: feed,
		customData: `<language>${siteConfig.lang}</language>`,
	});
}
