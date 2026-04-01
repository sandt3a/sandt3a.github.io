import I18nKey from "@i18n/i18nKey";
import { i18n } from "@i18n/translation";
import type { SiteConfig } from "@/types/config";

export const DEFAULT_LANG = "zh-cn";
export const LANGUAGES = ["zh-cn", "en"] as const;
export type Lang = (typeof LANGUAGES)[number];

export function getLangFromUrl(url: URL): Lang {
	if (url.pathname.startsWith("/en/") || url.pathname === "/en") return "en";
	return DEFAULT_LANG;
}

export function toSiteLang(lang: Lang): SiteConfig["lang"] {
	return lang === "en" ? "en" : "zh_CN";
}

export function getCleanSlug(slug: string): string {
	return slug.replace(/^(zh-cn|en)\//, "");
}

export function pathsEqual(path1: string, path2: string) {
	const normalizedPath1 = path1.replace(/^\/|\/$/g, "").toLowerCase();
	const normalizedPath2 = path2.replace(/^\/|\/$/g, "").toLowerCase();
	return normalizedPath1 === normalizedPath2;
}

function joinUrl(...parts: string[]): string {
	const joined = parts.join("/");
	return joined.replace(/\/+/g, "/");
}

export function getPostUrlBySlug(slug: string): string {
	const lang = slug.startsWith("en/") ? "en" : DEFAULT_LANG;
	const cleanSlug = getCleanSlug(slug);
	if (lang === "en") {
		return url(`/en/posts/${cleanSlug}/`);
	}
	return url(`/posts/${cleanSlug}/`);
}

export function getTagUrl(tag: string, lang: Lang = DEFAULT_LANG): string {
	if (!tag) return urlWithLang("/archive/", lang);
	return urlWithLang(`/archive/?tag=${encodeURIComponent(tag.trim())}`, lang);
}

export function getCategoryUrl(
	category: string | null,
	lang: Lang = DEFAULT_LANG,
): string {
	if (
		!category ||
		category.trim() === "" ||
		category.trim().toLowerCase() ===
			i18n(I18nKey.uncategorized, toSiteLang(lang)).toLowerCase()
	)
		return urlWithLang("/archive/?uncategorized=true", lang);
	return urlWithLang(
		`/archive/?category=${encodeURIComponent(category.trim())}`,
		lang,
	);
}

export function getDir(path: string): string {
	const lastSlashIndex = path.lastIndexOf("/");
	if (lastSlashIndex < 0) {
		return "/";
	}
	return path.substring(0, lastSlashIndex + 1);
}

export function url(path: string) {
	return joinUrl("", import.meta.env.BASE_URL, path);
}

export function urlWithLang(path: string, lang: Lang): string {
	if (lang === "en") {
		return url(`/en${path}`);
	}
	return url(path);
}

export function switchLangUrl(currentUrl: URL): string {
	const currentLang = getLangFromUrl(currentUrl);
	const pathname = currentUrl.pathname;

	if (currentLang === "en") {
		const zhPath = pathname.replace(/^\/en(\/|$)/, "/");
		return url(zhPath || "/");
	}

	return url(`/en${pathname}`);
}
