import I18nKey from "@i18n/i18nKey";
import { i18n } from "@i18n/translation";
import { type Lang, toSiteLang } from "@utils/url-utils";
import { LinkPreset, type NavBarLink } from "@/types/config";

export function getLinkPresets(lang: Lang): { [key in LinkPreset]: NavBarLink } {
	const siteLang = toSiteLang(lang);

	return {
		[LinkPreset.Home]: {
			name: i18n(I18nKey.home, siteLang),
			url: "/",
		},
		[LinkPreset.About]: {
			name: i18n(I18nKey.about, siteLang),
			url: "/about/",
		},
		[LinkPreset.Archive]: {
			name: i18n(I18nKey.archive, siteLang),
			url: "/archive/",
		},
	};
}
