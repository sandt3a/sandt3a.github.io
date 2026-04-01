<script lang="ts">
import Icon from "@iconify/svelte";
import { onMount } from "svelte";
import { type Lang, switchLangUrl } from "../utils/url-utils";

let currentLang: Lang = "zh-cn";

onMount(() => {
	const p = window.location.pathname;
	currentLang = p.startsWith("/en/") || p === "/en" ? "en" : "zh-cn";
});

function switchTo(lang: Lang) {
	if (lang === currentLang) return;

	const targetUrl = switchLangUrl(new URL(window.location.href));
	window.location.href = targetUrl;
}

function showPanel() {
	document.querySelector("#lang-panel")?.classList.remove("float-panel-closed");
}

function hidePanel() {
	document.querySelector("#lang-panel")?.classList.add("float-panel-closed");
}
</script>

<div class="relative z-50" role="menu" tabindex="-1" onmouseleave={hidePanel}>
	<button
		aria-label="Switch Language"
		class="btn-plain scale-animation rounded-lg h-11 w-11 active:scale-90 font-bold text-sm"
		onclick={() => switchTo(currentLang === "zh-cn" ? "en" : "zh-cn")}
		onmouseenter={showPanel}
	>
		<Icon icon="material-symbols:translate" class="text-[1.25rem]" />
	</button>

	<div id="lang-panel" class="hidden lg:block absolute transition float-panel-closed top-11 -right-2 pt-5">
		<div class="card-base float-panel p-2">
			<button
				class="flex transition whitespace-nowrap items-center !justify-start w-full btn-plain scale-animation rounded-lg h-9 px-3 font-medium active:scale-95 mb-0.5"
				class:current-theme-btn={currentLang === "zh-cn"}
				onclick={() => switchTo("zh-cn")}
			>
				简体中文
			</button>
			<button
				class="flex transition whitespace-nowrap items-center !justify-start w-full btn-plain scale-animation rounded-lg h-9 px-3 font-medium active:scale-95"
				class:current-theme-btn={currentLang === "en"}
				onclick={() => switchTo("en")}
			>
				English
			</button>
		</div>
	</div>
</div>
