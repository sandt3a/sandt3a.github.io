---
title: Welcome To My Blog
published: 2026-03-31
description: A bilingual static blog example built with Astro and Fuwari.
tags:
  - start
category: Notes
draft: false
lang: en
---

This is a bilingual static blog example built with Astro and Fuwari.

You are reading the English version. The Chinese homepage lives at `/`, the English homepage lives at `/en/`, and both languages share the same page structure and post slug.

## How this structure works

- Chinese homepage: `/`
- English homepage: `/en/`
- Chinese posts: `/posts/...`
- English posts: `/en/posts/...`

## Language switching

The language switch in the navbar tries to keep you on the current page:

- home switches to the matching homepage
- about switches to the matching about page
- posts switch to the translated post with the same slug

As long as both language versions use the same filename, the switch remains aligned.
