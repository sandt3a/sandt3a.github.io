---
title: Test Post With Image
published: 1200-04-01
description: An example post using a folder-based asset directory for the cover image.
image: ./assets/cover.png
tags:
  - test
  - image
category: Example
draft: false
lang: en
---

This is a sample post for testing the folder-based image post structure.

The directory looks like this:

```text
src/content/posts/en/test-picture/
├── assets/
│   └── cover.png
└── index.md
```

The cover image is referenced through `image: ./assets/cover.png` in the frontmatter, which is a good fit when you want the post content and local assets to stay together.

## Good use cases

- posts that need a dedicated cover image
- posts with several local images
- keeping content and assets in the same folder
