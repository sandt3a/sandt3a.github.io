---
title: 带图片的测试文章
published: 2026-04-01
description: 使用文件夹结构和 assets 目录保存封面图的示例文章。
image: ./assets/cover.png
tags:
  - 测试
  - 图片
category: 示例
draft: false
lang: zh_CN
---

这是一篇用于测试图片文章结构的示例。

当前目录结构如下：

```text
src/content/posts/zh-cn/test-picture/
├── assets/
│   └── cover.png
└── index.md
```

封面图通过 Frontmatter 中的 `image: ./assets/cover.png` 引用，适合把文章正文和资源文件放在同一个目录里管理。

## 适用场景

- 文章需要单独封面图
- 同一篇文章有多张本地图片
- 希望内容和资源文件一起维护
