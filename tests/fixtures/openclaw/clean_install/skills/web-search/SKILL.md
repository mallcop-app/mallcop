---
name: web-search
description: Search the web using DuckDuckGo
version: 1.2.0
author: openclaw-official
tags:
  - search
  - web
---

# Web Search

Search the internet for information using the DuckDuckGo search API.

## Setup

No additional setup required. This skill uses the built-in HTTP tools.

## Usage

Ask me to search for anything:
- "Search for Python tutorials"
- "Find recent news about AI"

## Tools

- `web_search(query: str) -> list[Result]`: Perform a web search and return results.

## Permissions

Read-only access to HTTPS endpoints. No file system access required.
