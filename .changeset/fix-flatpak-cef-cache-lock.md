---
default: patch
---

Fix the Flatpak app failing to launch after a previous run, where a leftover CEF cache lock was mistaken for a running instance.
