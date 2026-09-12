---
default: patch
---

Make notifications more reliable when the app is closed on Android: the push is decrypted inside a short-lived foreground service instead of being cut short by battery saving.
