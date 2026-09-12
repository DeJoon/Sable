---
default: patch
---

Fix sending the first message after startup taking up to 40 seconds in encrypted rooms: outgoing crypto requests and key backup checks now coalesce instead of queueing one full run per caller, and repeated undecryptable events no longer re-request the key backup version from the server.
