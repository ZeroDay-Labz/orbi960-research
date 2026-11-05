# RBSE 7215 → 7288 Lua delta (Track B evidence)

## Full .lua enumeration

Both `rbse_7215/rootfs/` and `rbse_7288/rootfs/` contain **120 common .lua files**
(no additions, no removals between the two versions).

## sha256-level change

Of the 120 files, exactly **ONE** differs between versions:

| path | 7215 sha256 | 7288 sha256 | size delta |
|---|---|---|---|
| `usr/lib/lua/luci/version.lua` | `9ab35d786acf…` | `3e1370f16b04…` | -16 |

### Diff of the only change

```diff
--- rbse_7215/rootfs/usr/lib/lua/luci/version.lua
+++ rbse_7288/rootfs/usr/lib/lua/luci/version.lua
@@ -16,5 +16,5 @@
   distversion = "Development Snapshot"
 end

-luciname    = "LuCI RTM_REL_BR_11_5 branch"
-luciversion = "git-24.319.57692-08d049b8bd"
+luciname    = "LuCI branch"
+luciversion = "git-26.056.23873-6d1a719c82"
```

Two string literals: the LuCI branch label and git revision. No code change,
no new constants, no validator. The size delta is entirely accounted for by
the shortened branch label.

## Interpretation

The RBSE firmware ships a LuCI stack (OpenWrt web interface) rather than
the master's Seal REST layer. The sat has **no `seal-services.lua`,
no `rest.lua`, and no `/api/v1/*` surface**. The entire Lua layer on the sat
was touched only to update a cosmetic version string.
