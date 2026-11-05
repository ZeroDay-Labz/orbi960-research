# Firmware diff: rbse_7215 -> rbse_7288

## Summary

- Total changes: **883**
- By status: {'changed': 883}
- By priority bucket: {'0': 2, '1': 5, '2': 1, '3': 25, '5': 850}

Priority buckets (lower = more security-relevant). 0=top SOAP/webui/remoteshell; 1=rpcd/http; 2=init/uci; 3=other binaries; 5=everything else.

## Priority 0

| Status | Path | Label | Note |
|---|---|---|---|
| changed | `usr/sbin/cgi-bin/soap_agent` | SOAP CGI — authenticated management surface | sha:a3ee8ac93b41->19feab2445e0 |
| changed | `usr/sbin/configd` | Configuration DAL daemon — gates SOAP state changes | sha:6caa0acf8a1c->a8a1dad56aa2 |

## Priority 1

| Status | Path | Label | Note |
|---|---|---|---|
| changed | `lib/librpc.so` | RPC core library (/lib path) | sha:19029e0491fd->25324d927287 |
| changed | `lib/modules/4.4.60/cryptodev.ko` | cryptodev kmod | sha:3e5985e2febc->358a0248c05f |
| changed | `lib/modules/4.4.60/qca-nss-crypto-tool.ko` | QCA NSS crypto driver | sha:2dce49527d7a->6f752596fa7c |
| changed | `lib/modules/4.4.60/qca-nss-crypto.ko` | QCA NSS crypto driver | sha:83a69b489765->49892ba52bd8 |
| changed | `usr/lib/libcrypto.so.1.1` | OpenSSL libcrypto (CVE-sensitive) | sha:06738356c2dd->62ded1ee87c5 |

## Priority 2

| Status | Path | Label | Note |
|---|---|---|---|
| changed | `usr/lib/lua/luci/version.lua` | LuCI/Lua app | sha:9ab35d786acf->3e1370f16b04 size:539->523 |

## Priority 3

| Status | Path | Label | Note |
|---|---|---|---|
| changed | `usr/bin/dumpimage` | User binary | sha:f3b065ccf5fa->431cf5ee41af |
| changed | `usr/bin/iostat` | User binary | sha:4726b00a2aea->12fc2f0b1b76 |
| changed | `usr/bin/mkimage` | User binary | sha:9dfdb884c8d7->ffbda503f452 |
| changed | `usr/bin/mpstat` | User binary | sha:202559293e15->d0e66d1b79c1 |
| changed | `usr/bin/pidstat` | User binary | sha:fe5bf83a2985->99213d2095db |
| changed | `usr/bin/sadf` | User binary | sha:c32efaf85439->4d63128c1339 |
| changed | `usr/bin/sar` | User binary | sha:9e2c3849deab->df1f31756238 |
| changed | `usr/bin/zip` | User binary | sha:3cb0d58c9544->30aeee6646cd |
| changed | `usr/bin/zipcloak` | User binary | sha:842d102e9bb5->4be3bd52207c |
| changed | `usr/bin/zipnote` | User binary | sha:bf9016e923d7->3bf1b47ece66 |
| changed | `usr/bin/zipsplit` | User binary | sha:9fd2eef21029->dd1a79cfb752 |
| changed | `usr/lib/libevent-2.1.so.7.0.0` | Shared library | sha:7871fdd3b01c->ce762697a88e |
| changed | `usr/lib/libevent_core-2.1.so.7.0.0` | Shared library | sha:ab282356034d->54e13a339dec |
| changed | `usr/lib/libtlvtemplate.so` | Shared library | sha:49732489be5c->5992a5d7c8ac |
| changed | `usr/lib/libuClibc++-0.2.4.so` | Shared library | sha:a37c73427a77->d3bc0e237306 |
| changed | `usr/sbin/athssd` | Admin binary | sha:f90c5fbd66a0->ab23c19e5e6e |
| changed | `usr/sbin/icm` | Admin binary | sha:417dfe804c23->c4307a0139ea |
| changed | `usr/sbin/ip` | Admin binary | sha:97e277416184->07344703f0af |
| changed | `usr/sbin/ipsec` | Admin binary | sha:dc82b5d6c728->d1818b286cbc |
| changed | `usr/sbin/lbd` | Admin binary | sha:ad1261984081->cb0bbff4903a |
| changed | `usr/sbin/lowi-server` | Admin binary | sha:64fed6476091->a3c1e8e4baf2 |
| changed | `usr/sbin/miniupnpd` | Admin binary | sha:8d2460b1b9f5->d02726cd5179 |
| changed | `usr/sbin/ssdk_sh` | Admin binary | sha:7442b0e00f16->090bd3d671c6 |
| changed | `usr/sbin/tc` | Admin binary | sha:2a10eb7ff801->aa927ea3be6a |
| changed | `usr/sbin/tcpdump` | Admin binary | sha:167bc4526f99->18d4e66a571b |

## Priority 5

| Status | Path | Label | Note |
|---|---|---|---|
| changed | `etc/banner` | Other | sha:f7b47f562b6e->5e46e71abdcf size:1132->1130 |
| changed | `etc/git_version` | Other | sha:c288cb561db3->6303a0fbb439 size:120->119 |
| changed | `etc/modules.d/73-sched` | Other | sha:5601dd28e93e->65816001af2a |
| changed | `etc/openwrt_release` | Other | sha:ce688b7a416a->eecd23601bf1 size:244->242 |
| changed | `etc/version` | Other | sha:0f8ca9599f8d->f435650b885d size:10->9 |
| changed | `ipk/qca-hyd-init.ipk` | Other | sha:7f6c987ba9f3->197c456baeaa size:39308->39425 |
| changed | `lib/modules/4.4.60/act_connmark.ko` | Other | sha:c0dae807ec88->1ff16635b8e5 |
| changed | `lib/modules/4.4.60/act_ipt.ko` | Other | sha:12ae1c76b75d->4e78271d4bac |
| changed | `lib/modules/4.4.60/act_mirred.ko` | Other | sha:596b831924f5->ad6ccf3142be |
| changed | `lib/modules/4.4.60/act_nssmirred.ko` | Other | sha:d16c2e410f58->8d1ed85dc218 |
| changed | `lib/modules/4.4.60/act_police.ko` | Other | sha:8025a1e321f2->74a6e173e919 |
| changed | `lib/modules/4.4.60/act_skbedit.ko` | Other | sha:ce0bca168bad->f44769b72f85 |
| changed | `lib/modules/4.4.60/af_key.ko` | Other | sha:e1e8505b8808->43afc7b2c491 |
| changed | `lib/modules/4.4.60/ah4.ko` | Other | sha:00b369d0267c->562155957ee4 |
| changed | `lib/modules/4.4.60/ah6.ko` | Other | sha:6fa8ec4d40d6->b702ff156f22 |
| changed | `lib/modules/4.4.60/ahci.ko` | Other | sha:7da50dddd7b4->7ff46166934f |
| changed | `lib/modules/4.4.60/ahci_platform.ko` | Other | sha:691478cdc339->d7a15b2219f8 |
| changed | `lib/modules/4.4.60/arp_tables.ko` | Other | sha:02d9b2e8175a->1d9e383cefb9 |
| changed | `lib/modules/4.4.60/arpt_mangle.ko` | Other | sha:bcdc2c850e73->b45052924306 |
| changed | `lib/modules/4.4.60/arptable_filter.ko` | Other | sha:abc218c5c14a->9f481d4f0906 |
| changed | `lib/modules/4.4.60/asf.ko` | Other | sha:59318085b338->90c638a097be |
| changed | `lib/modules/4.4.60/ath_pktlog.ko` | Other | sha:6b7f8315782b->cd1523035217 |
| changed | `lib/modules/4.4.60/authenc.ko` | Other | sha:abeb7ac1838d->f6205d7138aa |
| changed | `lib/modules/4.4.60/bonding.ko` | Other | sha:b04822dae34a->2b4bba1af6ef |
| changed | `lib/modules/4.4.60/bootconfig.ko` | Other | sha:5ee54b621d73->96ac6c03d090 |
| changed | `lib/modules/4.4.60/button-hotplug.ko` | Other | sha:72e35b9bee64->00a8cb0830f3 |
| changed | `lib/modules/4.4.60/cbc.ko` | Other | sha:9956363d746d->93d3cdd341bc |
| changed | `lib/modules/4.4.60/cfg80211.ko` | Other | sha:69cc6107ad05->630c6843c351 |
| changed | `lib/modules/4.4.60/cls_basic.ko` | Other | sha:cea745ea2808->e95ecd17a711 |
| changed | `lib/modules/4.4.60/cls_flow.ko` | Other | sha:9670e5dab137->2579af2e5d90 |
| … | _(820 more)_ | | |

