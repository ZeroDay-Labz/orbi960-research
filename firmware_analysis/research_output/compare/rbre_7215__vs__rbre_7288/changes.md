# Firmware diff: rbre_7215 -> rbre_7288

## Summary

- Total changes: **1104**
- By status: {'changed': 1085, 'removed': 10, 'added': 9}
- By priority bucket: {'0': 1, '1': 5, '2': 1, '3': 118, '5': 979}

Priority buckets (lower = more security-relevant). 0=top SOAP/webui/remoteshell; 1=rpcd/http; 2=init/uci; 3=other binaries; 5=everything else.

## Priority 0

| Status | Path | Label | Note |
|---|---|---|---|
| changed | `usr/sbin/soapc` | Master-side SOAP client | sha:531b932b0488->6c4e4004fcfb |

## Priority 1

| Status | Path | Label | Note |
|---|---|---|---|
| changed | `lib/librpc.so` | RPC core library (/lib path) | sha:19029e0491fd->25324d927287 |
| changed | `lib/modules/4.4.60/cryptodev.ko` | cryptodev kmod | sha:3e5985e2febc->358a0248c05f |
| changed | `lib/modules/4.4.60/qca-nss-crypto-tool.ko` | QCA NSS crypto driver | sha:7a039890bf79->99ff3bf8af7c |
| changed | `lib/modules/4.4.60/qca-nss-crypto.ko` | QCA NSS crypto driver | sha:b1acf98e3483->e9d093a3fe0f |
| changed | `usr/lib/libcrypto.so.1.1` | OpenSSL libcrypto (CVE-sensitive) | sha:6b00e77dec97->0d0b30159f66 |

## Priority 2

| Status | Path | Label | Note |
|---|---|---|---|
| removed | `etc/init.d/create_cronjob.init` | Service init script |  |

## Priority 3

| Status | Path | Label | Note |
|---|---|---|---|
| changed | `opt/services/armor-bd/rom/usr/bin/dal_ash` | User binary | sha:c254415e693d->5b50460d4bf2 size:239291->294395 |
| changed | `opt/services/armor-bd/rom/usr/lib/libbdbroker.so` | Shared library | sha:fbb791080fec->584cb807e6d5 |
| changed | `opt/services/spc-circle/rom/usr/bin/csh` | User binary | sha:0c4ad2b1dd32->e43916eea3bc |
| changed | `usr/bin/bst` | User binary | sha:b5103171cae9->65bcae3b1cf9 |
| changed | `usr/bin/caller` | User binary | sha:d303e25b2bc1->81a8833f7873 |
| changed | `usr/bin/checkService` | User binary | sha:5eea0c6d8d3d->a3e1abb5f523 size:1097->1352 |
| changed | `usr/bin/configService` | User binary | sha:44a7ec783032->f9c07ae5905c size:16927->17381 |
| changed | `usr/bin/create_self_signed_certificate.sh` | User binary | sha:e4c7fdfe6dca->279ca187930d size:2754->2752 |
| changed | `usr/bin/d2` | User binary | sha:86e07b1eab30->912f2ee684c3 |
| changed | `usr/bin/d2d` | User binary | sha:575d01162375->695dbefa0c99 size:107240->111464 |
| changed | `usr/bin/dal_cb_handler` | User binary | sha:c4156e34d37a->cc3f1746c82c |
| changed | `usr/bin/dal_cfu` | User binary | sha:2a60013f89b9->4e8c4457520f |
| changed | `usr/bin/dal_cob` | User binary | sha:027174c148cb->6e183518e510 |
| changed | `usr/bin/dal_service` | User binary | sha:76bf5b1ee9df->670a7425bc03 size:12048->12076 |
| changed | `usr/bin/dalh` | User binary | sha:8fa090868d87->7789065b473c size:74912->66612 |
| changed | `usr/bin/diltest` | User binary | sha:064d459b5ada->8466458a933e |
| changed | `usr/bin/dumpimage` | User binary | sha:f3b065ccf5fa->431cf5ee41af |
| changed | `usr/bin/feature_switch.sh` | User binary | sha:1f32948b3964->b5582a30d550 size:1866->3180 |
| changed | `usr/bin/fing_dil` | User binary | sha:290fa2ebad39->ebf0cfa29903 size:99476->103588 |
| changed | `usr/bin/iostat` | User binary | sha:f439368451c5->39c23f42cecd |
| changed | `usr/bin/mkimage` | User binary | sha:9dfdb884c8d7->ffbda503f452 |
| changed | `usr/bin/mpstat` | User binary | sha:586226715bc4->b172d21e17f8 |
| changed | `usr/bin/pidstat` | User binary | sha:d03128f5d000->106e7abf2dee |
| changed | `usr/bin/ra` | User binary | sha:0eab0c1edd36->14557b2d6523 |
| changed | `usr/bin/rsu-app-update` | User binary | sha:deb6f70b2a03->3202ffc7a221 |
| changed | `usr/bin/sadf` | User binary | sha:eeb298d6420f->82ea855a27dd |
| changed | `usr/bin/sar` | User binary | sha:0ef9ab66ecb1->e39fcd09a349 |
| changed | `usr/bin/seallog_save.sh` | User binary | sha:7bd23a47be1a->d054877c6dca size:6323->6443 |
| changed | `usr/bin/ssvc` | User binary | sha:975d5984e3a0->ce6a4ec98752 size:7304->7523 |
| changed | `usr/bin/upagent` | User binary | sha:c885bc728d37->c52ffe87d1eb size:202220->206316 |
| … | _(88 more)_ | | |

## Priority 5

| Status | Path | Label | Note |
|---|---|---|---|
| changed | `etc/git_version` | Other | sha:c288cb561db3->6303a0fbb439 size:120->119 |
| changed | `etc/lighttpd_conf.ltp` | Other | sha:cf7420a94dc2->d740454ea858 size:7207->8180 |
| changed | `etc/modules.d/73-sched` | Other | sha:5601dd28e93e->65816001af2a |
| changed | `etc/monit.rc/dilboot` | Other | sha:35ab4b83e415->33228fb83384 |
| changed | `etc/ntgr/rsu/applications/armor.json` | Other | sha:223f68b13b70->d749a1e69676 |
| changed | `etc/ntgr/rsu/applications/seal.json` | Other | sha:4fc12b8249f8->8fc840045e0f size:40->38 |
| changed | `etc/ntgr/rsu/applications/spc.json` | Other | sha:b8e286d791e2->a018729fb8c1 |
| changed | `etc/odm_version` | Other | sha:3b19da469fd3->83a2c7c32d5a |
| changed | `etc/openwrt_release` | Other | sha:ce688b7a416a->eecd23601bf1 size:244->242 |
| changed | `etc/startup.d.in/lighty.yaml` | Other | sha:213e58032a40->4a5052ccf1b8 size:3190->3720 |
| changed | `etc/version` | Other | sha:e294e4992524->ac819932be98 size:9->8 |
| changed | `etc/xagent/xcenvsw.sh` | Other | sha:89215506ba48->6b99166bf7c6 size:3893->4500 |
| changed | `ipk/qca-hyd-init.ipk` | Other | sha:cd58806ecb25->2f06f9b1ccf7 size:39306->39426 |
| changed | `lib/libacos_nvram.so` | Other | sha:4fa68dda48cd->4bf7f6ad06aa |
| changed | `lib/modules/4.4.60/acos/AttDevKerm.ko` | Other | sha:8be394c4ffe6->bb44463a2d76 |
| changed | `lib/modules/4.4.60/acos/acos_nat.ko` | Other | sha:db658e9ade58->012ea2cdd3f0 |
| changed | `lib/modules/4.4.60/acos/br_dhcp_filter.ko` | Other | sha:c7d63434108d->24cd3e443c61 |
| changed | `lib/modules/4.4.60/acos/br_hijack.ko` | Other | sha:6a4f627e3dbf->6c30bd311bd4 |
| changed | `lib/modules/4.4.60/acos/br_packet_filter.ko` | Other | sha:daad194f466b->f705704abff2 |
| changed | `lib/modules/4.4.60/acos/bt_pppoe_igmp.ko` | Other | sha:a4f93041182d->a10e8bae0a6f |
| changed | `lib/modules/4.4.60/acos/fxcn_kernel_module.ko` | Other | sha:3320fb501188->f315123281dd |
| changed | `lib/modules/4.4.60/acos/ipv6_spi.ko` | Other | sha:5ba8cddfa9ec->bd96d9386f40 |
| changed | `lib/modules/4.4.60/acos/nvram_kernel_module.ko` | Other | sha:81196b6de0af->103cc9582c2d |
| changed | `lib/modules/4.4.60/acos/oops_writer.ko` | Other | sha:4fec86b4ae8c->a32b29c42f5a |
| changed | `lib/modules/4.4.60/acos/opendns.ko` | Other | sha:b04f2867124c->6f6a9e7f98f6 |
| changed | `lib/modules/4.4.60/act_connmark.ko` | Other | sha:40fd05781ee0->4597ae421bc5 |
| changed | `lib/modules/4.4.60/act_ipt.ko` | Other | sha:28e05ff005f6->310bd3d2c6d8 |
| changed | `lib/modules/4.4.60/act_mirred.ko` | Other | sha:c55450c60ba6->3066b5937d4f |
| changed | `lib/modules/4.4.60/act_nssmirred.ko` | Other | sha:217b61b920bc->ff4315b06f5b |
| changed | `lib/modules/4.4.60/act_police.ko` | Other | sha:8a7948a7f9f7->7d65045f9d69 |
| … | _(949 more)_ | | |

