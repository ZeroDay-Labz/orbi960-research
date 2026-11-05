// rbse_7215 configd (sha256 6caa0acf...) authenticate_satellite_1_svc
// Ghidra 12.1.3 pseudocode at 0x24b1c

void authenticate_satellite_1_svc(int *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  size_t sVar5;
  int iVar6;
  void *__ptr;
  FILE *__stream;
  void *pvVar7;
  void *pvVar8;
  uchar *md;
  char cVar9;
  byte bVar10;
  undefined4 uVar11;
  byte *pbVar12;
  undefined8 uVar13;
  int local_2f8;
  int local_2f4;
  char acStack_2f0 [20];
  uchar auStack_2dc [40];
  undefined1 auStack_2b4 [64];
  undefined4 local_274;
  undefined1 auStack_270 [64];
  undefined4 local_230;
  undefined1 auStack_22c [512];
  int local_2c;

  local_2c = __stack_chk_guard;
  puVar1 = (undefined4 *)FUN_0001e7d8(4);
  local_230 = 0x30;
  memset(auStack_22c,0,0x1fe);
  local_274 = 0x30;
  memset(auStack_270,0,0x3d);
  local_2f8 = 0;
  iVar2 = nvram_get("legacy_auth_done");
  if (puVar1 == (undefined4 *)0x0) {
    dbg_print(1,"memory allocation failed at line %d of file %s\n",0xaf3,"ntgr_orbi_rpc_server.c");
    goto LAB_000251ac;
  }
  iVar3 = FUN_0001f7f8(*param_1,&DAT_00035d48,4);
  if (iVar3 == 0) {
    iVar3 = nvram_get("BhSta2.ssid");
    pcVar4 = (char *)nvram_get("BhSta2.passphrase");
    if (pcVar4 == (char *)0x0 || iVar3 == 0) {
      dbg_print(1,"unable to retrive ssid / passphrase in 2g bh trying 5g backhaul\n");
      iVar3 = nvram_get("BhSta5.ssid");
      pcVar4 = (char *)nvram_get("BhSta5.passphrase");
      if (pcVar4 == (char *)0x0 || iVar3 == 0) {
        dbg_print(1,"unable to retrive ssid / passphrase in 5g backhaul as well\n");
        goto LAB_00024cd4;
      }
    }
    sVar5 = strlen(pcVar4);
    if (sVar5 == 0x40) {
      pbVar12 = (byte *)(pcVar4 + -1);
      do {
        pbVar12 = pbVar12 + 1;
        iVar6 = isxdigit((uint)*pbVar12);
        if (iVar6 == 0) goto LAB_00024cf0;
      } while (pbVar12 != (byte *)(pcVar4 + 0x3f));
      iVar6 = FUN_0001e05c(&local_274,0x41,&local_2f8,pcVar4);
      if (-1 < iVar6) {
        iVar6 = FUN_0001f8b8(&local_274,param_1[1]);
        if (iVar6 != 0) goto LAB_00024cf0;
LAB_00024d64:
        *puVar1 = 0;
        goto LAB_000251ac;
      }
      pcVar4 = strerror(local_2f8);
      uVar11 = 0xb0f;
LAB_00024ccc:
      dbg_print(4,"snprintf failed due to %s in line %d func %s\n",pcVar4,uVar11,
                "authenticate_satellite_1_svc");
      goto LAB_00024cd4;
    }
LAB_00024cf0:
    FUN_0001e478(pcVar4,iVar3,&local_230);
    iVar3 = FUN_0001e05c(&local_274,0x41,&local_2f8,&local_230);
    if (iVar3 < 0) {
      pcVar4 = strerror(local_2f8);
      uVar11 = 0xb1b;
      goto LAB_00024ccc;
    }
    iVar3 = FUN_0001f8b8(&local_274,param_1[1]);
    if (iVar3 == 0) goto LAB_00024d64;
    iVar3 = *param_1;
    iVar6 = param_1[1];
    memset(auStack_2dc,0,0x28);
    if (iVar6 == 0 || iVar3 == 0) {
      dbg_print(4,"Argument is NULL\n");
LAB_000251a4:
      uVar11 = 0x191;
    }
    else {
      iVar3 = FUN_0001f7f8(iVar3,&DAT_00035d48,4);
      if (iVar3 != 0) {
        uVar11 = 0xa6d;
        pcVar4 = "Invalid Authentication username at line %d of file %s\n";
LAB_00025020:
        dbg_print(4,pcVar4,uVar11,"ntgr_orbi_rpc_server.c");
        goto LAB_000251a4;
      }
      local_2f4 = iVar3;
      __ptr = (void *)FUN_0001e7d8(0x28);
      memset(auStack_2b4,0,0x40);
      if (__ptr == (void *)0x0) {
        dbg_print(4,"malloc failed\n");
LAB_0002500c:
        uVar11 = 0xa72;
        pcVar4 = "MD5 string formation failed at line %d of file %s\n";
        goto LAB_00025020;
      }
      __stream = popen("(echo \"td s\"; usleep 500000) | hyt | grep \"Network relaying device\" | awk \'/^.*#.*device: [0-9a-fA-F:]*, IPv4 address: [0-9.]*(.*)?$/ { printf(\"%s\", $6);}\' $1 | cut -d \',\' -f 1"
                       ,"r");
      if (__stream == (FILE *)0x0) {
LAB_00025004:
        free(__ptr);
        goto LAB_0002500c;
      }
      pcVar4 = fgets(acStack_2f0,0x12,__stream);
      if (pcVar4 == (char *)0x0) {
        dbg_print(4,"error in fgets\n");
        pclose(__stream);
        goto LAB_00025004;
      }
      pclose(__stream);
      iVar3 = FUN_0001e05c(auStack_2b4,0x40,&local_2f4,"router.mac=%s",acStack_2f0);
      if (iVar3 < 0) {
        pcVar4 = strerror(local_2f4);
        dbg_print(4,"snprintf failed : %s in func %s",pcVar4,"form_md5_str");
        goto LAB_00025004;
      }
      iVar3 = nvram_get("router.mac");
      if ((iVar3 == 0) || (iVar3 = FUN_0001f7f8(iVar3,acStack_2f0,6), iVar3 != 0)) {
        uVar13 = nvram_set(auStack_2b4);
        if ((int)uVar13 == 0) {
          iVar3 = nvram_commit(0,(int)((ulonglong)uVar13 >> 0x20));
          if (iVar3 == 0) goto LAB_00024f34;
          uVar11 = 0x3f7;
        }
        else {
          uVar11 = 0x3f3;
        }
        dbg_print(4,"nvram set failed at line %d",uVar11);
        goto LAB_00025004;
      }
LAB_00024f34:
      uVar13 = nvram_get("boarddata.mac0");
      if ((int)uVar13 == 0) {
        pcVar4 = "Satellite base MAC not found in nvram";
LAB_00024f68:
        dbg_print(4,pcVar4);
        goto LAB_00025004;
      }
      pvVar7 = (void *)FUN_0001f378(acStack_2f0,(int)((ulonglong)uVar13 >> 0x20));
      if (pvVar7 == (void *)0x0) {
        pcVar4 = "Error in converting the router MAC address";
        goto LAB_00024f68;
      }
      pvVar8 = (void *)FUN_0001f378((int)uVar13);
      if (pvVar8 == (void *)0x0) {
        dbg_print(4,"Error in converting the satellite MAC address");
        free(pvVar7);
        goto LAB_00025004;
      }
      FUN_0001e05c(__ptr,0x28,&local_2f4,"NETGEAR_Orbi_%02X_%02X_%02X_%02X_%02X_%02X_password",
                   *(undefined1 *)((int)pvVar7 + 3),*(undefined1 *)((int)pvVar7 + 4),
                   *(undefined1 *)((int)pvVar7 + 5),*(undefined1 *)((int)pvVar8 + 3),
                   *(undefined1 *)((int)pvVar8 + 4),*(undefined1 *)((int)pvVar8 + 5));
      free(pvVar7);
      free(pvVar8);
      if (__ptr == (void *)0x0) goto LAB_0002500c;
      FUN_0001e6a4(auStack_2dc,0,0x28);
      FUN_0001e724(auStack_2dc,__ptr,0x28);
      pvVar7 = (void *)FUN_0001e7d8(0x22);
      md = (uchar *)FUN_0001e7d8(0x10);
      if (pvVar7 == (void *)0x0 || md == (uchar *)0x0) {
        // ... MD5 setup, returns iVar3=1 on failure
      }
      else {
        iVar3 = 0;
        // MD5 the NETGEAR_Orbi_MAC_password string -> hex
        // compare to param_1[1] (candidate password hash)
      }
    }
  }
  else {
LAB_00024cd4:
    uVar11 = 1;
  }
  *puVar1 = uVar11;
LAB_000251ac:
  if (local_2c == __stack_chk_guard) { return; }
  __stack_chk_fail(puVar1);
}
