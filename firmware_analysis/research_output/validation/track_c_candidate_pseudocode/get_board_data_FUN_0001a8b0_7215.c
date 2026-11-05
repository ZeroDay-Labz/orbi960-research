// configd internal function FUN_0001a8b0 ("get_board_data" per debug strings) (RBSE 7215)
// sha256: 6caa0acf8a1c741e34bb8d64c755758845396ef6fb51222cf1abf5ec56190979
// size: 424 bytes (procedure_address 0x1a8b0, file_offset 0xa8b0)

void FUN_0001a8b0(undefined4 param_1)
{
  int iVar1;
  char *pcVar2;
  FILE *__stream;
  undefined *puVar3;
  int local_5c;
  int local_58;
  char acStack_54 [64];
  int local_14;

  local_14 = __stack_chk_guard;
  memset(acStack_54,0,0x40);
  local_5c = 0;
  local_58 = 0;
  iVar1 = FUN_00019e64(acStack_54,0x40,&local_5c,"board_data -r %s",param_1);
  if (iVar1 < 0) {
    pcVar2 = strerror(local_5c);
    dbg_print(4,"snprintf failed : %s in func %s for %s",pcVar2,"get_board_data",param_1);
  }
  __stream = popen(acStack_54,"r");                               /* <-- sink */
  if (__stream == (FILE *)0x0) {
    dbg_print(4,"cmd error : in func %s","get_board_data");
    puVar3 = (undefined *)0x0;
  }
  else {
    iVar1 = FUN_0001a7d4(__stream,&local_58,"%[^\n]",&DAT_0004b434);
    if (iVar1 < 0) {
      pcVar2 = strerror(local_58);
      dbg_print(4,"fp_scanf error : %s in func %s for %s",pcVar2,"get_board_data",param_1);
    }
    iVar1 = pclose(__stream);
    if (iVar1 < 0) {
      dbg_print(4,"fp_close error : in func %s","get_board_data");
      puVar3 = &DAT_0004b434;
    }
    else {
      puVar3 = &DAT_0004b434;
    }
  }
  if (local_14 != __stack_chk_guard) {
    __stack_chk_fail(puVar3);
  }
  return;
}
