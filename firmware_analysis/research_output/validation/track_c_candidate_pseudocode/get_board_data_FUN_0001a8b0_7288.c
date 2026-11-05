// configd internal function FUN_0001a8b0 ("get_board_data" per debug strings) (RBSE 7288)
// sha256: a8a1dad56aa2f1166a39e07d337b6bf919fd9c8f2cc0d40b6bab9bf1feed7e7c
// size: 564 bytes (+140 bytes vs 7215, procedure_address 0x1a8b0)
//
// DELTA ANALYSIS:
//   The +140 byte growth is a new conditional block that rewrites the board_data
//   output string "RBS750QV" to "RBS750" (model normalization for the new
//   RBS750QV satellite variant). It is NOT input validation of param_1.
//
//   The command-injection-shaped primitive is UNCHANGED:
//       snprintf(buf, 64, "board_data -r %s", param_1); popen(buf, "r");
//
//   If param_1 is user-controllable at the RPC boundary, both versions are
//   equally vulnerable. VERDICT: NOT the CVE-2026-0415 fix. This is model-
//   support code added for RBS750 compatibility, same family as the "RBS750"/
//   "RBS750QV" string additions report 31 identified in soap_agent and sat
//   configd.

void FUN_0001a8b0(undefined4 param_1)
{
  int iVar1;
  char *pcVar2;
  FILE *__stream;
  undefined *puVar3;
  int local_64;
  int local_60;
  char acStack_5c [64];
  int local_1c;

  local_1c = __stack_chk_guard;
  memset(acStack_5c,0,0x40);
  local_64 = 0;
  local_60 = 0;
  iVar1 = FUN_00019e64(acStack_5c,0x40,&local_64,"board_data -r %s",param_1);
  if (iVar1 < 0) {
    pcVar2 = strerror(local_64);
    dbg_print(4,"snprintf failed : %s in func %s for %s",pcVar2,"get_board_data",param_1);
  }
  __stream = popen(acStack_5c,"r");                               /* <-- sink (unchanged) */
  if (__stream == (FILE *)0x0) {
    dbg_print(4,"cmd error : in func %s","get_board_data");
    puVar3 = (undefined *)0x0;
  }
  else {
    iVar1 = FUN_0001a7d4(__stream,&local_60,"%[^\n]",&DAT_0004b434);
    if (iVar1 < 0) {
      pcVar2 = strerror(local_60);
      dbg_print(4,"fp_scanf error : %s in func %s for %s",pcVar2,"get_board_data",param_1);
    }
    /* === +140 BYTES BEGIN: model normalization block (NOT a CVE fix) === */
    iVar1 = strncmp(&DAT_0004b434,"RBS750QV",8);
    if ((iVar1 == 0) && (iVar1 = FUN_00019e64(&DAT_0004b434,0x40,&local_64,"RBS750"), iVar1 < 0)) {
      pcVar2 = strerror(local_64);
      dbg_print(4,"snprintf failed : %s in func %s for %s",pcVar2,"get_board_data",param_1);
    }
    /* === +140 BYTES END === */
    iVar1 = pclose(__stream);
    if (iVar1 < 0) {
      dbg_print(4,"fp_close error : in func %s","get_board_data");
      puVar3 = &DAT_0004b434;
    }
    else {
      puVar3 = &DAT_0004b434;
    }
  }
  if (local_1c != __stack_chk_guard) {
    __stack_chk_fail(puVar3);
  }
  return;
}
