// configd exports execute_system_cmd  (RBSE 7215)
// sha256: 6caa0acf8a1c741e34bb8d64c755758845396ef6fb51222cf1abf5ec56190979
// size: 128 bytes
// VERDICT: byte-for-byte pseudocode identical to 7288 — NOT the CVE fix.

void execute_system_cmd(char *param_1)
{
  int iVar1;

  if (param_1 == (char *)0x0) {
    dbg_print(4,"NULL parameter at line %d of file %s\n",0x360,"ntgr_orbi_rpc_server.c");
  }
  dbg_print(4,"command executing is %s",param_1);
  iVar1 = system(param_1);
  if (iVar1 == 0) {
    return;
  }
  dbg_print(4,"Failed to execute system command at line %d of file %s\n",0x364,
            "ntgr_orbi_rpc_server.c");
  return;
}
