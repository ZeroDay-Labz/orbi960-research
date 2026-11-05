// configd exports execute_system_cmd  (RBSE 7288)
// sha256: a8a1dad56aa2f1166a39e07d337b6bf919fd9c8f2cc0d40b6bab9bf1feed7e7c
// size: 128 bytes

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
