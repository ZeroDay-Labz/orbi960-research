// configd exports get_command_output  (RBSE 7288)
// sha256: a8a1dad56aa2f1166a39e07d337b6bf919fd9c8f2cc0d40b6bab9bf1feed7e7c
// size: 696 bytes

undefined4 get_command_output(char **param_1,void *param_2,size_t param_3)
{
  int iVar1;
  ssize_t sVar2;
  char *pcVar3;
  char *pcVar4;
  char *pcVar5;
  undefined4 uVar6;
  __pid_t local_80;
  int iStack_7c;
  undefined1 auStack_78 [4];
  int local_74;
  int local_70;
  posix_spawn_file_actions_t pStack_6c;

  local_74 = -1;
  local_70 = -1;
  iVar1 = pipe(&local_74);
  if (iVar1 != 0) {
    dbg_print(4,"pipe creation failed at line %d in function %s\n",0x24f,"get_command_output");
    return 0xffffffff;
  }
  iVar1 = posix_spawn_file_actions_init(&pStack_6c);
  if (iVar1 != 0) {
    dbg_print(4,"posix_spawn_file_actions_init failed at line %d in function %s\n",0x254,
              "get_command_output");
    FUN_0001e678(local_74,auStack_78);
    FUN_0001e678(local_70,auStack_78);
    return 0xffffffff;
  }
  iVar1 = posix_spawn_file_actions_addclose(&pStack_6c,local_74);
  if (iVar1 == 0) {
    iVar1 = posix_spawn_file_actions_adddup2(&pStack_6c,local_70,1);
    if (iVar1 == 0) {
      iVar1 = posix_spawn_file_actions_addclose(&pStack_6c,local_70);
      if (iVar1 == 0) {
        iVar1 = posix_spawnp(&local_80,*param_1,&pStack_6c,(posix_spawnattr_t *)0x0,param_1,environ);
        if (iVar1 == 0) {
          FUN_0001e678(local_70,auStack_78);
          local_70 = -1;
          waitpid(local_80,&iStack_7c,0);
          sVar2 = read(local_74,param_2,param_3);
          if (sVar2 != -1) {
            dbg_print(1,"[%s:%d] value get_command_output is %s\n","ntgr_orbi_rpc_server.c",0x27d,
                      param_2);
            uVar6 = 0;
            goto LAB_00021714;
          }
          pcVar5 = (char *)0x279;
          pcVar4 = "ntgr_orbi_rpc_server.c";
          pcVar3 = "[%s:%d] error during read\n";
        }
        else {
          pcVar4 = (char *)0x26d;
          pcVar3 = "posix_spawnp failed at line %d in function %s\n";
          pcVar5 = "get_command_output";
        }
      }
      else {
        pcVar4 = (char *)0x267;
        pcVar3 = "posix_spawn_file_actions_addclose failed at line %d in function %s\n";
        pcVar5 = "get_command_output";
      }
    }
    else {
      pcVar4 = (char *)0x261;
      pcVar3 = "posix_spawn_file_actions_adddup2 failed at line %d in function %s\n";
      pcVar5 = "get_command_output";
    }
  }
  else {
    pcVar4 = (char *)0x25b;
    pcVar3 = "posix_spawn_file_actions_addclose failed at line %d in function %s\n";
    pcVar5 = "get_command_output";
  }
  uVar6 = 0xffffffff;
  dbg_print(4,pcVar3,pcVar4,pcVar5);
LAB_00021714:
  if (local_74 != -1) {
    FUN_0001e678(local_74,auStack_78);
    local_74 = -1;
  }
  if (local_70 != -1) {
    FUN_0001e678(local_70,auStack_78);
    local_70 = -1;
  }
  posix_spawn_file_actions_destroy(&pStack_6c);
  return uVar6;
}
