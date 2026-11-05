"""Interactive diag session — run from the project dir:
    python3 orbi_rpc_diag.py
"""
import getpass, json, sys
sys.path.insert(0, '/home/echo/PycharmProjects/orbi_test')
import orbi_satellite_ssh as tool

IP = "10.0.0.4"
print("Target:", IP)

log = tool.AuditLog(enabled=False)
client = tool.UbusClient(IP, log)

username = "admin"
password = getpass.getpass("Satellite admin password: ")

try:
    if not client.login(username, password):
        print("Authentication failed."); sys.exit(1)
    print("[+] authenticated")

    print("\n===== RAW UBUS LIST (will be empty — lighttpd proxy drops /list) =====")
    print(json.dumps(client._call_raw("list", [client.session, "*"]), indent=2))

    print("\n===== uci.configs (should WORK — lists config names) =====")
    print(json.dumps(client._call_raw("call",
        [client.session, "uci", "configs", {}]), indent=2))

    print("\n===== uci.get dropbear (likely [6] perm denied) =====")
    print(json.dumps(client._call_raw("call",
        [client.session, "uci", "get", {"config": "dropbear"}]), indent=2))

    print("\n===== session.access (full ACL dump) =====")
    print(json.dumps(client.session_access(), indent=2))
finally:
    password = None
