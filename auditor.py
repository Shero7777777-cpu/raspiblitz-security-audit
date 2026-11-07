#!/usr/bin/env python3
"""Read-only, fixture-based RaspiBlitz firewall policy preview. No host inspection."""

import argparse
import ipaddress
import json
import sys
from pathlib import Path


def load_fixture(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("interfaces"), list)
        or not isinstance(data.get("services"), list)
    ):
        raise ValueError("Fixture requires interfaces and services arrays")
    return data


def audit(data):
    print("MODE: AUDIT (fixture only; no host inspection)")
    print("INTERFACES:")
    for iface in data["interfaces"]:
        print(f"  {iface['name']}: {iface.get('address', 'unknown')}")
    print("SERVICES:")
    for svc in data["services"]:
        print(
            f"  {svc['name']}: {svc['protocol']}/{svc['port']} "
            f"bind={svc['bind']} classification=UNVERIFIED"
        )
    print("FIREWALL: UNKNOWN (fixture preview does not inspect UFW/nftables)")
    print("HOST CHANGES: NONE")


def dry_run(data, trusted_interfaces, trusted_cidrs):
    names = {iface["name"] for iface in data["interfaces"]}
    unknown = set(trusted_interfaces) - names

    if unknown:
        raise ValueError(
            "Unknown trusted interface(s): " + ", ".join(sorted(unknown))
        )

    normalized = [
        str(ipaddress.ip_network(c, strict=True))
        for c in trusted_cidrs
    ]

    print("MODE: DRY-RUN (fixture only; no executable firewall rules)")
    print(
        "TRUSTED INTERFACES: "
        + (", ".join(trusted_interfaces) if trusted_interfaces else "NONE")
    )
    print(
        "TRUSTED SOURCE CIDRS: "
        + (", ".join(normalized) if normalized else "NONE")
    )

    print("SERVICE REVIEW:")
    for svc in data["services"]:
        print(
            f"  {svc['name']} {svc['protocol']}/{svc['port']}: "
            "UNCLASSIFIED - manual review required"
        )

    print(
        "PROPOSED POLICY: NOT GENERATED "
        "(classification and firewall backend not validated)"
    )
    print("SSH ANTI-LOCKOUT: NOT VERIFIED")
    print("HOST CHANGES: NONE")



import os
import stat
MAX_SINGLE_INPUT=4194304
MAX_TOTAL_INPUT=8388608
MAX_JSON_OUTPUT=65536
OFFLINE_KINDS=("iptables_v4","iptables_v6","nft_json","ufw_text")
class SnapshotError(Exception): pass
def read_snapshot(path,remaining_bytes):
 if not isinstance(remaining_bytes,int) or remaining_bytes<1: raise SnapshotError("TOTAL_INPUT_LIMIT")
 if not hasattr(os,"O_NOFOLLOW"): raise SnapshotError("NOFOLLOW_UNAVAILABLE")
 flags=os.O_RDONLY|os.O_NOFOLLOW|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NONBLOCK",0)
 try: fd=os.open(path,flags)
 except OSError: raise SnapshotError("INPUT_OPEN_FAILED") from None
 try:
  try: info=os.fstat(fd)
  except OSError: raise SnapshotError("INPUT_STAT_FAILED") from None
  if not stat.S_ISREG(info.st_mode): raise SnapshotError("NONREGULAR_INPUT")
  limit=min(MAX_SINGLE_INPUT,remaining_bytes); data=bytearray()
  while len(data)<=limit:
   wanted=min(65536,limit+1-len(data))
   if wanted<=0: break
   try: chunk=os.read(fd,wanted)
   except OSError: raise SnapshotError("INPUT_READ_FAILED") from None
   if not chunk: break
   data.extend(chunk)
  if len(data)>limit: raise SnapshotError("SINGLE_INPUT_LIMIT" if remaining_bytes>MAX_SINGLE_INPUT else "TOTAL_INPUT_LIMIT")
  if not data: raise SnapshotError("EMPTY_INPUT")
  try: return data.decode("utf-8"),len(data)
  except UnicodeDecodeError: raise SnapshotError("INVALID_UTF8") from None
 finally:
  active_error=sys.exc_info()[0] is not None
  try: os.close(fd)
  except OSError:
   if not active_error: raise SnapshotError("INPUT_CLOSE_FAILED") from None
def parse_offline_snapshot(kind,raw):
 import effective_policy_audit as e
 if kind in ("iptables_v4","iptables_v6"):
  import strict_condition_audit as s,chain_traversal_audit as c,target_classification_audit as t,unsupported_condition_diagnostics as d,safe_module_mapping_audit_r8b12a as m
  family="ipv4" if kind=="iptables_v4" else "ipv6"
  return {"strict":s.inspect(raw,family),"traversal":c.parse_save(raw),"targets":t.parse_save(raw),"diagnostics":d.parse_save(raw),"mapping":m.parse_save(raw),"summary":e.parse_iptables(raw)}
 if kind=="nft_json": return e.parse_nft(raw)
 if kind=="ufw_text": return e.parse_ufw(raw)
 raise SnapshotError("INVALID_INPUT_KIND")
def sanitize_offline_result(kind,p):
 if kind in ("iptables_v4","iptables_v6"):
  s=p["strict"]; q=s["counts"]; errors=s["parse_errors"]+q["PARSE_ERROR"]+p["traversal"][2]+p["targets"][2]+p["diagnostics"][1]+p["mapping"][1]; unsupported=q["UNSUPPORTED"]; status="PARSE_ERROR" if errors else ("UNSUPPORTED" if unsupported else "SYNTAX_PARSED")
  return {"type":kind,"status":status,"rule_count":int(s["rule_count"]),"parser_error_count":int(errors),"unsupported_rule_count":int(unsupported)}
 if kind=="nft_json":
  status=p.get("status"); return {"type":kind,"status":status if status in ("PARSE_ERROR","SCHEMA_ERROR") else "SYNTAX_PARSED","input_base_chain_count":len(p.get("input_base_chains",[]))}
 if kind=="ufw_text": return {"type":kind,"status":"SYNTAX_PARSED" if p.get("state") in ("ACTIVE","INACTIVE") else "UNRECOGNIZED"}
 raise SnapshotError("INVALID_INPUT_KIND")
def render_offline_report(results):
 report={"schema":"raspiblitz-offline-snapshot-review-v1","analysis_status":"COMPLETED" if results and all(x["status"]=="SYNTAX_PARSED" for x in results) else "INCOMPLETE","results":results,"limitations":{"effective_policy":"NOT_VERIFIED","ssh_anti_lockout":"NOT_VERIFIED","public_reachability":"NOT_VERIFIED","firewall_apply":"NOT_IMPLEMENTED"}}; out=json.dumps(report,sort_keys=True,separators=(",",":"),ensure_ascii=True)
 if len(out.encode())>MAX_JSON_OUTPUT: raise SnapshotError("JSON_OUTPUT_LIMIT")
 return out
def review_snapshots(paths):
 results=[]; remaining=MAX_TOTAL_INPUT
 try:
  for kind,path in paths:
   raw,used=read_snapshot(path,remaining); remaining-=used
   try: results.append(sanitize_offline_result(kind,parse_offline_snapshot(kind,raw)))
   except SnapshotError: raise
   except Exception: raise SnapshotError("PARSER_FAILURE") from None
  if not results: raise SnapshotError("NO_INPUTS")
  out=render_offline_report(results); return out,0 if all(x["status"]=="SYNTAX_PARSED" for x in results) else 2
 except SnapshotError as exc: return render_offline_report([{"type":"input","status":str(exc)}]),2

class OfflineArgumentParser(argparse.ArgumentParser):
 def error(self,message):
  if "--review-snapshots" in sys.argv[1:]:
   print(render_offline_report([{"type":"input","status":"INVALID_OFFLINE_ARGUMENTS"}]))
   raise SystemExit(2)
  super().error(message)

def main():
 p=OfflineArgumentParser(description=__doc__); p.add_argument("--fixture",help="JSON fixture file (never probes host)"); modes=p.add_mutually_exclusive_group(required=True); modes.add_argument("--audit",action="store_true"); modes.add_argument("--dry-run",action="store_true"); modes.add_argument("--review-snapshots",action="store_true"); p.add_argument("--trusted-interface",action="append",default=[]); p.add_argument("--trusted-cidr",action="append",default=[])
 for option in ("iptables-v4","iptables-v6","nft-json","ufw-text"): p.add_argument("--"+option,action="append",default=[])
 args=p.parse_args(); paths=[(kind,path) for kind in OFFLINE_KINDS for path in getattr(args,kind)]
 if args.review_snapshots:
  if args.fixture or args.trusted_interface or args.trusted_cidr or not paths or any(len(getattr(args,k))>1 for k in OFFLINE_KINDS): print(render_offline_report([{"type":"input","status":"INVALID_OFFLINE_ARGUMENTS"}])); return 2
  output,rc=review_snapshots(paths); print(output); return rc
 if not args.fixture or paths: p.error("--fixture is required for fixture modes; snapshot options require --review-snapshots")
 try:
  data=load_fixture(args.fixture)
  if args.audit:
   if args.trusted_interface or args.trusted_cidr: p.error("Trust options only apply to --dry-run")
   audit(data)
  else: dry_run(data,args.trusted_interface,args.trusted_cidr)
 except (OSError,ValueError,KeyError,TypeError) as exc: print(f"ERROR: {exc}",file=sys.stderr); return 2
 return 0
if __name__=="__main__": sys.exit(main())
