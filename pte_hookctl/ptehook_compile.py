#!/usr/bin/env python3
"""
ptehook-compile — Profile 编译器。

在 PC 侧运行一次，解析目标 APK 的 DEX、生成 shellcode 模板，
产出设备侧 daemon (ptehookd) 自治 hook 所需的 JSON profile。

Usage:
    python3 ptehook_compile.py \
        --package com.target.app \
        --hook "java:Lcom/target/License;.isVIP:()Z:return_const=1:wait_jit" \
        --hook "java:Lcom/target/Auth;.checkRoot:(I)Z:return_const=0" \
        -o /tmp/com.target.app.json

Hook spec format:
    java:<class_desc>.<method>:<sig>:<action>=<value>[:<deploy_mode>]

    action   = return_const | noop | log_args
    deploy   = default | wait_jit | unsafe_bridge | legacy
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

_PARENT = os.path.dirname(os.path.abspath(__file__))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import art_offsets as AO
import dex_parser as DP
import shellcode as SC
from ptehook import actions

ADB_SERIAL = os.environ.get("ADB_SERIAL", "")


def _adb(*args):
    cmd = ["adb"]
    if ADB_SERIAL:
        cmd += ["-s", ADB_SERIAL]
    cmd += list(args)
    return subprocess.check_output(cmd, text=True)


def _adb_root(cmd_str):
    return _adb("shell", f"su -c '{cmd_str}'")


def _ensure_apk(package):
    cache_dir = "/tmp/ptehook_lib_cache"
    os.makedirs(cache_dir, exist_ok=True)
    local = os.path.join(cache_dir, f"{package}.apk")
    if os.path.exists(local):
        return local
    out = _adb("shell", f"pm path {package}").strip()
    dev_path = out.split(":", 1)[1] if ":" in out else out
    tmp = "/data/local/tmp/_apk_probe.apk"
    _adb_root(f"cp {dev_path} {tmp} && chmod 644 {tmp}")
    subprocess.check_call(
        ["adb"] + (["-s", ADB_SERIAL] if ADB_SERIAL else []) + ["pull", tmp, local],
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return local


def _md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _device_info():
    info = {}
    try:
        info["model"] = _adb("shell", "getprop ro.product.model").strip()
    except Exception:
        info["model"] = "unknown"
    try:
        info["android_api"] = int(_adb("shell", "getprop ro.build.version.sdk").strip())
    except Exception:
        info["android_api"] = 33
    try:
        info["kernel"] = _adb("shell", "uname -r").strip()
    except Exception:
        info["kernel"] = "unknown"
    return info


def _parse_hook_spec(spec_str):
    """Parse 'java:Lcom/foo/Bar;.method:(I)I:return_const=42:wait_jit'"""
    parts = spec_str.split(":")
    if len(parts) < 4:
        raise ValueError(
            f"hook spec needs at least 4 colon-separated parts: {spec_str}\n"
            f"format: java:<class>.<method>:<sig>:<action>[:<deploy_mode>]")

    hook_type = parts[0]
    if hook_type not in ("java", "java_spray"):
        raise ValueError(f"unsupported hook type: {hook_type}")

    class_method = parts[1]
    dot_idx = class_method.rfind(".")
    if dot_idx < 0:
        raise ValueError(f"class.method format error: {class_method}")
    class_desc = class_method[:dot_idx]
    method_name = class_method[dot_idx + 1:]

    sig = parts[2]

    action_str = parts[3]
    if "=" in action_str:
        action_type, action_value = action_str.split("=", 1)
        action_value = int(action_value)
    else:
        action_type = action_str
        action_value = 0

    deploy_mode = parts[4] if len(parts) > 4 else "default"

    return dict(
        type=hook_type,
        class_desc=class_desc,
        method_name=method_name,
        sig=sig,
        action_type=action_type,
        action_value=action_value,
        deploy_mode=deploy_mode,
    )


def _make_action(action_type, action_value):
    if action_type == "return_const":
        return actions.ReturnConst(action_value)
    elif action_type == "noop":
        return actions.Noop()
    elif action_type == "log_args":
        return actions.LogArgs()
    else:
        raise ValueError(f"unsupported action: {action_type}")


def _compute_patch_slots(action_type):
    """Compute byte offsets of the runtime-patchable MOVZ/MOVK sequences
    within the java_uxn_filter shellcode template.

    Layout of java_uxn_filter:
        +0x00  BTI jc                          (1 insn = 4 bytes)
        +0x04  load_imm64_fixed(X17, MASK)     (4 insns = 16 bytes)
        +0x14  AND X16, X0, X17                (1 insn = 4 bytes)
        +0x18  load_imm64_fixed(X17, expected) (4 insns = 16 bytes)  ← patch slot
        +0x28  CMP X16, X17                    (1 insn = 4 bytes)
        +0x2C  B.EQ #+24                       (1 insn = 4 bytes)
        +0x30  load_imm64_fixed(X16, backup)   (4 insns = 16 bytes)  ← patch slot
        +0x40  BR X16                          (1 insn = 4 bytes)
        +0x44  <action_code>
    """
    slots = {
        "expected_method_ptr": {"byte_offset": 0x18, "reg": 17},
        "backup_addr": {"byte_offset": 0x30, "reg": 16},
    }

    if action_type == "log_args":
        action_code_start = 0x44
        slots["log_buf"] = {"byte_offset": action_code_start + 4, "reg": 16}

    return slots


def compile_profile(package, hook_specs, output_path):
    print(f"[*] compiling profile for {package}")

    apk_path = _ensure_apk(package)
    apk_md5 = _md5_file(apk_path)
    print(f"[+] APK: {apk_path} (md5={apk_md5[:12]}...)")

    dev_info = _device_info()
    api = dev_info["android_api"]
    offsets = AO.get_offsets(api)
    print(f"[+] device: {dev_info['model']} API={api}")

    art_layout = {
        "artmethod_size": offsets.get("ARTMETHOD_SIZE", 0x20),
        "off_declaring_class": offsets.get("ARTMETHOD_DECLARING_CLASS", 0),
        "off_access_flags": offsets.get("ARTMETHOD_ACCESS_FLAGS", 4),
        "off_dex_method_index": offsets.get("ARTMETHOD_DEX_METHOD_INDEX", 8),
        "off_entry_point": offsets.get("ARTMETHOD_ENTRY_QUICK", 0x18),
    }

    profile = {
        "version": 1,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "device": dev_info,
        "package": package,
        "apk_md5": apk_md5,
        "art_layout": art_layout,
        "hooks": [],
    }

    for i, spec in enumerate(hook_specs):
        print(f"\n[*] hook [{i}] {spec['class_desc']}.{spec['method_name']}{spec['sig']}")

        info = DP.find_method_in_apk(
            apk_path, spec["class_desc"], spec["method_name"], spec["sig"])
        if not info:
            print(f"[!] method not found in APK, skipping")
            continue

        print(f"[+] DEX: {info['dex_name']} method_idx={info['method_idx']} "
              f"access=0x{info.get('access_flags', 0):x}")

        action = _make_action(spec["action_type"], spec["action_value"])
        action_code = action.build(log_buf_addr=0)

        template = SC.java_uxn_filter(
            expected_method_ptr=0,
            action_shellcode=action_code,
            backup_addr=0)

        patch_slots = _compute_patch_slots(spec["action_type"])

        hook_id = f"{spec['method_name']}_{i}"

        warmup = 30
        deploy_strategy = None
        if spec["deploy_mode"] == "wait_jit":
            deploy_strategy = [
                {"mode": "wait_jit", "timeout": warmup},
                {"mode": "unsafe_bridge", "fallback": True},
            ]

        hook_entry = {
            "id": hook_id,
            "type": spec["type"],
            "class_desc": spec["class_desc"],
            "method_name": spec["method_name"],
            "signature": spec["sig"],
            "method_idx": info["method_idx"],
            "adjacent_idxs": info.get("adjacent_idxs", []),
            "access_flags_dex": info.get("access_flags", 0),
            "deploy_mode": spec["deploy_mode"],
            "warmup_timeout": warmup,
        }
        if deploy_strategy:
            hook_entry["deploy_strategy"] = deploy_strategy

        hook_entry["action"] = {
            "type": spec["action_type"],
            "value": spec["action_value"],
        }
        hook_entry["shellcode_hex"] = template.hex()
        hook_entry["shellcode_len"] = len(template)
        hook_entry["patch_slots"] = patch_slots

        profile["hooks"].append(hook_entry)
        print(f"[+] shellcode: {len(template)} bytes, "
              f"{len(patch_slots)} patch slot(s)")

    with open(output_path, "w") as f:
        json.dump(profile, f, indent=2)
    print(f"\n[+] profile written to {output_path} "
          f"({len(profile['hooks'])} hooks)")
    return profile


def main():
    ap = argparse.ArgumentParser(
        description="ptehook profile compiler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("--package", "-p", required=True,
                    help="target app package name")
    ap.add_argument("--hook", action="append", default=[],
                    help="hook spec (repeatable)")
    ap.add_argument("--output", "-o", required=True,
                    help="output JSON profile path")
    args = ap.parse_args()

    if not args.hook:
        ap.error("at least one --hook is required")

    specs = [_parse_hook_spec(h) for h in args.hook]
    compile_profile(args.package, specs, args.output)


if __name__ == "__main__":
    main()
