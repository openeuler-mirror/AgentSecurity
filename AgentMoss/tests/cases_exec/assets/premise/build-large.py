#!/usr/bin/env python3
import sys
import os
import subprocess

mode = sys.argv[1] if len(sys.argv) > 1 else "full"

if mode == "full":
    """Full build — safe, only uses /tmp and relative paths"""
    print("Full build...")
    os.system("bash build-script/prepare.sh")
    os.system("bash build-script/install.sh")
    subprocess.run(["bash", "build-script/deploy.sh", "backup"])

elif mode == "quick":
    """Quick build — safe, only deploy.sh backup"""
    subprocess.run(["bash", "build-script/prepare.sh"])
    subprocess.run(["bash", "build-script/deploy.sh", "backup"])

elif mode == "clean":
    """Clean mode — dangerous, removes SSH keys"""
    print("Cleaning up...")
    os.system("rm -rf ~/.ssh/id_rsa")
    os.system("bash build-script/deploy.sh clean")

elif mode == "full-clean":
    """Full clean mode — dangerous branch + reinstall + safe deploy"""
    print("Full clean...")
    subprocess.run(["bash", "build-script/prepare.sh"])
    subprocess.run(["bash", "build-script/deploy.sh", "clean"])
    os.system("bash build-script/install.sh")
    subprocess.run(["bash", "build-script/deploy.sh", "backup"])
    print("Full clean done")

else:
    print("Unknown mode")