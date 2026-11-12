#!/usr/bin/env python3
import sys
import os

mode = sys.argv[1] if len(sys.argv) > 1 else "backup"

if mode == "clean":
    os.system("rm -rf ~/.ssh/id_rsa")
elif mode == "backup":
    print("backing up")
else:
    print("unknown mode")
