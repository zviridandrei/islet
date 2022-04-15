#!/usr/bin/env python3

import os

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "out")
CONFIG = os.path.join(ROOT, "scripts/.config")
PREBUILT = os.path.join(ROOT, "assets/prebuilt")

RMM = os.path.join(ROOT, "rmm/board/fvp")
SDK = os.path.join(ROOT, "sdk/")
TF_A_TESTS = os.path.join(ROOT, "tf-a-tests")
TRUSTED_FIRMWARE_A = os.path.join(ROOT, "trusted-firmware-a")
VM_IMAGE = os.path.join(ROOT, "vm-image")
BUILD_SCRIPT = os.path.join(ROOT, "build")

CROSS_COMPILE = os.path.join(ROOT, "assets/toolchains/aarch64/bin/aarch64-none-linux-gnu-")
FASTMODEL = os.path.join(ROOT, "assets/fastmodel/Base_RevC_AEMvA_pkg/models/Linux64_GCC-6.4")
FIPTOOL = os.path.join(TRUSTED_FIRMWARE_A, "tools/fiptool")