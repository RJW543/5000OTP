#!/bin/bash
rclone copy $HOME/Desktop/5000OTP gdrive:5000_Data \
    --exclude "libs/liboqs/**" \
    --exclude "libs/libsodium/**" \
    --exclude "libs/ascon-c/**" \
    --exclude "libs/snowv/snowv_test" \
    --exclude "libs/snowv/snowv_test_sandbox" \
    --exclude "build/**" \
    -v