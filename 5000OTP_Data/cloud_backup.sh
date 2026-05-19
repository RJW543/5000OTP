rclone sync $HOME/Desktop/5000OTP gdrive:5000OTP_Data \
    --exclude "libs/**" \
    --exclude "build/**" \
    --exclude ".git/**" \
    -v