set -e

echo "Starting environment setup..."

echo "Installing core dependencies..."
sudo apt-get update -y
sudo apt-get install -y build-essential cmake git ninja-build pkg-config autoconf automake libtool rclone

echo "Installing OpenSSL headers (with automatic version-mismatch handling)..."
if ! sudo apt-get install -y libssl-dev; then
    echo "Detected OpenSSL version mismatch bug. Applying downgrade sync..."
    sudo apt-get install -y --allow-downgrades libssl-dev=3.5.5-1~deb13u1 libssl3t64=3.5.5-1~deb13u1 openssl=3.5.5-1~deb13u1
fi

echo "Setting CPU governor to performance..."
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null

PROJECT_DIR="$HOME/Desktop/5000OTP"
mkdir -p "$PROJECT_DIR/libs"
cd "$PROJECT_DIR"

cat << 'EOF' > .gitignore
build/
*.o
*.so
*.a
libs/
*.csv
*.dat
.DS_Store
EOF

echo "Building libraries (Optimised for 512MB RAM constraints)..."
cd "$PROJECT_DIR/libs"

if [ ! -d "liboqs" ]; then
    git clone --branch 0.10.0 https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    mkdir -p build && cd build
    cmake -GNinja -DOQS_USE_OPENSSL=ON ..
    ninja -j1
    sudo ninja install
    cd ../../
fi

if [ ! -d "libsodium" ]; then
    git clone --branch 1.0.19-RELEASE https://github.com/jedisct1/libsodium.git
    cd libsodium
    ./autogen.sh
    ./configure
    make -j1
    sudo make install
    cd ../
fi

if [ ! -d "ascon-c" ]; then
    git clone https://github.com/ascon/ascon-c.git
fi

echo "Generating helper scripts..."
cd "$PROJECT_DIR"

cat << 'EOF' > cloud_backup.sh
#!/bin/bash
rclone sync $HOME/dissertation_project gdrive:Dissertation_Backup \
    --exclude "libs/**" \
    --exclude "build/**" \
    -v
EOF
chmod +x cloud_backup.sh

cat << 'EOF' > thermal_monitor.sh
#!/bin/bash
while true; do
    TEMP=$(cat /sys/class/thermal/thermal_zone0/temp)
    if [ "$TEMP" -gt 80000 ]; then
        echo "[$(date)] WARNING: CPU Temperature is ${TEMP}"
    fi
    sleep 2
done
EOF
chmod +x thermal_monitor.sh

sudo ldconfig

echo "Setup Complete!"
echo "Run 'rclone config' to link your Google Drive (name the remote 'gdrive')."