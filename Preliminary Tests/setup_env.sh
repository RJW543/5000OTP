echo "[*] Updating system and installing build dependencies..."
sudo apt update && sudo apt install -y cmake gcc libssl-dev python3-dev python3-venv python3-pip git

echo "[*] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install psutil

echo "[*] Cloning and installing liboqs (C library)..."
if [ ! -d "liboqs" ]; then
    git clone --branch main https://github.com/open-quantum-safe/liboqs.git
fi
cd liboqs
mkdir -p build && cd build
cmake -GNinja .. -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=ON
make -j$(nproc)
sudo make install
sudo ldconfig
cd ../..

echo "[*] Installing liboqs-python wrapper..."
if [ ! -d "liboqs-python" ]; then
    git clone --branch main https://github.com/open-quantum-safe/liboqs-python.git
fi
cd liboqs-python
pip install .
cd ..

echo "[SUCCESS] Environment ready."