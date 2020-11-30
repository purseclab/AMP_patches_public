# AMP patches

The code has been tested on Ubuntu 18.04.

## Installation

```bash
# install and upgrade pip
sudo apt install python3-pip
pip3 install --upgrade pip

# install dependencies
sudo apt install nasm clang clang-10 gcc-avr binutils-avr avr-libc
pip3 install git+https://github.com/angr/angr-platforms.git@wip/avr

# install patcherex
pip3 install git+https://github.com/angr/patcherex.git@feat/multiarch
```

## Usage
```bash
cd Challenge_01
./patch.py /path/to/original_binary /tmp/patched_binary
```