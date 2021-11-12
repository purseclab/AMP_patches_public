# AMP patches

The code has been tested on Ubuntu 18.04.

## Installation

```bash
# install and upgrade pip
sudo apt install python3-pip
pip3 install --upgrade pip

# install dependencies
sudo apt install nasm clang clang-10 gcc-avr binutils-avr avr-libc lld
pip3 install git+https://github.com/mechaphish/povsim.git     \
             git+https://github.com/mechaphish/compilerex.git \
             git+https://github.com/angr/fidget.git           \
             git+https://github.com/angr/tracer.git           \
             git+https://github.com/angr/angr-platforms.git

# install patcherex
pip3 install git+https://github.com/angr/patcherex.git@feat/multiarch
```

## Usage

### Challenge_01
```bash
cd Challenge_01
./patch.py /path/to/original_binary /tmp/patched_binary
```
`/path/to/original_binary` is supposed to be `BrakeFlasher_AVR_Vuln.ino.elf` (sha256: `6D23C15E2EA583A45DCCE52CDDA155E9D3838D4E4DC4C7588D200D5762FEAD61`), not included in this repository.

### Challenge_02
```bash
cd Challenge_02
./patch.py /path/to/original_binary /tmp/patched_binary
```
`/path/to/original_binary` should be the `Nucleo-32.elf` file (SHA256: `1B3ABBF957197A7557E59DE2AEA90EA334303086A38431D2CE94CBA7C9A35205`), from the `AMP_Challenge-Problems` repository.

### Challenge_03
```bash
cd Challenge_03
python3 ./patch.py /path/to/original_binary /tmp/patched_binary
```
`/path/to/original_binary` should be the `program_c` file (SHA256: `D5C40E53C28B373C4B8BFDFE7278E15EBDE33C4527AA526BBDF148818C17A218`), from the `AMP_Challenge-Problems` repository.

### Challenge_05
```bash
cd Challenge_05
python3 ./patch.py /path/to/original_binary /tmp/patched_binary
```
`/path/to/original_binary` should be the `program_c.gcc.vuln` file (SHA256: `CE582F72FE1416A3660A5E432B0B28BF533B2A76B83AB860B5F7DD5465977070`), from the `AMP_Challenge-Problems` repository.
