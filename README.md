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
`/path/to/original_binary` is supposed to be `Nucleo-32.elf` (sha256: `1B3ABBF957197A7557E59DE2AEA90EA334303086A38431D2CE94CBA7C9A35205`), not included in this repository.
