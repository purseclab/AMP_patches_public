from argparse import ArgumentParser
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *

parser = ArgumentParser()
parser.add_argument("original")
parser.add_argument("patched")
args = parser.parse_args()

backend = DetourBackend(args.original)
patches = []

code = '''
mov r22, r17
ldi r23, 0x00
ldi r24, 0x00
ldi r25, 0x00
ldi r20, 0x0a
jmp 0xfb8
'''

# Line 58: Serial.print(speed_value/256);
patches.append(InsertCodePatch(0xf84, code))

# Line 65: if (speed_value > 0 && previous_brake_state != brake_state){
patches.append(InlinePatch(0xff4, "or r16, r17\nnop\n"))
patches.append(InlinePatch(0xff8, "breq +0x16\n")) # 0xff8 + 0x16 = 0x100e

backend.apply_patches(patches)
backend.save(args.patched)
