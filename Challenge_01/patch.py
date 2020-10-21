from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *

backend = DetourBackend("./BrakeFlasher_AVR_Vuln.ino.elf")

patches = []

code = '''
mov r22, r17
ldi r23, 0x00
ldi r24, 0x00
ldi r25, 0x00
ldi r20, 0x0a
'''

# Line 58: Serial.print(speed_value/256);
patches.append(InlinePatch(0xf7a, "nop\n" * 26)) # fill "nop" from 0xf7a to 0xfac
patches.append(InlinePatch(0xfae, code))

# Line 65: if (speed_value > 0 && previous_brake_state != brake_state){
patches.append(InlinePatch(0xff4, "or r16, r17\nnop\n"))
patches.append(InlinePatch(0xff8, "breq +0x16\n")) # 0xff8 + 0x16 = 0x100e


backend.apply_patches(patches)
backend.save("/tmp/Challenge01_Patched")
