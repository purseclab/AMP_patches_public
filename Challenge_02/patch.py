from argparse import ArgumentParser
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
import os
import subprocess


parser = ArgumentParser()
parser.add_argument("original")
parser.add_argument("patched")
args = parser.parse_args()

try:
	os.unlink(args.patched)
except OSError:
	pass
try:
	os.unlink(args.patched+".bin")
except OSError:
	pass

backend = DetourBackend(args.original, variant="stm32")
patches = []

typedef = '''
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
'''
transmit_code = '''
void rx_brake_routine( unsigned char buff[], void *bumper ){
	uint16_t speed_value;  
	uint8_t brake_switch;
	speed_value  = (buff[3] << 8) + buff[2];
	brake_switch = (buff[4] & 0b00001100) >> 2;
	((unsigned char*)bumper)[13] = (brake_switch) ? 1 : 0;

	if ( ((unsigned char*)bumper)[13] ) {
		if ((speed_value > 0) && ( ((unsigned char*)bumper)[12] != ((unsigned char*)bumper)[13] )){ 
			((unsigned char*)bumper)[14] = 1;
			((unsigned int*)bumper)[4] = ((unsigned char*)bumper)[12];
		}
	}
	else {
	    ((unsigned char*)bumper)[14] = 0;
	}
	((unsigned char*)bumper)[12] = ((unsigned char*)bumper)[13];
}
'''

transmit_code = typedef + transmit_code.replace("\n", " ")

patches.append(ReplaceFunctionPatch(0x80003AC, 0x38, transmit_code))
backend.apply_patches(patches)
backend.save(args.patched)

subprocess.Popen(["arm-none-eabi-objcopy", "-O", "binary", args.patched, args.patched+".bin"], shell=True)
