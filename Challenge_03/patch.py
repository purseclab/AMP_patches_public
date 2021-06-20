from argparse import ArgumentParser
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *

parser = ArgumentParser()
parser.add_argument("original")
parser.add_argument("patched")
args = parser.parse_args()

backend = DetourBackend(args.original)
patches = []

typedef = '''
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
'''
transmit_code = '''
void rx_brake_routine( uint8_t buff[], void *bumper ){
	uint16_t speed_value;  
	uint8_t brake_switch;

	speed_value  = (buff[3] << 8) + buff[2];
	brake_switch = (buff[4] & 0b00001100) >> 2;
	((uint8_t*)bumper)[5] = (brake_switch) ? 1 : 0;

	if ( ((uint8_t*)bumper)[5] ) {
		if ((speed_value > 0) && ( !((uint8_t*)bumper)[4]) ){ 
			((uint8_t*)bumper)[6] = 1;
		}
	}
	else {
	    ((uint8_t*)bumper)[6] = 0;
		((uint8_t*)bumper)[4] = 0;
	}
}
'''

transmit_code = typedef + transmit_code.replace("\n", " ")

patches.append(ReplaceFunctionPatch(0x400cc4, 0x84, transmit_code))
backend.apply_patches(patches)
backend.save(args.patched)
