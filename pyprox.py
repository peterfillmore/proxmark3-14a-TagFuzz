import serial
from struct import *
import time
ser = serial.Serial('/dev/tty.usbmodemfd1251')
ser.timeout=10
#bootloader
CMD_DEVICE_INFO     = 0x0000
CMD_SETUP_WRITE     = 0x0001
CMD_FINISH_WRITE    = 0x0003
CMD_HARDWARE_RESET  = 0x0004
CMD_START_FLASH     = 0x0005
CMD_NACK            = 0x00fe
CMD_ACK             = 0x00ff

# general stuff
CMD_DEBUG_PRINT_STRING = 0x0100
CMD_DEBUG_PRINT_INTEGERS = 0x0101
CMD_DEBUG_PRINT_BYTES = 0x0102
CMD_LCD_RESET = 0x0103
CMD_LCD = 0x0104
CMD_BUFF_CLEAR  = 0x0105
CMD_READ_MEM = 0x0106
CMD_VERSION = 0x0107

# low frequency
CMD_READ_TI_TYPE    = 0x0202
CMD_WRITE_TI_TYPE    = 0x0202
CMD_DOWNLOADED_RAW_BITS_TI_TYPE    = 0x0202

# EMV commands
CMD_EMV_READ_RECORD = 0x0700
CMD_EMV_TRANSACTION = 0x0701
CMD_EMV_CLONE = 0x0702
CMD_EMV_SIM = 0x0703
CMD_EMV_TEST = 0x0704
CMD_EMV_FUZZ_RATS = 0x0705
CMD_UNKNOWN = 0x0000

fuzzstring = "0b788081024b4f4e411411".decode("hex")
commandstring = pack("=QQQQ512s",CMD_EMV_FUZZ_RATS,len(fuzzstring),0,0,fuzzstring)
counter = 0
while(1):
    print counter 
    ser.write(commandstring)
    counter = counter + 1 
    time.sleep(5)
ser.close()
