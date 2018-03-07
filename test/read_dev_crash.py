#!/usr/bin/python

import os, sys
import argparse

class dcrash:
	def __init__(self, base_addr):
		self.base_addr = base_addr
		self.fd = os.open("/dev/crash", os.O_RDONLY)

	def __del__(self):
		os.close(self.fd)

	def get_word(self, offset):
		num = 0
		os.lseek(self.fd, self.base_addr + offset, 0)

		for i in range(0, 8):
			data = os.read(self.fd, 1)
			num += ord(data) << i * 8
		return num

	def print_word(self, offset):
		data = self.get_word(offset)
		print hex(self.base_addr+offset)+" : "+hex(data)

	def print_words(self, offset, size):
		for i in range(0, size/8):
			poffset = offset + i * 8
			data = self.get_word(poffset)
			print hex(self.base_addr+poffset)+" : "+hex(data)

parser = argparse.ArgumentParser()
parser.add_argument("address")
parser.add_argument("length")
args = parser.parse_args()

base_addr = int(args.address, 0)
size = int(args.length, 0)
crash = dcrash(base_addr)
crash.print_words(0, size)

