#!/usr/bin/env python2
from __future__ import absolute_import


READ_MASK  = 0b10
WRITE_MASK = 0b01

SIZE_MASK  = 0b00111111111111110000000000000000
SIZE_SHIFT = 16

CHAR_MASK  = 0b00000000000000001111111100000000
CHAR_SHIFT = 8

FUNC_MASK  = 0b00000000000000000000000011111111

class IOCTL(object):g
	def __init__(self, value):
		self.read = bool(value & 0b10)
		self.write = bool(value & 0b01)
		self.rw = self.read and self.write

		self.size = (self.value & SIZE_MASK) >> SIZE_SHIFT
		self.char = (self.value & CHAR_MASK) >> CHAR_SHIFT

		self.func = self.value & self.FUNC_MASK

def ioctl(value):
	"""decode_ioctl(value) -> IOCTL object

	Decodes an I/O Control Code (IOCTL) from the Linux kernel into its
	individual parts.

	Arguments:
		value(int): Integer value of the IOCTL code

	Returns:
		:class:`IOCTL` object
	"""