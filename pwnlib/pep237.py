from __future__ import absolute_import
#
# Override the behavior of the built-in hex() method
# to strip the trailing 'L'.
#
# This has no meaning anymore, as of 2006.
#
# https://www.python.org/dev/peps/pep-0237/
# https://mail.python.org/pipermail/python-dev/2006-June/065918.html
#
import six.moves.builtins

original_hex = six.moves.builtins.hex

def hex(number):
    original_hex.__doc__
    return original_hex(number).rstrip('L')

six.moves.builtins.hex = hex
