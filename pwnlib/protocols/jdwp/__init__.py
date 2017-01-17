"""Implements the JDWP protocol

Documentation:
    https://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp-spec.html
"""
import struct

from pwnlib.log import Logger
from pwnlib.util import packing
from pwnlib.tubes.tube import tube
from pwnlib.tubes.remote import remote

################################################################################
#
# JDWP protocol variables
#
HANDSHAKE                 = "JDWP-Handshake"

REQUEST_PACKET_TYPE       = 0x00
REPLY_PACKET_TYPE         = 0x80

# Command signatures
VERSION_SIG               = (1, 1)
CLASSESBYSIGNATURE_SIG    = (1, 2)
ALLCLASSES_SIG            = (1, 3)
ALLTHREADS_SIG            = (1, 4)
IDSIZES_SIG               = (1, 7)
CREATESTRING_SIG          = (1, 11)
SUSPENDVM_SIG             = (1, 8)
RESUMEVM_SIG              = (1, 9)
SIGNATURE_SIG             = (2, 1)
FIELDS_SIG                = (2, 4)
METHODS_SIG               = (2, 5)
GETVALUES_SIG             = (2, 6)
CLASSOBJECT_SIG           = (2, 11)
INVOKESTATICMETHOD_SIG    = (3, 3)
REFERENCETYPE_SIG         = (9, 1)
INVOKEMETHOD_SIG          = (9, 6)
STRINGVALUE_SIG           = (10, 1)
THREADNAME_SIG            = (11, 1)
THREADSUSPEND_SIG         = (11, 2)
THREADRESUME_SIG          = (11, 3)
THREADSTATUS_SIG          = (11, 4)
EVENTSET_SIG              = (15, 1)
EVENTCLEAR_SIG            = (15, 2)
EVENTCLEARALL_SIG         = (15, 3)

# Other codes
MODKIND_COUNT             = 1
MODKIND_THREADONLY        = 2
MODKIND_CLASSMATCH        = 5
MODKIND_LOCATIONONLY      = 7
EVENT_BREAKPOINT          = 2
SUSPEND_EVENTTHREAD       = 1
SUSPEND_ALL               = 2
NOT_IMPLEMENTED           = 99
VM_DEAD                   = 112
INVOKE_SINGLE_THREADED    = 2
TAG_OBJECT                = 76
TAG_STRING                = 115
TYPE_CLASS                = 1



class CommandPacket(object):
    header_format = '>IIccc'
    header_length = struct.calcsize(command_header_format)

    def __init__(self, jdwp, command_set, command, data):
        self.jdwp = jdwp
        self.id = jdwp.generate_id()
        self.flags = 0
        self.data = data
        self.command_set = command_set
        self.command = command

    def __str__(self):
        return struct.pack(CommandPacket.header_format,
                           header_format.header_length + len(self.data),
                           self.id,
                           self.flags,
                           self.command_set,
                           self.command) + self.data

    def __flat__(self):
        return str(self)

class VirtualMachineCommandPacket(CommandPacket):
    def __init__(self, jdwp, command):
        super(VMCommandPacket, self).__init__(jdwp, 1, command)

class VersionPacket(VirtualMachineCommandPacket):
    def __init__(self, jdwp):
        super(VersionPacket, self).__init__(jdwp, 1)

class IDSizesPacket(VirtualMachineCommandPacket):
    def __init__(self, jdwp):
        super(IDSizesPacket, self,).__init__(jdwp, 7)

class StringReferenceValuePacket(CommandPacket):
    def __init__(self, jdwp, objectID):
        super(StringReferenceValuePacket, self).__init__(jdwp, 10, 1, objectID)

class ReplyPacket(object):
    header_format = '>IIcH'
    header_length = struct.calcsize(command_header_format)

    contents_format = {}

    def __init__(self, jdwp, header):
        self.jdwp = jdwp

        self.length, self.id, self.flags, self.errorcode =\
            struct.unpack(ReplyPacket.header_format, data)

        need = self.length - ReplyPacket.header_length
        self.data = self.jdwp.connection.recvn(need)

        self.reset()
        self.contents = self.parse()

    def __iter__(self):
        for k,v in self.contents.items():
            yield (k,v)

    def reset(self):
        self.tube = tube(self.contents)

    def C(self):
        return self.tube.u8(1)
    def I(self):
        return self.tube.u32()
    def L(self):
        return self.tube.u64()
    def S(self):
        return self.tube.recvn(self.I())
    def Z(self):
        return {
            ord('s'): self.STRING,
            ord('I'): self.INT
        }[self.C()]()

    def STRING(self, objId):
        objectID = self.L()


    def parse_long(self, data):
        return packing.unpack(data, bytes=4)


    def parse(self, tube):
        for name, size in self.contents_format.items():
            if size == 'L':
            elif size == ''


class JdwpByte(int):
    def __init__(self, value=None):
        self.value = value

class Byte(object):
    format_string = ''
    def __init__(self, value=None):


class IDSizesReplyPacket(ReplyPacket):
    contents_format = {
        "fieldIDSize": "I",
        "methodIDSize": "I",
        "objectIDSize": "I",
        "referenceTypeIDSize": "I",
        "frameIDSize": "I",
    }

class MruDict(dict):
    """``dict`` instance which only keeps the highest ``maxlen`` keys.

    Example:

        >>> d = MruDict(5)
        >>> d.update({x:x for x in range(10)})
        >>> len(d)
        5
        >>> all(x in d for x in range(5,10))
        True
        >>> not any(x in d for x in range(0,5))
        True
    """
    def __init__(self, maxlen=100, *a, **kw):
        super(MruDict,self).__init__(*a, **kw)
        self._maxlen = maxlen
        self.cull()

    def cull(self):
        count = len(self) - self._maxlen
        if count <= 0:
            return
        for key in sorted(self)[:count]:
            del self[key]

    def update(self, *a, **kw):
        rv = super(MruDict,self).update(*a, **kw)
        self.cull()
        return rv

    def __setitem__(self, *a, **kw):
        rv = super(MruDict,self).__setitem__(*a, **kw)
        self.cull()
        return rv

class Jdwp(Logger):
    """Implements a JDWP client, per Oracle's specification.

    See:
        https://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp-spec.html
    """

    def __init__(self, *a, **kw):
        self.connection = remote(*a, **kw)

        # Initialize packet counter
        self.packet_count = 0

        # List of replies awaiting processing
        # K:V is id:reply
        self.replies = {}

        # Send the connection handshake
        self.connection.send(HANDSHAKE)
        handshake = self.connection.recvuntil(HANDSHAKE)

        if handshake != HANDSHAKE:
            self.error("Handshake failed")

        # Enumerate sizes of basic types
        self.IDSizesPacket(self)
        self.send(IDSizesPacket())
        self.wait(id_sizes)

        reply = self.reply()

    def send(self, *a, **kw):
        self.connection.flat(*a, **kw)


    def reply(self):
        return ReplyPacket.from_tube(self.connection)

    def wait(self, packet):
        """wait(CommandPacket) -> ReplyPacket

        Wait for the reply to a command.
        """
        while packet.id not in self.replies:
            reply = self.reply()
            self.replies[reply.id] = reply

    def handshake(self):

    def create_packet(self, *a, **kw):
        return CommandPacket(self.connection, )

    def idsizes(self):
        # Figure out the size to everything
        self.connection.send(CommandPacket(IDSIZES_SIG))


        for name, size


    def create_packet(self, cmdsig, data=""):
        fmt = ">IIccc"
        flags = 0x00
        cmdset, cmd = cmdsig
        pktlen = len(data) + 11
        packing.p32(pktlen)
        pkt =
        pkt+= data
        self.id += 2
        return pkt


    def read_reply(self):
        header = self.socket.recv(11)
        pktlen, id, flags, errcode = struct.unpack(">IIcH", header)

        if flags == chr(REPLY_PACKET_TYPE):
            if errcode :
                raise Exception("Received errcode %d" % errcode)

        buf = ""
        while len(buf) + 11 < pktlen:
            data = self.socket.recv(1024)
            if len(data):
                buf += data
            else:
                time.sleep(1)
        return buf

