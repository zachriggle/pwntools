import os

from .abi import ABI
from .log import getLogger
from .tubes.process import process
from .util.packing import pack

log = getLogger(__name__)

class FormatFunction(object):
    """Encapsulates data about a function which takes a format string.
    """
    registry = {}

    def __init__(self, index, name=None):
        #: Argument index of the format string
        self.format_index = index
        self.name = name

        if name:
            FormatFunction.registry.setdefault(name, self)

    @property
    def stack_index(self):
        """The dollar-argument index for the top of the stack.

        This varies by function, depending on the architecture.
        """
        abi   = ABI.default()
        return max(0, len(abi.register_arguments) - self.format_index)

    def __repr__(self):
        return '%s(%s, %r)' % (self.__class__.__name__,
                               self.format_index,
                               self.name)

# First argument
printf   = FormatFunction(1, 'printf')
scanf    = FormatFunction(1, 'scanf')

# Second argument
dprintf  = FormatFunction(2, 'dprintf')
sprintf  = FormatFunction(2, 'sprintf')
fprintf  = FormatFunction(2, 'fprintf')
asprintf = FormatFunction(2, 'asprintf')
fscanf   = FormatFunction(2, 'fscanf')
sscanf   = FormatFunction(2, 'sscanf')

# Third argument
snprintf = FormatFunction(3, 'snprintf')

class FormatString(object):
    def __init__(self, on_stack=False, format_index=None, function=None):
        """Initialize a FormatString object.

        Arguments:
            on_stack(bool): Whether the format string itself is on the stack.
            format_index(int): Argument index of the format string.
                For example, printf=1, sprintf=2, snprintf=3.
            function(FormatFunction, str): Format function which is invoked.
                Can be either a function name (e.g. ``"snprintf"``) or an
                instance of ``FormatFunction``.
        """

        # Must specify one of format_index or function
        mutually_exclusive = [format_index, function]
        if all(mutually_exclusive) or not any(mutually_exclusive):
            log.error("Must specify exactly one of 'format_index' or 'function'.")

        # Determine our calling convention / dollar-argument model
        if isinstance(function, str):
            function = FormatFunction.registry.get(function, None)

        if function is None:
            if format_index is not None:
                function = FormatFunction(format_index)
            else:
                function = printf

        #: Target function which is invkoed
        self.function = function

        #: Whether the format string buffer itself is on the stack
        self.on_stack = False

        #: Operand stack, of what is being performed

    @property
    def format_index(self):
        return self.function.format_index

    @property
    def stack_index(self):
        return self.function.stack_index

    # ----- WRITE RELATED FUNCTIONS -----
    def __contains__(self, index):
        return index in self.memory

    def __getitem__(self, index):
        return self.memory.get(index, None)

    def __setitem__(self, index, value):
        if isinstance(value, int):
            value = pack(value)

        if not isinstance(value, (str, bytes)):
            log.error("Data must be an integer (packed to default width) or a byte string")

        for i, byte in enumerate(value):
            self.memory[index + i] = byte

    # ----- READ RELATED FUNCTIONS -----
    def leak(self, address):
        pass

class AutomaticDiscoveryProcess(process):
    def __init__(self, argv, remote=True, size=None, **kw):
        """Object for automatic discovery of format string parameters.

        Arguments:
            argv(list): List of arguments.  See ``process``.
            remote(bool): Whether the target process is remote or
            size(int): Size of format string buffer.
                If unbounded and no crashes will occur with large sizes, use ``None``.
                Otherwise, enter the largest size which does not cause a crash.
            kwargs: Additional arguments to ``process``.
        """
        self._format_size = size
        super(AutomaticDiscovery, self).__init__(argv, **kw)

    def submit(self, format_string):
        """subit(format_string) -> str

        Submit a format string to the target binary, and return its output.
        Must only return bytes printed by the format function.

        Arguments:
            format_string(str): Complete format string to submit.

        Returns:
            String printed by the function, or ``None``.
        """
        raise NotImplementedError('Must subclass and implement submit')
