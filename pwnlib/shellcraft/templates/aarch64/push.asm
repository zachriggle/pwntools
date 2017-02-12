<%
    from pwnlib import shellcraft
    from pwnlib.util.packing import flat, unpack
    from pwnlib.util.iters import group
%>
<%page args="value, register1='x14', register2='x15'"/>
<%docstring>
Pushes a value onto the stack without using null bytes or newline characters.

If src is a string, then we try to evaluate using :func:`pwnlib.constants.eval`
before determining how to push it.

Note that this means that this shellcode can change behavior depending on
the value of `context.os`.

Note:
    AArch64 requires that the stack remain 16-byte aligned at all times,
    so this alignment is preserved.

Args:
    value(int,str): The value or register to push
    register1(str): Scratch register to use
    register2(str): Second scratch register to use

Example:

    >>> print pwnlib.shellcraft.i386.push(0).rstrip()
        /* push 0 */
        push 1
        dec byte ptr [esp]
    >>> print pwnlib.shellcraft.i386.push(1).rstrip()
        /* push 1 */
        push 1
    >>> print pwnlib.shellcraft.i386.push(256).rstrip()
        /* push 0x100 */
        push 0x1010201
        xor dword ptr [esp], 0x1010301
    >>> print pwnlib.shellcraft.i386.push('SYS_execve').rstrip()
        /* push (SYS_execve) (0xb) */
        push 0xb
    >>> print pwnlib.shellcraft.i386.push('SYS_sendfile').rstrip()
        /* push (SYS_sendfile) (0xbb) */
        push 0x1010101
        xor dword ptr [esp], 0x10101ba
    >>> with context.local(os = 'freebsd'):
    ...     print pwnlib.shellcraft.i386.push('SYS_execve').rstrip()
        /* push (SYS_execve) (0x3b) */
        push 0x3b
</%docstring>
    ${shellcraft.pushstr(flat(value), register1=register1, register2=register2)}
