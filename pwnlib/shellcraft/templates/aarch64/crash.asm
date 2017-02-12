<% import pwnlib.shellcraft as S %>
<%docstring>Crashes the process.</%docstring>
    ${S.mov('x30', 0)}
    ret
