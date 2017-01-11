#!/bin/sh
set -x
PWNLIB_NOTERM=1 coverage run -m sphinx -b doctest docs/source docs/build/doctest
echo SCRIPT_AFTER
dmesg
cat /var/log/apport.log
ls -la /var/crash"
set +x
