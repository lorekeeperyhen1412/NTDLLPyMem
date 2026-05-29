[![GitHub license](https://img.shields.io/github/license/srounet/pymem.svg)](https://github.com/lorekeeperyhen1412/Pymem)
[![Build status](https://ci.appveyor.com/api/projects/status/sfdvrtuh9qa2f3aa/branch/master?svg=true)](https://ci.appveyor.com/project/srounet/pymem/branch/master)

NTMem
=====

A python library to manipulate Windows processes (32 and 64 bits).  
With pymem you can hack into windows process and manipulate memory (read / write).

Documentation
=============
Its the same thing as pymem except instead of ``pymem.Pymem`` its ``ntmem.Open``.

Listing process modules
-----------------------

````python
import ntmem

pm = ntmem.Open('python.exe')
modules = list(pm.list_modules())
for module in modules:
    print(module.name)
````

Injecting a python interpreter into any process
-----------------------------------------------

`````python
from ntmem import Open as NTMem

notepad = subprocess.Popen(['notepad.exe'])

pm = NTMem('notepad.exe')
pm.inject_python_interpreter()
filepath = os.path.join(os.path.abspath('.'), 'pymem_injection.txt')
filepath = filepath.replace("\\", "\\\\")
shellcode = """
f = open("{}", "w+")
f.write("pymem_injection")
f.close()
""".format(filepath)
pm.inject_python_shellcode(shellcode)
notepad.kill()
`````
