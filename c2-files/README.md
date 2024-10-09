# Dropper

- Compiled into .DLL, URL to Fileserver gets passed in as arg.
- `DotNetToJScript.exe implant.dll -l JScript -v v4 -c MainStarter -o cradle.js`
- 

Main Changes: 
- When C2 agent ran from memory, DLL needs to pass in an empty argument (Not NULL) - Else, the program crashes (C# Lines 538 onward).
