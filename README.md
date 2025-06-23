# How to build
1. Download Visual Studio
2. Open pinject.cpp in Visual Studio 
3. Build 
## What does it do
It utilizes the Win32API to inject shellcode into a target process's memory You can use msfvenom to customize a payload, be sure it's x64 architecture though
## Usage
```
.\pinject.exe <PID of target Process>
```
![image](https://github.com/user-attachments/assets/3a9dc57d-8592-472d-8b38-dcd5a03942c9)

And it's done just like that 
## TODO 
1. Implement a custom shellcode payload to download from a server
2. AV / EDR Bypass
3. API Hashing 
4. MAYBE code virtualization/protection with a proprietary protector
