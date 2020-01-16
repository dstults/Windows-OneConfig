# Win10, Server, VM Initial Configuration PowerShell
 Config everything automatically and saves hours of time

Simply select the ps1 files most related to what you're doing and then execute it after initial Windows install completes.

# How to run script: Easy Mode
1) Open PowerShell as Administrator!
2) ...Then open this page in web browser or open a copy of ps1 in notepad.
3) Copy, Paste into Powershell.
Yay!

# How to customize it?
It's super easy! No functions, no questions, just comment-uncomment.
Also, here is a link for more, probably much more frequently updated code:
(THE SOURCE) https://github.com/Disassembler0/Win10-Initial-Setup-Script/blob/master/Win10.psm1

# Why is there a separate "Fresh Install" script?
To unpin everything and uninstall OneDrive. You only want to do this at the very beginning.

1) The script unpins everything in the start menu and taskbar. You don't want to do that on a machine that you're in the middle of using, but you do want to do it when you have 20 bloatware links in your fresh Windows 10 installation.

2) You also want to uninstall OneDrive only once at the very beginning. If you use it, when you reinstall you can move the share folder where you actually want it. If you don't use OneDrive, then you just saved time uninstalling it.

# Why not execute the ps1 (powrshell) script?
You'd either have to reduce computer security and/or browse to the right folder or type commands and it just becomes a layered mess.

# Windows Server 2016 or 2019?
As far as I know, both.

# Future plans?

Wishlist/To do:
  - Unpin Documents and Pictures from Quick Access (it should have Desktop/Downloads only)

Work that still needs to be done:
  - Forever testing.
  - Add script that sets Downloads location to "C:\Downloads"
  - Pin the explorer window menu open
  - Add shortcut to desktop that goes straight to "Control Panel\Network and Internet\Network Connections" named "Adapters"

# Special Thanks to:
Disassembler0 for original script ( https://github.com/Disassembler0/Win10-Initial-Setup-Script/blob/master/Win10.psm1 )
alirobe for Reclaim Windows 10 version, otherwise I would never have heard about it ( https://github.com/alirobe/Reclaim-Windows10/blob/master/Reclaim-Windows10/Reclaim-Windows10.psm1 )
  Finding all this stuff out is torture. Really good job.
