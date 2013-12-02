xnlib
=====

xnlib is a nifty little library for mischief inside 32-bit PE modules *only*. 64-bit would crash and burn.  
Namely, it does `farjmp`, `call`, `detour`, `IAT` and `EAT` hooking and PE traversal.

Uses BeaEngine Cheetah for disassembly.

To use the library, you must first fill the Globals::mKernel structure with valid function pointers.  
How you obtain those pointers and the functions' implementation detail is up to you.

Licensed under WTFPL 2.0.  
For full license text, see the LICENSE file.
