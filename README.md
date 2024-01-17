# Injecting a dll into an executable by adding an import descriptor to the import table.

based on the great post by https://www.x86matthew.com/view_post?id=import_dll_injection

## Usage

1. Download and build the repo.
2. Run the program:

   InjectDllUsingImportList.exe (_path-to-exe_) (_path-to-injected-dll_)

## Notice

32/64 bit InjectDllUsingImportList.exe should be used with 32/64 bit exe and dll, respectively.
In the 64 bit version, we need to make sure that the relative pointers within the PE structures are close enough to the exe base address (and can be stored in a 32 bit DWORD), for the whole thing to work.
For this purpose, in the 64 bit version we use MSDetours function called _FindAndAllocateNearBase()_.
