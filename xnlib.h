#pragma once

#include <windows.h>
//#include <strsafe.h>
#include <string>
#include <vector>
#include <list>

namespace xn {

  using std::string;
  using std::wstring;
  using std::vector;
  using std::list;

  typedef list<wstring> StringList;

# define X86_BYTECODE_FARJMP 0xE9
# define X86_BYTECODE_SHORTJMP 0xEB
# define X86_BYTECODE_CALL 0xE8

  typedef BOOL (WINAPI *fnDisableThreadLibraryCalls)( HMODULE hLibModule );
  typedef BOOL (WINAPI *fnFlushInstructionCache)( HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize );
  typedef BOOL (WINAPI *fnFreeLibrary)( HMODULE hModule );
  typedef HANDLE (WINAPI *fnGetCurrentProcess)( VOID );
  typedef DWORD (WINAPI *fnGetModuleFileNameW)( HMODULE hModule, LPWSTR lpFilename, DWORD nSize );
  typedef HMODULE (WINAPI *fnGetModuleHandleW)( LPCWSTR lpModuleName );
  typedef FARPROC (WINAPI *fnGetProcAddress)( HMODULE hModule, LPCSTR lpProcName );
  typedef HMODULE (WINAPI *fnLoadLibraryW)( LPCWSTR lpLibFileName );
  typedef LPVOID (WINAPI *fnVirtualAlloc)( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
  typedef BOOL (WINAPI *fnVirtualFree)( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );
  typedef BOOL (WINAPI *fnVirtualProtect)( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
  typedef int (WINAPI *fnMultiByteToWideChar)( UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar );

  struct Kernel {
    HMODULE hModule;
    fnDisableThreadLibraryCalls pfnDisableThreadLibraryCalls;
    fnFlushInstructionCache pfnFlushInstructionCache;
    fnFreeLibrary pfnFreeLibrary;
    fnGetCurrentProcess pfnGetCurrentProcess;
    fnGetModuleFileNameW pfnGetModuleFileNameW;
    fnGetModuleHandleW pfnGetModuleHandleW;
    fnGetProcAddress pfnGetProcAddress;
    fnLoadLibraryW pfnLoadLibraryW;
    fnVirtualAlloc pfnVirtualAlloc;
    fnVirtualFree pfnVirtualFree;
    fnVirtualProtect pfnVirtualProtect;
    fnMultiByteToWideChar pfnMultiByteToWideChar;
  };

  struct Globals {
  public:
    static Kernel mKernel;
  };

  bool __fastcall calculateCopySize( DWORD_PTR pAddress, DWORD dwDesired, DWORD* pdwSize );
  bool __fastcall extractTransfer( DWORD_PTR pAddress, DWORD_PTR* pTarget );

  // -- HookManager module ----------------------------------------------------

  class Hook {
  public:
    virtual void remove() = 0;
  };

  // Hook by far jmp
  class FarJmpHook: public Hook {
  public:
    ULONG_PTR mAddress;
    BYTE mOriginalBytes[5];
    explicit FarJmpHook( ULONG_PTR pAddress, LPVOID pfnTarget );
    virtual void remove();
  };

  // Hook by call
  class CallHook: public Hook {
  public:
    ULONG_PTR mAddress;
    BYTE mOriginalBytes[5];
    explicit CallHook( ULONG_PTR pAddress, LPVOID pfnTarget );
    virtual void remove();
  };

  // Hook by detour
  class DetourHook: public Hook {
  public:
    ULONG_PTR mAddress;
    LPVOID mTarget;
    LPVOID mBuffer;
    DWORD mCopySize;
    explicit DetourHook( ULONG_PTR pAddress, LPVOID pfnTarget, LPVOID& ppfnOriginal, bool bPushCallee );
    virtual void remove();
  };

  typedef list<Hook*> HookList;

  class HookManager {
  protected:
    HookList mHooks;
  public:
    void addFarJmpHook( ULONG_PTR pAddress, LPVOID pfnTarget );
    void addCallHook( ULONG_PTR pAddress, LPVOID pfnTarget );
    void addDetourHook( ULONG_PTR pAddress, LPVOID pfnTarget, LPVOID& ppfnOriginal, bool bPushCallee );
    void removeHooks();
    HookManager();
    ~HookManager();
  };

  // -- MemoryPE module -------------------------------------------------------

  class MemoryPE;

  struct ImportedFunction {
    ULONG_PTR* ppfnFunction;
    ULONG_PTR pfnOriginal;
    bool bHooked;
    ImportedFunction(): ppfnFunction( NULL ), pfnOriginal( NULL ),
      bHooked( false ) {}
  };

  typedef list<ImportedFunction> ImportedFunctionList;

  class ImportedModule {
  friend class MemoryPE;
  protected:
    wstring sModuleName;
    ImportedFunctionList flFunctions;
    HMODULE hModule;
  public:
    bool hook( const string& sAPI, LPVOID pfnNew );
    void unhookAll( void );
    const wstring& getName() throw() { return sModuleName; }
    const ImportedFunctionList& getFunctions() throw() { return flFunctions; }
  };

  typedef list<ImportedModule> ImportedModuleList;

  struct ExportedFunction {
    LPVOID pfnFunction;
    DWORD dwOrdinal;
    StringList fnlNames;
  };

  typedef list<ExportedFunction> ExportedFunctionList;

  class ExportedModule {
  friend class MemoryPE;
  protected:
    wstring sModuleName;
    ExportedFunctionList flFunctions;
  public:
    void clear( void );
    const wstring& getName() throw() { return sModuleName; }
    const ExportedFunctionList& getFunctions() throw() { return flFunctions; }
  };

  class MemoryPE {
  private:
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_IMPORT_DESCRIPTOR pImports;
    PIMAGE_EXPORT_DIRECTORY pExports;
  protected:
    ImportedModuleList mImports;
    ExportedModule mExports;
    void processImports( void );
    void processExports( void );
  public:
    explicit MemoryPE( HMODULE hModule );
    HMODULE getModule() throw() { return (HMODULE)pDosHeader; }
    ImportedModule* findImportedModule( HMODULE hModule );
    ImportedModule* findImportedModule( const wstring& sName );
    ImportedModuleList& getImports() throw() { return mImports; }
    ExportedModule& getExports() throw() { return mExports; }
  };

  // -- Internal --------------------------------------------------------------

  inline wstring utf8ToWide( const string& sIn );

}