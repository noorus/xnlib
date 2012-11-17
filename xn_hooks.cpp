#include "xnlib.h"

#pragma warning( push )
#pragma warning( disable:4309 4244 )

namespace xn {

  // FarJmpHook ---------------------------------------------------------------

  FarJmpHook::FarJmpHook( ULONG_PTR pAddress, LPVOID pfnTarget ):
  mAddress( pAddress )
  {
    DWORD dwOldProtection;
    Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, PAGE_WRITECOPY, &dwOldProtection );
    memcpy( mOriginalBytes, (LPCVOID)mAddress, 5 );
    *(LPBYTE)mAddress = X86_BYTECODE_FARJMP;
    *(LPDWORD)( (LPBYTE)mAddress + 1 ) = (DWORD)pfnTarget - ((DWORD)mAddress + 5);
    Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, dwOldProtection, &dwOldProtection );
  }

  void FarJmpHook::remove()
  {
    DWORD dwOldProtection;
    Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, PAGE_WRITECOPY, &dwOldProtection );
    memcpy( (LPVOID)mAddress, (LPCVOID)mOriginalBytes, 5 );
    Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, dwOldProtection, &dwOldProtection );
  }

  // CallHook -----------------------------------------------------------------

  CallHook::CallHook( ULONG_PTR pAddress, LPVOID pfnTarget ):
  mAddress( pAddress )
  {
    DWORD dwOldProtect = 0, dwOldProtect2 = 0;
    Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, PAGE_WRITECOPY, &dwOldProtect );
    memcpy( mOriginalBytes, (LPCVOID)mAddress, 5 );
    *(LPBYTE)mAddress = X86_BYTECODE_CALL;
    *(LPDWORD)( (LPBYTE)mAddress + 1 ) = (DWORD)PtrToUlong(pfnTarget) - (DWORD)(PtrToUlong(mAddress) + 5);
    Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, dwOldProtect, &dwOldProtect2);
  }

  void CallHook::remove()
  {
    DWORD dwOldProtection;
    Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, PAGE_WRITECOPY, &dwOldProtection );
    memcpy( (LPVOID)mAddress, (LPCVOID)mOriginalBytes, 5 );
    Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, dwOldProtection, &dwOldProtection );
  }

  // DetourHook class ---------------------------------------------------------

  DetourHook::DetourHook( ULONG_PTR pAddress, LPVOID pfnTarget,
  LPVOID& ppfnOriginal, bool pushCallee ):
  mAddress( pAddress ), mTarget( pfnTarget ), mBuffer( NULL ), mCopySize( 0 )
  {
    DWORD buffSize = 0, oldProtect1, oldProtect2;

    if ( !calculateCopySize( (DWORD_PTR)mAddress, pushCallee ? 8 : 5, &mCopySize ) )
      throw new std::exception( "calculateCopySize failed" );

    buffSize = mCopySize + 5; // trampoline + farjmp

    mBuffer = Globals::mKernel.pfnVirtualAlloc( 0, buffSize,
      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    if ( !mBuffer )
      throw new std::exception( "VirtualAlloc failed" );

    LPBYTE jmpAddress = (LPBYTE)mBuffer + mCopySize;

    if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, mCopySize,
      PAGE_EXECUTE_READWRITE, &oldProtect1 ) )
      throw new std::exception( "VirtualProtect failed" );

    memcpy( mBuffer, (LPCVOID)mAddress, mCopySize );
    *(PBYTE)jmpAddress = X86_BYTECODE_FARJMP;
    *(PULONG_PTR)(jmpAddress + 1) = (DWORD)PtrToUlong(mAddress) + mCopySize - (DWORD)(PtrToUlong(jmpAddress) + 5);

    if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, mCopySize, oldProtect1, &oldProtect2 ) )
      throw new std::exception( "VirtualProtect failed" );

    if ( pushCallee )
    {
      BYTE baBytecode[4] = {
        0xFF, 0x34, 0x24, // push dword ptr ss:[esp]
        0xE9 // far jmp
      };
      if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 8, PAGE_WRITECOPY, &oldProtect1 ) )
        throw new std::exception( "VirtualProtect failed" );
      memcpy( (LPVOID)mAddress, baBytecode, 4 );
      *(PULONG_PTR)((PBYTE)mAddress + 4) = (DWORD)PtrToUlong(mTarget) - (DWORD)(PtrToUlong(mAddress) + 8);
      if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 8, oldProtect1, &oldProtect2 ) )
        throw new std::exception( "VirtualProtect failed" );
    }
    else
    {
      if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, PAGE_WRITECOPY, &oldProtect1 ) )
        throw new std::exception( "VirtualProtect failed" );
      *(PBYTE)mAddress = X86_BYTECODE_FARJMP;
      *(PULONG_PTR)((PBYTE)mAddress + 1) = (DWORD)PtrToUlong(mTarget) - (DWORD)(PtrToUlong(mAddress) + 5);
      if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, 5, oldProtect1, &oldProtect2 ) )
        throw new std::exception( "VirtualProtect failed" );
    }
    ppfnOriginal = mBuffer;
  }

  void DetourHook::remove()
  {
    DWORD oldProtect1, oldProtect2;
    if ( mBuffer )
    {
      if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, mCopySize,
        PAGE_EXECUTE_READWRITE, &oldProtect1 ) )
        throw new std::exception( "VirtualProtect failed" );
      memcpy( (LPVOID)mAddress, mBuffer, mCopySize );
      if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)mAddress, mCopySize, oldProtect1, &oldProtect2 ) )
        throw new std::exception( "VirtualProtect failed" );
      Globals::mKernel.pfnVirtualFree( mBuffer, 0, MEM_RELEASE );
    }
  }

  // HookManager class -------------------------------------------------------

  HookManager::HookManager()
  {
    //
  }

  void HookManager::addFarJmpHook( ULONG_PTR pAddress, LPVOID pfnTarget )
  {
    FarJmpHook* pHook = new FarJmpHook( pAddress, pfnTarget );
    mHooks.push_back( pHook );
  }

  void HookManager::addCallHook( ULONG_PTR pAddress, LPVOID pfnTarget )
  {
    CallHook* pHook = new CallHook( pAddress, pfnTarget );
    mHooks.push_back( pHook );
  }

  void HookManager::addDetourHook( ULONG_PTR pAddress, LPVOID pfnTarget, LPVOID& ppfnOriginal, bool bPushCallee )
  {
    DetourHook* pHook = new DetourHook( pAddress, pfnTarget, ppfnOriginal,
      bPushCallee );
    mHooks.push_back( pHook );
  }

  void HookManager::removeHooks()
  {
    for ( HookList::iterator it = mHooks.begin(); it != mHooks.end(); ++it )
    {
      (*it)->remove();
    }
    mHooks.clear();
  }

  HookManager::~HookManager()
  {
    removeHooks();
  }

};

#pragma warning( pop )