#include "xnlib.h"
#include "BeaEngine.h"

namespace xn {

  Kernel Globals::mKernel;

  bool __fastcall calculateCopySize( DWORD_PTR pAddress, DWORD dwDesired,
  DWORD* pdwSize )
  {
    LPBYTE pPosition = (LPBYTE)pAddress;
    LPBYTE pEnd = pPosition + dwDesired;
    DISASM dsm;
    memset( &dsm, 0, sizeof(DISASM) );
    while ( pPosition <= pEnd )
    {
      dsm.EIP = (UIntPtr)pPosition;
      dsm.VirtualAddr = dsm.EIP;
      int len = Disasm( &dsm );
      if ( len == UNKNOWN_OPCODE || len == OUT_OF_BLOCK )
        return false;
      pPosition += len;
    }
    *pdwSize = (DWORD)( pPosition - (LPBYTE)pAddress );
    return true;
  }

  bool __fastcall extractTransfer( DWORD_PTR pAddress, DWORD_PTR* pTarget )
  {
    DISASM dsm;
    memset( &dsm, 0, sizeof(DISASM) );
    dsm.EIP = (UIntPtr)pAddress;
    dsm.VirtualAddr = dsm.EIP;
    int len = Disasm( &dsm );
    if ( len == UNKNOWN_OPCODE || len == OUT_OF_BLOCK )
      return false;
    if ( ( dsm.Instruction.Category & CONTROL_TRANSFER ) == 0 )
      return false;
    if ( !dsm.Instruction.AddrValue )
      return false;
    *pTarget = (DWORD_PTR)dsm.Instruction.AddrValue;
    return true;
  }

  inline wstring utf8ToWide( const string& sIn )
  {
    DWORD dwLength = Globals::mKernel.pfnMultiByteToWideChar( CP_UTF8, NULL,
      sIn.c_str(), -1, NULL, NULL );
    if ( dwLength == 0 )
      return wstring();
    vector<WCHAR> vConversion( dwLength );
    Globals::mKernel.pfnMultiByteToWideChar( CP_UTF8, NULL,
      sIn.c_str(), -1, &vConversion[0], dwLength );
    return wstring( &vConversion[0] );
  }

}