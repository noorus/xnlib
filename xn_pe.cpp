#include "xnlib.h"

namespace xn {

  MemoryPE::MemoryPE( HMODULE hModule )
  {
    if ( !hModule )
      throw std::exception( "No module" );

    pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
      throw std::exception( "Invalid DOS header" );

    pNtHeader = (PIMAGE_NT_HEADERS)( (DWORD)pDosHeader + pDosHeader->e_lfanew );
    if ( pNtHeader->Signature != IMAGE_NT_SIGNATURE )
      throw std::exception( "Invalid NT header" );

    WORD wSections = pNtHeader->FileHeader.NumberOfSections;
    WORD wOptionalHeaderSize = pNtHeader->FileHeader.SizeOfOptionalHeader;
    DWORD dwExportDirSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    processImports();
    processExports();
  }

  void ExportedModule::clear( void )
  {
    sModuleName.clear();
    flFunctions.clear();
  }

  // this function assumes that the imported functions have already been resolved by the image loader.
  // if they haven't, you have to write some new code.
  void MemoryPE::processImports( void )
  {
    mImports.clear();

    if ( pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 )
      return;

    pImports = (PIMAGE_IMPORT_DESCRIPTOR)( (DWORD)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );

    PIMAGE_IMPORT_DESCRIPTOR pImport = pImports;
    while ( pImport->FirstThunk )
    {
      ImportedModule mModule;
      if ( !pImport->Name )
        throw std::exception( "Empty import entry" );

      // you could check with IsBadStringPtrA() here for additional safety
      LPSTR pszName = (LPSTR)( (DWORD)pDosHeader + pImport->Name );
      char szName[256] = { NULL };
      strncpy_s( szName, 256, pszName, 255 );
      mModule.sModuleName = utf8ToWide( szName );

      mModule.hModule = Globals::mKernel.pfnGetModuleHandleW( mModule.sModuleName.c_str() );
      if ( !mModule.hModule )
        throw std::exception( "Couldn't fetch module handle" );

      PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)( (DWORD)pDosHeader + pImport->FirstThunk );
      while ( pThunk->u1.Function )
      {
         ImportedFunction f;
         f.ppfnFunction = (ULONG_PTR*)&pThunk->u1.Function;
         f.pfnOriginal = pThunk->u1.Function;
         mModule.flFunctions.push_back( f );
         pThunk++;
      }
      mImports.push_back( mModule );
      pImport++;
    }
  }

  ImportedModule* MemoryPE::findImportedModule( HMODULE hModule )
  {
    for ( ImportedModuleList::iterator it = mImports.begin(); it != mImports.end(); ++it )
    {
      if ( (*it).hModule == hModule )
        return &(*it);
    }
    return NULL;
  }

  ImportedModule* MemoryPE::findImportedModule( const wstring& sName )
  {
    return findImportedModule( Globals::mKernel.pfnGetModuleHandleW( sName.c_str() ) );
  }

  bool ImportedModule::hook( const string& sAPI, LPVOID pfnNew )
  {
    ULONG_PTR pfnTarget = (ULONG_PTR)Globals::mKernel.pfnGetProcAddress( hModule, sAPI.c_str() );
    for ( ImportedFunctionList::iterator it = flFunctions.begin(); it != flFunctions.end(); ++it )
    {
      if ( (*it).pfnOriginal == pfnTarget )
      {
        if ( (*it).bHooked )
          return false;
        DWORD dwOldProtection;
        if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)( (*it).ppfnFunction ), 4, PAGE_WRITECOPY, &dwOldProtection ) )
          return false;
        *( (*it).ppfnFunction ) = (ULONG_PTR)pfnNew;
        Globals::mKernel.pfnVirtualProtect( (LPVOID)( (*it).ppfnFunction ), 4, dwOldProtection, &dwOldProtection );
        (*it).bHooked = true;
        return true;
      }
    }
    return false;
  }

  void ImportedModule::unhookAll( void )
  {
    for ( ImportedFunctionList::iterator it = flFunctions.begin(); it != flFunctions.end(); ++it )
    {
      if ( (*it).bHooked == false )
        continue;
      DWORD dwOldProtection;
      if ( !Globals::mKernel.pfnVirtualProtect( (LPVOID)( (*it).ppfnFunction ), 4, PAGE_WRITECOPY, &dwOldProtection ) )
        continue;
      *( (*it).ppfnFunction ) = (*it).pfnOriginal;
      Globals::mKernel.pfnVirtualProtect( (LPVOID)( (*it).ppfnFunction ), 4, dwOldProtection, &dwOldProtection );
      (*it).bHooked = false;
    }
  }

  void MemoryPE::processExports( void )
  {
    mExports.clear();

    if ( pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 )
      return;

    pExports = (PIMAGE_EXPORT_DIRECTORY)( (DWORD)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
    ULONG_PTR pExportsEnd = (ULONG_PTR)pExports + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if ( pExports->Name > 0 )
    {
      // you could check with IsBadStringPtrA() here for additional safety
      LPSTR pszName = (LPSTR)( (DWORD)pDosHeader + pExports->Name );
      char szName[256] = { NULL };
      strncpy_s( szName, 256, pszName, 255 );
      mExports.sModuleName = utf8ToWide( szName );
    }

    if ( pExports->NumberOfFunctions > 0 )
    {
      DWORD* pdwExpNames = (DWORD*)( (DWORD)pDosHeader + pExports->AddressOfNames );
      DWORD* pdwExpFunctions = (DWORD*)( (DWORD)pDosHeader + pExports->AddressOfFunctions );
      WORD*  pwExpOrdinals = (WORD*)( (DWORD)pDosHeader + pExports->AddressOfNameOrdinals );
      for ( DWORD i = 0; i < pExports->NumberOfFunctions; i++ )
      {
        ExportedFunction f;
        ULONG_PTR ptr = (ULONG_PTR)( (DWORD)pDosHeader + pdwExpFunctions[i] );
        if ( ptr >= (ULONG_PTR)pExports && ptr <= pExportsEnd ) {
          f.bForwarded = true;
          f.pfnFunction = NULL;
          f.pszForward = (PSTR)ptr;
        } else {
          f.bForwarded = false;
          f.pfnFunction = (LPVOID)ptr;
          f.pszForward = NULL;
        }
        f.dwOrdinal = pExports->Base + i;
        mExports.flFunctions.push_back( f );
      }
      for ( DWORD i = 0; i < pExports->NumberOfNames; i++ )
      {
        LPSTR pszName = (LPSTR)( (DWORD)pDosHeader + pdwExpNames[i] );
        DWORD dwIndex = ( (WORD)( pwExpOrdinals[i] ) );
        DWORD dwOrdinal = pExports->Base + dwIndex;
        for ( ExportedFunctionList::iterator it = mExports.flFunctions.begin(); it != mExports.flFunctions.end(); ++it )
        {
          if ( (*it).dwOrdinal == dwOrdinal )
          {
            (*it).fnlNames.push_back( utf8ToWide( pszName ) );
            break;
          }
        }
      }
    }
  }

  HMODULE MemoryPE::getModule() throw()
  {
    return (HMODULE)pDosHeader;
  }

  ULONG_PTR MemoryPE::getEntryPoint() throw()
  {
    return (ULONG_PTR)pDosHeader + pNtHeader->OptionalHeader.AddressOfEntryPoint;
  }

  ImportedModuleList& MemoryPE::getImports() throw()
  {
    return mImports;
  }

  ExportedModule& MemoryPE::getExports() throw()
  {
    return mExports;
  }

}