program loader;

//http://index-of.es/Windows/dbgk-1.pdf
//https://processhacker.sourceforge.io/doc/ntdbg_8h.html

uses windows,sysutils,jwapsapi;

function DebugActiveProcessStop(pid: dword):boolean; stdcall;external 'kernel32.dll';
//function DebugBreakProcess (processhandle:THandle):boolean; stdcall;external 'kernel32.dll';
function DebugSetProcessKillOnExit(KillOnExit: boolean):boolean; stdcall;external 'kernel32.dll';
//function IsDebuggerPresent:boolean; stdcall;external 'kernel32.dll';
function DebugActiveProcess(dwProcessId:DWORD):WINBOOL; external 'kernel32.dll';
function ContinueDebugEvent(dwProcessId:DWORD; dwThreadId:DWORD; dwContinueStatus:DWORD):WINBOOL; external 'kernel32.dll';

type
{$ifdef CPU64}
    IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
    PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS64;
  {$else}
    IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;
    PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS32;
  {$endif}
    TImageNtHeaders = IMAGE_NT_HEADERS;
    PImageNtHeaders = PIMAGE_NT_HEADERS;

function ImageNtHeader(Base: Pointer): PIMAGE_NT_HEADERS; stdcall; external 'dbghelp.dll';


var
    procinfo:TProcessInformation;
    stop:boolean=false;
    cs:trtlcriticalsection;

    function handleToFilename(loadDllInfo: TLoadDLLDebugInfo; hProcess:THANDLE):string;
    var
    hFileMapping:thandle=thandle(-1);
    fileName:pchar;
    hview:pointer;
    length:dword;
    begin
     //hFileMapping := CreateFileMapping(loadDllInfo.hFile, nil,PAGE_READONLY, 0, 0, 'temp');
     //hView := MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0); //not sure this is needed?
     //writeln(inttohex(nativeuint(hview),sizeof(hview)));
     getmem(filename,MAX_PATH);
     length := GetMappedFileName(hProcess, loadDllInfo.lpBaseOfDll,fileName, MAX_PATH);
    UnmapViewOfFile(nil);
    if hFileMapping <>thandle(-1) then CloseHandle(hFileMapping);
    result:=strpas(fileName);
    freemem(filename,max_path);
    end;

procedure log(msg:string);
begin
writeln(msg);
end;

//look at NtSetInformationThread+ThreadHideFromDebugger
//also look at https://ntquery.wordpress.com/2014/03/29/anti-debug-ntcreatethreadex/

function debug(param:pointer):dword;stdcall;
var
DebugEvent: TDebugEvent;
dwContinueStatus: DWORD;
hthread,hprocess:thandle;
p:pchar;
bytesread:ptruint;
loaddll,injectdll:string;
modinfo:MODULEINFO;
b:boolean;
fi:_BY_HANDLE_FILE_INFORMATION;
ImageHandle:thandle=thandle(-1);
ImagePointer:lpvoid=nil;
ntHeader : PIMAGE_NT_HEADERS=nil;
EntryPoint:qword=0;
bytesWritten:ptruint;
buf:byte=$c3; //ret
begin
log('debug:start');
while 1=1 do
  begin
  if not WaitForDebugEvent(debugEvent, INFINITE) then break ;
  dwContinueStatus := DBG_CONTINUE;
  case DebugEvent.dwDebugEventCode of
  EXCEPTION_DEBUG_EVENT:
    begin
    log(inttostr(debugEvent.dwThreadId )+' EXCEPTION_DEBUG_EVENT '
      +' '+inttohex(debugEvent.Exception.ExceptionRecord.ExceptionCode,8)   );
    case debugEvent.Exception.ExceptionRecord.ExceptionCode of
      //C0000005 ACCESS_VIOLATION
      EXCEPTION_INVALID_HANDLE:
        begin
        //reallly?
        log(inttostr(DebugEvent.dwThreadId)
                  +' '+'EXCEPTION_INVALID_HANDLE'
                  +' '+ inttohex(debugEvent.Exception.ExceptionRecord.ExceptionCode,8)
                  + ' @ '+ inttohex(dword(debugEvent.Exception.ExceptionRecord.ExceptionAddress ),8)
                  + ' : '+ inttostr(debugEvent.Exception.ExceptionRecord.ExceptionInformation [0])
                  + ' : '+ inttostr(debugEvent.Exception.ExceptionRecord.ExceptionInformation [1])) ;
        //dwContinueStatus := DBG_EXCEPTION_NOT_HANDLED;
        end;
      EXCEPTION_BREAKPOINT:
        begin
        // stay with DBG_CONTINUE at least for the first breakpoint.
        // continue, don't pass this back to process being debugged.
        log(inttostr(DebugEvent.dwThreadId)
                              +' '+'EXCEPTION_BREAKPOINT'   );
        end;
      //EXCEPTION_SINGLE_STEP:form1.Memo1.Lines.Add(timetostr(now)+' EXCEPTION_SINGLE_STEP'   );
      else
        begin
        // handles all other stuff like EXCEPTION_ACCESS_VIOLATION
        // pass these back to the process being debugged...
        //(r.ExceptionInformation[0] == 0 ? "read" : (r.ExceptionInformation[0] == 1 ? "write"
        log(inttostr(DebugEvent.dwThreadId)
                  +' '+'DBG_EXCEPTION_NOT_HANDLED'
                   +' '+inttohex(debugEvent.Exception.ExceptionRecord.ExceptionCode,8)
                  + ' @ '+inttohex(dword(debugEvent.Exception.ExceptionRecord.ExceptionAddress ),8)
                  + ' : '  +inttostr(debugEvent.Exception.ExceptionRecord.ExceptionInformation [0])
                  + ' : '  +inttohex(debugEvent.Exception.ExceptionRecord.ExceptionInformation [1],8)) ;
        dwContinueStatus := DBG_EXCEPTION_NOT_HANDLED;
        end;
    end;//case
    end;
  CREATE_THREAD_DEBUG_EVENT:
    begin
    log(inttostr(DebugEvent.dwThreadId)
                          +' '+'CREATE_THREAD_DEBUG_EVENT'
                          +' '+inttostr(DebugEvent.CreateThread.hThread)
                          + ' @ '+inttohex(dword(DebugEvent.CreateThread.lpStartAddress ),8));
    //hthread:=OpenThread(THREAD_ALL_ACCESS,false,DebugEvent.dwThreadId);
    //DuplicateHandle(hprocess,DebugEvent.CreateThread.hThread,currentprocess ,@hthread, PROCESS_ALL_ACCESS,FALSE, 0);
    //GetThreadContext(DebugEvent.CreateThread.hThread,context);
    //form1.Memo1.Lines.Add('DuplicateHandle:'+inttostr(hthread ));
    //?
    //if pause=true then SuspendThread(DebugEvent.CreateThread.hThread);
    end;
  CREATE_PROCESS_DEBUG_EVENT:
    begin
    //u.CreateProcessInfo.hProcess (process)
    //u.CreateProcessInfo.hThread (initial thread)
    log(inttostr(DebugEvent.dwThreadId)
                          +' '+'CREATE_PROCESS_DEBUG_EVENT'
                          +' '+inttostr(DebugEvent.CreateProcessInfo.hThread )
                          + ' @ '+inttohex(nativeuint(DebugEvent.CreateProcessInfo.lpStartAddress ),8));
    //form1.Memo1.Lines.Add('threadid hprocess:TID '+inttostr(DebugEvent.dwThreadId)+' '+inttostr(DebugEvent.CreateProcessInfo.hProcess ));
    hprocess := DebugEvent.CreateProcessInfo.hProcess ;
    //store handle to main thread???

    //GetFileNameFromHandle(DebugEvent.CreateProcessInfo.hFile);

    //we could inject here using context
    //
    end;
  EXIT_THREAD_DEBUG_EVENT:
    begin

    log(inttostr(DebugEvent.dwThreadId)
                         +' '+'EXIT_THREAD_DEBUG_EVENT'+' '+inttostr(hthread));
    //if main_thread = DebugEvent.dwThreadId then break;
    end;
  EXIT_PROCESS_DEBUG_EVENT:
    begin
    log('EXIT_PROCESS_DEBUG_EVENT');
    stop:=true;
    break;
    end;
  LOAD_DLL_DEBUG_EVENT:
    begin
    loaddll:=ExtractFileName(handleToFilename(DebugEvent.LoadDll,hprocess));

    //if GetFileInformationByHandle(DebugEvent.LoadDll.hFile ,FI)=true then
            begin
            //log(inttostr(fi.nFileSizeLow  ));
            //ImageHandle := CreateFileMapping(DebugEvent.LoadDll.hFile, nil,PAGE_READONLY, fi.nFileSizeHigh , fi.nFileSizeLow, 'temp');
            ImageHandle := CreateFileMapping(DebugEvent.LoadDll.hFile, nil,PAGE_READONLY, 0 , 0, nil);
            //ImagePointer := MapViewOfFile(ImageHandle, FILE_MAP_READ, 0, 0, fi.nFileSizeLow);
            ImagePointer := MapViewOfFile(ImageHandle, FILE_MAP_READ, 0, 0, 0);
            NTHeader := ImageNtHeader(ImagePointer);
            //writeln(inttohex(ntHeader^.Signature,sizeof(dword)));
            if NTHeader^.Signature=$00004550 then
                    begin
                    //we could patch the entry point with a ret=$c3
                    //https://ethicalchaos.dev/category/bypass/
                    EntryPoint := qword(ntHeader^.OptionalHeader.AddressOfEntryPoint);
                    //log('EntryPoint:'+inttohex(EntryPoint,sizeof(EntryPoint)));
                    //writeln(inttohex(ntHeader^.OptionalHeader.ImageBase,sizeof(pointer)));
                    //writeln(inttohex(ntHeader^.OptionalHeader.AddressOfEntryPoint ,sizeof(pointer)));
                    if pos('atcuf64.dll',loaddll )>0
                          then if WriteProcessMemory(hProcess, pointer(nativeuint(DebugEvent.LoadDll.lpBaseOfDll)+entrypoint), @buf, 1, @bytesWritten)=true
                                then log('patched OK @'+inttohex(EntryPoint,sizeof(EntryPoint)))
                                else log('patched NOK,'+inttostr(getlasterror));
                    end;
            if ImagePointer<>nil then UnmapViewOfFile(ImagePointer);
            if ImageHandle<>thandle(-1) then CloseHandle(ImageHandle);
            end;

    {
    //log(inttostr(DebugEvent.LoadDll.hFile));
    //fillchar(modinfo ,sizeof(modinfo ),0);
    if GetModuleInformation(hprocess ,DebugEvent.LoadDll.hFile  ,modinfo,sizeof(moduleinfo))=true then
      begin
      log(loaddll+' '+inttohex(dword(modinfo.lpBaseOfDll),8)+' '+inttostr(modinfo.SizeOfImage ));
      end
      else log('GetModuleInformation failed,'+inttostr(getlasterror));
    }
    log(inttostr(DebugEvent.dwThreadId)
                          +' '+'LOAD_DLL_DEBUG_EVENT '+inttohex(nativeuint(DebugEvent.LoadDll.lpBaseOfDll),8 )+' '+loaddll);
    end;
  UNLOAD_DLL_DEBUG_EVENT:
    begin
    //log('UNLOAD_DLL_DEBUG_EVENT:'+inttohex(dword(DebugEvent.UnloadDll.lpBaseOfDll),8));
    end;
  OUTPUT_DEBUG_STRING_EVENT:
    begin
    if DebugEvent.DebugString.nDebugStringLength>0 then
    begin
    entercriticalsection(cs);
    getmem(p,DebugEvent.DebugString.nDebugStringLength);
    try
    bytesread:=0;
    b:=ReadProcessMemory(hprocess , DebugEvent.DebugString.lpDebugStringData  , p, DebugEvent.DebugString.nDebugStringLength, bytesRead);
    if (bytesread>0) and (b=true) then log(inttostr(DebugEvent.dwThreadId)
                                              +' '+'OUTPUT_DEBUG_STRING_EVENT '+strpas(p));
    finally
    freemem(p,DebugEvent.DebugString.nDebugStringLength);
    end;//try
    leavecriticalsection(cs);
    end;//if DebugEvent.DebugString.nDebugStringLength>0 then
    end;
  RIP_EVENT:log('RIP_EVENT');
  else log(inttostr(debugEvent.dwDebugEventCode ));
  end;//case
  //Causes a breakpoint exception to occur in the specified process. This allows the calling thread to signal the debugger to handle the exception.
  //???
  //if pause=true then DebugBreakProcess (ProcInfo.hProcess);
  if stop=true then begin DebugActiveProcessStop (debugEvent.dwProcessId );exit;end;
  {if pause=false then} ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, dwContinueStatus);

  end;
  log('debug:end');
  DebugActiveProcessStop (debugEvent.dwProcessId );
end;

function load(ExecuteFile,paramstring:string):boolean;
var
StartInfo  : TStartupInfo;
    CreateOK   : Boolean;
    ret,prio,ErrorCode:dword;
begin
//createprocess

    ErrorCode := 0;
    FillChar(StartInfo,SizeOf(TStartupInfo),#0);
    FillChar(ProcInfo,SizeOf(TProcessInformation),#0);
    StartInfo.cb := SizeOf(TStartupInfo);
    //StartInfo.dwFlags :=STARTF_USESHOWWINDOW;
    //StartInfo.wShowWindow :=SW_SHOWNORMAL ;
    prio:=NORMAL_PRIORITY_CLASS;

    CreateOK := Windows.CreateProcess(nil, //PChar(ExecuteFile),
                PChar(ExecuteFile + ' ' + paramstring), //PChar(paramstring),
                nil,
                nil,
                false,
                {CREATE_NEW_CONSOLE or}  {process_all_access or} prio or {DEBUG_PROCESS  or DEBUG_ONLY_THIS_PROCESS or} create_suspended , //flag
                nil,
                pchar( ExtractFileDir(ExecuteFile) ),
                StartInfo,
                ProcInfo);

    if CreateOK =false then
            begin
            log('CreateProcess NOT');
            exit;
            end;
//do something like inject eventually
//start
ResumeThread(ProcInfo.hThread );
//debug
if DebugActiveProcess(ProcInfo.dwProcessId )=false
      //DbgUiDebugActiveProcess
      then log('DebugActiveProcess false')
      else log('DebugActiveProcess true');
    DebugSetProcessKillOnExit(true);
    // NtSetInformationDebugObject(Handle, DebugObjectKillProcessOnExitInformation, &State, sizeof(State), NULL);

    debug(nil);
//end
while 1=1 do
   begin
    ret:= WaitForSingleObject(ProcInfo.hProcess, 1000) ;
    if ret=WAIT_TIMEOUT then
            begin
              //log('WAIT_TIMEOUT');
              //break;
            end;
    if (ret=0) or (ret=WAIT_FAILED) then break;
   end;

   getExitCodeProcess(ProcInfo.hProcess, ErrorCode);
   log('exe terminated:'+inttostr(errorcode));


   //TerminateThread(debug_thread,0 );

   try
   CloseHandle(ProcInfo.hProcess);
   CloseHandle(ProcInfo.hThread);
   except
   end;
end;

begin
if paramcount=0 then exit;
if paramcount=1 then load (paramstr(1),'');
if paramcount=2 then load (paramstr(1),paramstr(2));
end.

initialization
initializecriticalsection(cs);

