#include <windows.h>
#include <commctrl.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <Psapi.h>
#include <Lmcons.h>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "version.lib")

struct PROCESS_INFO
{
	DWORD pid;
	TCHAR pidStr[30];
	TCHAR processName[257];
	TCHAR userName[257];
	TCHAR memoryStr[257];
	TCHAR description[1024];
};

BOOL showingAllUser = FALSE;
std::vector<PROCESS_INFO> processes;

void printError( TCHAR* msg )
{
  DWORD eNum;
  TCHAR sysMsg[256];
  TCHAR* p;

  eNum = GetLastError( );
  FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
         NULL, eNum,
         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
         sysMsg, 256, NULL );

  // Trim the end of the line and terminate it with a null
  p = sysMsg;
  while( ( *p > 31 ) || ( *p == 9 ) )
    ++p;
  do { *p-- = 0; } while( ( p >= sysMsg ) &&
                          ( ( *p == '.' ) || ( *p < 33 ) ) );

  // Display the message
  _tprintf( TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg );
}

void enableDebugPrivileges()
{
    HANDLE hcurrent=GetCurrentProcess();
    HANDLE hToken;
    BOOL bret=OpenProcessToken(hcurrent,40,&hToken);
    LUID luid;
    bret=LookupPrivilegeValue(NULL,SE_LOAD_DRIVER_NAME, &luid);
    TOKEN_PRIVILEGES NewState,PreviousState;
    DWORD ReturnLength;
    NewState.PrivilegeCount =1;
    NewState.Privileges[0].Luid =luid;
    NewState.Privileges[0].Attributes=2;
    AdjustTokenPrivileges(hToken,FALSE,&NewState,28,&PreviousState,&ReturnLength);
}

BOOL GetProcessUsername(BOOL alluser, TCHAR CurUserName[UNLEN + 1], HANDLE hProcess, BOOL bIncDomain, TCHAR *pret) 
{
    TCHAR sname[300];
    HANDLE tok = 0;
    TOKEN_USER *ptu;
    DWORD nlen, dlen;
    TCHAR name[300], dom[300], tubuf[300];
    int iUse;
	
    //open the processes token
    if (!OpenProcessToken(hProcess,TOKEN_QUERY,&tok)) {
		printError( TEXT("OpenProcessToken") );
		goto ert;
	}
    //get the SID of the token
    ptu = (TOKEN_USER*)tubuf;
    if (!GetTokenInformation(tok,(TOKEN_INFORMATION_CLASS)1,ptu,300,&nlen)) {
		printError( TEXT("GetTokenInformation") );
		goto ert;
	}
	
    //get the account/domain name of the SID
    dlen = 300;
    nlen = 300;
    if (!LookupAccountSid(0, ptu->User.Sid, name, &nlen, dom, &dlen, (PSID_NAME_USE)&iUse)) {
		printError( TEXT("LookupAccountSid") );
		goto ert;
	}
    //copy info to our static buffer
    if (dlen && bIncDomain) {
		wsprintf(sname, TEXT("%s %s"), dom, name);
    } else {
		wsprintf(sname, TEXT("%s"), name);
    }
    //set our return variable
	if (pret)
		wsprintf(pret, TEXT("%s"), sname);

	if (alluser || _tcscmp(CurUserName, name) == 0)
		return TRUE;
	else
		return FALSE;
    ert:
    if (tok) CloseHandle(tok);
	return FALSE;
}

SIZE_T GetPagefileUsage(HANDLE hProcess) {
  PROCESS_MEMORY_COUNTERS pmc;
  if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
    return pmc.PagefileUsage;
  }
  return 0;
}

bool GetMemoryBytes(HANDLE hProcess, SIZE_T* private_bytes) {
  // PROCESS_MEMORY_COUNTERS_EX is not supported until XP SP2.
  // GetProcessMemoryInfo() will simply fail on prior OS. So the requested
  // information is simply not available. Hence, we will return 0 on unsupported
  // OSes. Unlike most Win32 API, we don't need to initialize the "cb" member.
  PROCESS_MEMORY_COUNTERS_EX pmcx;
  if (private_bytes &&
      GetProcessMemoryInfo(hProcess,
                           reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmcx),
                           sizeof(pmcx))) {
    *private_bytes = pmcx.PrivateUsage;
  }

  return true;
}

BOOL GetFileVersion(HANDLE hProcess, LPTSTR VersionInfo, DWORD nSize)
{
    DWORD    dwCount, 
            dwHandle,
            dwValueLen;
    BOOL    bRet;

    TCHAR    *pcValue, 
            *pc,
            *pBuffer,
            szQuery[100];

    TCHAR lpFilename[MAX_PATH];
	DWORD lpdwSize = MAX_PATH;
	struct LANGANDCODEPAGE {
	  WORD wLanguage;
	  WORD wCodePage;
	} *lpTranslate;

	if (!QueryFullProcessImageName(hProcess, 0, lpFilename, &lpdwSize) ) printError( TEXT("QueryFullProcessImageName"));

    if (nSize == 0)
        return FALSE;

    if ((dwCount = GetFileVersionInfoSize(lpFilename, &dwHandle)) != 0)
	{
        pBuffer = new TCHAR[dwCount];
        if (!pBuffer)
            return FALSE;

        if (GetFileVersionInfo(lpFilename, dwHandle, dwCount, pBuffer) != 0) 
        {
            BOOL bVer = VerQueryValue(pBuffer, TEXT("\\VarFileInfo\\Translation"), //INTERNAL USE ONLY
                (LPVOID*) &lpTranslate, (UINT *) &dwValueLen);

            if (bVer && dwValueLen != 0)
            {   
                
                wsprintf(szQuery, TEXT("\\StringFileInfo\\%04X%04X\\FileDescription"), //INTERNAL USE ONLY
                    lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);    // Localization OK
                bRet = VerQueryValue(pBuffer, szQuery, (void **) &pcValue, 
                    (UINT *) &dwValueLen);

                if (bRet)
                {
                    while ((pc = _tcschr(pcValue, '(')) != NULL)
                        *pc = '{';
                    while ((pc = _tcschr(pcValue, ')')) != NULL)
                        *pc = '}';

                    _tcsncpy(VersionInfo, pcValue, nSize);
                    VersionInfo[nSize - 1] = '\0';
                    delete [] pBuffer;
                    return TRUE;
                }
            }
        }

        delete [] pBuffer;
    }

    return FALSE;
}

BOOL GetProcessList(BOOL alluser)
{
  HANDLE hProcessSnap;
  HANDLE hProcess;
  PROCESSENTRY32 pe32;
  TCHAR CurUserName[UNLEN + 1];
  DWORD lpnSize = UNLEN + 1;
  GetUserName(CurUserName, &lpnSize);

  // Take a snapshot of all processes in the system.
  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    printError( TEXT("CreateToolhelp32Snapshot (of processes)") );
    return( FALSE );
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof( PROCESSENTRY32 );

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if( !Process32First( hProcessSnap, &pe32 ) )
  {
    printError( TEXT("Process32First") ); // show cause of failure
    CloseHandle( hProcessSnap );          // clean the snapshot object
    return( FALSE );
  }

  // Now walk the snapshot of processes, and
  // display information about each process in turn
  processes.clear();
  do
  {
    TCHAR pusername[300];
    SIZE_T virtualMem = 0;
    TCHAR VersionInfo[1000] = TEXT(" ");
	PROCESS_INFO pi;
	
    // Retrieve the priority class.
    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID );
    if( hProcess == NULL ) continue;
    else
    {
	  if (!GetProcessUsername(alluser, CurUserName, hProcess,0, pusername)) continue;
	  GetMemoryBytes(hProcess, &virtualMem);
	  GetFileVersion(hProcess, VersionInfo, 1000);
      CloseHandle( hProcess );
    }
	
	
	pi.pid = pe32.th32ProcessID;
	wsprintf(pi.pidStr, TEXT("%d"), pe32.th32ProcessID);
	_tcscpy(pi.processName, pe32.szExeFile);
	_tcscpy(pi.userName, pusername);
	wsprintf(pi.memoryStr, TEXT("%d K"), virtualMem / 1024);
	_tcscpy(pi.description, VersionInfo);
	processes.push_back(pi);

    //_tprintf( TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile );
    //_tprintf( TEXT("\n  User Name         = %s"), pusername );
    //_tprintf( TEXT("\n  Memory            = %d K"), virtualMem / 1024 );
    //_tprintf( TEXT("\n  Description       = %s"), VersionInfo );

  } while( Process32Next( hProcessSnap, &pe32 ) );

  CloseHandle( hProcessSnap );
  return( TRUE );
}


BOOL killProcessByPid(DWORD pid)
{
	BOOL success = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, 0, pid);
    if (hProcess != NULL)
    {
		TCHAR username[UNLEN + 1];
		if (GetProcessUsername(0, TEXT("SYSTEM"), hProcess, 0, username)) {
			success = FALSE;
		}
		else {
			TerminateProcess(hProcess, 9);
			success = TRUE;
		}
		CloseHandle(hProcess);
     }
	return success;
}

BOOL CreatePro( TCHAR *cmdLine )
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPTSTR szCmdline=_tcsdup(cmdLine);
 
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
 
    // Start the child process.
    if( !CreateProcess( NULL,   // No module name (use command line)
       szCmdline,      // Command line
       NULL,           // Process handle not inheritable
       NULL,           // Thread handle not inheritable
       FALSE,          // Set handle inheritance to FALSE
       0,              // No creation flags
       NULL,           // Use parent's environment block
       NULL,           // Use parent's starting directory
       &si,            // Pointer to STARTUPINFO structure
       &pi )           // Pointer to PROCESS_INFORMATION structure
       )
    {
       return false;
    }
 
    // Wait until child process exits.
    //WaitForSingleObject( pi.hProcess, INFINITE );
 
    // Close process and thread handles.
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );
	return true;
}

// Global variables

// The main window class name.
static TCHAR szWindowClass[] = _T("win32app");
static TCHAR szWindowClassCP[] = _T("win32app2");

// The string that appears in the application's title bar.
static TCHAR szTitle[] = _T("Windows Process Manager");

HINSTANCE hInst;
HWND hWnd;

HWND hwndButtonCreateProcess;
HWND hwndButtonKillProcess;
HWND hwndButtonViewAllProcesses;

HWND hwndListView;

HWND hWndCP;
HWND hCPText;
HWND hCPButtonOK, hCPButtonCancel;

// Forward declarations of functions included in this code module:
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

// CreateListView: Creates a list-view control in report view.
// Returns the handle to the new control
// TO DO:  The calling procedure should determine whether the handle is NULL, in case 
// of an error in creation.
//
// HINST hInst: The global handle to the applicadtion instance.
// HWND  hWndParent: The handle to the control's parent window. 
//
HWND CreateListView(HWND hwndParent) 
{
    INITCOMMONCONTROLSEX icex;           // Structure for control initialization.
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    // Create the list-view window in report view with label editing enabled.
    HWND hWndListView = CreateWindow(WC_LISTVIEW,
                                     L"",
                                     WS_TABSTOP | WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_EDITLABELS,
                                     10, 40,
									 400, 500,
                                     hwndParent,
                                     NULL,
                                     hInst,
                                     NULL);

    return hWndListView;
}

// InitListViewColumns: Adds columns to a list-view control.
// hWndListView:        Handle to the list-view control. 
// Returns TRUE if successful, and FALSE otherwise. 
BOOL InitListViewColumns(HWND hWndListView) 
{ 
    WCHAR szText[5][256];
	wsprintf(szText[0], _T("%s"), _T("Process ID"));
	wsprintf(szText[1], _T("%s"), _T("Process Name"));
	wsprintf(szText[2], _T("%s"), _T("User Name"));
	wsprintf(szText[3], _T("%s"), _T("Memory"));
	wsprintf(szText[4], _T("%s"), _T("Description"));

	LVCOLUMN lvc = {0};
    // Initialize the LVCOLUMN structure.
    // The mask specifies that the format, width, text,
    // and subitem members of the structure are valid.
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    // Add the columns.
    for (int iCol = 0; iCol < 5; iCol++)
    {
        lvc.iSubItem = iCol;
		lvc.iOrder = iCol;
        lvc.pszText = szText[iCol];
        lvc.cx = 100;               // Width of column in pixels.
        lvc.fmt = LVCFMT_LEFT;  // Left-aligned column.

        // Insert the columns into the list view.
        ListView_InsertColumn(hWndListView, iCol, &lvc);
    }
    
    return TRUE;
}

// InsertListViewItems: Inserts items into a list view. 
// hWndListView:        Handle to the list-view control.
// cItems:              Number of items to insert.
// Returns TRUE if successful, and FALSE otherwise.
BOOL InsertListViewItems(HWND hWndListView)
{
    LVITEM lvI;

    // Initialize LVITEM members that are common to all items.
    lvI.pszText   = LPSTR_TEXTCALLBACK; // Sends an LVN_GETDISPINFO message.
    lvI.mask      = LVIF_TEXT | LVIF_IMAGE | LVIF_STATE;
    lvI.stateMask = 0;
    lvI.iSubItem  = 0;
    lvI.state     = 0;

    // Initialize LVITEM members that are different for each item.
	for (size_t index = 0; index < processes.size(); index++)
    {
        lvI.iItem  = index;
        lvI.iImage = index;
    
        // Insert items into the list.
        if (ListView_InsertItem(hWndListView, &lvI) == -1)
            return FALSE;
    }

    return TRUE;
}

void refreshList()
{
	GetProcessList(showingAllUser);
	ListView_DeleteAllItems(hwndListView);
	InsertListViewItems(hwndListView);
}

int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine,
                   int nCmdShow)
{
	WNDCLASSEX wcex = {0};

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPLICATION));
    wcex.hCursor        = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = NULL;
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_APPLICATION));

    if (!RegisterClassEx(&wcex))
    {
        MessageBox(NULL,
            _T("Call to RegisterClassEx failed!"),
            _T("Create Process"),
            NULL);

        return 1;
    }

    hInst = hInstance; // Store instance handle in our global variable

    // The parameters to CreateWindow explained:
    // szWindowClass: the name of the application
    // szTitle: the text that appears in the title bar
    // WS_OVERLAPPEDWINDOW: the type of window to create
    // CW_USEDEFAULT, CW_USEDEFAULT: initial position (x, y)
    // 500, 100: initial size (width, length)
    // NULL: the parent of this window
    // NULL: this application does not have a menu bar
    // hInstance: the first parameter from WinMain
    // NULL: not used in this application
    hWnd = CreateWindow(
        szWindowClass,
        szTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        440, 600,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (!hWnd)
    {
        MessageBox(NULL,
            _T("Call to CreateWindow failed!"),
            _T("Win32 Guided Tour"),
            NULL);

        return 1;
    }

	hwndButtonCreateProcess = CreateWindow( 
		L"BUTTON",  // Predefined class; Unicode assumed 
		L"Create Process",      // Button text 
		WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,  // Styles 
		10,         // x position 
		10,         // y position 
		125,        // Button width
		20,        // Button height
		hWnd,     // Parent window
		NULL,       // No menu.
		hInst, 
		NULL);      // Pointer not needed.

	hwndButtonKillProcess = CreateWindow( 
		L"BUTTON",  // Predefined class; Unicode assumed 
		L"Kill Process",      // Button text 
		WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,  // Styles 
		145,         // x position 
		10,         // y position 
		105,        // Button width
		20,        // Button height
		hWnd,     // Parent window
		NULL,       // No menu.
		hInst, 
		NULL);      // Pointer not needed.

	hwndButtonViewAllProcesses = CreateWindow( 
		L"BUTTON",  // Predefined class; Unicode assumed 
		L"View All Processes",      // Button text 
		WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,  // Styles 
		260,         // x position 
		10,         // y position 
		145,        // Button width
		20,        // Button height
		hWnd,     // Parent window
		NULL,       // No menu.
		hInst, 
		NULL);      // Pointer not needed.

	hwndListView = CreateListView(hWnd);
	InitListViewColumns(hwndListView);

	// CreateProcess window:
	hWndCP = CreateWindow(
        szWindowClass,
        szTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        440, 120,
        NULL,
        NULL,
        hInstance,
        NULL
    );

	hCPText = CreateWindowEx(
		WS_EX_CLIENTEDGE,
		L"Edit",
		L"",
		WS_TABSTOP | WS_VISIBLE | WS_CHILD | WS_BORDER | ES_LEFT,
		10, 10, 420, 30,
		hWndCP, NULL, hInst, NULL);

	hCPButtonOK = CreateWindow( 
		L"BUTTON",  // Predefined class; Unicode assumed 
		L"OK",      // Button text 
		WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,  // Styles 
		10,         // x position 
		50,         // y position 
		100,        // Button width
		20,        // Button height
		hWndCP,     // Parent window
		NULL,       // No menu.
		hInst, 
		NULL);      // Pointer not needed.
	
	hCPButtonCancel = CreateWindow( 
		L"BUTTON",  // Predefined class; Unicode assumed 
		L"Cancel",      // Button text 
		WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,  // Styles 
		120,         // x position 
		50,         // y position 
		100,        // Button width
		20,        // Button height
		hWndCP,     // Parent window
		NULL,       // No menu.
		hInst, 
		NULL);      // Pointer not needed.

	enableDebugPrivileges();
	refreshList();

	SetTimer(hWnd, NULL, 6000, NULL);

    // The parameters to ShowWindow explained:
    // hWnd: the value returned from CreateWindow
    // nCmdShow: the fourth parameter from WinMain
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    // Main message loop:
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int) msg.wParam;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND curWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
	case WM_TIMER:
		refreshList();
		break;
	case WM_NOTIFY:
		{
			NMLVDISPINFO* plvdi;
			switch (((LPNMHDR) lParam)->code)
			{
				case LVN_GETDISPINFO:
					plvdi = (NMLVDISPINFO*)lParam;
					switch (plvdi->item.iSubItem)
					{
						case 0:
							plvdi->item.pszText = processes[plvdi->item.iItem].pidStr;
							break;	
						case 1:
							plvdi->item.pszText = processes[plvdi->item.iItem].processName;
							break;
						case 2:
							plvdi->item.pszText = processes[plvdi->item.iItem].userName;
							break;
						case 3:
							plvdi->item.pszText = processes[plvdi->item.iItem].memoryStr;
							break;
						case 4:
							plvdi->item.pszText = processes[plvdi->item.iItem].description;
							break;
						default:
							break;
					}
				break;
			}
		}
		break;
	case WM_COMMAND:
		if ((HWND) lParam == hwndButtonCreateProcess)
		{
			ShowWindow(hWndCP, SW_NORMAL);
			refreshList();
		}
		else if ((HWND) lParam == hwndButtonKillProcess)
		{
			// Get the first selected item
			int iPos = ListView_GetNextItem(hwndListView, -1, LVNI_SELECTED);
			while (iPos != -1)
			{
				// iPos is the index of a selected item
				// do whatever you want with it
				WCHAR szText[256];
				wsprintf(szText, TEXT("iPos=%d"), iPos);
				//MessageBox(NULL, szText, _T(""), NULL);
				if(!killProcessByPid(processes[iPos].pid)) {
					MessageBox(NULL,
						_T("System process can't been terminated!"),
						_T("Windows Notification"),
						NULL);
				}
				// Get the next selected item
				refreshList();
				iPos = ListView_GetNextItem(hwndListView, iPos, LVNI_SELECTED);
			}
		}
		else if ((HWND) lParam == hwndButtonViewAllProcesses)
		{
			if (showingAllUser == TRUE)
			{
				showingAllUser = FALSE;
				SetWindowText(hwndButtonViewAllProcesses, TEXT("View All Processes"));
			}
			else
			{
				showingAllUser = TRUE;
				SetWindowText(hwndButtonViewAllProcesses, TEXT("View My Processes"));
			}
			refreshList();
		}
		else if ((HWND) lParam == hCPButtonOK)
		{
			const int cmdLineSize = 256;
			TCHAR cmdLine[cmdLineSize + 1];
			GetWindowText(hCPText, cmdLine, cmdLineSize);
			if(!CreatePro(cmdLine)) {
				MessageBox(NULL,
						_T("The application name can't be found. Please make sure whether the name is right!"),
						_T("Windows Notification"),
						NULL);
			}
			ShowWindow(hWndCP, SW_HIDE);
			refreshList();
		}
		else if ((HWND) lParam == hCPButtonCancel)
		{
			ShowWindow(hWndCP, SW_HIDE);
		}
        else
		{
			return DefWindowProc(curWnd, message, wParam, lParam);
		}
		break;
    case WM_DESTROY:
		if (curWnd == hWnd)
			PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(curWnd, message, wParam, lParam);
        break;
    }
    return 0;
}
