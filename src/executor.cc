#include "executor.h"

#include <sstream>

#ifdef WIN32
#define _WINSOCKAPI_
#include <tchar.h>
#include <userenv.h>
#include <windows.h>
#include <wtsapi32.h>
#endif

namespace internal {

std::string dwordToHexString(DWORD value) {
  std::stringstream ss;
  ss << "0x" << std::hex << std::uppercase << value;
  return ss.str();
}

void closeHandle(HANDLE *hToken) { CloseHandle(*hToken); }

// error code define
DWORD ERR_INVAILD_INPUT = 0x52e;   // 用户名或密码错误

BOOL EnablePrivilege(LPCTSTR privilege) {
  TOKEN_PRIVILEGES tp;
  HANDLE hToken;
  LUID luid;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    std::cerr << "OpenProcessToken failed: " << GetLastError();
    return FALSE;
  }

  if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
    std::cerr << "LookupPrivilegeValue failed: " << GetLastError();
    CloseHandle(hToken);
    return FALSE;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
    std::cerr << "AdjustTokenPrivileges failed: " << GetLastError();
    CloseHandle(hToken);
    return FALSE;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
    std::cerr << "The token does not have the specified privilege. ";
    CloseHandle(hToken);
    return FALSE;
  }

  CloseHandle(hToken);
  return TRUE;
}

int LogonAndUnlockDesktop(std::wstring wusername, std::wstring wdomain, std::wstring wpassword) {
  HANDLE hToken = NULL;
  STARTUPINFO si = {sizeof(si)};
  PROCESS_INFORMATION pi;
  LPWSTR pszCommandLine = const_cast<LPWSTR>(L"notepad.exe");
  BOOL bResult = FALSE;

  // 1. 登录用户 - 假设用户名、密码和域已知
  if (LogonUser(wusername.c_str(), wdomain.c_str(), wpassword.c_str(), LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT, &hToken)) {
    // if (!internal::EnablePrivilege(SE_TCB_NAME)) {
    //   std::cerr << "Failed to enable privilege: SE_TCB_NAME";
    //   return 1;
    // }
    // if (!internal::EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME)) {
    //   std::cerr << "Failed to enable privilege: SE_ASSIGNPRIMARYTOKEN_NAME";
    //   return 1;
    // }
    if (!internal::EnablePrivilege(SE_INCREASE_QUOTA_NAME)) {
      std::cerr << "Failed to enable privilege: SE_INCREASE_QUOTA_NAME";
      return 1;
    }
    if (!internal::EnablePrivilege(SE_IMPERSONATE_NAME)) {
      std::cerr << "Failed to enable privilege: SE_IMPERSONATE_NAME";
      return 1;
    }

    // 2. 创建进程 - 使用CreateProcessAsUser
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.lpDesktop = (LPWSTR) L"winsta0\\default";
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    bResult = CreateProcessAsUser(hToken,           // 用户令牌句柄
                                  NULL,             // 应用程序名称
                                  pszCommandLine,   // 命令行字符串
                                  NULL,             // 进程安全属性
                                  NULL,             // 线程安全属性
                                  FALSE,            // 句柄继承选项
                                  0,                // 创建标志
                                  NULL,             // 新环境块
                                  NULL,             // 当前目录名
                                  &si,              // STARTUPINFO指针
                                  &pi               // 接收PROCESS_INFORMATION
    );

    if (!bResult) {
      std::cerr << "CreateProcessAsUser failed: " << GetLastError() << std::endl;
    } else {
      // 3. 等待进程结束
      WaitForSingleObject(pi.hProcess, INFINITE);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    }

    // 4. 关闭令牌句柄
    CloseHandle(hToken);
  } else {
    std::cerr << "LogonUser failed: " << GetLastError() << std::endl;
  }

  return bResult ? 0 : -1;
}

int Logon(std::wstring wusername, std::wstring wdomain, std::wstring wpassword) {
  using unique_handle_t = std::unique_ptr<HANDLE, decltype(&internal::closeHandle)>;
  HANDLE hToken;
  unique_handle_t deferToken(&hToken, internal::closeHandle);
  BOOL result = LogonUser(wusername.c_str(), wdomain.c_str(), wpassword.c_str(), LOGON32_LOGON_INTERACTIVE,
                          LOGON32_PROVIDER_DEFAULT, &hToken);
  if (!result) {
    std::cerr << "LogonUser failed: " << GetLastError() << std::endl;
    return -1;
  }
  return 0;
}

}   // namespace internal

WindowsLogonUserExecutor::WindowsLogonUserExecutor() {}
WindowsLogonUserExecutor::~WindowsLogonUserExecutor() {}

bool WindowsLogonUserExecutor::Execute(Json::Value &req, Json::Value &rep) {
  std::string username = req["username"].asString();
  std::string password = req["password"].asString();
  std::string domain = req["domain"].asString();

  std::cout << "WindowsLogonUserExecutor::Execute()" << std::endl;
  std::cout << "ussername: " << username << std::endl;
  std::cout << "password: " << password << std::endl;
  std::cout << "domain: " << domain << std::endl;

  std::wstring wusername(username.begin(), username.end());
  std::wstring wpassword(password.begin(), password.end());
  std::wstring wdomain(domain.begin(), domain.end());

  int ret = internal::LogonAndUnlockDesktop(wusername, wdomain, wpassword);
  rep["result"] = ret == 0 ? "ok" : "fail";

  return true;
}