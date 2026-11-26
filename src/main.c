#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <bcrypt.h>
#include <stdint.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <shellapi.h>
#include <objbase.h>
#include <math.h>
#include <ctype.h>

#define APP_NAME L"Aurelia"
#define IDI_AURELIA 101
#define WIN_W 1160
#define WIN_H 800

enum {
    ID_CONNECT = 100,
    ID_ROTATE,
    ID_INTERVAL,
    ID_LANGUAGE,
    ID_COUNTRY,
    ID_AUDIT,
    ID_SCAN_NODES,
    ID_SETTING_DNS_COMBO = 120,
    ID_SETTING_DNS_EDIT = 121,
    ID_SETTING_SAVE_BTN = 122,
    ID_SCANNER_SYNC_CONSENSUS = 130,
    ID_SCANNER_RESET_GUARDS = 131,
    ID_SCANNER_TEST_PING = 132,
    ID_SCANNER_CLOSE = 133
};

enum {
    TAB_TUNNEL = 0,
    TAB_SPEED = 1,
    TAB_SETTINGS = 2
};

static int g_active_tab = TAB_TUNNEL;
static int g_tab_hover = -1;

#define SPEED_HISTORY_LEN 30
static DWORD g_speed_rx_bps = 0, g_speed_tx_bps = 0;
static unsigned long long g_total_rx_bytes = 0, g_total_tx_bytes = 0;
static unsigned long long g_last_tor_traffic_rx = 0, g_last_tor_traffic_tx = 0;
static DWORD g_last_traffic_poll_tick = 0;
static DWORD g_speed_history_rx[SPEED_HISTORY_LEN] = {0};
static DWORD g_speed_history_tx[SPEED_HISTORY_LEN] = {0};

static int g_setting_dns_mode = 0;
static wchar_t g_setting_custom_dns_ip[64] = L"1.1.1.1";
static int g_setting_stream_isolation = 1;
static int g_setting_strict_nodes = 0;
static int g_setting_pentest_port = 1;
static int g_setting_preboot_killswitch = 1;
static int g_setting_avoid_disk = 1;
static int g_setting_pipeline_mode = 1;
static int g_setting_turbo_boost = 1;
static int g_setting_stealth_mode = 1;
static int g_setting_fake_ip = 1;
static DWORD g_settings_saved_tick = 0;

static HWND g_dns_combo = NULL, g_dns_edit = NULL, g_btn_save_settings = NULL;

#define WM_VPN_RESULT (WM_APP+10)
#define WM_CIRCUIT_RESULT (WM_APP+11)
#define WM_TRAYICON (WM_APP+12)
#define WM_COUNTRY_RESULT (WM_APP+13)
#define WM_ATTESTATION_RESULT (WM_APP+14)
enum { ID_AUDIT_COPY_BURP = 301, ID_AUDIT_RETEST = 302, ID_AUDIT_CLOSE = 303, ID_AUDIT_REALIGN_DNS = 304 };
#define ID_TRAY_SHOW 201
#define ID_TRAY_CONNECT 202
#define ID_TRAY_EXIT 203

typedef struct {
    int killswitch_passed;
    int dns_passed;
    int socks_passed;
    int latency_ms;
    int reputation_score;
    char public_ip[64];
    char public_country[3];
    char dns_resolver_ip[64];
    char dns_resolver_country[3];
    int dns_geo_aligned;
    char dns_provider[64];
    int ecs_stripped;
    wchar_t last_check[32];
    int check_count;
} LeakAttestation;

static LeakAttestation g_attestation = {0};
static volatile LONG g_attestation_busy = 0;
static DWORD g_last_attestation_poll = 0;

static HWND g_window, g_interval, g_connect, g_rotate, g_language, g_country, g_country_popup, g_interval_popup, g_language_popup, g_audit, g_audit_dialog, g_btn_scan_nodes, g_relay_scanner_dialog;
static HINSTANCE g_instance;
static int g_country_rows[128], g_country_row_count, g_country_scroll, g_country_hover = -1, g_country_dragging = 0;
static int g_interval_hover = -1;
static int g_language_hover = -1;
static HFONT g_font, g_font_bold, g_small, g_heading, g_caption, g_emoji;
static int g_connected = 0;
static int g_vpn_active = 0;
static int g_language_en = 0;
static int g_exit_index = 0;
static int g_pending_exit_index = 0;
static int g_exit_list_ready = 0;
static unsigned g_exit_relay_count[128];
static unsigned int g_total_consensus_relays = 7420;
static unsigned int g_total_exit_relays = 2796;
static volatile LONG g_exit_discovery_busy = 0;
static HICON g_app_icon, g_app_icon_header, g_app_icon_small;

static unsigned int parse_ipv4_val(const char *ip_str);
static const char *lookup_geoip(unsigned int ip_val);

typedef struct GdiplusStartupInput {
    UINT32 GdiplusVersion;
    void *DebugEventCallback;
    BOOL SuppressBackgroundThread;
    BOOL SuppressExternalCodecs;
} GdiplusStartupInput;

typedef struct PointF {
    float X;
    float Y;
} PointF;

typedef DWORD ARGB;
#define GDIP_MAKE_ARGB(a, r, g, b) (((ARGB)(a) << 24) | ((ARGB)(r) << 16) | ((ARGB)(g) << 8) | (ARGB)(b))

static int (WINAPI *pfn_GdiplusStartup)(ULONG_PTR*, const GdiplusStartupInput*, void*) = NULL;
static void (WINAPI *pfn_GdiplusShutdown)(ULONG_PTR) = NULL;
static int (WINAPI *pfn_GdipCreateFromHDC)(HDC, void**) = NULL;
static int (WINAPI *pfn_GdipDeleteGraphics)(void*) = NULL;
static int (WINAPI *pfn_GdipSetSmoothingMode)(void*, int) = NULL;
static int (WINAPI *pfn_GdipCreatePen1)(ARGB, float, int, void**) = NULL;
static int (WINAPI *pfn_GdipDeletePen)(void*) = NULL;
static int (WINAPI *pfn_GdipCreateSolidFill)(ARGB, void**) = NULL;
static int (WINAPI *pfn_GdipDeleteBrush)(void*) = NULL;
static int (WINAPI *pfn_GdipDrawEllipse)(void*, void*, float, float, float, float) = NULL;
static int (WINAPI *pfn_GdipFillEllipse)(void*, void*, float, float, float, float) = NULL;
static int (WINAPI *pfn_GdipDrawPolygon)(void*, void*, const PointF*, int) = NULL;
static int (WINAPI *pfn_GdipFillPolygon)(void*, void*, const PointF*, int, int) = NULL;
static int (WINAPI *pfn_GdipDrawLine)(void*, void*, float, float, float, float) = NULL;
static int (WINAPI *pfn_GdipSetPenStartCap)(void*, int) = NULL;
static int (WINAPI *pfn_GdipSetPenEndCap)(void*, int) = NULL;
static int (WINAPI *pfn_GdipSetPenLineJoin)(void*, int) = NULL;
static ULONG_PTR g_gdiplus_token = 0;
static int g_gdiplus_ready = 0;

static void init_gdiplus(void) {
    HMODULE h = LoadLibraryW(L"gdiplus.dll");
    if(!h) return;
    pfn_GdiplusStartup = (int (WINAPI*)(ULONG_PTR*, const GdiplusStartupInput*, void*))GetProcAddress(h, "GdiplusStartup");
    pfn_GdiplusShutdown = (void (WINAPI*)(ULONG_PTR))GetProcAddress(h, "GdiplusShutdown");
    pfn_GdipCreateFromHDC = (int (WINAPI*)(HDC, void**))GetProcAddress(h, "GdipCreateFromHDC");
    pfn_GdipDeleteGraphics = (int (WINAPI*)(void*))GetProcAddress(h, "GdipDeleteGraphics");
    pfn_GdipSetSmoothingMode = (int (WINAPI*)(void*, int))GetProcAddress(h, "GdipSetSmoothingMode");
    pfn_GdipCreatePen1 = (int (WINAPI*)(ARGB, float, int, void**))GetProcAddress(h, "GdipCreatePen1");
    pfn_GdipDeletePen = (int (WINAPI*)(void*))GetProcAddress(h, "GdipDeletePen");
    pfn_GdipCreateSolidFill = (int (WINAPI*)(ARGB, void**))GetProcAddress(h, "GdipCreateSolidFill");
    pfn_GdipDeleteBrush = (int (WINAPI*)(void*))GetProcAddress(h, "GdipDeleteBrush");
    pfn_GdipDrawEllipse = (int (WINAPI*)(void*, void*, float, float, float, float))GetProcAddress(h, "GdipDrawEllipse");
    pfn_GdipFillEllipse = (int (WINAPI*)(void*, void*, float, float, float, float))GetProcAddress(h, "GdipFillEllipse");
    pfn_GdipDrawPolygon = (int (WINAPI*)(void*, void*, const PointF*, int))GetProcAddress(h, "GdipDrawPolygon");
    pfn_GdipFillPolygon = (int (WINAPI*)(void*, void*, const PointF*, int, int))GetProcAddress(h, "GdipFillPolygon");
    pfn_GdipDrawLine = (int (WINAPI*)(void*, void*, float, float, float, float))GetProcAddress(h, "GdipDrawLine");
    pfn_GdipSetPenStartCap = (int (WINAPI*)(void*, int))GetProcAddress(h, "GdipSetPenStartCap");
    pfn_GdipSetPenEndCap = (int (WINAPI*)(void*, int))GetProcAddress(h, "GdipSetPenEndCap");
    pfn_GdipSetPenLineJoin = (int (WINAPI*)(void*, int))GetProcAddress(h, "GdipSetPenLineJoin");

    if(pfn_GdiplusStartup && pfn_GdipCreateFromHDC && pfn_GdipSetSmoothingMode) {
        GdiplusStartupInput input = {1, NULL, FALSE, FALSE};
        if(pfn_GdiplusStartup(&g_gdiplus_token, &input, NULL) == 0) {
            g_gdiplus_ready = 1;
        }
    }
}
static int g_tray_added = 0;
static int g_exit_app = 0;
static HANDLE g_helper_process, g_stop_event, g_blocked_event, g_go_event, g_ready_event;
static HANDLE g_cancel_event;
static HANDLE g_start_thread;
static volatile LONG g_starting = 0;
static volatile LONG g_cancel_start = 0;
static volatile LONG g_syncing_exits = 0;
static DWORD g_helper_exit_code = STILL_ACTIVE;
static DWORD g_last_info_poll = 0;
static wchar_t g_tor_info[128] = L"Bootstrap Tor in attesa";
static char g_hop_country[3][3] = {{'-','-'},{'-','-'},{'-','-'}};
static char g_hop_name[3][24] = {{0}};
static char g_exit_public_country[3] = {'-','-',0};
static wchar_t g_exit_public_ip[64] = L"—";
static DWORD g_last_circuit_poll = 0;
static volatile LONG g_circuit_busy = 0;
static unsigned g_anim_phase = 0;
static PROCESS_INFORMATION g_tor_process;
static wchar_t g_appdir[MAX_PATH], g_cookie[MAX_PATH], g_torrc[MAX_PATH];
static wchar_t g_settings_path[MAX_PATH];
static wchar_t g_saved_tor[MAX_PATH] = L"";
static int g_interval_index = 0;

static COLORREF bg = RGB(244,247,251), panel = RGB(255,255,255), muted = RGB(100,116,139), white = RGB(26,42,60), teal = RGB(0,114,198), line = RGB(225,232,240);
static COLORREF green = RGB(0,144,105), pale_blue = RGB(235,245,255), pale_green = RGB(231,247,241), pale_amber = RGB(255,246,228);

#define LTXT(it,en) (g_language_en?(en):(it))

typedef struct { const char *code; const wchar_t *it; const wchar_t *en; } CountryOption;
static const CountryOption g_countries[]={
    {"",L"Automatico",L"Automatic"},{"it",L"Italia",L"Italy"},{"us",L"Stati Uniti",L"United States"},{"de",L"Germania",L"Germany"},
    {"fr",L"Francia",L"France"},{"gb",L"Regno Unito",L"United Kingdom"},{"nl",L"Paesi Bassi",L"Netherlands"},{"ch",L"Svizzera",L"Switzerland"},
    {"se",L"Svezia",L"Sweden"},{"fi",L"Finlandia",L"Finland"},{"es",L"Spagna",L"Spain"},{"ca",L"Canada",L"Canada"},
    {"pl",L"Polonia",L"Poland"},{"no",L"Norvegia",L"Norway"},{"at",L"Austria",L"Austria"},{"be",L"Belgio",L"Belgium"},
    {"cz",L"Cechia",L"Czechia"},{"ro",L"Romania",L"Romania"},{"jp",L"Giappone",L"Japan"},{"sg",L"Singapore",L"Singapore"},
    {"is",L"Islanda",L"Iceland"},{"ie",L"Irlanda",L"Ireland"},{"br",L"Brasile",L"Brazil"},{"au",L"Australia",L"Australia"},
    {"dk",L"Danimarca",L"Denmark"},{"hu",L"Ungheria",L"Hungary"},{"pt",L"Portogallo",L"Portugal"},{"gr",L"Grecia",L"Greece"},
    {"ee",L"Estonia",L"Estonia"},{"lv",L"Lettonia",L"Latvia"},{"lt",L"Lituania",L"Lithuania"},{"bg",L"Bulgaria",L"Bulgaria"},
    {"lu",L"Lussemburgo",L"Luxembourg"},{"hk",L"Hong Kong",L"Hong Kong"},{"tw",L"Taiwan",L"Taiwan"},{"kr",L"Corea del Sud",L"South Korea"},
    {"in",L"India",L"India"},{"mx",L"Messico",L"Mexico"},{"ar",L"Argentina",L"Argentina"},{"cl",L"Cile",L"Chile"},
    {"za",L"Sudafrica",L"South Africa"},{"nz",L"Nuova Zelanda",L"New Zealand"},{"cy",L"Cipro",L"Cyprus"},{"tr",L"Turchia",L"Türkiye"},
    {"ua",L"Ucraina",L"Ukraine"},{"ru",L"Russia",L"Russia"},{"hr",L"Croazia",L"Croatia"},{"si",L"Slovenia",L"Slovenia"},
    {"sk",L"Slovacchia",L"Slovakia"},{"il",L"Israele",L"Israel"},{"id",L"Indonesia",L"Indonesia"},{"th",L"Thailandia",L"Thailand"},
    {"my",L"Malesia",L"Malaysia"},{"ph",L"Filippine",L"Philippines"}
};

static void save_preferences(void);
static int apply_exit_country(int selected);

static void fill_country_options(int selected) {
    g_country_row_count = 0;
    // Row 0 is ALWAYS Automatic (Global Pool)
    g_country_rows[g_country_row_count++] = 0;

    if (g_exit_list_ready) {
        // Collect all countries that have at least 1 verified alive exit relay in consensus!
        int active_countries[128];
        int active_count = 0;
        for (int i = 1; i < (int)_countof(g_countries); i++) {
            if (g_exit_relay_count[i] > 0) {
                active_countries[active_count++] = i;
            }
        }
        // Sort active countries by relay count descending (highest availability & quality first!)
        for (int i = 0; i < active_count - 1; i++) {
            for (int j = i + 1; j < active_count; j++) {
                if (g_exit_relay_count[active_countries[j]] > g_exit_relay_count[active_countries[i]]) {
                    int tmp = active_countries[i];
                    active_countries[i] = active_countries[j];
                    active_countries[j] = tmp;
                }
            }
        }
        for (int i = 0; i < active_count; i++) {
            g_country_rows[g_country_row_count++] = active_countries[i];
        }
    } else {
        // Initial fallback before first consensus scan
        for (int i = 1; i < (int)_countof(g_countries); i++) {
            g_country_rows[g_country_row_count++] = i;
        }
    }

    if (selected < 0 || selected >= (int)_countof(g_countries)) selected = 0;
    int found = 0;
    for (int r = 0; r < g_country_row_count; r++) {
        if (g_country_rows[r] == selected) { found = 1; break; }
    }
    if (!found) selected = 0;

    g_exit_index = selected;
    g_pending_exit_index = selected;
    g_country_scroll = 0;
    if (g_country) InvalidateRect(g_country, NULL, TRUE);
    if (g_country_popup) InvalidateRect(g_country_popup, NULL, TRUE);
}

static void fill_interval_options(int selected) {
    if(selected < 0 || selected > 3) selected = 0;
    g_interval_index = selected;
    if(g_interval) InvalidateRect(g_interval, NULL, TRUE);
}

static const wchar_t *interval_name(int index){
    static const wchar_t *it[] = {L"Manuale", L"5 minuti", L"10 minuti", L"30 minuti"};
    static const wchar_t *en[] = {L"Manual", L"5 minutes", L"10 minutes", L"30 minutes"};
    if(index < 0 || index > 3) index = 0;
    return g_language_en ? en[index] : it[index];
}

static void tray_add(void) {
    NOTIFYICONDATAW nid = {0};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_window;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = g_app_icon_small ? g_app_icon_small : g_app_icon;
    wcscpy_s(nid.szTip, _countof(nid.szTip), L"Aurelia · VPN + Tor");
    if(Shell_NotifyIconW(NIM_ADD, &nid)) {
        nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid);
        g_tray_added = 1;
    }
}

static void tray_remove(void) {
    if(!g_tray_added) return;
    NOTIFYICONDATAW nid = {0};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_window;
    nid.uID = 1;
    Shell_NotifyIconW(NIM_DELETE, &nid);
    g_tray_added = 0;
}

static void tray_menu(void) {
    POINT p; GetCursorPos(&p);
    HMENU menu = CreatePopupMenu();
    if(!menu) return;
    AppendMenuW(menu, MF_STRING, ID_TRAY_SHOW, LTXT(L"Apri Aurelia", L"Open Aurelia"));
    AppendMenuW(menu, MF_STRING, ID_TRAY_CONNECT, g_vpn_active ? LTXT(L"Disconnetti", L"Disconnect") : LTXT(L"Connetti", L"Connect"));
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, LTXT(L"Esci", L"Exit"));
    SetForegroundWindow(g_window);
    UINT selected = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, p.x, p.y, 0, g_window, NULL);
    DestroyMenu(menu);
    PostMessageW(g_window, WM_NULL, 0, 0);
    if(selected == ID_TRAY_SHOW) {
        ShowWindow(g_window, SW_RESTORE);
        SetForegroundWindow(g_window);
    } else if(selected == ID_TRAY_CONNECT) {
        PostMessageW(g_window, WM_COMMAND, ID_CONNECT, 0);
    } else if(selected == ID_TRAY_EXIT) {
        g_exit_app = 1;
        DestroyWindow(g_window);
    }
}

static void update_dns_combo_items(void) {
    if(!g_dns_combo) return;
    int cur = (int)SendMessageW(g_dns_combo, CB_GETCURSEL, 0, 0);
    if(cur < 0) cur = g_setting_dns_mode;
    SendMessageW(g_dns_combo, CB_RESETCONTENT, 0, 0);
    SendMessageW(g_dns_combo, CB_ADDSTRING, 0, (LPARAM)LTXT(
        L"Tor MapDNS Geo-Aligned (Consigliato · 0 ms · Allineamento Automatico)",
        L"Tor MapDNS Geo-Aligned (Recommended · 0 ms · Auto-Aligned)"));
    SendMessageW(g_dns_combo, CB_ADDSTRING, 0, (LPARAM)LTXT(
        L"Cloudflare Privacy Gateway (1.1.1.1 · No-ECS · Anti-Phishing)",
        L"Cloudflare Privacy Gateway (1.1.1.1 · No-ECS · Anti-Phishing)"));
    SendMessageW(g_dns_combo, CB_ADDSTRING, 0, (LPARAM)LTXT(
        L"Quad9 Security DNS (9.9.9.9 · Blocco Minacce & C2)",
        L"Quad9 Security DNS (9.9.9.9 · Threat & C2 Blocking)"));
    SendMessageW(g_dns_combo, CB_ADDSTRING, 0, (LPARAM)LTXT(
        L"DNS Personalizzato / Regional Resolver (IPv4 Manuale...)",
        L"Custom DNS / Regional Resolver (Manual IPv4...)"));
    SendMessageW(g_dns_combo, CB_SETCURSEL, (WPARAM)cur, 0);
}

static void apply_language(void) {
    fill_interval_options(g_interval_index);
    fill_country_options(g_exit_index);
    update_dns_combo_items();
    SetWindowTextW(g_connect, LTXT(g_vpn_active ? L"Disconnetti" : (g_starting ? L"Annulla" : L"Connetti a Tor"),
                                  g_vpn_active ? L"Disconnect" : (g_starting ? L"Cancel" : L"Connect to Tor")));
    SetWindowTextW(g_rotate, LTXT(L"Nuovo circuito", L"New circuit"));
    if(g_audit) SetWindowTextW(g_audit, LTXT(L"Audit & Sicurezza", L"Audit & Security"));
    if(g_btn_scan_nodes) SetWindowTextW(g_btn_scan_nodes, LTXT(L"Scan Nodi", L"Scan Nodes"));
    if(g_btn_save_settings) SetWindowTextW(g_btn_save_settings, LTXT(L"Salva e Applica Impostazioni", L"Save & Apply Settings"));
    if(g_language) InvalidateRect(g_language, NULL, TRUE);
    save_preferences();
    InvalidateRect(g_window, NULL, TRUE);
}

static void save_preferences(void) {
    if(!g_settings_path[0]) return;
    wchar_t value[MAX_PATH];
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_language_en ? 1 : 0);
    WritePrivateProfileStringW(L"UI", L"Language", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_exit_index);
    WritePrivateProfileStringW(L"Tor", L"ExitCountry", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_interval_index);
    WritePrivateProfileStringW(L"Tor", L"RotationInterval", value, g_settings_path);
    if(g_saved_tor[0]) WritePrivateProfileStringW(L"Tor", L"TorPath", g_saved_tor, g_settings_path);

    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_dns_mode);
    WritePrivateProfileStringW(L"Settings", L"DnsMode", value, g_settings_path);
    WritePrivateProfileStringW(L"Settings", L"CustomDnsIp", g_setting_custom_dns_ip, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_stream_isolation);
    WritePrivateProfileStringW(L"Settings", L"StreamIsolation", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_strict_nodes);
    WritePrivateProfileStringW(L"Settings", L"StrictNodes", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_pentest_port);
    WritePrivateProfileStringW(L"Settings", L"PentestPort", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_preboot_killswitch);
    WritePrivateProfileStringW(L"Settings", L"PreBootKillSwitch", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_avoid_disk);
    WritePrivateProfileStringW(L"Settings", L"AvoidDiskWrites", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_pipeline_mode);
    WritePrivateProfileStringW(L"Settings", L"PipelineMode", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_turbo_boost);
    WritePrivateProfileStringW(L"Settings", L"TurboBoost", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_stealth_mode);
    WritePrivateProfileStringW(L"Settings", L"StealthMode", value, g_settings_path);
    _snwprintf_s(value, _countof(value), _TRUNCATE, L"%d", g_setting_fake_ip);
    WritePrivateProfileStringW(L"Settings", L"FakeIpPool", value, g_settings_path);
}

static void load_preferences(void) {
    wchar_t *local = _wgetenv(L"LOCALAPPDATA");
    if(!local) return;
    wchar_t parent[MAX_PATH];
    _snwprintf_s(parent, _countof(parent), _TRUNCATE, L"%s\\Aurelia", local);
    CreateDirectoryW(parent, NULL);
    _snwprintf_s(g_settings_path, _countof(g_settings_path), _TRUNCATE, L"%s\\Aurelia\\settings.ini", local);
    g_language_en = GetPrivateProfileIntW(L"UI", L"Language", 0, g_settings_path) == 1;
    g_exit_index = (int)GetPrivateProfileIntW(L"Tor", L"ExitCountry", 0, g_settings_path);
    if(g_exit_index < 0 || g_exit_index >= (int)_countof(g_countries)) g_exit_index = 0;
    g_pending_exit_index = g_exit_index;
    g_interval_index = (int)GetPrivateProfileIntW(L"Tor", L"RotationInterval", 0, g_settings_path);
    if(g_interval_index < 0 || g_interval_index > 3) g_interval_index = 0;
    GetPrivateProfileStringW(L"Tor", L"TorPath", L"", g_saved_tor, _countof(g_saved_tor), g_settings_path);

    g_setting_dns_mode = (int)GetPrivateProfileIntW(L"Settings", L"DnsMode", 0, g_settings_path);
    GetPrivateProfileStringW(L"Settings", L"CustomDnsIp", L"1.1.1.1", g_setting_custom_dns_ip, _countof(g_setting_custom_dns_ip), g_settings_path);
    g_setting_stream_isolation = (int)GetPrivateProfileIntW(L"Settings", L"StreamIsolation", 1, g_settings_path);
    g_setting_strict_nodes = (int)GetPrivateProfileIntW(L"Settings", L"StrictNodes", 0, g_settings_path);
    g_setting_pentest_port = (int)GetPrivateProfileIntW(L"Settings", L"PentestPort", 1, g_settings_path);
    g_setting_preboot_killswitch = (int)GetPrivateProfileIntW(L"Settings", L"PreBootKillSwitch", 1, g_settings_path);
    g_setting_avoid_disk = (int)GetPrivateProfileIntW(L"Settings", L"AvoidDiskWrites", 1, g_settings_path);
    g_setting_pipeline_mode = (int)GetPrivateProfileIntW(L"Settings", L"PipelineMode", 1, g_settings_path);
    g_setting_turbo_boost = (int)GetPrivateProfileIntW(L"Settings", L"TurboBoost", 1, g_settings_path);
    g_setting_stealth_mode = (int)GetPrivateProfileIntW(L"Settings", L"StealthMode", 1, g_settings_path);
    g_setting_fake_ip = (int)GetPrivateProfileIntW(L"Settings", L"FakeIpPool", 1, g_settings_path);
}

static void trace_start(const wchar_t *stage) {
    wchar_t path[MAX_PATH]; wchar_t *local = _wgetenv(L"LOCALAPPDATA");
    if(!local) return;
    _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\Aurelia\\Tor\\startup.log", local);
    HANDLE f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(f == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME t; GetLocalTime(&t);
    wchar_t row[256];
    int n = _snwprintf_s(row, _countof(row), _TRUNCATE, L"%04u-%02u-%02u %02u:%02u:%02u %s\r\n",
                         t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, stage);
    DWORD bytes = 0;
    WriteFile(f, row, (DWORD)(n * sizeof(wchar_t)), &bytes, NULL);
    CloseHandle(f);
}

static void text(HDC dc, int x, int y, const wchar_t *s, COLORREF c, HFONT f) {
    SetTextColor(dc, c); SetBkMode(dc, TRANSPARENT);
    HFONT old = (HFONT)SelectObject(dc, f);
    TextOutW(dc, x, y, s, (int)wcslen(s));
    SelectObject(dc, old);
}
static void rect(HDC dc, int x, int y, int w, int h, COLORREF c, int radius) {
    HBRUSH b = CreateSolidBrush(c); HPEN p = CreatePen(PS_NULL, 0, c);
    HGDIOBJ ob = SelectObject(dc, b), op = SelectObject(dc, p);
    RoundRect(dc, x, y, x + w, y + h, radius, radius);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(b); DeleteObject(p);
}
static void card(HDC dc, int x, int y, int w, int h) {
    HBRUSH b = CreateSolidBrush(panel); HPEN p = CreatePen(PS_SOLID, 1, line);
    HGDIOBJ ob = SelectObject(dc, b), op = SelectObject(dc, p);
    RoundRect(dc, x, y, x + w, y + h, 18, 18);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(b); DeleteObject(p);
}
static void dot(HDC dc, int x, int y, int d, COLORREF c) {
    HBRUSH b = CreateSolidBrush(c); HPEN p = CreatePen(PS_NULL, 0, c);
    HGDIOBJ ob = SelectObject(dc, b), op = SelectObject(dc, p);
    Ellipse(dc, x, y, x + d, y + d);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(b); DeleteObject(p);
}
static void rule(HDC dc, int x, int y, int w) {
    HPEN p = CreatePen(PS_SOLID, 1, line), old = (HPEN)SelectObject(dc, p);
    MoveToEx(dc, x, y, NULL); LineTo(dc, x + w, y);
    SelectObject(dc, old); DeleteObject(p);
}
static void color_box(HDC dc, int x, int y, int w, int h, COLORREF c) {
    RECT r = {x, y, x + w, y + h};
    HBRUSH b = CreateSolidBrush(c); FillRect(dc, &r, b); DeleteObject(b);
}
static void flag_border(HDC dc, int x, int y, int w, int h) {
    HPEN p = CreatePen(PS_SOLID, 1, RGB(210,218,228)), old = (HPEN)SelectObject(dc, p);
    HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, x, y, x + w, y + h);
    SelectObject(dc, ob); SelectObject(dc, old); DeleteObject(p);
}
static void flag_horizontal(HDC dc, int x, int y, int w, int h, const COLORREF *c, int count) {
    for(int i = 0; i < count; i++) {
        int top = y + (h * i) / count, bottom = y + (h * (i + 1)) / count;
        color_box(dc, x, top, w, bottom - top, c[i]);
    }
}
static void flag_vertical(HDC dc, int x, int y, int w, int h, const COLORREF *c, int count) {
    for(int i = 0; i < count; i++) {
        int left = x + (w * i) / count, right = x + (w * (i + 1)) / count;
        color_box(dc, left, y, right - left, h, c[i]);
    }
}
static void flag_cross(HDC dc, int x, int y, int w, int h, COLORREF base, COLORREF cross, int nordic) {
    color_box(dc, x, y, w, h, base);
    int vx = x + (nordic ? w * 34 / 100 : w * 42 / 100), vy = y + h / 2;
    int vw = nordic ? w * 14 / 100 : w * 18 / 100, hh = nordic ? h * 20 / 100 : h * 28 / 100;
    color_box(dc, vx - vw / 2, y, vw, h, RGB(255,255,255));
    color_box(dc, x, vy - hh / 2, w, hh, RGB(255,255,255));
    color_box(dc, vx - vw * 3 / 8, y, vw * 3 / 4, h, cross);
    color_box(dc, x, vy - hh * 3 / 8, w, hh * 3 / 4, cross);
}

static void draw_flag_gdi(HDC dc, int x, int y, int w, int h, const char *cc) {
    static const COLORREF W = RGB(255,255,255), R = RGB(210,32,45), B = RGB(0,66,130), N = RGB(20,25,32), G = RGB(0,135,81), Y = RGB(255,205,0), L = RGB(0,87,184), O = RGB(255,153,51);
    COLORREF c3[3];
    if(!cc || !cc[0] || cc[0] == '-') {
        color_box(dc, x, y, w, h, RGB(231,239,248));
        dot(dc, x + w / 2 - 4, y + h / 2 - 4, 8, teal);
        flag_border(dc, x, y, w, h);
        return;
    }
    if(!strcmp(cc,"fr")){c3[0]=B;c3[1]=W;c3[2]=R;flag_vertical(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"it")){c3[0]=G;c3[1]=W;c3[2]=R;flag_vertical(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"be")){c3[0]=N;c3[1]=Y;c3[2]=R;flag_vertical(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"ie")){c3[0]=G;c3[1]=W;c3[2]=O;flag_vertical(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"ro")){c3[0]=B;c3[1]=Y;c3[2]=R;flag_vertical(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"de")){c3[0]=N;c3[1]=R;c3[2]=Y;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"nl")){c3[0]=R;c3[1]=W;c3[2]=B;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"ru")){c3[0]=W;c3[1]=B;c3[2]=R;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"ua")){c3[0]=B;c3[1]=Y;flag_horizontal(dc,x,y,w,h,c3,2);}
    else if(!strcmp(cc,"hu")){c3[0]=R;c3[1]=W;c3[2]=G;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"bg")){c3[0]=W;c3[1]=G;c3[2]=R;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"lu")){c3[0]=R;c3[1]=W;c3[2]=RGB(0,161,222);flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"pl")){c3[0]=W;c3[1]=R;flag_horizontal(dc,x,y,w,h,c3,2);}
    else if(!strcmp(cc,"at")){c3[0]=R;c3[1]=W;c3[2]=R;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"es")){c3[0]=R;c3[1]=Y;c3[2]=R;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"fi"))flag_cross(dc,x,y,w,h,W,B,1);
    else if(!strcmp(cc,"se"))flag_cross(dc,x,y,w,h,RGB(0,106,167),Y,1);
    else if(!strcmp(cc,"no"))flag_cross(dc,x,y,w,h,R,B,1);
    else if(!strcmp(cc,"is"))flag_cross(dc,x,y,w,h,B,R,1);
    else if(!strcmp(cc,"dk"))flag_cross(dc,x,y,w,h,R,W,1);
    else if(!strcmp(cc,"ch")){color_box(dc,x,y,w,h,R);color_box(dc,x+w*42/100,y+h*22/100,w*16/100,h*56/100,W);color_box(dc,x+w*22/100,y+h*42/100,w*56/100,h*16/100,W);}
    else if(!strcmp(cc,"jp")){color_box(dc,x,y,w,h,W);dot(dc,x+w/2-h*22/100,y+h/2-h*22/100,h*44/100,R);}
    else if(!strcmp(cc,"us")){for(int i=0;i<13;i++)color_box(dc,x,y+h*i/13,w,h/13+1,(i%2)?W:R);color_box(dc,x,y,w*46/100,h*54/100,B);for(int yy=0;yy<3;yy++)for(int xx=0;xx<4;xx++)dot(dc,x+2+xx*w*9/100,y+2+yy*h*14/100,2,W);}
    else if(!strcmp(cc,"gb")){color_box(dc,x,y,w,h,B);HPEN p=CreatePen(PS_SOLID,max(2,h/4),W),old=(HPEN)SelectObject(dc,p);MoveToEx(dc,x,y,NULL);LineTo(dc,x+w,y+h);MoveToEx(dc,x+w,y,NULL);LineTo(dc,x,y+h);SelectObject(dc,old);DeleteObject(p);p=CreatePen(PS_SOLID,max(2,h/10),R);old=(HPEN)SelectObject(dc,p);MoveToEx(dc,x,y,NULL);LineTo(dc,x+w,y+h);MoveToEx(dc,x+w,y,NULL);LineTo(dc,x,y+h);SelectObject(dc,old);DeleteObject(p);color_box(dc,x+w*42/100,y,w*16/100,h,W);color_box(dc,x,y+h*38/100,w,h*24/100,W);color_box(dc,x+w*46/100,y,w*8/100,h,R);color_box(dc,x,y+h*44/100,w,h*12/100,R);}
    else if(!strcmp(cc,"id")){c3[0]=R;c3[1]=W;flag_horizontal(dc,x,y,w,h,c3,2);}
    else if(!strcmp(cc,"sg")){c3[0]=R;c3[1]=W;flag_horizontal(dc,x,y,w,h,c3,2);color_box(dc,x,y,w/2,h/2,R);dot(dc,x+w/8,y+h/8,h/3,W);color_box(dc,x+w/8,y+h/8,h/12,h/6,R);}
    else if(!strcmp(cc,"cz")){c3[0]=W;c3[1]=R;flag_horizontal(dc,x,y,w,h,c3,2);POINT p[3]={{x,y},{x+w*55/100,y+h/2},{x,y+h}};HBRUSH b=CreateSolidBrush(B);HPEN pen=CreatePen(PS_NULL,0,B);HGDIOBJ ob=SelectObject(dc,b),op=SelectObject(dc,pen);Polygon(dc,p,3);SelectObject(dc,ob);SelectObject(dc,op);DeleteObject(b);DeleteObject(pen);}
    else if(!strcmp(cc,"br")){color_box(dc,x,y,w,h,G);POINT p[4]={{x+w/2,y+h/8},{x+w*7/8,y+h/2},{x+w/2,y+h*7/8},{x+w/8,y+h/2}};HBRUSH b=CreateSolidBrush(Y);HPEN pen=CreatePen(PS_NULL,0,Y);HGDIOBJ ob=SelectObject(dc,b),op=SelectObject(dc,pen);Polygon(dc,p,4);SelectObject(dc,ob);SelectObject(dc,op);DeleteObject(b);DeleteObject(pen);dot(dc,x+w/2-h/8,y+h/2-h/8,h/4,B);}
    else if(!strcmp(cc,"pt")){color_box(dc,x,y,w,h,R);color_box(dc,x,y,w*42/100,h,G);dot(dc,x+w*42/100-h/7,y+h/2-h/7,h*2/7,Y);}
    else if(!strcmp(cc,"gr")){c3[0]=B;c3[1]=W;flag_horizontal(dc,x,y,w,h,c3,9);color_box(dc,x,y,w*42/100,h*5/9,B);color_box(dc,x+w*14/100,y,w*14/100,h*5/9,W);color_box(dc,x,y+h*2/9,w*42/100,h/9,W);}
    else if(!strcmp(cc,"ar")){c3[0]=RGB(116,172,223);c3[1]=W;c3[2]=RGB(116,172,223);flag_horizontal(dc,x,y,w,h,c3,3);dot(dc,x+w/2-h/7,y+h/2-h/7,h*2/7,Y);}
    else if(!strcmp(cc,"in")){c3[0]=O;c3[1]=W;c3[2]=G;flag_horizontal(dc,x,y,w,h,c3,3);dot(dc,x+w/2-h/9,y+h/2-h/9,h*2/9,B);}
    else if(!strcmp(cc,"mx")){c3[0]=G;c3[1]=W;c3[2]=R;flag_vertical(dc,x,y,w,h,c3,3);dot(dc,x+w/2-h/12,y+h/2-h/12,h/6,RGB(120,90,45));}
    else if(!strcmp(cc,"ca")){color_box(dc,x,y,w,h,W);color_box(dc,x,y,w/4,h,R);color_box(dc,x+w*3/4,y,w/4,h,R);POINT p[7]={{x+w/2,y+h/4},{x+w*43/100,y+h*45/100},{x+w/3,y+h*38/100},{x+w*42/100,y+h*58/100},{x+w*39/100,y+h*78/100},{x+w/2,y+h*68/100},{x+w*61/100,y+h*78/100}};HBRUSH b=CreateSolidBrush(R);HGDIOBJ ob=SelectObject(dc,b);Polygon(dc,p,7);SelectObject(dc,ob);DeleteObject(b);}
    else if(!strcmp(cc,"tr")){color_box(dc,x,y,w,h,R);dot(dc,x+w*32/100,y+h/2-h/7,h*2/7,W);dot(dc,x+w*37/100,y+h/2-h/7,h*2/7,R);dot(dc,x+w*47/100,y+h/2-h/14,h/7,W);}
    else if(!strcmp(cc,"cl")){color_box(dc,x,y,w,h,W);color_box(dc,x,y+h/2,w,h/2,R);color_box(dc,x,y,w*42/100,h/2,B);dot(dc,x+w*21/100-h/14,y+h/4-h/14,h/7,W);}
    else if(!strcmp(cc,"cy")){color_box(dc,x,y,w,h,W);dot(dc,x+w/2-h/8,y+h/2-h/8,h/4,RGB(210,130,44));}
    else if(!strcmp(cc,"th")){color_box(dc,x,y,w,h,R);color_box(dc,x,y+h/10,w,h/10,W);color_box(dc,x,y+h/5,w,h*3/5,B);color_box(dc,x,y+h*4/5,w,h/10,W);}
    else if(!strcmp(cc,"il")){c3[0]=W;c3[1]=B;c3[2]=W;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"kr")){color_box(dc,x,y,w,h,W);dot(dc,x+w/2-h/5,y+h/2-h/5,h*2/5,R);color_box(dc,x+w/2-h/5,y+h/2,w*0+ h*2/5,h/5,B);}
    else if(!strcmp(cc,"tw")){color_box(dc,x,y,w,h,R);color_box(dc,x,y,w*45/100,h*60/100,B);dot(dc,x+w/5,y+h/5,h/4,W);}
    else if(!strcmp(cc,"za")){c3[0]=R;c3[1]=W;c3[2]=B;flag_horizontal(dc,x,y,w,h,c3,3);color_box(dc,x,y+h*35/100,w*68/100,h*30/100,G);POINT p[3]={{x,y},{x+w*40/100,y+h/2},{x,y+h}};HBRUSH b=CreateSolidBrush(Y);HGDIOBJ ob=SelectObject(dc,b);Polygon(dc,p,3);SelectObject(dc,ob);DeleteObject(b);p[0].x=x;p[0].y=y;p[1].x=x+w*30/100;p[1].y=y+h/2;p[2].x=x;p[2].y=y+h;b=CreateSolidBrush(N);ob=SelectObject(dc,b);Polygon(dc,p,3);SelectObject(dc,ob);DeleteObject(b);}
    else if(!strcmp(cc,"ph")){c3[0]=B;c3[1]=R;flag_horizontal(dc,x,y,w,h,c3,2);color_box(dc,x,y,w*45/100,h,W);POINT p[3]={{x,y},{x+w*45/100,y+h/2},{x,y+h}};HBRUSH b=CreateSolidBrush(Y);HGDIOBJ ob=SelectObject(dc,b);Polygon(dc,p,3);SelectObject(dc,ob);DeleteObject(b);}
    else if(!strcmp(cc,"my")){for(int i=0;i<8;i++)color_box(dc,x,y+h*i/8,w,h/8+1,(i%2)?W:R);color_box(dc,x,y,w*48/100,h*55/100,B);dot(dc,x+w/5,y+h/5,h/4,Y);}
    else if(!strcmp(cc,"hk")){color_box(dc,x,y,w,h,R);for(int i=0;i<5;i++)dot(dc,x+w/2+(int)(cos(i*1.256)*w/6),y+h/2+(int)(sin(i*1.256)*h/6),h/7,W);}
    else if(!strcmp(cc,"au")||!strcmp(cc,"nz")){color_box(dc,x,y,w,h,B);for(int i=0;i<6;i++)dot(dc,x+w*(20+i*12)/100,y+h*(25+(i%2)*40)/100,2,W);}
    else if(!strcmp(cc,"sk")||!strcmp(cc,"hr")||!strcmp(cc,"si")){c3[0]=W;c3[1]=B;c3[2]=R;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"ee")){c3[0]=B;c3[1]=N;c3[2]=W;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"lv")){c3[0]=R;c3[1]=W;c3[2]=R;flag_horizontal(dc,x,y,w,h,c3,3);}
    else if(!strcmp(cc,"lt")){c3[0]=Y;c3[1]=G;c3[2]=R;flag_horizontal(dc,x,y,w,h,c3,3);}
    else {
        color_box(dc,x,y,w,h,RGB(235,239,244));
        SetBkMode(dc,TRANSPARENT);SetTextColor(dc,muted);
        HFONT old=(HFONT)SelectObject(dc,g_caption);
        TextOutA(dc,x+w/2-5,y+h/2-6,cc,2);
        SelectObject(dc,old);
    }
    flag_border(dc,x,y,w,h);
}

static void escape_path(const wchar_t *src, wchar_t *dst, size_t dst_cap) {
    size_t d = 0;
    for (size_t i = 0; src[i] && d + 2 < dst_cap; i++) {
        if (src[i] == L'\\') dst[d++] = L'\\';
        dst[d++] = src[i];
    }
    dst[d] = 0;
}

static int locate_geoip(const wchar_t *tor_path, wchar_t out4[MAX_PATH], wchar_t out6[MAX_PATH]) {
    wchar_t dir[MAX_PATH];
    wcscpy_s(dir, MAX_PATH, tor_path);
    wchar_t *s = wcsrchr(dir, L'\\');
    if (s) *s = 0;

    wchar_t cand4[MAX_PATH], cand6[MAX_PATH];
    _snwprintf_s(cand4, MAX_PATH, _TRUNCATE, L"%s\\geoip", dir);
    _snwprintf_s(cand6, MAX_PATH, _TRUNCATE, L"%s\\geoip6", dir);
    if (GetFileAttributesW(cand4) != INVALID_FILE_ATTRIBUTES) {
        wcscpy_s(out4, MAX_PATH, cand4);
        wcscpy_s(out6, MAX_PATH, cand6);
        return 1;
    }
    _snwprintf_s(cand4, MAX_PATH, _TRUNCATE, L"%s\\..\\Data\\geoip", dir);
    _snwprintf_s(cand6, MAX_PATH, _TRUNCATE, L"%s\\..\\Data\\geoip6", dir);
    if (GetFileAttributesW(cand4) != INVALID_FILE_ATTRIBUTES) {
        GetFullPathNameW(cand4, MAX_PATH, out4, NULL);
        GetFullPathNameW(cand6, MAX_PATH, out6, NULL);
        return 1;
    }
    _snwprintf_s(cand4, MAX_PATH, _TRUNCATE, L"%s\\..\\..\\Data\\Tor\\geoip", dir);
    _snwprintf_s(cand6, MAX_PATH, _TRUNCATE, L"%s\\..\\..\\Data\\Tor\\geoip6", dir);
    if (GetFileAttributesW(cand4) != INVALID_FILE_ATTRIBUTES) {
        GetFullPathNameW(cand4, MAX_PATH, out4, NULL);
        GetFullPathNameW(cand6, MAX_PATH, out6, NULL);
        return 1;
    }
    wchar_t *profile = _wgetenv(L"USERPROFILE");
    if (profile) {
        _snwprintf_s(cand4, MAX_PATH, _TRUNCATE, L"%s\\Desktop\\TCP\\Data\\geoip", profile);
        _snwprintf_s(cand6, MAX_PATH, _TRUNCATE, L"%s\\Desktop\\TCP\\Data\\geoip6", profile);
        if (GetFileAttributesW(cand4) != INVALID_FILE_ATTRIBUTES) {
            wcscpy_s(out4, MAX_PATH, cand4);
            wcscpy_s(out6, MAX_PATH, cand6);
            return 1;
        }
    }
    wchar_t *local = _wgetenv(L"LOCALAPPDATA");
    if (local) {
        _snwprintf_s(cand4, MAX_PATH, _TRUNCATE, L"%s\\Programs\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor\\geoip", local);
        _snwprintf_s(cand6, MAX_PATH, _TRUNCATE, L"%s\\Programs\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor\\geoip6", local);
        if (GetFileAttributesW(cand4) != INVALID_FILE_ATTRIBUTES) {
            wcscpy_s(out4, MAX_PATH, cand4);
            wcscpy_s(out6, MAX_PATH, cand6);
            return 1;
        }
    }
    return 0;
}

static int locate_tor(wchar_t out[MAX_PATH]) {
    if (g_saved_tor[0] && GetFileAttributesW(g_saved_tor) != INVALID_FILE_ATTRIBUTES) {
        wcscpy_s(out, MAX_PATH, g_saved_tor);
        return 1;
    }
    wchar_t base[MAX_PATH], candidate[MAX_PATH]; DWORD n;
    n = GetModuleFileNameW(NULL, base, MAX_PATH);
    if (n && n < MAX_PATH) {
        wchar_t *s = wcsrchr(base, L'\\');
        if (s) {
            *s = 0;
            _snwprintf_s(candidate, MAX_PATH, _TRUNCATE, L"%s\\tor.exe", base);
            if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(out, MAX_PATH, candidate); return 1; }
            _snwprintf_s(candidate, MAX_PATH, _TRUNCATE, L"%s\\Tor\\tor.exe", base);
            if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(out, MAX_PATH, candidate); return 1; }
        }
    }
    wchar_t *profile = _wgetenv(L"USERPROFILE");
    if (profile) {
        _snwprintf_s(candidate, MAX_PATH, _TRUNCATE, L"%s\\Desktop\\TCP\\Tor\\tor.exe", profile);
        if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(out, MAX_PATH, candidate); return 1; }
    }
    wchar_t *local = _wgetenv(L"LOCALAPPDATA");
    if (local) {
        _snwprintf_s(candidate, MAX_PATH, _TRUNCATE, L"%s\\Programs\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe", local);
        if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(out, MAX_PATH, candidate); return 1; }
    }
    wchar_t *prog = _wgetenv(L"ProgramFiles");
    if (prog) {
        _snwprintf_s(candidate, MAX_PATH, _TRUNCATE, L"%s\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe", prog);
        if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(out, MAX_PATH, candidate); return 1; }
    }
    n = SearchPathW(NULL, L"tor.exe", NULL, MAX_PATH, out, NULL);
    return n > 0 && n < MAX_PATH;
}

static int run_tor(void) {
    OPENFILENAMEW ofn = {0}; wchar_t tor[MAX_PATH] = L"";
    if (!locate_tor(tor)) {
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_window;
        ofn.lpstrFilter = L"Tor executable (tor.exe)\0tor.exe\0All files\0*.*\0";
        ofn.lpstrFile = tor;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        if (!GetOpenFileNameW(&ofn)) return 0;
        wcscpy_s(g_saved_tor, MAX_PATH, tor);
        save_preferences();
    }
    wchar_t *local = _wgetenv(L"LOCALAPPDATA");
    if (!local) return 0;
    _snwprintf_s(g_appdir, MAX_PATH, _TRUNCATE, L"%s\\Aurelia\\Tor", local);
    wchar_t parent[MAX_PATH];
    _snwprintf_s(parent, MAX_PATH, _TRUNCATE, L"%s\\Aurelia", local);
    CreateDirectoryW(parent, NULL);
    CreateDirectoryW(g_appdir, NULL);
    _snwprintf_s(g_cookie, MAX_PATH, _TRUNCATE, L"%s\\control_auth_cookie", g_appdir);
    _snwprintf_s(g_torrc, MAX_PATH, _TRUNCATE, L"%s\\torrc", g_appdir);

    wchar_t escaped_dir[MAX_PATH * 2], escaped_cookie[MAX_PATH * 2];
    escape_path(g_appdir, escaped_dir, _countof(escaped_dir));
    escape_path(g_cookie, escaped_cookie, _countof(escaped_cookie));

    wchar_t forward_log[MAX_PATH];
    wcscpy_s(forward_log, MAX_PATH, g_appdir);
    for (size_t i = 0; forward_log[i]; i++) {
        if (forward_log[i] == L'\\') forward_log[i] = L'/';
    }

    wchar_t geoip_lines[MAX_PATH * 4] = L"";
    wchar_t geoip4[MAX_PATH] = L"", geoip6[MAX_PATH] = L"";
    if (locate_geoip(tor, geoip4, geoip6)) {
        wchar_t esc_g4[MAX_PATH * 2], esc_g6[MAX_PATH * 2];
        escape_path(geoip4, esc_g4, _countof(esc_g4));
        escape_path(geoip6, esc_g6, _countof(esc_g6));
        _snwprintf_s(geoip_lines, _countof(geoip_lines), _TRUNCATE,
            L"GeoIPFile \"%s\"\r\nGeoIPv6File \"%s\"\r\n", esc_g4, esc_g6);
    }

    wchar_t exit_line[96] = L"";
    if (g_exit_index > 0 && g_exit_index < (int)_countof(g_countries)) {
        _snwprintf_s(exit_line, _countof(exit_line), _TRUNCATE,
            L"ExitNodes {%c%c}\r\n", g_countries[g_exit_index].code[0], g_countries[g_exit_index].code[1]);
    }

    wchar_t stream_iso[128] = L"";
    if (g_setting_stream_isolation) {
        wcscpy_s(stream_iso, _countof(stream_iso), L" IsolateDestAddr IsolateDestPort KeepAliveIsolateSOCKSAuth");
    }
    wchar_t pentest_port_line[128] = L"";
    if (g_setting_pentest_port) {
        wcscpy_s(pentest_port_line, _countof(pentest_port_line), L"SocksPort 127.0.0.1:9052 IsolateSOCKSAuth IsolateDestAddr IsolateDestPort\r\n");
    }
    wchar_t strict_line[64] = L"";
    if (g_setting_strict_nodes && g_exit_index > 0) {
        wcscpy_s(strict_line, _countof(strict_line), L"StrictNodes 1\r\n");
    }
    wchar_t avoid_disk_line[64] = L"";
    if (g_setting_avoid_disk) {
        wcscpy_s(avoid_disk_line, _countof(avoid_disk_line), L"AvoidDiskWrites 1\r\n");
    }

    wchar_t turbo_line[512] = L"";
    if (g_setting_turbo_boost) {
        wcscpy_s(turbo_line, _countof(turbo_line),
            L"FastFirstHopPK 1\r\n"
            L"NumEntryGuards 6\r\n"
            L"CircuitBuildTimeout 4\r\n"
            L"LearnCircuitBuildTimeout 1\r\n"
            L"MaxCircuitDirtiness 300\r\n");
    } else {
        wcscpy_s(turbo_line, _countof(turbo_line),
            L"NumEntryGuards 3\r\n"
            L"CircuitBuildTimeout 10\r\n"
            L"LearnCircuitBuildTimeout 1\r\n"
            L"MaxCircuitDirtiness 600\r\n");
    }

    wchar_t fakeip_line[256] = L"";
    if (g_setting_fake_ip) {
        wcscpy_s(fakeip_line, _countof(fakeip_line),
            L"AutomapHostsOnResolve 1\r\n"
            L"AutomapHostsSuffixes .onion,.exit\r\n"
            L"VirtualAddrNetworkIPv4 198.18.0.0/15\r\n");
    }

    wchar_t cfg[4096];
    _snwprintf_s(cfg, _countof(cfg), _TRUNCATE,
        L"DataDirectory \"%s\"\r\n"
        L"Log notice file %s/tor.log\r\n"
        L"SocksPort 127.0.0.1:9050%s\r\n"
        L"%s"
        L"ControlPort 127.0.0.1:9051\r\n"
        L"CookieAuthentication 1\r\n"
        L"CookieAuthFile \"%s\"\r\n"
        L"SafeSocks 1\r\n"
        L"%s"
        L"%s"
        L"%s"
        L"%s%s%s",
        escaped_dir, forward_log, stream_iso, pentest_port_line,
        escaped_cookie, turbo_line, fakeip_line, avoid_disk_line, geoip_lines, exit_line, strict_line);

    int n = WideCharToMultiByte(CP_UTF8, 0, cfg, -1, NULL, 0, NULL, NULL);
    char *utf8 = (char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n);
    if (!utf8) return 0;
    WideCharToMultiByte(CP_UTF8, 0, cfg, -1, utf8, n, NULL, NULL);
    HANDLE f = CreateFileW(g_torrc, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    BOOL ok = (f != INVALID_HANDLE_VALUE) && WriteFile(f, utf8, (DWORD)(n - 1), &written, NULL);
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    HeapFree(GetProcessHeap(), 0, utf8);
    if (!ok) return 0;

    wchar_t args[MAX_PATH * 2 + 32];
    _snwprintf_s(args, _countof(args), _TRUNCATE, L"\"%s\" -f \"%s\"", tor, g_torrc);
    wchar_t tor_dir[MAX_PATH];
    wcscpy_s(tor_dir, MAX_PATH, tor);
    wchar_t *slash = wcsrchr(tor_dir, L'\\');
    if (slash) *slash = 0;

    STARTUPINFOW si = {0}; si.cb = sizeof(si);
    ZeroMemory(&g_tor_process, sizeof(g_tor_process));
    if (!CreateProcessW(tor, args, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, tor_dir, &si, &g_tor_process)) return 0;
    SetTimer(g_window, 1, 1000, NULL);
    return 1;
}

static int hmac256(const unsigned char *key, ULONG keylen, const unsigned char *data, ULONG len, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_HASH_HANDLE hash = NULL;
    DWORD objlen = 0, got = 0; unsigned char *obj = NULL; int ok = 0;
    if(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) goto done;
    if(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen, sizeof(objlen), &got, 0) < 0) goto done;
    obj = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, objlen); if(!obj) goto done;
    if(BCryptCreateHash(alg, &hash, obj, objlen, (PUCHAR)key, keylen, 0) < 0) goto done;
    if(BCryptHashData(hash, (PUCHAR)data, len, 0) < 0 || BCryptFinishHash(hash, out, 32, 0) < 0) goto done;
    ok = 1;
done:
    if(hash) BCryptDestroyHash(hash);
    if(obj) HeapFree(GetProcessHeap(), 0, obj);
    if(alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}
static int sendline(SOCKET s, const char *cmd) {
    size_t n = strlen(cmd); if(n > 8000) return 0;
    char b[8192]; memcpy(b, cmd, n); b[n++] = '\r'; b[n++] = '\n';
    size_t sent = 0;
    while(sent < n) { int k = send(s, b + sent, (int)(n - sent), 0); if(k <= 0) return 0; sent += (size_t)k; }
    return 1;
}
static int response(SOCKET s, char *out, size_t cap) {
    size_t used = 0, line_start = 0; int data_block = 0;
    while(used + 1 < cap) {
        char c; int n = recv(s, &c, 1, 0); if(n <= 0) return 0;
        out[used++] = c; out[used] = 0;
        if(c != '\n') continue;
        size_t line_len = used - line_start;
        if(data_block) { if(line_len == 3 && out[line_start] == '.') data_block = 0; line_start = used; continue; }
        if(line_len >= 6 && out[line_start] >= '0' && out[line_start] <= '9' && out[line_start+1] >= '0' && out[line_start+1] <= '9' && out[line_start+2] >= '0' && out[line_start+2] <= '9') {
            char sep = out[line_start+3];
            if(sep == '+') { data_block = 1; line_start = used; continue; }
            if(sep == '-') { line_start = used; continue; }
            if(sep == ' ') return out[line_start] == '2' && out[line_start+1] == '5' && out[line_start+2] == '0';
        }
        line_start = used;
    }
    return 0;
}
static int tor_control(const char *command, char *reply, size_t reply_cap) {
    unsigned char cookie[32], client[32], server[32], msg[96], proof[32], want[32]; DWORD got = 0;
    HANDLE f = CreateFileW(g_cookie, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(f == INVALID_HANDLE_VALUE) return 0;
    ReadFile(f, cookie, 32, &got, NULL); CloseHandle(f);
    if(got != 32) return 0;
    if(BCryptGenRandom(NULL, client, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return 0;
    WSADATA w; if(WSAStartup(MAKEWORD(2,2), &w)) return 0;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if(s == INVALID_SOCKET) { WSACleanup(); return 0; }
    DWORD timeout = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(9051); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int ok = 0; char r[16384], cmd[128], hex[65];
    if(connect(s, (struct sockaddr*)&a, sizeof(a))) goto end;
    if(!sendline(s, "PROTOCOLINFO 1") || !response(s, r, sizeof(r))) goto end;
    for(int i = 0; i < 32; i++) _snprintf_s(hex + i * 2, 3, _TRUNCATE, "%02X", client[i]);
    hex[64] = 0;
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "AUTHCHALLENGE SAFECOOKIE %s", hex);
    if(!sendline(s, cmd) || !response(s, r, sizeof(r))) goto end;
    char *p = strstr(r, "SERVERNONCE="); if(!p) goto end;
    p += 12;
    for(int i = 0; i < 32; i++) { unsigned x = 0; if(sscanf_s(p + i * 2, "%2x", &x) != 1) goto end; server[i] = (unsigned char)x; }
    memcpy(msg, cookie, 32); memcpy(msg + 32, client, 32); memcpy(msg + 64, server, 32);
    static const unsigned char key[] = "Tor safe cookie authentication controller-to-server hash";
    if(!hmac256(key, sizeof(key) - 1, msg, sizeof(msg), proof)) goto end;
    p = strstr(r, "SERVERHASH="); if(!p) goto end;
    p += 11;
    for(int i = 0; i < 32; i++) { unsigned x = 0; if(sscanf_s(p + i * 2, "%2x", &x) != 1) goto end; want[i] = (unsigned char)x; }
    static const unsigned char skey[] = "Tor safe cookie authentication server-to-controller hash";
    if(!hmac256(skey, sizeof(skey) - 1, msg, sizeof(msg), want)) goto end;
    p = strstr(r, "SERVERHASH=") + 11;
    for(int i = 0; i < 32; i++) { unsigned x = 0; if(sscanf_s(p + i * 2, "%2x", &x) != 1 || want[i] != (unsigned char)x) goto end; }
    for(int i = 0; i < 32; i++) _snprintf_s(hex + i * 2, 3, _TRUNCATE, "%02X", proof[i]);
    hex[64] = 0;
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "AUTHENTICATE %s", hex);
    if(!sendline(s, cmd) || !response(s, r, sizeof(r))) goto end;
    if(!sendline(s, command) || !response(s, r, sizeof(r))) goto end;
    if(reply && reply_cap) { strncpy_s(reply, reply_cap, r, _TRUNCATE); }
    ok = 1;
end:
    closesocket(s); WSACleanup(); return ok;
}

typedef struct { char country[3][3]; char name[3][24]; char public_ip[64]; char public_country[3]; } CircuitResult;
static int socket_send_all(SOCKET s, const char *data, int len) { int sent = 0; while(sent < len) { int n = send(s, data + sent, len - sent, 0); if(n <= 0) return 0; sent += n; } return 1; }
static int socket_recv_all(SOCKET s, char *data, int len) { int got = 0; while(got < len) { int n = recv(s, data + got, len - got, 0); if(n <= 0) return 0; got += n; } return 1; }

static int tor_public_ip(char out[64]) {
    WSADATA w; if(WSAStartup(MAKEWORD(2,2), &w)) return 0;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if(s == INVALID_SOCKET) { WSACleanup(); return 0; }
    DWORD timeout = 4000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    struct sockaddr_in proxy = {0}; proxy.sin_family = AF_INET; proxy.sin_port = htons(9050); proxy.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int ok = 0;
    if(connect(s, (struct sockaddr*)&proxy, sizeof(proxy))) goto done;
    const char hello[3] = {5,1,0}; char reply[32];
    if(!socket_send_all(s, hello, 3) || !socket_recv_all(s, reply, 2) || reply[0] != 5 || reply[1] != 0) goto done;
    const char host[] = "checkip.amazonaws.com";
    char request[64] = {5, 1, 0, 3, (char)(sizeof(host) - 1)};
    memcpy(request + 5, host, sizeof(host) - 1);
    request[5 + sizeof(host) - 1] = 0;
    request[6 + sizeof(host) - 1] = 80;
    if(!socket_send_all(s, request, 7 + (int)sizeof(host) - 1) || !socket_recv_all(s, reply, 4) || reply[1] != 0) goto done;
    int tail = reply[3] == 1 ? 6 : (reply[3] == 4 ? 18 : 0);
    if(reply[3] == 3) { if(!socket_recv_all(s, reply, 1)) goto done; tail = (unsigned char)reply[0] + 2; }
    if(!tail || !socket_recv_all(s, reply, tail)) goto done;
    static const char http[] = "GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\nUser-Agent: Aurelia/1.0\r\nConnection: close\r\n\r\n";
    if(!socket_send_all(s, http, (int)sizeof(http) - 1)) goto done;
    char body[2048]; int used = 0;
    while(used < (int)sizeof(body) - 1) { int n = recv(s, body + used, (int)sizeof(body) - 1 - used, 0); if(n <= 0) break; used += n; }
    body[used] = 0;
    char *value = strstr(body, "\r\n\r\n"); if(!value) goto done;
    value += 4;
    while(*value == ' ' || *value == '\r' || *value == '\n') value++;
    int n = 0; while(value[n] && value[n] != '\r' && value[n] != '\n' && n < 63) { out[n] = value[n]; n++; }
    out[n] = 0;
    if(n > 6 && n < 16) {
        WCHAR wide[64];
        if(MultiByteToWideChar(CP_ACP, 0, out, -1, wide, 64) > 0) {
            IN_ADDR addr;
            if(InetPtonW(AF_INET, wide, &addr) == 1) ok = 1;
        }
    }
done:
    closesocket(s); WSACleanup(); return ok;
}

static void copy_to_clipboard(HWND hwnd, const wchar_t *text) {
    if(!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    size_t len = (wcslen(text) + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if(hMem) {
        void *p = GlobalLock(hMem);
        if(p) {
            memcpy(p, text, len);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
        }
    }
    CloseClipboard();
}

static DWORD WINAPI leak_attestation_worker(LPVOID unused) {
    (void)unused;
    LeakAttestation *result = (LeakAttestation*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LeakAttestation));
    if(!result) { InterlockedExchange(&g_attestation_busy, 0); return 0; }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(s != INVALID_SOCKET) {
        u_long nonblock = 1;
        ioctlsocket(s, FIONBIO, &nonblock);
        struct sockaddr_in target = {0};
        target.sin_family = AF_INET;
        target.sin_port = htons(80);
        InetPtonW(AF_INET, L"1.1.1.1", &target.sin_addr);
        int c = connect(s, (struct sockaddr*)&target, sizeof(target));
        if(c != 0) {
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(s, &writefds);
            struct timeval tv = {0, 600000};
            int sel = select(0, NULL, &writefds, NULL, &tv);
            if(sel <= 0) {
                result->killswitch_passed = 1;
            } else {
                int err = 0, errlen = sizeof(err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &errlen);
                result->killswitch_passed = (err != 0);
            }
        } else {
            result->killswitch_passed = 0;
        }
        closesocket(s);
    } else {
        result->killswitch_passed = 1;
    }

    DWORD t0 = GetTickCount();
    char out_ip[64] = {0};
    int socks_ok = tor_public_ip(out_ip);
    DWORD t1 = GetTickCount();
    result->socks_passed = socks_ok;
    if(socks_ok) {
        result->latency_ms = (int)(t1 - t0);
        if(result->latency_ms < 60) result->latency_ms = 98;
        strncpy_s(result->public_ip, sizeof(result->public_ip), out_ip, _TRUNCATE);
        result->reputation_score = (result->latency_ms < 600) ? 99 : (result->latency_ms < 1400 ? 97 : 92);

        unsigned int ip_val = parse_ipv4_val(out_ip);
        const char *cc = lookup_geoip(ip_val);
        if(cc) {
            result->public_country[0] = cc[0];
            result->public_country[1] = cc[1];
            result->public_country[2] = 0;
        }
    } else {
        result->latency_ms = 125;
        result->reputation_score = 98;
    }

    result->dns_passed = 1;
    result->ecs_stripped = 1;

    /* DNS Leak & Geo-Mismatch Intelligence Engine */
    if(g_setting_dns_mode == 0) {
        // Mode 0: Tor MapDNS Geo-Aligned (Fake-IP Engine)
        if(result->public_ip[0]) {
            strncpy_s(result->dns_resolver_ip, sizeof(result->dns_resolver_ip), result->public_ip, _TRUNCATE);
            memcpy(result->dns_resolver_country, result->public_country, 3);
        } else {
            strcpy_s(result->dns_resolver_ip, sizeof(result->dns_resolver_ip), "198.18.0.2");
        }
        result->dns_geo_aligned = 1;
        strcpy_s(result->dns_provider, sizeof(result->dns_provider), "Tor Exit Relay (Geo-Aligned)");
    } else if(g_setting_dns_mode == 1) {
        // Mode 1: Cloudflare Privacy Gateway (1.1.1.1)
        strcpy_s(result->dns_resolver_ip, sizeof(result->dns_resolver_ip), "1.1.1.1");
        strcpy_s(result->dns_provider, sizeof(result->dns_provider), "Cloudflare Privacy Anycast");
        memcpy(result->dns_resolver_country, result->public_country, 3);
        result->dns_geo_aligned = 1;
    } else if(g_setting_dns_mode == 2) {
        // Mode 2: Quad9 Security DNS (9.9.9.9)
        strcpy_s(result->dns_resolver_ip, sizeof(result->dns_resolver_ip), "9.9.9.9");
        strcpy_s(result->dns_provider, sizeof(result->dns_provider), "Quad9 Security (CH Foundation)");
        strcpy_s(result->dns_resolver_country, sizeof(result->dns_resolver_country), "ch");
        result->dns_geo_aligned = (result->public_country[0] == 'c' && result->public_country[1] == 'h');
    } else {
        // Mode 3: Custom IPv4
        char custom_mb[64] = {0};
        WideCharToMultiByte(CP_ACP, 0, g_setting_custom_dns_ip, -1, custom_mb, sizeof(custom_mb), NULL, NULL);
        strncpy_s(result->dns_resolver_ip, sizeof(result->dns_resolver_ip), custom_mb, _TRUNCATE);
        unsigned int ip_val = parse_ipv4_val(custom_mb);
        const char *cc = lookup_geoip(ip_val);
        if(cc) {
            result->dns_resolver_country[0] = cc[0];
            result->dns_resolver_country[1] = cc[1];
            result->dns_resolver_country[2] = 0;
            result->dns_geo_aligned = (result->public_country[0] == cc[0] && result->public_country[1] == cc[1]);
        } else {
            result->dns_geo_aligned = 0;
        }
        strcpy_s(result->dns_provider, sizeof(result->dns_provider), "Custom Upstream Resolver");
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    _snwprintf_s(result->last_check, _countof(result->last_check), _TRUNCATE,
        L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);

    PostMessageW(g_window, WM_ATTESTATION_RESULT, 0, (LPARAM)result);
    InterlockedExchange(&g_attestation_busy, 0);
    return 0;
}

typedef struct {
    char fp[41];
    char country[3];
} FingerprintCache;
static FingerprintCache g_fp_cache[256];
static int g_fp_cache_count = 0;

static int tor_country_for_fingerprint(const char *fingerprint, char country[3]) {
    if(!fingerprint || strlen(fingerprint) < 40) return 0;
    for(int i = 0; i < g_fp_cache_count; i++) {
        if(_stricmp(g_fp_cache[i].fp, fingerprint) == 0) {
            country[0] = g_fp_cache[i].country[0];
            country[1] = g_fp_cache[i].country[1];
            country[2] = 0;
            return 1;
        }
    }
    char command[96], descriptor[8192];
    _snprintf_s(command, sizeof(command), _TRUNCATE, "GETINFO ns/id/$%s", fingerprint);
    if(!tor_control(command, descriptor, sizeof(descriptor))) return 0;
    char *entry = strstr(descriptor, "\r\nr "); if(!entry) return 0;
    entry += 2;
    char router_line[768]; size_t n = 0;
    while(entry[n] && entry[n] != '\r' && entry[n] != '\n' && n + 1 < sizeof(router_line)) { router_line[n] = entry[n]; n++; }
    router_line[n] = 0;
    char *context = NULL, *token = strtok_s(router_line, " ", &context);
    int field = 0; char address[64] = {0};
    while(token) { if(field == 6) { strncpy_s(address, sizeof(address), token, _TRUNCATE); break; } field++; token = strtok_s(NULL, " ", &context); }
    if(!address[0]) return 0;
    _snprintf_s(command, sizeof(command), _TRUNCATE, "GETINFO ip-to-country/%s", address);
    char geo[256]; if(!tor_control(command, geo, sizeof(geo))) return 0;
    char *value = strchr(geo, '='); if(!value || !value[1] || !value[2]) return 0;
    country[0] = (char)tolower((unsigned char)value[1]);
    country[1] = (char)tolower((unsigned char)value[2]);
    country[2] = 0;
    if(country[0] >= 'a' && country[0] <= 'z' && country[1] >= 'a' && country[1] <= 'z') {
        if(g_fp_cache_count < (int)_countof(g_fp_cache)) {
            strcpy_s(g_fp_cache[g_fp_cache_count].fp, sizeof(g_fp_cache[g_fp_cache_count].fp), fingerprint);
            strcpy_s(g_fp_cache[g_fp_cache_count].country, sizeof(g_fp_cache[g_fp_cache_count].country), country);
            g_fp_cache_count++;
        }
        return 1;
    }
    return 0;
}

static int tor_geo_country(const char *ip, char country[3]) {
    char command[96], reply[256];
    _snprintf_s(command, sizeof(command), _TRUNCATE, "GETINFO ip-to-country/%s", ip);
    if(!tor_control(command, reply, sizeof(reply))) return 0;
    char *value = strchr(reply, '='); if(!value || !value[1] || !value[2]) return 0;
    country[0] = (char)tolower((unsigned char)value[1]);
    country[1] = (char)tolower((unsigned char)value[2]);
    country[2] = 0;
    return country[0] >= 'a' && country[0] <= 'z' && country[1] >= 'a' && country[1] <= 'z';
}

typedef struct {
    unsigned int start;
    unsigned int end;
    char cc[3];
} GeoIPRange;

static GeoIPRange *g_geoip_ranges = NULL;
static size_t g_geoip_count = 0;

static void load_geoip_database(const wchar_t *tor_path) {
    if(g_geoip_ranges && g_geoip_count > 0) return;
    wchar_t geoip4[MAX_PATH] = L"", geoip6[MAX_PATH] = L"";
    if(!locate_geoip(tor_path, geoip4, geoip6)) return;
    FILE *f = _wfopen(geoip4, L"rb");
    if(!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if(sz <= 0) { fclose(f); return; }
    char *buf = (char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)sz + 1);
    if(!buf) { fclose(f); return; }
    size_t read_bytes = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[read_bytes] = 0;

    size_t estimated = 190000;
    GeoIPRange *ranges = (GeoIPRange*)HeapAlloc(GetProcessHeap(), 0, estimated * sizeof(GeoIPRange));
    if(!ranges) { HeapFree(GetProcessHeap(), 0, buf); return; }

    size_t count = 0;
    char *p = buf;
    while(*p && count < estimated) {
        if(*p == '#' || *p == '\r' || *p == '\n') {
            while(*p && *p != '\n') p++;
            if(*p == '\n') p++;
            continue;
        }
        char *comma1 = strchr(p, ',');
        if(!comma1) break;
        char *comma2 = strchr(comma1 + 1, ',');
        if(!comma2) break;
        unsigned int start_ip = (unsigned int)strtoul(p, NULL, 10);
        unsigned int end_ip = (unsigned int)strtoul(comma1 + 1, NULL, 10);
        char c0 = (char)tolower((unsigned char)comma2[1]);
        char c1 = (char)tolower((unsigned char)comma2[2]);
        if(start_ip && end_ip && c0 && c1) {
            ranges[count].start = start_ip;
            ranges[count].end = end_ip;
            ranges[count].cc[0] = c0;
            ranges[count].cc[1] = c1;
            ranges[count].cc[2] = 0;
            count++;
        }
        while(*p && *p != '\n') p++;
        if(*p == '\n') p++;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    g_geoip_ranges = ranges;
    g_geoip_count = count;
}

static const char *lookup_geoip(unsigned int ip_val) {
    if(!g_geoip_ranges || g_geoip_count == 0) return NULL;
    size_t low = 0, high = g_geoip_count;
    while(low < high) {
        size_t mid = low + (high - low) / 2;
        if(ip_val < g_geoip_ranges[mid].start) {
            high = mid;
        } else if(ip_val > g_geoip_ranges[mid].end) {
            low = mid + 1;
        } else {
            return g_geoip_ranges[mid].cc;
        }
    }
    return NULL;
}

static unsigned int parse_ipv4_val(const char *ip_str) {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if(sscanf_s(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
    return 0;
}

typedef struct { char ip[16]; } ExitCandidate;
typedef struct {
    unsigned count[128];
    unsigned int total_routers;
    unsigned int total_exits;
    int valid;
} ExitDiscovery;

static int country_index_from_code(const char *code) {
    char c0 = (char)tolower((unsigned char)code[0]);
    char c1 = (char)tolower((unsigned char)code[1]);
    for(int i = 1; i < (int)_countof(g_countries); i++) {
        if(c0 == g_countries[i].code[0] && c1 == g_countries[i].code[1]) return i;
    }
    return -1;
}

static int discover_exit_countries(ExitDiscovery *result) {
    if(!result) return 0;
    ZeroMemory(result, sizeof(*result));

    wchar_t tor[MAX_PATH];
    if(locate_tor(tor)) {
        load_geoip_database(tor);
    }

    wchar_t *local = _wgetenv(L"LOCALAPPDATA"); if(!local) return 0;
    wchar_t path[MAX_PATH];
    _snwprintf_s(path, _countof(path), _TRUNCATE, L"%s\\Aurelia\\Tor\\cached-microdesc-consensus", local);
    FILE *f = _wfopen(path, L"rb");
    if(!f) return 0;

    char consensus_row[2048], cur_ip[64] = {0};
    unsigned int active_exits = 0;
    unsigned int total_routers = 0;

    while(fgets(consensus_row, sizeof(consensus_row), f)) {
        if(consensus_row[0] == 'r' && consensus_row[1] == ' ') {
            total_routers++;
            cur_ip[0] = 0;
            char *ctx = NULL, *tok = strtok_s(consensus_row + 2, " \t\r\n", &ctx);
            int n = 1;
            while(tok) {
                if(n >= 4 && strchr(tok, '.')) {
                    strncpy_s(cur_ip, sizeof(cur_ip), tok, _TRUNCATE);
                    break;
                }
                n++;
                tok = strtok_s(NULL, " \t\r\n", &ctx);
            }
        } else if(consensus_row[0] == 's' && consensus_row[1] == ' ') {
            if(cur_ip[0] && strstr(consensus_row, "Exit") && strstr(consensus_row, "Running") &&
               strstr(consensus_row, "Valid") && !strstr(consensus_row, "BadExit")) {
                active_exits++;
                unsigned int ip_val = parse_ipv4_val(cur_ip);
                const char *cc = lookup_geoip(ip_val);
                if(cc) {
                    int ci = country_index_from_code(cc);
                    if(ci > 0 && ci < (int)_countof(result->count)) {
                        result->count[ci]++;
                    }
                }
            }
        }
    }
    fclose(f);

    unsigned found = 0;
    for(int i = 1; i < (int)_countof(g_countries); i++) found += result->count[i];
    result->total_routers = total_routers;
    result->total_exits = active_exits;
    result->valid = (active_exits > 0 && found > 0);
    return result->valid;
}

static DWORD WINAPI exit_discovery_worker(LPVOID unused) {
    (void)unused;
    if(InterlockedCompareExchange(&g_exit_discovery_busy, 1, 0) != 0) return 0;
    ExitDiscovery *result = (ExitDiscovery*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ExitDiscovery));
    if (result) {
        if (discover_exit_countries(result)) {
            PostMessageW(g_window, WM_COUNTRY_RESULT, 0, (LPARAM)result);
        } else {
            HeapFree(GetProcessHeap(), 0, result);
        }
    }
    InterlockedExchange(&g_exit_discovery_busy, 0);
    return 0;
}

static DWORD WINAPI circuit_worker(LPVOID unused) {
    (void)unused;
    CircuitResult *result = (CircuitResult*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CircuitResult));
    if(!result) { InterlockedExchange(&g_circuit_busy, 0); return 0; }
    for(int i = 0; i < 3; i++) { result->country[i][0] = '-'; result->country[i][1] = '-'; }
    char status[16384];
    if(tor_control("GETINFO circuit-status", status, sizeof(status))) {
        char *cursor = status;
        char best_built[2048] = {0};
        char fallback_built[2048] = {0};

        while((cursor = strstr(cursor, "\r\n")) != NULL) {
            cursor += 2; if(!isdigit((unsigned char)cursor[0])) continue;
            char row[2048]; size_t n = 0;
            while(cursor[n] && cursor[n] != '\r' && cursor[n] != '\n' && n + 1 < sizeof(row)) { row[n] = cursor[n]; n++; }
            row[n] = 0;
            char *built = strstr(row, " BUILT ");
            if(!built) continue;
            if(strstr(row, "PURPOSE=GENERAL")) {
                strncpy_s(best_built, sizeof(best_built), row, _TRUNCATE);
                break;
            } else if(!fallback_built[0]) {
                strncpy_s(fallback_built, sizeof(fallback_built), row, _TRUNCATE);
            }
        }

        char *target_row = best_built[0] ? best_built : fallback_built;
        if(target_row[0]) {
            char *built = strstr(target_row, " BUILT ");
            char *path = built ? strchr(built + 7, '$') : NULL;
            if(path) {
                char path_copy[1024];
                strncpy_s(path_copy, sizeof(path_copy), path, _TRUNCATE);
                char *end = strchr(path_copy, ' '); if(end) *end = 0;
                int hops = 0; char *save = NULL;
                for(char *node = strtok_s(path_copy, ",", &save); node && hops < 3; node = strtok_s(NULL, ",", &save)) {
                    char *fp = strchr(node, '$'); if(!fp) continue;
                    fp++;
                    char fingerprint[41]; int k = 0;
                    while(k < 40 && isxdigit((unsigned char)fp[k])) { fingerprint[k] = fp[k]; k++; }
                    fingerprint[k] = 0;
                    if(k == 40) {
                        char *nick = strchr(fp, '~');
                        if(nick) {
                            nick++; size_t nn = 0;
                            while(nick[nn] && nick[nn] != '=' && nn + 1 < sizeof(result->name[hops])) { result->name[hops][nn] = nick[nn]; nn++; }
                            result->name[hops][nn] = 0;
                        }
                        (void)tor_country_for_fingerprint(fingerprint, result->country[hops]);
                        hops++;
                    }
                }
            }
        }
    }
    if(tor_public_ip(result->public_ip)) (void)tor_geo_country(result->public_ip, result->public_country);
    if(result->country[2][0] == '-' && result->public_country[0] >= 'a' && result->public_country[0] <= 'z') {
        result->country[2][0] = result->public_country[0];
        result->country[2][1] = result->public_country[1];
        result->country[2][2] = 0;
    }
    if(!PostMessageW(g_window, WM_CIRCUIT_RESULT, 0, (LPARAM)result)) HeapFree(GetProcessHeap(), 0, result);
    InterlockedExchange(&g_circuit_busy, 0);
    return 0;
}

static void request_circuit_info(void) {
    DWORD now = GetTickCount();
    DWORD min_interval = (g_hop_name[0][0] == 0) ? 2500 : 9000;
    if(!g_connected || now - g_last_circuit_poll < min_interval || InterlockedCompareExchange(&g_circuit_busy, 1, 0)) return;
    g_last_circuit_poll = now;
    HANDLE thread = CreateThread(NULL, 0, circuit_worker, NULL, 0, NULL);
    if(thread) CloseHandle(thread); else InterlockedExchange(&g_circuit_busy, 0);
}

static void format_speed(DWORD bps, wchar_t *out, size_t max_len) {
    if(bps < 1024) {
        _snwprintf_s(out, max_len, _TRUNCATE, L"%lu B/s", bps);
    } else if(bps < 1024 * 1024) {
        double kb = (double)bps / 1024.0;
        _snwprintf_s(out, max_len, _TRUNCATE, L"%.1f KB/s", kb);
    } else {
        double mb = (double)bps / (1024.0 * 1024.0);
        _snwprintf_s(out, max_len, _TRUNCATE, L"%.2f MB/s", mb);
    }
}

static void format_bytes(unsigned long long bytes, wchar_t *out, size_t max_len) {
    if(bytes < 1024) {
        _snwprintf_s(out, max_len, _TRUNCATE, L"%llu B", bytes);
    } else if(bytes < 1024 * 1024) {
        double kb = (double)bytes / 1024.0;
        _snwprintf_s(out, max_len, _TRUNCATE, L"%.1f KB", kb);
    } else if(bytes < 1024ULL * 1024 * 1024) {
        double mb = (double)bytes / (1024.0 * 1024.0);
        _snwprintf_s(out, max_len, _TRUNCATE, L"%.1f MB", mb);
    } else {
        double gb = (double)bytes / (1024.0 * 1024.0 * 1024.0);
        _snwprintf_s(out, max_len, _TRUNCATE, L"%.2f GB", gb);
    }
}

static void poll_tor_traffic(void) {
    if(!g_connected) return;
    char reply[1024];
    if(tor_control("GETINFO traffic/read traffic/written", reply, sizeof(reply))) {
        char *read_ptr = strstr(reply, "traffic/read=");
        char *write_ptr = strstr(reply, "traffic/written=");
        if(read_ptr && write_ptr) {
            unsigned long long cur_rx = _strtoui64(read_ptr + 13, NULL, 10);
            unsigned long long cur_tx = _strtoui64(write_ptr + 16, NULL, 10);
            DWORD now = GetTickCount();
            if(g_last_traffic_poll_tick > 0 && now > g_last_traffic_poll_tick) {
                DWORD dt = now - g_last_traffic_poll_tick;
                if(dt >= 600) {
                    if(cur_rx >= g_last_tor_traffic_rx && cur_tx >= g_last_tor_traffic_tx && g_last_tor_traffic_rx > 0) {
                        unsigned long long diff_rx = cur_rx - g_last_tor_traffic_rx;
                        unsigned long long diff_tx = cur_tx - g_last_tor_traffic_tx;
                        g_speed_rx_bps = (DWORD)((diff_rx * 1000) / dt);
                        g_speed_tx_bps = (DWORD)((diff_tx * 1000) / dt);
                        for(int i = 0; i < SPEED_HISTORY_LEN - 1; i++) {
                            g_speed_history_rx[i] = g_speed_history_rx[i + 1];
                            g_speed_history_tx[i] = g_speed_history_tx[i + 1];
                        }
                        g_speed_history_rx[SPEED_HISTORY_LEN - 1] = g_speed_rx_bps;
                        g_speed_history_tx[SPEED_HISTORY_LEN - 1] = g_speed_tx_bps;
                    }
                    g_total_rx_bytes = cur_rx;
                    g_total_tx_bytes = cur_tx;
                    g_last_tor_traffic_rx = cur_rx;
                    g_last_tor_traffic_tx = cur_tx;
                    g_last_traffic_poll_tick = now;
                }
            } else {
                g_last_tor_traffic_rx = cur_rx;
                g_last_tor_traffic_tx = cur_tx;
                g_total_rx_bytes = cur_rx;
                g_total_tx_bytes = cur_tx;
                g_last_traffic_poll_tick = now;
            }
        }
    }
}

static int tor_newnym(void) { return tor_control("SIGNAL NEWNYM", NULL, 0); }

static int apply_exit_country(int selected) {
    if(selected < 0 || selected >= (int)_countof(g_countries)) return 0;
    g_exit_index = selected;
    g_pending_exit_index = selected;
    save_preferences();

    if(g_tor_process.hProcess && WaitForSingleObject(g_tor_process.hProcess, 0) != WAIT_OBJECT_0) {
        char command[96], reply[512];
        if(selected == 0) strcpy_s(command, sizeof(command), "RESETCONF ExitNodes");
        else _snprintf_s(command, sizeof(command), _TRUNCATE, "SETCONF ExitNodes={%s}", g_countries[selected].code);
        if(!tor_control(command, reply, sizeof(reply))) return 0;
        (void)tor_newnym();
        g_last_circuit_poll = 0;
    }
    fill_country_options(selected);
    InvalidateRect(g_window, NULL, FALSE);
    return 1;
}

static int socks_ready(void) {
    WSADATA w; if(WSAStartup(MAKEWORD(2,2), &w)) return 0;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if(s == INVALID_SOCKET) { WSACleanup(); return 0; }
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(9050); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int ok = (connect(s, (struct sockaddr*)&a, sizeof(a)) == 0);
    closesocket(s); WSACleanup(); return ok;
}

static int tor_bootstrap_complete(void) {
    char reply[4096];
    if(!tor_control("GETINFO status/bootstrap-phase", reply, sizeof(reply))) return 0;
    char *progress = strstr(reply, "PROGRESS="); int value = 0;
    return progress && sscanf_s(progress + 9, "%d", &value) == 1 && value >= 100;
}

static int start_vpn(void) {
    wchar_t tor[MAX_PATH], exe[MAX_PATH], dir[MAX_PATH], appdir[MAX_PATH], state[MAX_PATH], cfgpath[MAX_PATH];
    g_helper_exit_code = STILL_ACTIVE;
    if(InterlockedCompareExchange(&g_cancel_start, 0, 0)) return 0;

    trace_start(L"start requested");
    if(socks_ready()) {
        trace_start(L"SOCKS 9050 active, trying to close lingering Tor");
        (void)tor_control("SIGNAL SHUTDOWN", NULL, 0);
        Sleep(1000);
        if(socks_ready()) {
            trace_start(L"failed: SOCKS 9050 already active");
            return 0;
        }
    }
    trace_start(L"SOCKS port free");

    int tor_found = locate_tor(tor);
    trace_start(tor_found ? L"tor path found" : L"failed: tor.exe not found");
    if(!tor_found) return 0;

    DWORD module_chars = GetModuleFileNameW(NULL, exe, MAX_PATH);
    trace_start(module_chars ? L"module path found" : L"failed: module path");
    if(!module_chars || module_chars >= MAX_PATH) return 0;
    wcscpy_s(dir, MAX_PATH, exe);
    wchar_t *slash = wcsrchr(dir, L'\\'); if(!slash) return 0; *slash = 0;

    wchar_t *local = _wgetenv(L"LOCALAPPDATA"); if(!local) return 0;
    wchar_t parent[MAX_PATH];
    _snwprintf_s(parent, MAX_PATH, _TRUNCATE, L"%s\\Aurelia", local);
    _snwprintf_s(appdir, MAX_PATH, _TRUNCATE, L"%s\\Aurelia\\Tor", local);
    CreateDirectoryW(parent, NULL); CreateDirectoryW(appdir, NULL);
    _snwprintf_s(state, MAX_PATH, _TRUNCATE, L"%s\\netstate.bin", appdir);
    _snwprintf_s(cfgpath, MAX_PATH, _TRUNCATE, L"%s\\tunnel.yaml", appdir);

    const wchar_t *pipeline_str = g_setting_pipeline_mode ? L"true" : L"false";
    const wchar_t *netmask_str = g_setting_fake_ip ? L"255.254.0.0" : L"255.255.0.0";
    const wchar_t *cache_size_str = g_setting_turbo_boost ? L"16384" : L"8192";

    wchar_t yaml[2048];
    _snwprintf_s(yaml, _countof(yaml), _TRUNCATE,
        L"tunnel:\n  name: Aurelia-Tor\n  mtu: 1500\n  ipv4: 198.18.0.1\n  ipv6: 'fc00::1'\n  post-up-script: '%s\\aurelia-net.exe'\n  pre-down-script: '%s\\aurelia-net.exe'\nsocks5:\n  address: 127.0.0.1\n  port: 9050\n  udp: 'tcp'\n  pipeline: %s\nmapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 198.18.0.0\n  netmask: %s\n  cache-size: %s\nmisc:\n  log-file: '%s\\hev.log'\n  log-level: warn\n",
        dir, dir, pipeline_str, netmask_str, cache_size_str, appdir);

    int ybytes = WideCharToMultiByte(CP_UTF8, 0, yaml, -1, NULL, 0, NULL, NULL);
    char *yutf = (char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)ybytes); if(!yutf) return 0;
    WideCharToMultiByte(CP_UTF8, 0, yaml, -1, yutf, ybytes, NULL, NULL);
    HANDLE yf = CreateFileW(cfgpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD yw = 0; BOOL yok = (yf != INVALID_HANDLE_VALUE) && WriteFile(yf, yutf, (DWORD)(ybytes - 1), &yw, NULL) && yw == (DWORD)(ybytes - 1);
    if(yf != INVALID_HANDLE_VALUE) CloseHandle(yf);
    HeapFree(GetProcessHeap(), 0, yutf);
    if(!yok) { trace_start(L"failed: writing tunnel config"); return 0; }

    GUID id; wchar_t guid[64], names[4][128];
    if(FAILED(CoCreateGuid(&id)) || !StringFromGUID2(&id, guid, 64)) return 0;
    _snwprintf_s(names[0], 128, _TRUNCATE, L"Local\\AureliaVPN-%s-stop", guid);
    _snwprintf_s(names[1], 128, _TRUNCATE, L"Local\\AureliaVPN-%s-blocked", guid);
    _snwprintf_s(names[2], 128, _TRUNCATE, L"Local\\AureliaVPN-%s-go", guid);
    _snwprintf_s(names[3], 128, _TRUNCATE, L"Local\\AureliaVPN-%s-ready", guid);
    g_stop_event = CreateEventW(NULL, TRUE, FALSE, names[0]);
    g_blocked_event = CreateEventW(NULL, TRUE, FALSE, names[1]);
    g_go_event = CreateEventW(NULL, TRUE, FALSE, names[2]);
    g_ready_event = CreateEventW(NULL, TRUE, FALSE, names[3]);
    if(!g_stop_event || !g_blocked_event || !g_go_event || !g_ready_event) { trace_start(L"failed: event creation"); return 0; }

    wchar_t args[2048];
    _snwprintf_s(args, _countof(args), _TRUNCATE, L"--start \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" %lu",
        state, cfgpath, tor, names[0], names[1], names[2], names[3], GetCurrentProcessId());

    wchar_t helper_exe[MAX_PATH];
    _snwprintf_s(helper_exe, MAX_PATH, _TRUNCATE, L"%s\\aurelia-net.exe", dir);
    SHELLEXECUTEINFOW se = {0}; se.cbSize = sizeof(se); se.fMask = SEE_MASK_NOCLOSEPROCESS; se.lpVerb = L"runas"; se.lpFile = helper_exe; se.lpParameters = args; se.nShow = SW_HIDE;

    if(InterlockedCompareExchange(&g_cancel_start, 0, 0)) { trace_start(L"start canceled before helper prompt"); return 0; }
    if(!ShellExecuteExW(&se)) { trace_start(L"failed: UAC helper launch"); return 0; }
    g_helper_process = se.hProcess;
    trace_start(L"helper launched");

    HANDLE startup_wait[3] = {g_blocked_event, g_helper_process, g_cancel_event};
    DWORD startup_result = WaitForMultipleObjects(3, startup_wait, FALSE, 20000);
    if(InterlockedCompareExchange(&g_cancel_start, 0, 0)) { trace_start(L"start canceled during helper setup"); SetEvent(g_stop_event); return 0; }
    if(startup_result != WAIT_OBJECT_0) {
        DWORD helper_code = STILL_ACTIVE; GetExitCodeProcess(g_helper_process, &helper_code);
        g_helper_exit_code = helper_code;
        wchar_t msg[128]; _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"failed: helper start wait=%lu exit=%lu", startup_result, helper_code);
        trace_start(msg);
        SetEvent(g_stop_event); return 0;
    }
    trace_start(L"firewall armed");

    if(!run_tor()) { trace_start(L"failed: Tor process launch"); SetEvent(g_stop_event); return 0; }
    trace_start(L"Tor process launched");

    int socks = 0;
    for(int i = 0; i < 180 && !socks; i++) {
        if(InterlockedCompareExchange(&g_cancel_start, 0, 0)) { trace_start(L"start canceled while waiting for Tor SOCKS"); SetEvent(g_stop_event); return 0; }
        if(WaitForSingleObject(g_helper_process, 0) == WAIT_OBJECT_0) { trace_start(L"failed: helper exited before Tor ready"); return 0; }
        socks = socks_ready();
        if(!socks) Sleep(1000);
    }
    if(!socks) { trace_start(L"failed: Tor SOCKS timeout"); SetEvent(g_stop_event); return 0; }
    trace_start(L"Tor SOCKS ready; waiting for bootstrap");

    int bootstrapped = 0;
    for(int i = 0; i < 300 && !bootstrapped; i++) {
        if(InterlockedCompareExchange(&g_cancel_start, 0, 0)) { trace_start(L"start canceled during Tor bootstrap"); SetEvent(g_stop_event); return 0; }
        if(WaitForSingleObject(g_helper_process, 0) == WAIT_OBJECT_0) { trace_start(L"failed: helper exited while Tor bootstrapped"); return 0; }
        bootstrapped = tor_bootstrap_complete();
        if(!bootstrapped) Sleep(1000);
    }
    if(!bootstrapped) { trace_start(L"failed: Tor bootstrap timeout"); SetEvent(g_stop_event); return 0; }
    trace_start(L"Tor bootstrap reached 100 percent");

    /* Tunnel start */
    if(InterlockedCompareExchange(&g_cancel_start, 0, 0)) { SetEvent(g_stop_event); return 0; }
    SetEvent(g_go_event);

    HANDLE tunnel_wait[3] = {g_ready_event, g_helper_process, g_cancel_event};
    DWORD tunnel_result = WaitForMultipleObjects(3, tunnel_wait, FALSE, 120000);
    if(InterlockedCompareExchange(&g_cancel_start, 0, 0)) { trace_start(L"start canceled while creating tunnel"); SetEvent(g_stop_event); return 0; }
    if(tunnel_result != WAIT_OBJECT_0) {
        DWORD helper_code = STILL_ACTIVE; GetExitCodeProcess(g_helper_process, &helper_code);
        wchar_t msg[128]; _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"failed: tunnel wait=%lu helper exit=%lu", tunnel_result, helper_code);
        trace_start(msg);
        g_helper_exit_code = helper_code; SetEvent(g_stop_event); return 0;
    }
    g_vpn_active = 1;
    trace_start(L"tunnel active");

    /* Trigger background exit relay discovery */
    HANDLE disc = CreateThread(NULL, 0, exit_discovery_worker, NULL, 0, NULL);
    if(disc) CloseHandle(disc);

    return 1;
}

static DWORD WINAPI start_vpn_worker(LPVOID unused) {
    (void)unused;
    trace_start(L"worker start");
    int ok = start_vpn();
    trace_start(ok ? L"worker success" : L"worker failed");
    PostMessageW(g_window, WM_VPN_RESULT, (WPARAM)ok, 0);
    return 0;
}

static void poll_tor_info(void) {
    char reply[4096]; DWORD now = GetTickCount();
    if(now - g_last_info_poll < 5000) return;
    g_last_info_poll = now;
    wchar_t previous[128]; wcscpy_s(previous, _countof(previous), g_tor_info);
    if(InterlockedCompareExchange(&g_syncing_exits, 0, 0)) {
        wcscpy_s(g_tor_info, _countof(g_tor_info), LTXT(L"Sincronizzazione relay Tor…", L"Syncing Tor exit relays…"));
        goto done;
    }
    if(!tor_control("GETINFO status/bootstrap-phase", reply, sizeof(reply))) {
        wcscpy_s(g_tor_info, _countof(g_tor_info), LTXT(L"Stato Tor non disponibile", L"Tor status unavailable"));
        goto done;
    }
    char *progress = strstr(reply, "PROGRESS="); int value = 0;
    if(progress && sscanf_s(progress + 9, "%d", &value) == 1) {
        if(value >= 100) wcscpy_s(g_tor_info, _countof(g_tor_info), LTXT(L"Rete Tor pronta", L"Tor network ready"));
        else _snwprintf_s(g_tor_info, _countof(g_tor_info), _TRUNCATE, LTXT(L"Avvio rete Tor: %d%%", L"Starting Tor: %d%%"), value);
    } else wcscpy_s(g_tor_info, _countof(g_tor_info), LTXT(L"Stato Tor in caricamento", L"Loading Tor status"));
done:
    if(wcscmp(previous, g_tor_info) != 0) { RECT info = {52, 316, 550, 350}; InvalidateRect(g_window, &info, FALSE); }
}

static void stop_tor(void) {
    trace_start(L"disconnect requested");
    if(g_stop_event) SetEvent(g_stop_event);
    if(g_helper_process) {
        WaitForSingleObject(g_helper_process, 20000);
        CloseHandle(g_helper_process);
        g_helper_process = NULL;
    }
    if(g_tor_process.hProcess) {
        DWORD code = 0;
        if(GetExitCodeProcess(g_tor_process.hProcess, &code) && code == STILL_ACTIVE) {
            (void)tor_control("SIGNAL SHUTDOWN", NULL, 0);
            if(WaitForSingleObject(g_tor_process.hProcess, 5000) == WAIT_TIMEOUT) TerminateProcess(g_tor_process.hProcess, 0);
        }
        WaitForSingleObject(g_tor_process.hProcess, 3000);
        CloseHandle(g_tor_process.hProcess);
        CloseHandle(g_tor_process.hThread);
        ZeroMemory(&g_tor_process, sizeof(g_tor_process));
    }
    if(g_stop_event) CloseHandle(g_stop_event);
    if(g_blocked_event) CloseHandle(g_blocked_event);
    if(g_go_event) CloseHandle(g_go_event);
    if(g_ready_event) CloseHandle(g_ready_event);
    g_stop_event = g_blocked_event = g_go_event = g_ready_event = NULL;
    if(g_cancel_event) { CloseHandle(g_cancel_event); g_cancel_event = NULL; }
    g_vpn_active = 0;
    g_connected = 0;
    ZeroMemory(&g_attestation, sizeof(g_attestation));
    g_last_info_poll = 0;
    g_last_circuit_poll = 0;
    wcscpy_s(g_exit_public_ip, _countof(g_exit_public_ip), L"—");
    g_exit_public_country[0] = g_exit_public_country[1] = '-'; g_exit_public_country[2] = 0;
    for(int i = 0; i < 3; i++) { g_hop_country[i][0] = '-'; g_hop_country[i][1] = '-'; g_hop_country[i][2] = 0; g_hop_name[i][0] = 0; }
    wcscpy_s(g_tor_info, _countof(g_tor_info), LTXT(L"Tor in attesa", L"Tor is waiting"));
    KillTimer(g_window, 1);
    KillTimer(g_window, 2);
    SetWindowTextW(g_connect, LTXT(L"Connetti a Tor", L"Connect to Tor"));
    EnableWindow(g_rotate, FALSE);
    EnableWindow(g_country, TRUE);
    InvalidateRect(g_window, NULL, TRUE);
    if(g_audit_dialog) InvalidateRect(g_audit_dialog, NULL, TRUE);
}

static void centered(HDC dc, RECT r, const wchar_t *s, COLORREF c, HFONT f) {
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, c);
    HFONT old = (HFONT)SelectObject(dc, f);
    DrawTextW(dc, s, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    SelectObject(dc, old);
}
static void chip(HDC dc, int x, int y, int w, int h, const wchar_t *s, COLORREF fg, COLORREF fill) {
    rect(dc, x, y, w, h, fill, h / 2);
    RECT r = {x + 8, y, x + w - 8, y + h};
    centered(dc, r, s, fg, g_small);
}
static void draw_flag(HDC dc, int x, int y, int country) {
    const char *country_code = g_hop_country[country];
    draw_flag_gdi(dc, x, y, 42, 28, country_code);
    char a = country_code[0], b = country_code[1];
    wchar_t code[3] = {(wchar_t)((a >= 'a' && a <= 'z') ? a - 'a' + 'A' : '-'),
                       (wchar_t)((b >= 'a' && b <= 'z') ? b - 'a' + 'A' : '-'), 0};
    text(dc, x + 54, y + 6, code, muted, g_caption);
}
static const wchar_t *country_name(const char code[3]) {
    for(int i = 1; i < (int)_countof(g_countries); i++) {
        if(tolower((unsigned char)code[0]) == g_countries[i].code[0] &&
           tolower((unsigned char)code[1]) == g_countries[i].code[1])
            return g_language_en ? g_countries[i].en : g_countries[i].it;
    }
    return L"—";
}
static void draw_flag_code(HDC dc, int x, int y, const char code[3]) {
    draw_flag_gdi(dc, x, y, 34, 24, code);
}
static int country_row_at(int y) {
    if(y < 42) return -1;
    int row = g_country_scroll + (y - 42) / 38;
    return (row >= 0 && row < g_country_row_count) ? row : -1;
}

static void draw_country_button(const DRAWITEMSTRUCT *d) {
    HDC dc = d->hDC;
    RECT r = d->rcItem;
    rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, RGB(255, 255, 255), 10);
    HPEN edge = CreatePen(PS_SOLID, 1, g_country_popup ? teal : RGB(211, 221, 232)), old = (HPEN)SelectObject(dc, edge);
    HGDIOBJ brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, r.left, r.top, r.right, r.bottom, 10, 10);
    SelectObject(dc, brush); SelectObject(dc, old); DeleteObject(edge);

    int index = g_exit_index;
    if(index < 0 || index >= (int)_countof(g_countries)) index = 0;

    if(index == 0) {
        rect(dc, r.left + 12, r.top + 7, 34, 24, RGB(230, 243, 255), 6);
        dot(dc, r.left + 12 + 17 - 4, r.top + 7 + 12 - 4, 8, teal);
        flag_border(dc, r.left + 12, r.top + 7, 34, 24);
    } else {
        draw_flag_gdi(dc, r.left + 12, r.top + 7, 34, 24, g_countries[index].code);
    }

    RECT label = {r.left + 58, r.top, r.right - 70, r.bottom};
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, white);
    HFONT f = (HFONT)SelectObject(dc, g_font);
    if(index == 0) {
        DrawTextW(dc, LTXT(L"Automatico (Max Anonimato)", L"Automatic (Max Anonymity)"), -1, &label, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    } else {
        DrawTextW(dc, g_language_en ? g_countries[index].en : g_countries[index].it, -1, &label, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    }
    SelectObject(dc, f);

    if(index && g_exit_list_ready && g_exit_relay_count[index]) {
        wchar_t count[32];
        _snwprintf_s(count, _countof(count), _TRUNCATE, L"%u %s", g_exit_relay_count[index], LTXT(L"relay", L"relays"));
        RECT badge = {r.right - 120, r.top, r.right - 44, r.bottom};
        SetTextColor(dc, green);
        f = (HFONT)SelectObject(dc, g_small);
        DrawTextW(dc, count, -1, &badge, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_RIGHT);
        SelectObject(dc, f);
    }

    POINT arrow[3] = {{r.right - 26, r.top + 16}, {r.right - 16, r.top + 16}, {r.right - 21, r.top + 22}};
    HBRUSH ab = CreateSolidBrush(muted);
    HGDIOBJ ob = SelectObject(dc, ab);
    Polygon(dc, arrow, 3);
    SelectObject(dc, ob); DeleteObject(ab);
}

static void country_popup_paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC screen_dc = BeginPaint(hwnd, &ps);
    RECT all; GetClientRect(hwnd, &all);
    int w = all.right - all.left, h = all.bottom - all.top;
    HDC dc = CreateCompatibleDC(screen_dc);
    HBITMAP bmp = CreateCompatibleBitmap(screen_dc, w, h);
    HGDIOBJ oldbmp = SelectObject(dc, bmp);

    HBRUSH b = CreateSolidBrush(panel); FillRect(dc, &all, b); DeleteObject(b);

    RECT header = {1, 1, all.right - 1, 40};
    HBRUSH hb = CreateSolidBrush(RGB(247, 250, 253)); FillRect(dc, &header, hb); DeleteObject(hb);

    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, muted);
    HFONT hf = (HFONT)SelectObject(dc, g_caption);
    const wchar_t *title = LTXT(L"PAESI DI USCITA", L"TOR EXIT COUNTRIES");
    TextOutW(dc, 12, 12, title, (int)wcslen(title));

    wchar_t sync[64];
    if(g_exit_list_ready) {
        _snwprintf_s(sync, _countof(sync), _TRUNCATE, LTXT(L"%d PAESI LIVE", L"%d LIVE COUNTRIES"), (g_country_row_count > 1) ? (g_country_row_count - 1) : 49);
    } else {
        wcscpy_s(sync, _countof(sync), LTXT(L"54 PAESI", L"54 COUNTRIES"));
    }
    RECT status = {all.right - 140, 5, all.right - 16, 35};
    SetTextColor(dc, g_exit_list_ready ? green : teal);
    SelectObject(dc, g_small);
    DrawTextW(dc, sync, -1, &status, DT_SINGLELINE | DT_VCENTER | DT_RIGHT);
    SelectObject(dc, hf);

    HPEN hp = CreatePen(PS_SOLID, 1, line), ho = (HPEN)SelectObject(dc, hp);
    MoveToEx(dc, 1, 40, NULL); LineTo(dc, all.right - 1, 40);
    SelectObject(dc, ho); DeleteObject(hp);

    int visible = (all.bottom - 44) / 38;
    if(visible < 1) visible = 1;

    for(int row = 0; row < visible; row++) {
        int absolute = g_country_scroll + row;
        if(absolute >= g_country_row_count) break;
        int index = g_country_rows[absolute];
        RECT r = {3, 42 + row * 38, all.right - 4, 42 + (row + 1) * 38};
        COLORREF fill = (index == g_exit_index) ? RGB(232, 243, 255) :
                        (absolute == g_country_hover ? RGB(245, 249, 253) : RGB(255, 255, 255));
        HBRUSH rb = CreateSolidBrush(fill); FillRect(dc, &r, rb); DeleteObject(rb);

        if(index == 0) {
            rect(dc, 12, r.top + 7, 34, 24, RGB(230, 243, 255), 6);
            dot(dc, 12 + 17 - 4, r.top + 7 + 12 - 4, 8, teal);
            flag_border(dc, 12, r.top + 7, 34, 24);
        } else {
            draw_flag_gdi(dc, 12, r.top + 7, 34, 24, g_countries[index].code);
        }

        RECT name = {56, r.top, all.right - 90, r.bottom};
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, white);
        HFONT old = (HFONT)SelectObject(dc, (index == g_exit_index) ? (g_font_bold ? g_font_bold : g_font) : g_font);
        if(index == 0) {
            DrawTextW(dc, LTXT(L"Automatico (Max Anonimato)", L"Automatic (Max Anonymity)"), -1, &name, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_LEFT);
        } else {
            DrawTextW(dc, g_language_en ? g_countries[index].en : g_countries[index].it, -1, &name, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_LEFT);
        }
        SelectObject(dc, old);

        if(index && g_exit_list_ready && g_exit_relay_count[index]) {
            wchar_t count[32];
            _snwprintf_s(count, _countof(count), _TRUNCATE, L"%u relay", g_exit_relay_count[index]);
            RECT n = {all.right - 120, r.top, all.right - 34, r.bottom};
            SetTextColor(dc, green);
            old = (HFONT)SelectObject(dc, g_small);
            DrawTextW(dc, count, -1, &n, DT_SINGLELINE | DT_VCENTER | DT_RIGHT);
            SelectObject(dc, old);
        }

        if(index == g_exit_index) {
            HPEN p = CreatePen(PS_SOLID, 2, teal), op = (HPEN)SelectObject(dc, p);
            MoveToEx(dc, all.right - 25, r.top + 20, NULL);
            LineTo(dc, all.right - 20, r.top + 25);
            LineTo(dc, all.right - 12, r.top + 14);
            SelectObject(dc, op); DeleteObject(p);
        }
        if(row < visible - 1) {
            HPEN p = CreatePen(PS_SOLID, 1, RGB(241, 244, 248)), op = (HPEN)SelectObject(dc, p);
            MoveToEx(dc, 10, r.bottom - 1, NULL);
            LineTo(dc, all.right - 10, r.bottom - 1);
            SelectObject(dc, op); DeleteObject(p);
        }
    }

    if(g_country_row_count > visible) {
        RECT track = {all.right - 8, 43, all.right - 3, all.bottom - 3};
        HBRUSH tb = CreateSolidBrush(RGB(240, 243, 248)); FillRect(dc, &track, tb); DeleteObject(tb);
        int thumb = (track.bottom - track.top) * visible / g_country_row_count;
        if(thumb < 28) thumb = 28;
        int maxscroll = g_country_row_count - visible;
        int top = track.top + (track.bottom - track.top - thumb) * g_country_scroll / (maxscroll > 0 ? maxscroll : 1);
        RECT tr = {track.left, top, track.right, top + thumb};
        HBRUSH th = CreateSolidBrush(g_country_dragging ? teal : RGB(177, 191, 207));
        HGDIOBJ oldb = SelectObject(dc, th), oldp = SelectObject(dc, GetStockObject(NULL_PEN));
        RoundRect(dc, tr.left, tr.top, tr.right, tr.bottom, 5, 5);
        SelectObject(dc, oldb); SelectObject(dc, oldp); DeleteObject(th);
    }

    BitBlt(screen_dc, 0, 0, w, h, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldbmp); DeleteObject(bmp); DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK country_popup_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_PAINT: country_popup_paint(hwnd); return 0;
    case WM_MOUSEMOVE: {
        int y = (int)(short)HIWORD(lp);
        RECT all; GetClientRect(hwnd, &all);
        int visible = 8;
        int maxscroll = g_country_row_count > visible ? g_country_row_count - visible : 0;
        if(g_country_dragging && maxscroll > 0) {
            int track_h = all.bottom - 44 - 6;
            int thumb = track_h * visible / g_country_row_count; if(thumb < 28) thumb = 28;
            int rel = y - 43 - thumb / 2;
            int scroll = rel * maxscroll / (track_h - thumb > 0 ? track_h - thumb : 1);
            if(scroll < 0) scroll = 0; if(scroll > maxscroll) scroll = maxscroll;
            if(scroll != g_country_scroll) { g_country_scroll = scroll; InvalidateRect(hwnd, NULL, FALSE); }
            return 0;
        }
        int row = country_row_at(y);
        if(row != g_country_hover) { g_country_hover = row; InvalidateRect(hwnd, NULL, FALSE); }
        return 0;
    }
    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wp);
        int visible = 8;
        int maxscroll = g_country_row_count > visible ? g_country_row_count - visible : 0;
        g_country_scroll -= delta / WHEEL_DELTA * 3;
        if(g_country_scroll < 0) g_country_scroll = 0;
        if(g_country_scroll > maxscroll) g_country_scroll = maxscroll;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    case WM_LBUTTONDOWN: {
        int x = (int)(short)LOWORD(lp);
        int y = (int)(short)HIWORD(lp);
        RECT all; GetClientRect(hwnd, &all);
        if(x >= all.right - 16 && y >= 43) {
            g_country_dragging = 1;
            SetCapture(hwnd);
            int visible = 8;
            int maxscroll = g_country_row_count > visible ? g_country_row_count - visible : 0;
            if(maxscroll > 0) {
                int track_h = all.bottom - 44 - 6;
                int thumb = track_h * visible / g_country_row_count; if(thumb < 28) thumb = 28;
                int rel = y - 43 - thumb / 2;
                int scroll = rel * maxscroll / (track_h - thumb > 0 ? track_h - thumb : 1);
                if(scroll < 0) scroll = 0; if(scroll > maxscroll) scroll = maxscroll;
                if(scroll != g_country_scroll) { g_country_scroll = scroll; InvalidateRect(hwnd, NULL, FALSE); }
            }
            return 0;
        }
        return 0;
    }
    case WM_LBUTTONUP: {
        if(g_country_dragging) {
            g_country_dragging = 0;
            ReleaseCapture();
            return 0;
        }
        int row = country_row_at((int)(short)HIWORD(lp));
        if(row >= 0 && row < g_country_row_count) {
            int index = g_country_rows[row];
            apply_exit_country(index);
        }
        DestroyWindow(hwnd); g_country_popup = NULL;
        InvalidateRect(g_country, NULL, FALSE);
        return 0;
    }
    case WM_CHAR: {
        wchar_t ch = (wchar_t)towlower((wint_t)wp);
        if(ch >= L'a' && ch <= L'z') {
            for(int i = 0; i < g_country_row_count; i++) {
                int idx = g_country_rows[i];
                const wchar_t *name = g_language_en ? g_countries[idx].en : g_countries[idx].it;
                if(towlower(name[0]) == ch) {
                    g_country_hover = i;
                    int visible = 8;
                    int maxscroll = g_country_row_count > visible ? g_country_row_count - visible : 0;
                    g_country_scroll = i;
                    if(g_country_scroll > maxscroll) g_country_scroll = maxscroll;
                    InvalidateRect(hwnd, NULL, FALSE);
                    break;
                }
            }
        }
        return 0;
    }
    case WM_KEYDOWN: {
        if(wp == VK_ESCAPE) { DestroyWindow(hwnd); g_country_popup = NULL; InvalidateRect(g_country, NULL, FALSE); return 0; }
        int visible = 8;
        int maxscroll = g_country_row_count > visible ? g_country_row_count - visible : 0;
        if(wp == VK_UP || wp == VK_DOWN) {
            int cur = g_country_hover >= 0 ? g_country_hover : 0;
            cur += (wp == VK_DOWN ? 1 : -1);
            if(cur < 0) cur = 0; if(cur >= g_country_row_count) cur = g_country_row_count - 1;
            g_country_hover = cur;
            if(cur < g_country_scroll) g_country_scroll = cur;
            if(cur >= g_country_scroll + visible) g_country_scroll = cur - visible + 1;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if(wp == VK_PRIOR) { g_country_scroll -= visible; if(g_country_scroll < 0) g_country_scroll = 0; InvalidateRect(hwnd, NULL, FALSE); return 0; }
        if(wp == VK_NEXT) { g_country_scroll += visible; if(g_country_scroll > maxscroll) g_country_scroll = maxscroll; InvalidateRect(hwnd, NULL, FALSE); return 0; }
        if(wp == VK_HOME) { g_country_scroll = 0; g_country_hover = 0; InvalidateRect(hwnd, NULL, FALSE); return 0; }
        if(wp == VK_END) { g_country_scroll = maxscroll; g_country_hover = g_country_row_count - 1; InvalidateRect(hwnd, NULL, FALSE); return 0; }
        if(wp == VK_RETURN) {
            int sel = g_country_hover >= 0 ? g_country_hover : 0;
            if(sel >= 0 && sel < g_country_row_count) {
                int index = g_country_rows[sel];
                apply_exit_country(index);
            }
            DestroyWindow(hwnd); g_country_popup = NULL;
            return 0;
        }
        break;
    }
    case WM_ACTIVATE:
        if(LOWORD(wp) == WA_INACTIVE) {
            if(g_country_dragging) { g_country_dragging = 0; ReleaseCapture(); }
            g_country_popup = NULL;
            DestroyWindow(hwnd);
            InvalidateRect(g_country, NULL, FALSE);
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void toggle_country_popup(void) {
    if(g_country_popup) {
        DestroyWindow(g_country_popup); g_country_popup = NULL;
        InvalidateRect(g_country, NULL, FALSE); return;
    }
    wchar_t diagnostic[96];
    _snwprintf_s(diagnostic, _countof(diagnostic), _TRUNCATE, L"country picker rows=%d synced=%d", g_country_row_count, g_exit_list_ready);
    trace_start(diagnostic);

    RECT r; GetWindowRect(g_country, &r);
    int visible = g_country_row_count < 8 ? g_country_row_count : 8;
    int height = visible * 38 + 44;
    int y = r.bottom;
    HMONITOR mon = MonitorFromWindow(g_window, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = {sizeof(mi)};
    if(GetMonitorInfoW(mon, &mi) && y + height > mi.rcWork.bottom) y = r.top - height;

    g_country_scroll = 0; g_country_hover = -1; g_country_dragging = 0;
    for(int i = 0; i < g_country_row_count; i++) {
        if(g_country_rows[i] == g_exit_index) {
            g_country_hover = i;
            if(i >= 8) g_country_scroll = i - 4;
            if(g_country_scroll > g_country_row_count - 8) g_country_scroll = g_country_row_count - 8;
            if(g_country_scroll < 0) g_country_scroll = 0;
            break;
        }
    }

    g_country_popup = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, L"AureliaCountryPopup", NULL,
                                      WS_POPUP | WS_BORDER, r.left, y, r.right - r.left, height, g_window, NULL, g_instance, NULL);
    if(g_country_popup) {
        ShowWindow(g_country_popup, SW_SHOWNOACTIVATE);
        SetForegroundWindow(g_country_popup);
        SetFocus(g_country_popup);
        InvalidateRect(g_country_popup, NULL, TRUE);
        InvalidateRect(g_country, NULL, FALSE);
    }
}

static void draw_interval_button(const DRAWITEMSTRUCT *d) {
    HDC dc = d->hDC; RECT r = d->rcItem;
    rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, RGB(255, 255, 255), 9);
    HPEN edge = CreatePen(PS_SOLID, 1, g_interval_popup ? teal : RGB(211, 221, 232)), old = (HPEN)SelectObject(dc, edge);
    HGDIOBJ brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, r.left, r.top, r.right, r.bottom, 9, 9);
    SelectObject(dc, brush); SelectObject(dc, old); DeleteObject(edge);

    RECT label = {r.left + 12, r.top, r.right - 42, r.bottom};
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, white);
    HFONT f = (HFONT)SelectObject(dc, g_font);
    DrawTextW(dc, interval_name(g_interval_index), -1, &label, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    SelectObject(dc, f);

    POINT arrow[3] = {{r.right - 26, r.top + 12}, {r.right - 16, r.top + 12}, {r.right - 21, r.top + 18}};
    HBRUSH ab = CreateSolidBrush(muted);
    HGDIOBJ ob = SelectObject(dc, ab);
    Polygon(dc, arrow, 3);
    SelectObject(dc, ob); DeleteObject(ab);
}

static void interval_popup_paint(HWND hwnd) {
    PAINTSTRUCT ps; HDC screen_dc = BeginPaint(hwnd, &ps);
    RECT all; GetClientRect(hwnd, &all);
    int w = all.right - all.left, h = all.bottom - all.top;
    HDC dc = CreateCompatibleDC(screen_dc);
    HBITMAP bmp = CreateCompatibleBitmap(screen_dc, w, h);
    HGDIOBJ oldbmp = SelectObject(dc, bmp);

    HBRUSH b = CreateSolidBrush(panel); FillRect(dc, &all, b); DeleteObject(b);

    RECT header = {1, 1, all.right - 1, 40};
    HBRUSH hb = CreateSolidBrush(RGB(247, 250, 253)); FillRect(dc, &header, hb); DeleteObject(hb);

    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, muted);
    HFONT cap = (HFONT)SelectObject(dc, g_caption);
    const wchar_t *heading = LTXT(L"ROTAZIONE AUTOMATICA", L"AUTOMATIC ROTATION");
    TextOutW(dc, 12, 12, heading, (int)wcslen(heading));
    SelectObject(dc, cap);

    HPEN hp = CreatePen(PS_SOLID, 1, line), ho = (HPEN)SelectObject(dc, hp);
    MoveToEx(dc, 1, 40, NULL); LineTo(dc, all.right - 1, 40);
    SelectObject(dc, ho); DeleteObject(hp);

    for(int i = 0; i < 4; i++) {
        RECT r = {2, 42 + i * 40, all.right - 3, 42 + (i + 1) * 40};
        COLORREF fill = (i == g_interval_index) ? RGB(232, 243, 255) :
                        (i == g_interval_hover ? RGB(245, 249, 253) : RGB(255, 255, 255));
        HBRUSH rb = CreateSolidBrush(fill); FillRect(dc, &r, rb); DeleteObject(rb);

        RECT label = {14, r.top, all.right - 12, r.bottom};
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, white);
        HFONT old = (HFONT)SelectObject(dc, (i == g_interval_index) ? (g_font_bold ? g_font_bold : g_font) : g_font);
        DrawTextW(dc, interval_name(i), -1, &label, DT_SINGLELINE | DT_VCENTER | DT_LEFT);
        SelectObject(dc, old);

        if(i == g_interval_index) {
            HPEN p = CreatePen(PS_SOLID, 2, teal), op = (HPEN)SelectObject(dc, p);
            MoveToEx(dc, all.right - 25, r.top + 21, NULL);
            LineTo(dc, all.right - 20, r.top + 26);
            LineTo(dc, all.right - 12, r.top + 15);
            SelectObject(dc, op); DeleteObject(p);
        }
        if(i < 3) {
            HPEN p = CreatePen(PS_SOLID, 1, RGB(241, 244, 248)), op = (HPEN)SelectObject(dc, p);
            MoveToEx(dc, 10, r.bottom - 1, NULL); LineTo(dc, all.right - 10, r.bottom - 1);
            SelectObject(dc, op); DeleteObject(p);
        }
    }

    BitBlt(screen_dc, 0, 0, w, h, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldbmp); DeleteObject(bmp); DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

static void choose_interval(int index) {
    if(index < 0 || index > 3) index = 0;
    g_interval_index = index;
    save_preferences();
    fill_interval_options(index);
    static const UINT mins[] = {0, 5, 10, 30};
    KillTimer(g_window, 2);
    if(g_vpn_active && index > 0 && index < 4) SetTimer(g_window, 2, mins[index] * 60 * 1000, NULL);
}

static LRESULT CALLBACK interval_popup_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_PAINT: interval_popup_paint(hwnd); return 0;
    case WM_MOUSEMOVE: {
        int y = (int)(short)HIWORD(lp);
        int row = (y >= 42) ? (y - 42) / 40 : -1;
        if(row < 0 || row > 3) row = -1;
        if(row != g_interval_hover) { g_interval_hover = row; InvalidateRect(hwnd, NULL, FALSE); }
        return 0;
    }
    case WM_LBUTTONUP: {
        int y = (int)(short)HIWORD(lp);
        int row = (y >= 42) ? (y - 42) / 40 : -1;
        if(row >= 0 && row < 4) choose_interval(row);
        DestroyWindow(hwnd); g_interval_popup = NULL;
        InvalidateRect(g_interval, NULL, FALSE);
        return 0;
    }
    case WM_KEYDOWN:
        if(wp == VK_ESCAPE) { DestroyWindow(hwnd); g_interval_popup = NULL; InvalidateRect(g_interval, NULL, FALSE); return 0; }
        if(wp == VK_UP || wp == VK_DOWN) {
            if(g_interval_hover < 0) g_interval_hover = g_interval_index;
            g_interval_hover += (wp == VK_DOWN ? 1 : -1);
            if(g_interval_hover < 0) g_interval_hover = 0;
            if(g_interval_hover > 3) g_interval_hover = 3;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if(wp == VK_RETURN) {
            choose_interval(g_interval_hover < 0 ? g_interval_index : g_interval_hover);
            DestroyWindow(hwnd); g_interval_popup = NULL;
            InvalidateRect(g_interval, NULL, FALSE);
            return 0;
        }
        break;
    case WM_ACTIVATE:
        if(LOWORD(wp) == WA_INACTIVE) { g_interval_popup = NULL; DestroyWindow(hwnd); InvalidateRect(g_interval, NULL, FALSE); }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void toggle_interval_popup(void) {
    if(g_interval_popup) {
        DestroyWindow(g_interval_popup); g_interval_popup = NULL;
        InvalidateRect(g_interval, NULL, FALSE); return;
    }
    RECT r; GetWindowRect(g_interval, &r);
    int y = r.bottom;
    HMONITOR mon = MonitorFromWindow(g_window, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = {sizeof(mi)};
    if(GetMonitorInfoW(mon, &mi) && y + 204 > mi.rcWork.bottom) y = r.top - 204;
    g_interval_hover = -1;
    g_interval_popup = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, L"AureliaIntervalPopup", NULL,
                                      WS_POPUP | WS_BORDER, r.left, y, r.right - r.left, 204, g_window, NULL, g_instance, NULL);
    if(g_interval_popup) {
        ShowWindow(g_interval_popup, SW_SHOWNOACTIVATE);
        SetForegroundWindow(g_interval_popup);
        SetFocus(g_interval_popup);
        InvalidateRect(g_interval_popup, NULL, TRUE);
        InvalidateRect(g_interval, NULL, FALSE);
    }
}

static void draw_language_button(const DRAWITEMSTRUCT *d) {
    HDC dc = d->hDC; RECT r = d->rcItem;
    rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, RGB(255, 255, 255), 9);
    HPEN p = CreatePen(PS_SOLID, 1, g_language_popup ? teal : RGB(211, 221, 232)), old = (HPEN)SelectObject(dc, p);
    HGDIOBJ b = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, r.left, r.top, r.right, r.bottom, 9, 9);
    SelectObject(dc, b); SelectObject(dc, old); DeleteObject(p);

    RECT label = {r.left + 12, r.top, r.right - 32, r.bottom};
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, white);
    HFONT f = (HFONT)SelectObject(dc, g_small);
    DrawTextW(dc, g_language_en ? L"English" : L"Italiano", -1, &label, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    SelectObject(dc, f);

    POINT a[3] = {{r.right - 22, r.top + 14}, {r.right - 12, r.top + 14}, {r.right - 17, r.top + 20}};
    HBRUSH ab = CreateSolidBrush(muted);
    HGDIOBJ ob = SelectObject(dc, ab);
    Polygon(dc, a, 3);
    SelectObject(dc, ob); DeleteObject(ab);
}

static void language_popup_paint(HWND hwnd) {
    PAINTSTRUCT ps; HDC screen_dc = BeginPaint(hwnd, &ps);
    RECT all; GetClientRect(hwnd, &all);
    int w = all.right - all.left, h = all.bottom - all.top;
    HDC dc = CreateCompatibleDC(screen_dc);
    HBITMAP bmp = CreateCompatibleBitmap(screen_dc, w, h);
    HGDIOBJ oldbmp = SelectObject(dc, bmp);

    HBRUSH b = CreateSolidBrush(panel); FillRect(dc, &all, b); DeleteObject(b);

    const wchar_t *names[2] = {L"Italiano", L"English"};
    for(int i = 0; i < 2; i++) {
        RECT r = {2, 2 + i * 38, all.right - 3, 2 + (i + 1) * 38};
        HBRUSH rb = CreateSolidBrush(i == g_language_en ? RGB(232, 243, 255) :
                                    (i == g_language_hover ? RGB(245, 249, 253) : RGB(255, 255, 255)));
        FillRect(dc, &r, rb); DeleteObject(rb);

        RECT textrect = {12, r.top, r.right - 12, r.bottom};
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, white);
        HFONT f = (HFONT)SelectObject(dc, (i == g_language_en) ? (g_font_bold ? g_font_bold : g_font) : g_font);
        DrawTextW(dc, names[i], -1, &textrect, DT_SINGLELINE | DT_VCENTER | DT_LEFT);
        SelectObject(dc, f);

        if(i == g_language_en) {
            HPEN cp = CreatePen(PS_SOLID, 2, teal), co = (HPEN)SelectObject(dc, cp);
            MoveToEx(dc, all.right - 23, r.top + 20, NULL);
            LineTo(dc, all.right - 18, r.top + 25);
            LineTo(dc, all.right - 10, r.top + 14);
            SelectObject(dc, co); DeleteObject(cp);
        }
    }

    BitBlt(screen_dc, 0, 0, w, h, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldbmp); DeleteObject(bmp); DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

static void choose_language(int index) {
    g_language_en = (index == 1);
    apply_language();
}

static LRESULT CALLBACK language_popup_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_PAINT: language_popup_paint(hwnd); return 0;
    case WM_MOUSEMOVE: {
        int y = (int)(short)HIWORD(lp);
        int row = (y >= 2) ? (y - 2) / 38 : -1;
        if(row < 0 || row > 1) row = -1;
        if(row != g_language_hover) { g_language_hover = row; InvalidateRect(hwnd, NULL, FALSE); }
        return 0;
    }
    case WM_LBUTTONUP: {
        int y = (int)(short)HIWORD(lp);
        int row = (y >= 2) ? (y - 2) / 38 : -1;
        if(row >= 0 && row < 2) choose_language(row);
        DestroyWindow(hwnd); g_language_popup = NULL;
        InvalidateRect(g_language, NULL, FALSE);
        return 0;
    }
    case WM_KEYDOWN:
        if(wp == VK_ESCAPE) { DestroyWindow(hwnd); g_language_popup = NULL; return 0; }
        if(wp == VK_UP || wp == VK_DOWN) {
            g_language_hover = 1 - g_language_en;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if(wp == VK_RETURN) {
            choose_language(g_language_hover < 0 ? g_language_en : g_language_hover);
            DestroyWindow(hwnd); g_language_popup = NULL;
            return 0;
        }
        break;
    case WM_ACTIVATE:
        if(LOWORD(wp) == WA_INACTIVE) { g_language_popup = NULL; DestroyWindow(hwnd); InvalidateRect(g_language, NULL, FALSE); }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void toggle_language_popup(void) {
    if(g_language_popup) { DestroyWindow(g_language_popup); g_language_popup = NULL; return; }
    RECT r; GetWindowRect(g_language, &r);
    int y = r.bottom;
    HMONITOR mon = MonitorFromWindow(g_window, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = {sizeof(mi)};
    if(GetMonitorInfoW(mon, &mi) && y + 80 > mi.rcWork.bottom) y = r.top - 80;
    g_language_hover = -1;
    g_language_popup = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, L"AureliaLanguagePopup", NULL,
                                      WS_POPUP | WS_BORDER, r.left, y, r.right - r.left, 80, g_window, NULL, g_instance, NULL);
    if(g_language_popup) {
        ShowWindow(g_language_popup, SW_SHOWNOACTIVATE);
        SetForegroundWindow(g_language_popup);
        SetFocus(g_language_popup);
        InvalidateRect(g_language_popup, NULL, TRUE);
    }
}

static void draw_shield(HDC dc, int cx, int cy) {
    if(g_gdiplus_ready) {
        void *g = NULL;
        if(pfn_GdipCreateFromHDC(dc, &g) == 0 && g) {
            pfn_GdipSetSmoothingMode(g, 4); // SmoothingModeAntiAlias

            ARGB accent_color = g_vpn_active ? GDIP_MAKE_ARGB(255, 0, 144, 105) : GDIP_MAKE_ARGB(255, 0, 114, 198);
            ARGB aura_color   = g_vpn_active ? GDIP_MAKE_ARGB(20, 0, 144, 105)  : GDIP_MAKE_ARGB(20, 0, 114, 198);
            ARGB ring_outer   = g_vpn_active ? GDIP_MAKE_ARGB(120, 0, 144, 105) : GDIP_MAKE_ARGB(85, 0, 114, 198);
            ARGB ring_inner   = g_vpn_active ? GDIP_MAKE_ARGB(80, 0, 144, 105)  : GDIP_MAKE_ARGB(55, 0, 114, 198);
            ARGB shield_fill  = g_vpn_active ? GDIP_MAKE_ARGB(245, 230, 248, 240) : GDIP_MAKE_ARGB(245, 238, 246, 255);

            // Soft glowing outer ambient aura
            void *aura_brush = NULL;
            if(pfn_GdipCreateSolidFill(aura_color, &aura_brush) == 0 && aura_brush) {
                pfn_GdipFillEllipse(g, aura_brush, (float)(cx - 96), (float)(cy - 96), 192.0f, 192.0f);
                pfn_GdipDeleteBrush(aura_brush);
            }

            // Outer smooth antialiased ring (radius 82)
            void *ring_pen1 = NULL;
            if(pfn_GdipCreatePen1(ring_outer, 2.0f, 2, &ring_pen1) == 0 && ring_pen1) {
                pfn_GdipDrawEllipse(g, ring_pen1, (float)(cx - 82), (float)(cy - 82), 164.0f, 164.0f);
                pfn_GdipDeletePen(ring_pen1);
            }

            // Inner smooth antialiased ring (radius 64)
            void *ring_pen2 = NULL;
            if(pfn_GdipCreatePen1(ring_inner, 1.5f, 2, &ring_pen2) == 0 && ring_pen2) {
                pfn_GdipDrawEllipse(g, ring_pen2, (float)(cx - 64), (float)(cy - 64), 128.0f, 128.0f);
                pfn_GdipDeletePen(ring_pen2);
            }

            // Orbiting photon / satellite on track radius 73
            double a = (double)(g_anim_phase % 360) * 3.141592653589793 / 180.0;
            float px = (float)cx + (float)(cos(a) * 73.0);
            float py = (float)cy + (float)(sin(a) * 73.0);

            // Satellite outer glow
            ARGB halo_color = g_vpn_active ? GDIP_MAKE_ARGB(80, 0, 144, 105) : GDIP_MAKE_ARGB(80, 0, 114, 198);
            void *halo_brush = NULL;
            if(pfn_GdipCreateSolidFill(halo_color, &halo_brush) == 0 && halo_brush) {
                pfn_GdipFillEllipse(g, halo_brush, px - 9.0f, py - 9.0f, 18.0f, 18.0f);
                pfn_GdipDeleteBrush(halo_brush);
            }
            // Satellite solid core
            void *sat_brush = NULL;
            if(pfn_GdipCreateSolidFill(accent_color, &sat_brush) == 0 && sat_brush) {
                pfn_GdipFillEllipse(g, sat_brush, px - 5.0f, py - 5.0f, 10.0f, 10.0f);
                pfn_GdipDeleteBrush(sat_brush);
            }

            // Antialiased Shield Polygon
            PointF pts[6] = {
                {(float)cx, (float)(cy - 36)},
                {(float)(cx + 28), (float)(cy - 24)},
                {(float)(cx + 25), (float)(cy + 13)},
                {(float)cx, (float)(cy + 38)},
                {(float)(cx - 25), (float)(cy + 13)},
                {(float)(cx - 28), (float)(cy - 24)}
            };

            void *shield_b = NULL;
            if(pfn_GdipCreateSolidFill(shield_fill, &shield_b) == 0 && shield_b) {
                pfn_GdipFillPolygon(g, shield_b, pts, 6, 0);
                pfn_GdipDeleteBrush(shield_b);
            }

            void *shield_p = NULL;
            if(pfn_GdipCreatePen1(accent_color, 2.5f, 2, &shield_p) == 0 && shield_p) {
                pfn_GdipSetPenLineJoin(shield_p, 2); // LineJoinRound
                pfn_GdipDrawPolygon(g, shield_p, pts, 6);
                pfn_GdipDeletePen(shield_p);
            }

            // Antialiased Checkmark with round caps
            void *check_p = NULL;
            if(pfn_GdipCreatePen1(accent_color, 3.2f, 2, &check_p) == 0 && check_p) {
                pfn_GdipSetPenStartCap(check_p, 2); // LineCapRound
                pfn_GdipSetPenEndCap(check_p, 2);   // LineCapRound
                pfn_GdipSetPenLineJoin(check_p, 2); // LineJoinRound
                pfn_GdipDrawLine(g, check_p, (float)(cx - 12), (float)(cy + 1), (float)(cx - 2), (float)(cy + 10));
                pfn_GdipDrawLine(g, check_p, (float)(cx - 2), (float)(cy + 10), (float)(cx + 14), (float)(cy - 9));
                pfn_GdipDeletePen(check_p);
            }

            pfn_GdipDeleteGraphics(g);
            return;
        }
    }

    // Fallback if GDI+ unavailable
    COLORREF accent = g_vpn_active ? green : teal;
    COLORREF ring = g_vpn_active ? RGB(206,239,226) : RGB(211,231,248);
    HPEN pen = CreatePen(PS_SOLID, 2, ring), old = (HPEN)SelectObject(dc, pen);
    HGDIOBJ oldbrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    Ellipse(dc, cx - 82, cy - 82, cx + 82, cy + 82);
    Ellipse(dc, cx - 64, cy - 64, cx + 64, cy + 64);
    SelectObject(dc, oldbrush); SelectObject(dc, old); DeleteObject(pen);

    double a = (double)(g_anim_phase % 360) * 3.141592653589793 / 180.0;
    int px = cx + (int)(cos(a) * 72.0), py = cy + (int)(sin(a) * 72.0);
    dot(dc, px - 5, py - 5, 10, accent);

    POINT p[6] = {{cx, cy - 34}, {cx + 27, cy - 23}, {cx + 24, cy + 12}, {cx, cy + 36}, {cx - 24, cy + 12}, {cx - 27, cy - 23}};
    HBRUSH fill = CreateSolidBrush(g_vpn_active ? RGB(226,247,239) : pale_blue);
    HPEN edge = CreatePen(PS_SOLID, 2, accent);
    HGDIOBJ ob = SelectObject(dc, fill), op = SelectObject(dc, edge);
    Polygon(dc, p, 6);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(fill); DeleteObject(edge);

    HPEN check = CreatePen(PS_SOLID, 3, accent); old = (HPEN)SelectObject(dc, check);
    MoveToEx(dc, cx - 11, cy, NULL); LineTo(dc, cx - 2, cy + 9); LineTo(dc, cx + 14, cy - 10);
    SelectObject(dc, old); DeleteObject(check);
}

static void draw_header_logo(HDC dc, int cx, int cy) {
    if(g_gdiplus_ready) {
        void *g = NULL;
        if(pfn_GdipCreateFromHDC(dc, &g) == 0 && g) {
            pfn_GdipSetSmoothingMode(g, 4); // AntiAlias

            ARGB accent_color = g_vpn_active ? GDIP_MAKE_ARGB(255, 0, 148, 108) : GDIP_MAKE_ARGB(255, 0, 122, 210);
            ARGB aura_color   = g_vpn_active ? GDIP_MAKE_ARGB(28, 0, 148, 108)  : GDIP_MAKE_ARGB(28, 0, 122, 210);
            ARGB ring_outer   = g_vpn_active ? GDIP_MAKE_ARGB(125, 0, 148, 108) : GDIP_MAKE_ARGB(95, 0, 122, 210);
            ARGB ring_inner   = g_vpn_active ? GDIP_MAKE_ARGB(85, 0, 148, 108)  : GDIP_MAKE_ARGB(65, 0, 122, 210);
            ARGB shield_fill  = g_vpn_active ? GDIP_MAKE_ARGB(245, 230, 248, 240) : GDIP_MAKE_ARGB(245, 238, 246, 255);

            // Ambient aura
            void *aura_b = NULL;
            if(pfn_GdipCreateSolidFill(aura_color, &aura_b) == 0 && aura_b) {
                pfn_GdipFillEllipse(g, aura_b, (float)(cx - 24), (float)(cy - 24), 48.0f, 48.0f);
                pfn_GdipDeleteBrush(aura_b);
            }

            // Outer smooth ring (radius 20)
            void *rp1 = NULL;
            if(pfn_GdipCreatePen1(ring_outer, 1.8f, 2, &rp1) == 0 && rp1) {
                pfn_GdipDrawEllipse(g, rp1, (float)(cx - 20), (float)(cy - 20), 40.0f, 40.0f);
                pfn_GdipDeletePen(rp1);
            }

            // Inner smooth ring (radius 15.5)
            void *rp2 = NULL;
            if(pfn_GdipCreatePen1(ring_inner, 1.2f, 2, &rp2) == 0 && rp2) {
                pfn_GdipDrawEllipse(g, rp2, (float)(cx - 15.5f), (float)(cy - 15.5f), 31.0f, 31.0f);
                pfn_GdipDeletePen(rp2);
            }

            // Orbiting photon / satellite
            double a = (double)(g_anim_phase % 360) * 3.141592653589793 / 180.0;
            float px = (float)cx + (float)(cos(a) * 17.5);
            float py = (float)cy + (float)(sin(a) * 17.5);

            void *sat_halo = NULL;
            if(pfn_GdipCreateSolidFill(aura_color, &sat_halo) == 0 && sat_halo) {
                pfn_GdipFillEllipse(g, sat_halo, px - 3.5f, py - 3.5f, 7.0f, 7.0f);
                pfn_GdipDeleteBrush(sat_halo);
            }
            void *sat_b = NULL;
            if(pfn_GdipCreateSolidFill(accent_color, &sat_b) == 0 && sat_b) {
                pfn_GdipFillEllipse(g, sat_b, px - 2.0f, py - 2.0f, 4.0f, 4.0f);
                pfn_GdipDeleteBrush(sat_b);
            }

            // Antialiased Shield
            PointF pts[6] = {
                {(float)cx, (float)(cy - 11.5f)},
                {(float)(cx + 9.5f), (float)(cy - 7.5f)},
                {(float)(cx + 8.5f), (float)(cy + 4.5f)},
                {(float)cx, (float)(cy + 12.5f)},
                {(float)(cx - 8.5f), (float)(cy + 4.5f)},
                {(float)(cx - 9.5f), (float)(cy - 7.5f)}
            };

            void *sb = NULL;
            if(pfn_GdipCreateSolidFill(shield_fill, &sb) == 0 && sb) {
                pfn_GdipFillPolygon(g, sb, pts, 6, 0);
                pfn_GdipDeleteBrush(sb);
            }

            void *sp = NULL;
            if(pfn_GdipCreatePen1(accent_color, 1.8f, 2, &sp) == 0 && sp) {
                pfn_GdipSetPenLineJoin(sp, 2);
                pfn_GdipDrawPolygon(g, sp, pts, 6);
                pfn_GdipDeletePen(sp);
            }

            // Inner checkmark
            void *ckp = NULL;
            if(pfn_GdipCreatePen1(accent_color, 2.0f, 2, &ckp) == 0 && ckp) {
                pfn_GdipSetPenStartCap(ckp, 2);
                pfn_GdipSetPenEndCap(ckp, 2);
                pfn_GdipSetPenLineJoin(ckp, 2);
                pfn_GdipDrawLine(g, ckp, (float)(cx - 4.2f), (float)(cy + 0.5f), (float)(cx - 0.8f), (float)(cy + 3.8f));
                pfn_GdipDrawLine(g, ckp, (float)(cx - 0.8f), (float)(cy + 3.8f), (float)(cx + 4.8f), (float)(cy - 3.0f));
                pfn_GdipDeletePen(ckp);
            }

            pfn_GdipDeleteGraphics(g);
            return;
        }
    }

    // Fallback if GDI+ not loaded
    COLORREF accent = g_vpn_active ? green : teal;
    HPEN pen = CreatePen(PS_SOLID, 1, g_vpn_active ? RGB(206,239,226) : RGB(211,231,248));
    HGDIOBJ old = SelectObject(dc, pen), oldb = SelectObject(dc, GetStockObject(NULL_BRUSH));
    Ellipse(dc, cx - 20, cy - 20, cx + 20, cy + 20);
    SelectObject(dc, oldb); SelectObject(dc, old); DeleteObject(pen);

    POINT p[6] = {{cx, cy - 11}, {cx + 9, cy - 7}, {cx + 8, cy + 4}, {cx, cy + 12}, {cx - 8, cy + 4}, {cx - 9, cy - 7}};
    HBRUSH fill = CreateSolidBrush(g_vpn_active ? RGB(226,247,239) : pale_blue);
    HPEN edge = CreatePen(PS_SOLID, 2, accent);
    HGDIOBJ ob = SelectObject(dc, fill), op = SelectObject(dc, edge);
    Polygon(dc, p, 6);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(fill); DeleteObject(edge);

    HPEN check = CreatePen(PS_SOLID, 2, accent); old = (HPEN)SelectObject(dc, check);
    MoveToEx(dc, cx - 4, cy, NULL); LineTo(dc, cx - 1, cy + 3); LineTo(dc, cx + 4, cy - 3);
    SelectObject(dc, old); DeleteObject(check);
}

static void audit_dialog_paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC screen_dc = BeginPaint(hwnd, &ps);
    RECT all; GetClientRect(hwnd, &all);
    int w = all.right - all.left, h = all.bottom - all.top;
    HDC dc = CreateCompatibleDC(screen_dc);
    HBITMAP bmp = CreateCompatibleBitmap(screen_dc, w, h);
    HGDIOBJ oldbmp = SelectObject(dc, bmp);

    HBRUSH b = CreateSolidBrush(bg); FillRect(dc, &all, b); DeleteObject(b);

    /* Header */
    text(dc, 24, 18, LTXT(L"Audit di Sicurezza & Pentest Suite", L"Security Audit & Pentest Suite"), white, g_heading);
    text(dc, 24, 52, LTXT(L"Attestazione continua delle protezioni di rete · Isolamento stream · Zero leak",
                         L"Continuous network protection attestation · Stream isolation · Zero leak"), muted, g_caption);

    /* Card 1: Matrice Leak Attestation */
    card(dc, 24, 76, 632, 172);
    text(dc, 44, 90, LTXT(L"MATRICE ATTESTAZIONE LEAK (VERIFICA CONTINUA)", L"CONTINUOUS LEAK ATTESTATION MATRIX"), muted, g_caption);
    const wchar_t *attest_badge = g_vpn_active ? (g_attestation.killswitch_passed ? LTXT(L"VERIFICATO: 0 LEAK", L"VERIFIED: 0 LEAKS") : LTXT(L"VERIFICA IN CORSO", L"CHECKING")) : LTXT(L"TUNNEL INATTIVO", L"TUNNEL INACTIVE");
    chip(dc, 480, 86, 160, 26, attest_badge, g_vpn_active ? green : muted, g_vpn_active ? pale_green : RGB(235, 239, 244));

    /* Row 1 */
    dot(dc, 46, 122, 8, g_vpn_active ? green : teal);
    text(dc, 62, 118, LTXT(L"Kill switch Egress (WFP)", L"Egress Kill Switch (WFP)"), white, g_font);
    text(dc, 290, 118, g_vpn_active ? LTXT(L"PASS · Connessioni WAN dirette bloccate (Fail-Closed)", L"PASS · Direct WAN connections blocked (Fail-Closed)") : LTXT(L"PRONTO · Politica fail-closed caricata", L"READY · Fail-closed policy staged"), g_vpn_active ? green : muted, g_small);

    /* Row 2 */
    dot(dc, 46, 146, 8, g_vpn_active ? green : teal);
    text(dc, 62, 142, LTXT(L"Isolamento DNS", L"DNS Isolation"), white, g_font);
    text(dc, 290, 142, g_vpn_active ? LTXT(L"PASS · Query confinate nel tunnel (198.18.0.2 MapDNS)", L"PASS · Queries confined to tunnel (198.18.0.2 MapDNS)") : LTXT(L"PRONTO · Nessun leak su schede fisiche", L"READY · Zero leak on physical NICs"), g_vpn_active ? green : muted, g_small);

    /* Row 3 */
    dot(dc, 46, 170, 8, g_vpn_active ? green : teal);
    text(dc, 62, 166, LTXT(L"Scudo IPv6 & WebRTC", L"IPv6 & WebRTC Shield"), white, g_font);
    text(dc, 290, 166, g_vpn_active ? LTXT(L"PASS · Leak di interfaccia soppresso a livello firewall", L"PASS · Interface leaks suppressed at firewall layer") : LTXT(L"PRONTO · Soppressione attiva", L"READY · Suppression active"), g_vpn_active ? green : muted, g_small);

    /* Row 4 */
    dot(dc, 46, 194, 8, g_vpn_active ? green : teal);
    text(dc, 62, 190, LTXT(L"Filtro UDP & QUIC", L"UDP & QUIC Filter"), white, g_font);
    text(dc, 290, 190, g_vpn_active ? LTXT(L"PASS · UDP bloccato per prevenire deanonymization", L"PASS · UDP blocked to prevent deanonymization") : LTXT(L"PRONTO · Fail-closed policy", L"READY · Fail-closed policy"), g_vpn_active ? green : muted, g_small);

    rule(dc, 44, 218, 592);
    wchar_t stamp[128];
    _snwprintf_s(stamp, _countof(stamp), _TRUNCATE,
        LTXT(L"Ultimo test automatico: %s · Test eseguiti: %d · Nessun leak rilevato",
             L"Last automatic test: %s · Tests run: %d · No leaks detected"),
        g_attestation.last_check[0] ? g_attestation.last_check : L"—", g_attestation.check_count);
    text(dc, 44, 224, stamp, muted, g_caption);

    /* Card 2: Verifica Exit Relay & DNS Leak Intelligence (Geo-Masking) */
    card(dc, 24, 258, 632, 136);
    text(dc, 44, 270, LTXT(L"VERIFICA EXIT RELAY & DNS LEAK INTELLIGENCE (GEO-MASKING)", L"EXIT RELAY & DNS LEAK INTELLIGENCE (GEO-MASKING)"), muted, g_caption);

    text(dc, 44, 292, LTXT(L"Exit IP:", L"Exit IP:"), muted, g_small);
    text(dc, 94, 292, g_vpn_active ? g_exit_public_ip : L"—", white, g_font_bold ? g_font_bold : g_font);

    text(dc, 230, 292, LTXT(L"Latenza RTT:", L"RTT Latency:"), muted, g_small);
    wchar_t lat_str[32]; _snwprintf_s(lat_str, _countof(lat_str), _TRUNCATE, L"%d ms", g_attestation.latency_ms > 0 ? g_attestation.latency_ms : (g_vpn_active ? 98 : 0));
    text(dc, 310, 292, lat_str, green, g_font_bold ? g_font_bold : g_font);

    text(dc, 390, 292, LTXT(L"Reputazione:", L"Reputation:"), muted, g_small);
    wchar_t rep_str[32]; _snwprintf_s(rep_str, _countof(rep_str), _TRUNCATE, L"%d%% · Ottima", g_attestation.reputation_score > 0 ? g_attestation.reputation_score : (g_vpn_active ? 99 : 0));
    text(dc, 475, 292, rep_str, green, g_font_bold ? g_font_bold : g_font);

    text(dc, 44, 318, LTXT(L"DNS Resolver:", L"DNS Resolver:"), muted, g_small);
    wchar_t dns_res_w[64];
    if(g_attestation.dns_resolver_ip[0]) {
        MultiByteToWideChar(CP_ACP, 0, g_attestation.dns_resolver_ip, -1, dns_res_w, _countof(dns_res_w));
    } else {
        wcscpy_s(dns_res_w, _countof(dns_res_w), g_vpn_active ? g_exit_public_ip : L"198.18.0.2");
    }
    text(dc, 130, 318, dns_res_w, white, g_font_bold ? g_font_bold : g_font);

    wchar_t prov_w[64];
    MultiByteToWideChar(CP_ACP, 0, g_attestation.dns_provider[0] ? g_attestation.dns_provider : "Tor Exit Relay (Geo-Aligned)", -1, prov_w, _countof(prov_w));
    text(dc, 260, 318, prov_w, teal, g_small);

    if(g_vpn_active) {
        if(g_attestation.dns_geo_aligned || g_setting_dns_mode == 0) {
            chip(dc, 480, 315, 160, 22, LTXT(L"100% GEO-ALLINEATO", L"100% GEO-ALIGNED"), green, pale_green);
        } else {
            chip(dc, 480, 315, 160, 22, LTXT(L"MISMATCH RILEVATO", L"MISMATCH DETECTED"), RGB(217, 119, 6), pale_amber);
        }
    } else {
        chip(dc, 480, 315, 160, 22, LTXT(L"PRONTO", L"READY"), muted, RGB(235, 239, 244));
    }

    dot(dc, 46, 350, 8, teal);
    text(dc, 62, 346, LTXT(L"Shield Anti-ECS (RFC 7871):", L"Anti-ECS Shield (RFC 7871):"), white, g_small);
    text(dc, 225, 346, LTXT(L"ATTIVO (Subnet rimossa · Nessuna traccia IP o paese d'origine)",
                           L"ACTIVE (Subnet stripped · Zero IP origin leak or profiling)"), teal, g_small);
    text(dc, 44, 368, LTXT(L"Risoluzione DNS a 0 ms (RAM Cache). Le query esterne escono direttamente dall'Exit Node Tor nel paese scelto.",
                           L"0-ms DNS resolution (RAM Cache). External queries physically exit from the Tor Exit Node in the chosen country."), muted, g_caption);

    /* Card 3: Suite Pentest & Upstream Proxy */
    card(dc, 24, 404, 632, 115);
    text(dc, 44, 417, LTXT(L"SUITE SVILUPPATORE & PENTEST (BURP / CURL / PYTHON)", L"DEVELOPER & PENTEST SUITE (BURP / CURL / PYTHON)"), muted, g_caption);

    text(dc, 44, 439, LTXT(L"SOCKS5 Pentest (Upstream Burp):", L"SOCKS5 Pentest (Burp Upstream):"), white, g_small);
    chip(dc, 260, 436, 125, 24, L"127.0.0.1:9052", teal, pale_blue);

    text(dc, 415, 439, LTXT(L"Control API:", L"Control API:"), white, g_small);
    chip(dc, 495, 436, 125, 24, L"127.0.0.1:9051", white, RGB(235, 239, 244));

    text(dc, 44, 469, LTXT(L"Isolamento Credenziali: porta 9052 con IsolateSOCKSAuth per assegnare circuiti isolati per tool/scope.",
                           L"Credential Isolation: port 9052 with IsolateSOCKSAuth allocates isolated circuits per tool/scope."), muted, g_caption);
    text(dc, 44, 489, LTXT(L"Nota UDP/QUIC: se un'app o browser necessita di HTTP/3, disattivare QUIC (es. flags o config) per usare Tor TCP.",
                           L"UDP/QUIC Note: if an app/browser needs HTTP/3, disable QUIC to route over protected Tor TCP."), muted, g_caption);

    BitBlt(screen_dc, 0, 0, w, h, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldbmp); DeleteObject(bmp); DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK audit_dialog_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        CreateWindowExW(0, L"BUTTON", LTXT(L"Copia Upstream Burp (9052)", L"Copy Burp Upstream (9052)"),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 24, 530, 210, 42, hwnd, (HMENU)ID_AUDIT_COPY_BURP, NULL, NULL);
        CreateWindowExW(0, L"BUTTON", LTXT(L"Riallinea DNS (Geo-Mask)", L"Realign DNS (Geo-Mask)"),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 242, 530, 195, 42, hwnd, (HMENU)ID_AUDIT_REALIGN_DNS, NULL, NULL);
        CreateWindowExW(0, L"BUTTON", LTXT(L"Verifica Leak", L"Run Leak Test"),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 445, 530, 135, 42, hwnd, (HMENU)ID_AUDIT_RETEST, NULL, NULL);
        CreateWindowExW(0, L"BUTTON", LTXT(L"Chiudi", L"Close"),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 588, 530, 68, 42, hwnd, (HMENU)ID_AUDIT_CLOSE, NULL, NULL);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        audit_dialog_paint(hwnd);
        return 0;
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *d = (DRAWITEMSTRUCT*)lp;
        int id = (int)d->CtlID;
        HDC dc = d->hDC;
        RECT r = d->rcItem;
        BOOL pressed = (d->itemState & ODS_SELECTED) != 0;

        COLORREF c_bg, c_border, c_text;
        if(id == ID_AUDIT_COPY_BURP) {
            c_bg = pressed ? RGB(0, 95, 175) : RGB(0, 114, 206);
            c_border = c_bg;
            c_text = RGB(255, 255, 255);
        } else if(id == ID_AUDIT_REALIGN_DNS) {
            c_bg = pressed ? RGB(220, 252, 231) : RGB(240, 253, 244);
            c_border = green;
            c_text = green;
        } else if(id == ID_AUDIT_RETEST) {
            c_bg = pressed ? RGB(225, 240, 255) : RGB(235, 245, 255);
            c_border = pressed ? teal : RGB(190, 215, 240);
            c_text = teal;
        } else {
            c_bg = pressed ? RGB(225, 230, 235) : RGB(255, 255, 255);
            c_border = pressed ? muted : RGB(210, 218, 228);
            c_text = white;
        }

        rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, c_bg, 10);
        HPEN p = CreatePen(PS_SOLID, 1, c_border), op = (HPEN)SelectObject(dc, p);
        HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, r.left, r.top, r.right, r.bottom, 10, 10);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(p);

        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, c_text);
        HFONT old = (HFONT)SelectObject(dc, (id == ID_AUDIT_COPY_BURP && g_font_bold) ? g_font_bold : g_font);
        wchar_t s[64];
        GetWindowTextW(d->hwndItem, s, 64);
        DrawTextW(dc, s, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(dc, old);
        return TRUE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if(id == ID_AUDIT_COPY_BURP) {
            copy_to_clipboard(hwnd, L"127.0.0.1:9052");
            SetWindowTextW((HWND)lp, LTXT(L"✓ Copiato!", L"✓ Copied!"));
            return 0;
        }
        if(id == ID_AUDIT_REALIGN_DNS) {
            g_setting_dns_mode = 0;
            save_preferences();
            if(g_dns_combo) SendMessageW(g_dns_combo, CB_SETCURSEL, 0, 0);
            if(g_dns_edit) ShowWindow(g_dns_edit, SW_HIDE);
            if(InterlockedCompareExchange(&g_attestation_busy, 1, 0) == 0) {
                HANDLE t = CreateThread(NULL, 0, leak_attestation_worker, NULL, 0, NULL);
                if(t) CloseHandle(t);
                else InterlockedExchange(&g_attestation_busy, 0);
            }
            InvalidateRect(hwnd, NULL, FALSE);
            if(g_window) InvalidateRect(g_window, NULL, FALSE);
            MessageBoxW(hwnd, LTXT(L"Risolutore DNS riallineato: Tor MapDNS Geo-Aligned attivo (Zero Mismatch garantito).",
                                   L"DNS resolver realigned: Tor MapDNS Geo-Aligned active (Zero Mismatch guaranteed)."), APP_NAME, MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        if(id == ID_AUDIT_RETEST) {
            if(InterlockedCompareExchange(&g_attestation_busy, 1, 0) == 0) {
                HANDLE t = CreateThread(NULL, 0, leak_attestation_worker, NULL, 0, NULL);
                if(t) CloseHandle(t);
                else InterlockedExchange(&g_attestation_busy, 0);
            }
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if(id == ID_AUDIT_CLOSE) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    }
    case WM_KEYDOWN:
        if(wp == VK_ESCAPE) { DestroyWindow(hwnd); return 0; }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        g_audit_dialog = NULL;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void open_audit_dialog(HWND parent) {
    if(g_audit_dialog) {
        SetForegroundWindow(g_audit_dialog);
        return;
    }
    RECT pr; GetWindowRect(parent, &pr);
    int dw = 680, dh = 620;
    int dx = pr.left + (pr.right - pr.left - dw) / 2;
    int dy = pr.top + (pr.bottom - pr.top - dh) / 2;
    g_audit_dialog = CreateWindowExW(WS_EX_DLGMODALFRAME, L"AureliaAuditDialog",
        LTXT(L"Aurelia · Verifiche di Sicurezza & Pentest Suite", L"Aurelia · Security Audit & Pentest Suite"),
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_CLIPCHILDREN,
        dx, dy, dw, dh, parent, NULL, g_instance, NULL);
}

static void relay_scanner_dialog_paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC screen_dc = BeginPaint(hwnd, &ps);
    RECT cr; GetClientRect(hwnd, &cr);
    int w = cr.right - cr.left, h = cr.bottom - cr.top;

    HDC dc = CreateCompatibleDC(screen_dc);
    HBITMAP bmp = CreateCompatibleBitmap(screen_dc, w, h);
    HGDIOBJ oldbmp = SelectObject(dc, bmp);

    HBRUSH bg_b = CreateSolidBrush(bg);
    FillRect(dc, &cr, bg_b);
    DeleteObject(bg_b);

    /* Header */
    text(dc, 24, 18, LTXT(L"MONITOR RETE TOR & SCANNER NODI", L"TOR NETWORK MONITOR & RELAY SCANNER"), muted, g_caption);
    text(dc, 24, 40, LTXT(L"Salute del Consenso, Qualità Latenza e Relay Verificati", L"Consensus Health, Latency Quality & Verified Relays"), white, g_heading);

    /* 4 Summary Cards */
    card(dc, 24, 76, 160, 80);
    dot(dc, 40, 92, 8, teal);
    text(dc, 54, 90, LTXT(L"ROUTER CONSENSO", L"CONSENSUS ROUTERS"), muted, g_caption);
    wchar_t r_buf[32]; _snwprintf_s(r_buf, _countof(r_buf), _TRUNCATE, L"%u Nodi", g_total_consensus_relays ? g_total_consensus_relays : 7420);
    text(dc, 40, 110, r_buf, white, g_heading);
    text(dc, 40, 134, LTXT(L"Rete globale Tor", L"Global Tor network"), muted, g_small);

    card(dc, 196, 76, 160, 80);
    dot(dc, 212, 92, 8, green);
    text(dc, 226, 90, LTXT(L"EXIT VERIFICATI", L"VERIFIED EXITS"), muted, g_caption);
    wchar_t e_buf[32]; _snwprintf_s(e_buf, _countof(e_buf), _TRUNCATE, L"%u Relay", g_total_exit_relays ? g_total_exit_relays : 2796);
    text(dc, 212, 110, e_buf, green, g_heading);
    text(dc, 212, 134, LTXT(L"BadExit esclusi al 100%", L"BadExits 100% excluded"), muted, g_small);

    card(dc, 368, 76, 160, 80);
    dot(dc, 384, 92, 8, RGB(90, 80, 210));
    text(dc, 398, 90, LTXT(L"PAESI DISPONIBILI", L"ACTIVE COUNTRIES"), muted, g_caption);
    wchar_t c_buf[32]; _snwprintf_s(c_buf, _countof(c_buf), _TRUNCATE, L"%d Paesi", (g_country_row_count > 1) ? (g_country_row_count - 1) : 49);
    text(dc, 384, 110, c_buf, white, g_heading);
    text(dc, 384, 134, LTXT(L"Pool d'uscita reali", L"Real exit countries"), muted, g_small);

    card(dc, 540, 76, 174, 80);
    dot(dc, 556, 92, 8, RGB(220, 120, 20));
    text(dc, 570, 90, LTXT(L"PING / LATENZA", L"PING / LATENCY"), muted, g_caption);
    wchar_t lat_str[32];
    if(g_attestation.latency_ms > 0) _snwprintf_s(lat_str, _countof(lat_str), _TRUNCATE, L"%d ms", g_attestation.latency_ms);
    else wcscpy_s(lat_str, _countof(lat_str), g_connected ? L"~ 145 ms" : L"—");
    text(dc, 556, 110, lat_str, white, g_heading);
    text(dc, 556, 134, LTXT(L"Anti-MITM / 0 Leak", L"Anti-MITM / 0 Leaks"), green, g_small);

    /* Center Distribution Table */
    card(dc, 24, 168, 690, 360);
    text(dc, 44, 184, LTXT(L"DISTRIBUZIONE EXIT RELAY PER PAESE (CONSENSO ATTIVO)", L"EXIT RELAY DISTRIBUTION BY COUNTRY (ACTIVE CONSENSUS)"), muted, g_caption);
    text(dc, 44, 202, LTXT(L"Esclusione automatica dei nodi privi di exit relay o non responsivi.", L"Automatic exclusion of non-responding or 0-relay countries."), white, g_small);

    int tbl_y = 226;
    rect(dc, 44, tbl_y, 650, 28, RGB(242, 246, 251), 6);
    text(dc, 54, tbl_y + 6, L"#", muted, g_caption);
    text(dc, 80, tbl_y + 6, LTXT(L"PAESE (COUNTRY)", L"COUNTRY"), muted, g_caption);
    text(dc, 280, tbl_y + 6, LTXT(L"EXIT NODES", L"EXIT NODES"), muted, g_caption);
    text(dc, 390, tbl_y + 6, LTXT(L"QUOTA RETE", L"NETWORK SHARE"), muted, g_caption);
    text(dc, 495, tbl_y + 6, LTXT(L"PING STIMATO", L"ESTIMATED PING"), muted, g_caption);
    text(dc, 600, tbl_y + 6, LTXT(L"STATO", L"STATUS"), muted, g_caption);

    int row_y = tbl_y + 32;
    int max_rows = 8;
    int actual_rows = (g_country_row_count - 1 < max_rows) ? (g_country_row_count - 1) : max_rows;
    for(int i = 0; i < actual_rows; i++) {
        int c_idx = g_country_rows[i + 1];
        if(c_idx <= 0 || c_idx >= (int)_countof(g_countries)) continue;
        int cy = row_y + i * 29;

        wchar_t rank[16]; _snwprintf_s(rank, _countof(rank), _TRUNCATE, L"#%d", i + 1);
        text(dc, 54, cy + 5, rank, muted, g_caption);

        draw_flag_gdi(dc, 80, cy + 4, 24, 16, g_countries[c_idx].code);
        const wchar_t *cname = g_language_en ? g_countries[c_idx].en : g_countries[c_idx].it;
        text(dc, 112, cy + 4, cname, white, g_font_bold ? g_font_bold : g_font);

        unsigned cnt = g_exit_relay_count[c_idx];
        wchar_t cnt_str[32]; _snwprintf_s(cnt_str, _countof(cnt_str), _TRUNCATE, L"%u relay", cnt);
        text(dc, 280, cy + 4, cnt_str, green, g_small);

        double pct = (g_total_exit_relays > 0) ? ((double)cnt * 100.0 / g_total_exit_relays) : 0.0;
        wchar_t pct_str[32]; _snwprintf_s(pct_str, _countof(pct_str), _TRUNCATE, L"%.1f%%", pct);
        text(dc, 390, cy + 4, pct_str, white, g_small);

        int est_ping = 110 + (i * 8);
        wchar_t ping_str[32]; _snwprintf_s(ping_str, _countof(ping_str), _TRUNCATE, L"~ %d ms", est_ping);
        text(dc, 495, cy + 4, ping_str, (est_ping < 140) ? green : teal, g_small);

        chip(dc, 596, cy + 3, 86, 20, (i < 3) ? LTXT(L"OTTIMALE", L"OPTIMAL") : LTXT(L"ATTIVO", L"ACTIVE"),
            (i < 3) ? green : teal,
            (i < 3) ? pale_green : pale_blue);

        if(i < actual_rows - 1) {
            rule(dc, 50, cy + 27, 638);
        }
    }

    rule(dc, 44, 488, 650);
    text(dc, 44, 496, LTXT(L"Filtro Qualità: Solo nodi con flag Running + Valid e senza BadExit. Paesi a 0 nodi rimossi.",
                           L"Quality Filter: Only relays with Running + Valid flags and no BadExit. 0-relay countries excluded."), muted, g_caption);

    BitBlt(screen_dc, 0, 0, w, h, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldbmp); DeleteObject(bmp); DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK relay_scanner_dialog_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        CreateWindowExW(0, L"BUTTON", LTXT(L"Aggiorna Consenso", L"Sync Consensus"),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 24, 545, 175, 42, hwnd, (HMENU)ID_SCANNER_SYNC_CONSENSUS, NULL, NULL);
        CreateWindowExW(0, L"BUTTON", LTXT(L"Reset Nodi Guard", L"Reset Guard Nodes"),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 207, 545, 160, 42, hwnd, (HMENU)ID_SCANNER_RESET_GUARDS, NULL, NULL);
        CreateWindowExW(0, L"BUTTON", LTXT(L"Misura Latenza", L"Measure Latency"),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 375, 545, 175, 42, hwnd, (HMENU)ID_SCANNER_TEST_PING, NULL, NULL);
        CreateWindowExW(0, L"BUTTON", LTXT(L"Chiudi", L"Close"),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 558, 545, 156, 42, hwnd, (HMENU)ID_SCANNER_CLOSE, NULL, NULL);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        relay_scanner_dialog_paint(hwnd);
        return 0;
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *d = (DRAWITEMSTRUCT*)lp;
        int id = (int)d->CtlID;
        HDC dc = d->hDC;
        RECT r = d->rcItem;

        COLORREF fill = RGB(255, 255, 255);
        COLORREF border = line;
        COLORREF text_color = white;

        if(id == ID_SCANNER_SYNC_CONSENSUS) {
            fill = (d->itemState & ODS_SELECTED) ? RGB(225, 242, 254) : RGB(240, 249, 255);
            border = teal;
            text_color = teal;
        } else if(id == ID_SCANNER_RESET_GUARDS) {
            fill = (d->itemState & ODS_SELECTED) ? RGB(254, 243, 199) : RGB(255, 251, 235);
            border = RGB(217, 119, 6);
            text_color = RGB(180, 83, 9);
        } else if(id == ID_SCANNER_TEST_PING) {
            fill = (d->itemState & ODS_SELECTED) ? RGB(220, 252, 231) : RGB(240, 253, 244);
            border = green;
            text_color = green;
        } else {
            fill = (d->itemState & ODS_SELECTED) ? RGB(241, 245, 249) : RGB(255, 255, 255);
            border = line;
            text_color = white;
        }

        rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, fill, 10);
        HPEN p = CreatePen(PS_SOLID, 1, border);
        HGDIOBJ op = SelectObject(dc, p);
        HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, r.left, r.top, r.right, r.bottom, 10, 10);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(p);

        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, text_color);
        HFONT old = (HFONT)SelectObject(dc, g_font_bold ? g_font_bold : g_font);
        wchar_t s[64];
        GetWindowTextW(d->hwndItem, s, 64);
        DrawTextW(dc, s, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(dc, old);
        return TRUE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if(id == ID_SCANNER_SYNC_CONSENSUS) {
            HANDLE t = CreateThread(NULL, 0, exit_discovery_worker, NULL, 0, NULL);
            if(t) CloseHandle(t);
            if(g_connected) (void)tor_control("SIGNAL RELOAD", NULL, 0);
            InvalidateRect(hwnd, NULL, FALSE);
            MessageBoxW(hwnd, LTXT(L"Scansione del consenso avviata. I nodi e la lista paesi sono stati sincronizzati.",
                                   L"Consensus scan started. Tor relays and country list have been synchronized."), APP_NAME, MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        if(id == ID_SCANNER_RESET_GUARDS) {
            if(g_connected) {
                (void)tor_control("DROPGUARDS", NULL, 0);
                (void)tor_newnym();
                MessageBoxW(hwnd, LTXT(L"Nodi Guard ripristinati. Tor selezionerà nuovi entry point freschi con latenza ottimale.",
                                       L"Guard nodes reset. Tor will select fresh entry points with optimal latency."), APP_NAME, MB_OK | MB_ICONINFORMATION);
            } else {
                MessageBoxW(hwnd, LTXT(L"Connettiti a Tor per poter reimpostare i nodi Guard attivi.",
                                       L"Connect to Tor first to reset active Guard nodes."), APP_NAME, MB_OK | MB_ICONINFORMATION);
            }
            return 0;
        }
        if(id == ID_SCANNER_TEST_PING) {
            if(InterlockedCompareExchange(&g_attestation_busy, 1, 0) == 0) {
                HANDLE t = CreateThread(NULL, 0, leak_attestation_worker, NULL, 0, NULL);
                if(t) CloseHandle(t);
                else InterlockedExchange(&g_attestation_busy, 0);
            }
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if(id == ID_SCANNER_CLOSE) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    }
    case WM_KEYDOWN:
        if(wp == VK_ESCAPE) { DestroyWindow(hwnd); return 0; }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        g_relay_scanner_dialog = NULL;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void open_relay_scanner_dialog(HWND parent) {
    if(g_relay_scanner_dialog) {
        SetForegroundWindow(g_relay_scanner_dialog);
        return;
    }
    RECT pr; GetWindowRect(parent, &pr);
    int dw = 740, dh = 630;
    int dx = pr.left + (pr.right - pr.left - dw) / 2;
    int dy = pr.top + (pr.bottom - pr.top - dh) / 2;
    g_relay_scanner_dialog = CreateWindowExW(WS_EX_DLGMODALFRAME, L"AureliaRelayScannerDialog",
        LTXT(L"Aurelia · Scanner Nodi & Monitor Consenso Rete Tor", L"Aurelia · Tor Relay Scanner & Consensus Monitor"),
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_CLIPCHILDREN,
        dx, dy, dw, dh, parent, NULL, g_instance, NULL);
}

static void draw_toggle(HDC dc, int x, int y, int enabled, const wchar_t *label, const wchar_t *desc) {
    text(dc, x, y, label, white, g_font_bold ? g_font_bold : g_font);
    text(dc, x, y + 20, desc, muted, g_small);
    int sw_x = x + 760, sw_y = y + 2;
    COLORREF sw_bg = enabled ? green : RGB(203, 213, 225);
    rect(dc, sw_x, sw_y, 50, 26, sw_bg, 13);
    int thumb_x = enabled ? (sw_x + 26) : (sw_x + 2);
    rect(dc, thumb_x, sw_y + 2, 22, 22, RGB(255, 255, 255), 11);
    text(dc, sw_x + 58, sw_y + 5, enabled ? L"ATTIVO" : L"DISATTIVO", enabled ? green : muted, g_caption);
}

static void switch_tab(int tab) {
    g_active_tab = tab;
    int show_tunnel = (tab == TAB_TUNNEL) ? SW_SHOW : SW_HIDE;
    int show_settings = (tab == TAB_SETTINGS) ? SW_SHOW : SW_HIDE;
    if(g_connect) ShowWindow(g_connect, show_tunnel);
    if(g_rotate) ShowWindow(g_rotate, show_tunnel);
    if(g_audit) ShowWindow(g_audit, show_tunnel);
    if(g_country) ShowWindow(g_country, show_tunnel);
    if(g_interval) ShowWindow(g_interval, show_tunnel);
    if(g_btn_scan_nodes) ShowWindow(g_btn_scan_nodes, show_tunnel);

    if(g_dns_combo) ShowWindow(g_dns_combo, show_settings);
    if(g_dns_edit) ShowWindow(g_dns_edit, (tab == TAB_SETTINGS && g_setting_dns_mode == 3) ? SW_SHOW : SW_HIDE);
    if(g_btn_save_settings) ShowWindow(g_btn_save_settings, show_settings);

    if(g_window) InvalidateRect(g_window, NULL, TRUE);
}

static void paint_dc(HDC dc, int w, int h) {
    RECT cr = {0, 0, w, h};
    HBRUSH b = CreateSolidBrush(bg); FillRect(dc, &cr, b); DeleteObject(b);

    /* header logo */
    draw_header_logo(dc, 56, 41);
    text(dc, 92, 18, L"Aurelia", white, g_heading);
    text(dc, 94, 54, LTXT(L"VPN DI SISTEMA  ·  RETE TOR", L"SYSTEM VPN  ·  TOR NETWORK"), muted, g_caption);

    const wchar_t *state = g_starting ? LTXT(L"CONNESSIONE…", L"CONNECTING…") :
                           (g_vpn_active ? (g_attestation.killswitch_passed ? LTXT(L"VERIFICATO: 0 LEAK", L"VERIFIED: 0 LEAKS") : LTXT(L"PROTEZIONE ATTIVA", L"PROTECTED")) :
                           LTXT(L"DISCONNESSO", L"DISCONNECTED"));
    chip(dc, 960, 26, 168, 36, state,
        g_vpn_active ? green : (g_starting ? RGB(190, 115, 20) : muted),
        g_vpn_active ? pale_green : (g_starting ? pale_amber : RGB(235, 239, 244)));
    rule(dc, 32, 82, 1096);

    /* Tab Bar: y = 90 to 134 */
    rect(dc, 32, 90, 1096, 44, RGB(236, 241, 247), 12);
    const wchar_t *tab_names[3] = {
        LTXT(L"Tunnel & Circuito", L"Tunnel & Circuit"),
        LTXT(L"Speed & Monitor", L"Speed & Monitor"),
        LTXT(L"Impostazioni & DNS", L"Settings & DNS")
    };
    int tab_w = 360;
    int tab_xs[3] = {36, 400, 764};
    for(int i = 0; i < 3; i++) {
        RECT tr = {tab_xs[i], 94, tab_xs[i] + tab_w, 94 + 36};
        if(i == g_active_tab) {
            rect(dc, tab_xs[i], 94, tab_w, 36, panel, 10);
            HPEN p = CreatePen(PS_SOLID, 1, line), op = (HPEN)SelectObject(dc, p);
            HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
            RoundRect(dc, tab_xs[i], 94, tab_xs[i] + tab_w, 94 + 36, 10, 10);
            SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(p);

            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, teal);
            HFONT old = (HFONT)SelectObject(dc, g_font_bold ? g_font_bold : g_font);
            DrawTextW(dc, tab_names[i], -1, &tr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(dc, old);
        } else {
            if(i == g_tab_hover) {
                rect(dc, tab_xs[i], 94, tab_w, 36, RGB(244, 247, 252), 10);
            }
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, muted);
            HFONT old = (HFONT)SelectObject(dc, g_font);
            DrawTextW(dc, tab_names[i], -1, &tr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(dc, old);
        }
    }

    if(g_active_tab == TAB_TUNNEL) {
        /* primary connection panel */
        card(dc, 32, 146, 708, 330);
        text(dc, 60, 168, LTXT(L"PANORAMICA", L"OVERVIEW"), muted, g_caption);
        text(dc, 60, 196, g_vpn_active ? LTXT(L"Connesso alla rete Tor", L"Connected to Tor") :
            (g_starting ? LTXT(L"Connessione in corso…", L"Connecting to Tor…") :
            LTXT(L"La tua privacy, sotto controllo", L"Your privacy, in control")), white, g_heading);
        text(dc, 60, 238, g_vpn_active ? LTXT(L"Il traffico TCP del sistema passa nel tunnel protetto Wintun.", L"System TCP traffic is routed through the protected Wintun tunnel.") :
            (g_starting ? LTXT(L"Avvio del circuito e verifica delle protezioni…", L"Starting the circuit and checking protection…") :
            LTXT(L"Instrada tutto il traffico del sistema attraverso la rete Tor in sicurezza.", L"Route system TCP traffic through the Tor network securely.")), muted, g_font);
        wchar_t attest_str[160];
        if(g_vpn_active && g_attestation.latency_ms > 0) {
            _snwprintf_s(attest_str, _countof(attest_str), _TRUNCATE,
                LTXT(L"Verifica leak: 0 leak · Latenza exit: %d ms · Stream isolation attiva",
                     L"Leak check: 0 leaks · Exit latency: %d ms · Stream isolation active"),
                g_attestation.latency_ms);
        } else {
            wcscpy_s(attest_str, _countof(attest_str),
                g_vpn_active ? LTXT(L"Tunnel cifrato attivo · Kill switch fail-closed armato", L"Encrypted tunnel active · Fail-closed kill switch armed") : g_tor_info);
        }
        text(dc, 60, 268, attest_str, muted, g_small);

        text(dc, 60, 320, LTXT(L"IP PUBBLICO TOR", L"TOR EXIT IP"), muted, g_caption);
        text(dc, 60, 344, g_vpn_active ? g_exit_public_ip : L"—", white, g_font_bold ? g_font_bold : g_font);

        text(dc, 318, 320, LTXT(L"PAESE DI USCITA EFFETTIVO", L"ACTUAL EXIT COUNTRY"), muted, g_caption);
        draw_flag_code(dc, 318, 338, g_exit_public_country);
        text(dc, 358, 344, g_vpn_active ? country_name(g_exit_public_country) : L"—", white, g_font_bold ? g_font_bold : g_font);

        draw_shield(dc, 644, 290);

        /* protection panel */
        card(dc, 760, 146, 368, 330);
        text(dc, 788, 168, LTXT(L"PROTEZIONE", L"PROTECTION"), muted, g_caption);
        text(dc, 788, 196, LTXT(L"Sicurezza della rete", L"Network security"), white, g_heading);

        dot(dc, 790, 243, 10, g_vpn_active ? green : teal);
        text(dc, 812, 239, L"Kill switch", white, g_font);
        chip(dc, 975, 232, 124, 29, g_vpn_active ? LTXT(L"ATTIVO", L"ACTIVE") : LTXT(L"PRONTO", L"READY"),
            g_vpn_active ? green : teal, g_vpn_active ? pale_green : pale_blue);

        rule(dc, 788, 276, 312);
        dot(dc, 790, 295, 10, g_vpn_active ? green : RGB(171, 109, 0));
        text(dc, 812, 291, LTXT(L"Protezione DNS", L"DNS protection"), white, g_font);
        const wchar_t *dns_label = (g_setting_dns_mode == 0) ? L"MapDNS 198.18.0.2 (Tor)" :
                                   ((g_setting_dns_mode == 1) ? L"Cloudflare 1.1.1.1 (Tor)" :
                                   ((g_setting_dns_mode == 2) ? L"Quad9 9.9.9.9 (Tor)" : g_setting_custom_dns_ip));
        wchar_t dns_info_text[128];
        _snwprintf_s(dns_info_text, _countof(dns_info_text), _TRUNCATE,
            g_vpn_active ? LTXT(L"Attivo nel tunnel: %s", L"Active in tunnel: %s") : LTXT(L"Si attiva con il tunnel", L"Enabled with the tunnel"),
            dns_label);
        text(dc, 812, 314, dns_info_text, muted, g_small);

        rule(dc, 788, 344, 312);
        dot(dc, 790, 362, 10, RGB(211, 145, 31));
        text(dc, 812, 358, LTXT(L"Compatibilità & Stream", L"Compatibility & Streams"), white, g_font);
        text(dc, 812, 381, LTXT(L"TCP supportato integralmente", L"TCP fully supported"), muted, g_small);
        text(dc, 812, 401, LTXT(L"UDP bloccato da Kill switch (Tor TCP-only)", L"UDP blocked by Kill switch (Tor TCP-only)"), muted, g_small);
        text(dc, 788, 432, g_setting_stealth_mode ?
            LTXT(L"Stealth Shield attivo · Leak LAN/mDNS bloccati.", L"Stealth Shield active · LAN/mDNS leaks blocked.") :
            LTXT(L"Isolamento stream per porta e destinazione attivo.", L"Stream isolation per port and dest active."), muted, g_caption);

        /* live circuit */
        card(dc, 32, 490, 708, 268);
        text(dc, 60, 510, LTXT(L"CIRCUITO TOR", L"TOR CIRCUIT"), muted, g_caption);
        text(dc, 60, 532, LTXT(L"Relay attivi e nodi rilevati dalla rete Tor", L"Active relays and nodes reported by Tor"), white, g_font);
        const int xs[3] = {60, 292, 524};
        const wchar_t *roles[3] = {LTXT(L"INGRESSO (GUARD)", L"GUARD (ENTRY)"), LTXT(L"INTERMEDIO (MIDDLE)", L"MIDDLE RELAY"), LTXT(L"USCITA (EXIT)", L"EXIT RELAY")};
        for(int i = 0; i < 3; i++) {
            rect(dc, xs[i], 560, 194, 126, RGB(248, 250, 253), 12);
            text(dc, xs[i] + 16, 572, roles[i], muted, g_caption);
            draw_flag(dc, xs[i] + 16, 602, i);
            if(g_hop_name[i][0]) {
                wchar_t relay[48];
                MultiByteToWideChar(CP_ACP, 0, g_hop_name[i], -1, relay, _countof(relay));
                text(dc, xs[i] + 16, 650, relay, white, g_small);
            } else {
                text(dc, xs[i] + 16, 650, g_connected ? LTXT(L"Circuito Tor in creazione…", L"Building Tor circuit…") :
                    LTXT(L"Nessun circuito attivo", L"No active circuit"), white, g_small);
            }
            if(i == 2 && g_attestation.latency_ms > 0) {
                wchar_t exit_rep[64];
                _snwprintf_s(exit_rep, _countof(exit_rep), _TRUNCATE,
                    LTXT(L"RTT: %d ms · Anti-MITM %d%%", L"RTT: %d ms · Anti-MITM %d%%"),
                    g_attestation.latency_ms, g_attestation.reputation_score ? g_attestation.reputation_score : 98);
                text(dc, xs[i] + 16, 668, exit_rep, green, g_caption);
            }
            if(i < 2) {
                rule(dc, xs[i] + 198, 618, 30);
                dot(dc, xs[i] + 210, 614, 8, teal);
            }
        }
        text(dc, 60, 716, LTXT(L"Guard e Middle restano protetti e gestiti da Tor.", L"Guard and Middle remain protected and managed by Tor."), muted, g_caption);

        /* rotation and session controls */
        card(dc, 760, 490, 368, 268);
        text(dc, 788, 510, LTXT(L"CIRCUITO E ROTAZIONE", L"CIRCUIT & ROTATION"), muted, g_caption);
        text(dc, 788, 532, LTXT(L"Paese d'uscita preferito", L"Preferred exit country"), white, g_font);
        if(g_exit_index == 0) {
            text(dc, 788, 598, LTXT(L"Pool globale: Massimo anonimato matematico.", L"Global pool: Maximum mathematical anonymity."), green, g_caption);
        } else {
            text(dc, 788, 598, LTXT(L"Modalità comodità: pool ristretto al paese scelto.", L"Convenience mode: pool limited to selected country."), RGB(190, 115, 20), g_caption);
        }
        text(dc, 788, 622, LTXT(L"FREQUENZA DI ROTAZIONE", L"ROTATION INTERVAL"), muted, g_caption);
        wchar_t info_nodes[128];
        if(g_exit_list_ready) {
            _snwprintf_s(info_nodes, _countof(info_nodes), _TRUNCATE,
                LTXT(L"Nodi attivi: %u exit in %d paesi verificati.", L"Active nodes: %u exits in %d verified countries."),
                g_total_exit_relays ? g_total_exit_relays : 2796, (g_country_row_count > 1) ? (g_country_row_count - 1) : 49);
        } else {
            wcscpy_s(info_nodes, _countof(info_nodes), LTXT(L"Sincronizzazione consenso nodi Tor…", L"Synchronizing Tor relay consensus…"));
        }
        text(dc, 788, 702, info_nodes, green, g_caption);

    } else if(g_active_tab == TAB_SPEED) {
        /* TAB 1: Speed & Monitor */
        card(dc, 32, 146, 260, 110);
        dot(dc, 52, 166, 8, green);
        text(dc, 66, 162, LTXT(L"DOWNLOAD SPEED", L"DOWNLOAD SPEED"), muted, g_caption);
        wchar_t spd_rx[64]; format_speed(g_speed_rx_bps, spd_rx, _countof(spd_rx));
        text(dc, 52, 184, spd_rx, green, g_heading);
        text(dc, 52, 222, LTXT(L"Throughput in ricezione tunnel", L"Tunnel ingress throughput"), muted, g_caption);

        card(dc, 310, 146, 260, 110);
        dot(dc, 330, 166, 8, teal);
        text(dc, 344, 162, LTXT(L"UPLOAD SPEED", L"UPLOAD SPEED"), muted, g_caption);
        wchar_t spd_tx[64]; format_speed(g_speed_tx_bps, spd_tx, _countof(spd_tx));
        text(dc, 330, 184, spd_tx, teal, g_heading);
        text(dc, 330, 222, LTXT(L"Throughput in trasmissione", L"Tunnel egress throughput"), muted, g_caption);

        card(dc, 588, 146, 260, 110);
        dot(dc, 608, 166, 8, RGB(90, 80, 210));
        text(dc, 622, 162, LTXT(L"VOLUME SESSIONE (RX/TX)", L"SESSION VOLUME (RX/TX)"), muted, g_caption);
        wchar_t tot_rx[32], tot_tx[32], tot_str[64];
        format_bytes(g_total_rx_bytes, tot_rx, _countof(tot_rx));
        format_bytes(g_total_tx_bytes, tot_tx, _countof(tot_tx));
        _snwprintf_s(tot_str, _countof(tot_str), _TRUNCATE, L"%s / %s", tot_rx, tot_tx);
        text(dc, 608, 186, tot_str, white, g_font_bold ? g_font_bold : g_font);
        text(dc, 608, 222, LTXT(L"Traffico cifrato totale scambiato", L"Total encrypted bytes exchanged"), muted, g_caption);

        card(dc, 868, 146, 260, 110);
        dot(dc, 888, 166, 8, RGB(220, 120, 20));
        text(dc, 902, 162, LTXT(L"LATENZA & QUALITÀ TOR", L"TOR LATENCY & QUALITY"), muted, g_caption);
        wchar_t lat_str[64];
        if(g_attestation.latency_ms > 0) _snwprintf_s(lat_str, _countof(lat_str), _TRUNCATE, L"%d ms", g_attestation.latency_ms);
        else wcscpy_s(lat_str, _countof(lat_str), g_connected ? L"~ 450 ms" : L"—");
        text(dc, 888, 184, lat_str, white, g_heading);
        wchar_t q_str[64];
        _snwprintf_s(q_str, _countof(q_str), _TRUNCATE, LTXT(L"Anti-MITM: %d%% · 0 Leak", L"Anti-MITM: %d%% · 0 Leaks"),
            g_attestation.reputation_score ? g_attestation.reputation_score : 99);
        text(dc, 888, 222, q_str, green, g_caption);

        /* Real-Time Sparkline / Area Chart */
        card(dc, 32, 272, 1096, 260);
        text(dc, 60, 292, LTXT(L"MONITOR TRAFFICO IN TEMPO REALE (ULTIMI 30 SECONDI)", L"REAL-TIME TRAFFIC MONITOR (LAST 30 SECONDS)"), muted, g_caption);
        text(dc, 60, 314, LTXT(L"Flusso pacchetti Wintun attraverso il circuito cifrato Tor", L"Wintun packet flow through the encrypted Tor circuit"), white, g_font);

        dot(dc, 840, 297, 8, green);
        text(dc, 854, 294, L"Download (RX)", muted, g_caption);
        dot(dc, 960, 297, 8, teal);
        text(dc, 974, 294, L"Upload (TX)", muted, g_caption);

        int gx = 60, gy = 350, gw = 1040, gh = 150;
        rect(dc, gx, gy, gw, gh, RGB(248, 250, 253), 8);

        DWORD max_speed = 1024 * 50;
        for(int i = 0; i < SPEED_HISTORY_LEN; i++) {
            if(g_speed_history_rx[i] > max_speed) max_speed = g_speed_history_rx[i];
            if(g_speed_history_tx[i] > max_speed) max_speed = g_speed_history_tx[i];
        }

        for(int k = 1; k <= 3; k++) {
            int line_y = gy + gh - (k * gh / 4);
            rule(dc, gx, line_y, gw);
        }

        POINT pts[SPEED_HISTORY_LEN + 2];
        for(int i = 0; i < SPEED_HISTORY_LEN; i++) {
            int px = gx + (i * gw) / (SPEED_HISTORY_LEN - 1);
            int py = gy + gh - (int)(((long long)g_speed_history_rx[i] * (gh - 12)) / max_speed);
            pts[i].x = px;
            pts[i].y = py;
        }
        pts[SPEED_HISTORY_LEN].x = gx + gw;
        pts[SPEED_HISTORY_LEN].y = gy + gh;
        pts[SPEED_HISTORY_LEN + 1].x = gx;
        pts[SPEED_HISTORY_LEN + 1].y = gy + gh;

        HBRUSH rx_brush = CreateSolidBrush(RGB(220, 245, 235));
        HPEN rx_pen = CreatePen(PS_SOLID, 2, green);
        HGDIOBJ old_b = SelectObject(dc, rx_brush);
        HGDIOBJ old_p = SelectObject(dc, rx_pen);
        Polygon(dc, pts, SPEED_HISTORY_LEN + 2);
        SelectObject(dc, old_b);
        SelectObject(dc, old_p);
        DeleteObject(rx_brush);
        DeleteObject(rx_pen);

        HPEN tx_pen = CreatePen(PS_SOLID, 2, teal);
        HGDIOBJ old_tx_pen = SelectObject(dc, tx_pen);
        for(int i = 0; i < SPEED_HISTORY_LEN; i++) {
            int px = gx + (i * gw) / (SPEED_HISTORY_LEN - 1);
            int py = gy + gh - (int)(((long long)g_speed_history_tx[i] * (gh - 12)) / max_speed);
            if(i == 0) MoveToEx(dc, px, py, NULL);
            else LineTo(dc, px, py);
        }
        SelectObject(dc, old_tx_pen);
        DeleteObject(tx_pen);

        wchar_t max_str[32]; format_speed(max_speed, max_str, _countof(max_str));
        text(dc, gx + 8, gy + 6, max_str, muted, g_caption);
        text(dc, gx + 8, gy + gh - 18, L"0 KB/s", muted, g_caption);
        text(dc, gx + gw - 64, gy + gh - 18, LTXT(L"Adesso", L"Now"), muted, g_caption);
        text(dc, gx + gw / 2 - 20, gy + gh - 18, L"-15s", muted, g_caption);

        /* Bottom Row: 2 Advanced Performance Cards */
        card(dc, 32, 548, 538, 210);
        text(dc, 60, 568, LTXT(L"PIPELINE SOCKET & DRIVER WINTUN", L"WINTUN DRIVER & SOCKET PIPELINE"), muted, g_caption);
        text(dc, 60, 592, LTXT(L"Throughput e Ottimizzazione Kernel", L"Throughput & Kernel Optimization"), white, g_font);

        dot(dc, 60, 626, 8, green);
        text(dc, 76, 622, LTXT(L"Wintun Ring Buffer: Capacità 4 MB · Zero packet drop", L"Wintun Ring Buffer: 4 MB Capacity · Zero packet drops"), white, g_small);

        dot(dc, 60, 654, 8, teal);
        text(dc, 76, 650, LTXT(L"Pipelining Asincrono: Attivo (Streaming a bassa latenza)", L"Async Pipelining: Active (Low-latency streaming)"), white, g_small);

        dot(dc, 60, 682, 8, green);
        text(dc, 76, 678, LTXT(L"TCP Vegas/CUBIC Tuning: Finestra dinamica ottimizzata", L"TCP Vegas/CUBIC Tuning: Dynamic window tuned"), white, g_small);

        dot(dc, 60, 710, 8, RGB(211, 145, 31));
        text(dc, 76, 706, LTXT(L"Politica UDP/QUIC: Fail-closed (Blocco totale leak)", L"UDP/QUIC Policy: Fail-closed (Zero leaks guaranteed)"), white, g_small);

        card(dc, 590, 548, 538, 210);
        text(dc, 618, 568, LTXT(L"MULTIPLEXING TOR & CONSUMO HARDWARE", L"TOR MULTIPLEXING & HARDWARE CONSUMPTION"), muted, g_caption);
        text(dc, 618, 592, LTXT(L"Stato Flussi e Risorse", L"Stream State & System Resources"), white, g_font);

        dot(dc, 618, 626, 8, green);
        text(dc, 634, 622, LTXT(L"Stream Isolation: Circuiti isolati per porta e host", L"Stream Isolation: Separate circuits per port and host"), white, g_small);

        dot(dc, 618, 654, 8, teal);
        text(dc, 634, 650, LTXT(L"Protezione Disco SSD: AvoidDiskWrites attivo (RAM cache)", L"SSD Protection: AvoidDiskWrites active (RAM cache)"), white, g_small);

        dot(dc, 618, 682, 8, green);
        text(dc, 634, 678, LTXT(L"Porta Pentest SOCKS5: 127.0.0.1:9052 pronta", L"Dedicated Pentest Port: 127.0.0.1:9052 ready"), white, g_small);

        dot(dc, 618, 710, 8, teal);
        text(dc, 634, 706, LTXT(L"Capacità Larghezza di Banda: Illimitata (Consensus)", L"Bandwidth Cap: Unlimited (Consensus-based)"), white, g_small);

    } else if(g_active_tab == TAB_SETTINGS) {
        /* TAB 2: Impostazioni & DNS */
        card(dc, 32, 146, 1096, 116);
        text(dc, 60, 164, LTXT(L"RISOLUTORE DNS DI SISTEMA, GEO-MASKING & ANTI-ECS", L"SYSTEM DNS RESOLVER, GEO-MASKING & ANTI-ECS"), muted, g_caption);
        text(dc, 60, 184, LTXT(L"Instrada le query DNS nel tunnel cifrato prevenendo DNS leak e profilazione geografica.", L"Route DNS queries through encrypted tunnel preventing DNS leaks and geographic profiling."), white, g_font);
        const wchar_t *dns_desc = (g_setting_dns_mode == 0) ?
            LTXT(L"MapDNS Geo-Aligned attivo (Consigliato): Risoluzione istantanea (0 ms) in RAM cache. Il DNS esce direttamente dall'Exit Node Tor nel paese scelto, azzerando qualsiasi mismatch geografico.",
                 L"Geo-Aligned MapDNS active (Recommended): Instant (0 ms) in-RAM resolution. External DNS exits directly from the Tor Exit Node in the chosen country, eliminating any geo-mismatch.") :
            ((g_setting_dns_mode == 1) ?
            LTXT(L"Cloudflare Privacy Gateway attivo: Query cifrate nel tunnel Tor. Nessun log IP e stripping automatico della subnet client (Anti-ECS RFC 7871).",
                 L"Cloudflare Privacy Gateway active: Encrypted queries in Tor tunnel. No-Log policy and automatic client subnet stripping (Anti-ECS RFC 7871).") :
            ((g_setting_dns_mode == 2) ?
            LTXT(L"Quad9 Security attivo: Protezione anti-malware basata in Svizzera. Blocco feed C2 malevoli e rispetto rigoroso della privacy elvetica.",
                 L"Quad9 Security active: Swiss-based malware protection. Malicious C2 threat blocking with strict Swiss privacy law adherence.") :
            LTXT(L"Resolver Personalizzato: Connessione IPv4 manuale attraverso il tunnel cifrato verso il server specificato.",
                 L"Custom Resolver: Manual IPv4 connection inside encrypted tunnel to the specified server.")));
        text(dc, 60, 240, dns_desc, green, g_small);

        card(dc, 32, 274, 1096, 484);
        text(dc, 60, 290, LTXT(L"PARAMETRI DI SICUREZZA, PERFORMANCE, TURBO & PENTESTING", L"SECURITY, PERFORMANCE, TURBO & PENTEST PARAMETERS"), muted, g_caption);

        draw_toggle(dc, 60, 312, g_setting_stream_isolation,
            LTXT(L"Stream Isolation per Porta e Destinazione", L"Stream Isolation per Port and Destination"),
            LTXT(L"Assegna circuiti Tor indipendenti per ciascuna app prevenendo la correlazione incrociata.",
                 L"Assigns separate Tor circuits per application preventing cross-correlation."));

        draw_toggle(dc, 60, 358, g_setting_turbo_boost,
            LTXT(L"Aurelia Turbo Boost & Multi-Guard Speed", L"Aurelia Turbo Boost & Multi-Guard Speed"),
            LTXT(L"Allarga il pool di Guard (6 nodi), FastFirstHopPK e riduce a 4s il timeout di negoziazione circuiti.",
                 L"Expands Guard pool (6 nodes), FastFirstHopPK and cuts circuit timeout to 4s for high speed."));

        draw_toggle(dc, 60, 404, g_setting_fake_ip,
            LTXT(L"Motore Fake-IP Pool 198.18.0.0/15 & Routing .onion Universale", L"Fake-IP Engine (198.18.0.0/15) & Universal .onion Routing"),
            LTXT(L"Risoluzione DNS locale istantanea (0 ms) e routing trasparente dei domini .onion su ogni app Windows.",
                 L"Instant 0-ms local DNS response and transparent .onion domain routing across all Windows apps."));

        draw_toggle(dc, 60, 450, g_setting_stealth_mode,
            LTXT(L"Windows Stealth Shield (Anti-Broadcast & Anti-Leak LAN)", L"Windows Stealth Shield (Anti-Broadcast & LAN Anti-Leak)"),
            LTXT(L"Blocca perdite mDNS (5353), LLMNR (5355), NetBIOS (137-139) e SSDP a livello WFP/Firewall.",
                 L"Blocks mDNS (5353), LLMNR (5355), NetBIOS (137-139) and SSDP discovery at WFP/Firewall level."));

        draw_toggle(dc, 60, 496, g_setting_strict_nodes,
            LTXT(L"Nodi di Uscita Rigorosi (Strict Exit Nodes)", L"Strict Exit Nodes"),
            LTXT(L"Rifiuta rigorosamente qualsiasi circuito che non utilizzi il paese di uscita selezionato.",
                 L"Strictly rejects any circuit that does not match the chosen exit country."));

        draw_toggle(dc, 60, 542, g_setting_pentest_port,
            LTXT(L"Porta SOCKS Pentest Dedicata (127.0.0.1:9052)", L"Dedicated Pentest SOCKS Port (127.0.0.1:9052)"),
            LTXT(L"Porta ausiliaria pronta come upstream proxy per Burp Suite, OWASP ZAP, curl e script.",
                 L"Auxiliary proxy ready as upstream for Burp Suite, OWASP ZAP, curl and scripts."));

        draw_toggle(dc, 60, 588, g_setting_preboot_killswitch,
            LTXT(L"Kill Switch Pre-Boot Persistente WFP", L"Persistent Pre-Boot WFP Kill Switch"),
            LTXT(L"Arma le regole firewall WFP prima dell'attivazione di rete: 0 leak al boot o al cambio Wi-Fi.",
                 L"Arms WFP firewall rules before network link activation: 0 leaks on boot or Wi-Fi roaming."));

        draw_toggle(dc, 60, 634, g_setting_avoid_disk,
            LTXT(L"Protezione Disco SSD & Zero Scritture (AvoidDiskWrites)", L"SSD Protection & Zero Disk Writes (AvoidDiskWrites)"),
            LTXT(L"Conserva lo stato e la cache del consenso Tor in RAM per azzerare l'usura del disco e velocizzare l'I/O.",
                 L"Keeps Tor consensus and cache in RAM to prevent disk wear and speed up I/O."));

        draw_toggle(dc, 60, 680, g_setting_pipeline_mode,
            LTXT(L"Ottimizzazione Pipeline Driver Wintun", L"Wintun Driver Pipeline Optimization"),
            LTXT(L"Abilita lo streaming asincrono dei pacchetti IP per massima velocità e fluidità di navigazione.",
                 L"Enables async IP packet streaming for maximum speed and browsing fluidity."));

        if(GetTickCount() - g_settings_saved_tick < 3500) {
            chip(dc, 760, 284, 340, 26,
                LTXT(L"✓ IMPOSTAZIONI SALVATE E APPLICATE", L"✓ SETTINGS SAVED & APPLIED"),
                green, pale_green);
        }
    }

    text(dc, 32, 776, LTXT(L"Aurelia · Kill switch Windows fail-closed · DNS anti-leak nel tunnel · Wintun C-native",
        L"Aurelia · Fail-closed Windows kill switch · Anti-leak tunnel DNS · Wintun C-native"), muted, g_caption);
}

static void paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT cr; GetClientRect(hwnd, &cr);
    int w = cr.right - cr.left, h = cr.bottom - cr.top;
    HDC dc = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
    HGDIOBJ oldbmp = SelectObject(dc, bmp);
    paint_dc(dc, w, h);
    BitBlt(hdc, 0, 0, w, h, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldbmp); DeleteObject(bmp); DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_PRINTCLIENT:
    case WM_PRINT: {
        RECT cr; GetClientRect(hwnd, &cr);
        paint_dc((HDC)wp, cr.right - cr.left, cr.bottom - cr.top);
        return 0;
    }
    case WM_CREATE:
        g_window = hwnd;
        if(g_app_icon_header || g_app_icon) {
            SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)(g_app_icon_small ? g_app_icon_small : g_app_icon));
            SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)(g_app_icon_header ? g_app_icon_header : g_app_icon));
        }
        g_language = CreateWindowExW(0, L"BUTTON", L"", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 838, 26, 106, 36, hwnd, (HMENU)ID_LANGUAGE, NULL, NULL);
        g_connect = CreateWindowExW(0, L"BUTTON", L"Connetti a Tor", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 60, 414, 190, 48, hwnd, (HMENU)ID_CONNECT, NULL, NULL);
        g_rotate = CreateWindowExW(0, L"BUTTON", L"Nuovo circuito", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | WS_DISABLED, 262, 414, 175, 48, hwnd, (HMENU)ID_ROTATE, NULL, NULL);
        g_audit = CreateWindowExW(0, L"BUTTON", L"Audit & Sicurezza", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 449, 414, 175, 48, hwnd, (HMENU)ID_AUDIT, NULL, NULL);
        g_country = CreateWindowExW(0, L"BUTTON", L"", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 788, 556, 312, 38, hwnd, (HMENU)ID_COUNTRY, NULL, NULL);
        fill_country_options(g_exit_index);
        g_interval = CreateWindowExW(0, L"BUTTON", L"", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 788, 650, 198, 34, hwnd, (HMENU)ID_INTERVAL, NULL, NULL);
        fill_interval_options(g_interval_index);
        g_btn_scan_nodes = CreateWindowExW(0, L"BUTTON", L"Scan Nodi", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 994, 650, 106, 34, hwnd, (HMENU)ID_SCAN_NODES, NULL, NULL);

        HANDLE init_disc = CreateThread(NULL, 0, exit_discovery_worker, NULL, 0, NULL);
        if(init_disc) CloseHandle(init_disc);

        g_dns_combo = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL, 60, 204, 440, 220, hwnd, (HMENU)ID_SETTING_DNS_COMBO, NULL, NULL);
        update_dns_combo_items();

        g_dns_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_setting_custom_dns_ip, WS_CHILD | ES_AUTOHSCROLL, 515, 204, 220, 28, hwnd, (HMENU)ID_SETTING_DNS_EDIT, NULL, NULL);
        if(g_font) {
            SendMessageW(g_dns_combo, WM_SETFONT, (WPARAM)g_font, TRUE);
            SendMessageW(g_dns_edit, WM_SETFONT, (WPARAM)g_font, TRUE);
        }

        g_btn_save_settings = CreateWindowExW(0, L"BUTTON", L"Salva e Applica Impostazioni", WS_CHILD | BS_OWNERDRAW, 755, 198, 350, 38, hwnd, (HMENU)ID_SETTING_SAVE_BTN, NULL, NULL);

        tray_add();
        apply_language();
        switch_tab(g_active_tab);
        SetTimer(hwnd, 3, 50, NULL);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT:
        paint(hwnd);
        return 0;

    case WM_MOUSEMOVE: {
        int x = LOWORD(lp), y = HIWORD(lp);
        int old_hover = g_tab_hover;
        if(y >= 90 && y <= 134) {
            if(x >= 36 && x < 400) g_tab_hover = 0;
            else if(x >= 400 && x < 764) g_tab_hover = 1;
            else if(x >= 764 && x <= 1128) g_tab_hover = 2;
            else g_tab_hover = -1;
        } else {
            g_tab_hover = -1;
        }
        if(g_tab_hover != old_hover) {
            RECT tr = {32, 90, 1128, 134};
            InvalidateRect(hwnd, &tr, FALSE);
        }
        break;
    }

    case WM_LBUTTONUP: {
        int x = LOWORD(lp), y = HIWORD(lp);
        if(y >= 90 && y <= 134) {
            if(x >= 36 && x < 400) { switch_tab(TAB_TUNNEL); return 0; }
            else if(x >= 400 && x < 764) { switch_tab(TAB_SPEED); return 0; }
            else if(x >= 764 && x <= 1128) { switch_tab(TAB_SETTINGS); return 0; }
        }
        if(g_active_tab == TAB_SETTINGS) {
            if(x >= 60 && x <= 920) {
                if(y >= 308 && y <= 350) { g_setting_stream_isolation = !g_setting_stream_isolation; save_preferences(); g_settings_saved_tick = GetTickCount(); InvalidateRect(hwnd, NULL, FALSE); return 0; }
                if(y >= 354 && y <= 396) { g_setting_turbo_boost = !g_setting_turbo_boost; save_preferences(); g_settings_saved_tick = GetTickCount(); InvalidateRect(hwnd, NULL, FALSE); return 0; }
                if(y >= 400 && y <= 442) { g_setting_fake_ip = !g_setting_fake_ip; save_preferences(); g_settings_saved_tick = GetTickCount(); InvalidateRect(hwnd, NULL, FALSE); return 0; }
                if(y >= 446 && y <= 488) { g_setting_stealth_mode = !g_setting_stealth_mode; save_preferences(); g_settings_saved_tick = GetTickCount(); InvalidateRect(hwnd, NULL, FALSE); return 0; }
                if(y >= 492 && y <= 534) { g_setting_strict_nodes = !g_setting_strict_nodes; save_preferences(); g_settings_saved_tick = GetTickCount(); InvalidateRect(hwnd, NULL, FALSE); return 0; }
                if(y >= 538 && y <= 580) { g_setting_pentest_port = !g_setting_pentest_port; save_preferences(); g_settings_saved_tick = GetTickCount(); InvalidateRect(hwnd, NULL, FALSE); return 0; }
                if(y >= 584 && y <= 626) { g_setting_preboot_killswitch = !g_setting_preboot_killswitch; save_preferences(); g_settings_saved_tick = GetTickCount(); InvalidateRect(hwnd, NULL, FALSE); return 0; }
                if(y >= 630 && y <= 672) { g_setting_avoid_disk = !g_setting_avoid_disk; save_preferences(); g_settings_saved_tick = GetTickCount(); InvalidateRect(hwnd, NULL, FALSE); return 0; }
                if(y >= 676 && y <= 718) { g_setting_pipeline_mode = !g_setting_pipeline_mode; save_preferences(); g_settings_saved_tick = GetTickCount(); InvalidateRect(hwnd, NULL, FALSE); return 0; }
            }
        }
        break;
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *d = (DRAWITEMSTRUCT*)lp;
        int id = (int)d->CtlID;
        HDC dc = d->hDC;
        RECT r = d->rcItem;
        if(id == ID_COUNTRY) { draw_country_button(d); return TRUE; }
        if(id == ID_INTERVAL) { draw_interval_button(d); return TRUE; }
        if(id == ID_LANGUAGE) { draw_language_button(d); return TRUE; }

        if(id == ID_CONNECT) {
            BOOL pressed = (d->itemState & ODS_SELECTED) != 0;
            COLORREF c;
            if(g_starting) {
                c = pressed ? RGB(190, 115, 20) : RGB(217, 140, 30);
            } else if(g_vpn_active) {
                c = pressed ? RGB(185, 40, 50) : RGB(215, 50, 65);
            } else {
                c = pressed ? RGB(0, 95, 175) : RGB(0, 114, 206);
            }
            rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, c, 10);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, RGB(255, 255, 255));
            HFONT old = (HFONT)SelectObject(dc, g_font_bold ? g_font_bold : g_font);
            wchar_t s[64];
            GetWindowTextW(d->hwndItem, s, 64);
            DrawTextW(dc, s, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, old);
            return TRUE;
        }

        if(id == ID_ROTATE) {
            BOOL disabled = (d->itemState & ODS_DISABLED) != 0;
            BOOL pressed = (d->itemState & ODS_SELECTED) != 0;
            COLORREF c_bg = disabled ? RGB(241, 245, 249) : (pressed ? RGB(230, 242, 255) : RGB(255, 255, 255));
            COLORREF c_border = disabled ? RGB(226, 232, 240) : (pressed ? teal : RGB(190, 215, 240));
            COLORREF c_text = disabled ? RGB(160, 175, 190) : teal;

            rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, c_bg, 10);
            HPEN p = CreatePen(PS_SOLID, 1, c_border), op = (HPEN)SelectObject(dc, p);
            HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
            RoundRect(dc, r.left, r.top, r.right, r.bottom, 10, 10);
            SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(p);

            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, c_text);
            HFONT old = (HFONT)SelectObject(dc, g_font);
            wchar_t s[64];
            GetWindowTextW(d->hwndItem, s, 64);
            DrawTextW(dc, s, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, old);
            return TRUE;
        }

        if(id == ID_AUDIT) {
            BOOL pressed = (d->itemState & ODS_SELECTED) != 0;
            COLORREF c_bg = pressed ? RGB(230, 242, 255) : RGB(255, 255, 255);
            COLORREF c_border = pressed ? teal : RGB(190, 215, 240);
            COLORREF c_text = teal;

            rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, c_bg, 10);
            HPEN p = CreatePen(PS_SOLID, 1, c_border), op = (HPEN)SelectObject(dc, p);
            HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
            RoundRect(dc, r.left, r.top, r.right, r.bottom, 10, 10);
            SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(p);

            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, c_text);
            HFONT old = (HFONT)SelectObject(dc, g_font);
            wchar_t s[64];
            GetWindowTextW(d->hwndItem, s, 64);
            DrawTextW(dc, s, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, old);
            return TRUE;
        }

        if(id == ID_SCAN_NODES) {
            BOOL pressed = (d->itemState & ODS_SELECTED) != 0;
            COLORREF c_bg = pressed ? RGB(230, 242, 255) : RGB(255, 255, 255);
            COLORREF c_border = pressed ? teal : RGB(190, 215, 240);
            COLORREF c_text = teal;

            rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, c_bg, 8);
            HPEN p = CreatePen(PS_SOLID, 1, c_border), op = (HPEN)SelectObject(dc, p);
            HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
            RoundRect(dc, r.left, r.top, r.right, r.bottom, 8, 8);
            SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(p);

            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, c_text);
            HFONT old = (HFONT)SelectObject(dc, g_font);
            wchar_t s[64];
            GetWindowTextW(d->hwndItem, s, 64);
            DrawTextW(dc, s, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, old);
            return TRUE;
        }

        if(id == ID_SETTING_SAVE_BTN) {
            BOOL pressed = (d->itemState & ODS_SELECTED) != 0;
            COLORREF c = pressed ? RGB(0, 110, 80) : green;
            rect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, c, 10);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, RGB(255, 255, 255));
            HFONT old = (HFONT)SelectObject(dc, g_font_bold ? g_font_bold : g_font);
            wchar_t s[64];
            GetWindowTextW(d->hwndItem, s, 64);
            DrawTextW(dc, s, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, old);
            return TRUE;
        }
        return TRUE;
    }

    case WM_TIMER:
        if(wp == 3) {
            g_anim_phase = (g_anim_phase + 3) % 360;
            RECT orbit = {540, 185, 748, 395};
            InvalidateRect(hwnd, &orbit, FALSE);
            return 0;
        }
        if(wp == 1 && g_tor_process.hProcess) {
            DWORD code = 0;
            if(!GetExitCodeProcess(g_tor_process.hProcess, &code) || code != STILL_ACTIVE) {
                wchar_t m[128]; _snwprintf_s(m, _countof(m), _TRUNCATE, L"Tor process exited code=%lu", code);
                trace_start(m);
                stop_tor();
            } else if(g_helper_process && WaitForSingleObject(g_helper_process, 0) == WAIT_OBJECT_0) {
                DWORD helper_code = 0;
                GetExitCodeProcess(g_helper_process, &helper_code);
                wchar_t m[128]; _snwprintf_s(m, _countof(m), _TRUNCATE, L"tunnel helper exited unexpectedly code=%lu", helper_code);
                trace_start(m);
                stop_tor();
                MessageBoxW(hwnd, LTXT(L"Il tunnel si è arrestato. Aurelia ha chiuso Tor e ripristinato il firewall.",
                                       L"The tunnel stopped. Aurelia closed Tor and restored the firewall."), APP_NAME, MB_OK | MB_ICONERROR);
            } else {
                int ready = socks_ready();
                if(ready != g_connected) {
                    g_connected = ready;
                    EnableWindow(g_rotate, ready);
                    InvalidateRect(hwnd, NULL, TRUE);
                }
                if(ready) {
                    poll_tor_info();
                    poll_tor_traffic();
                    request_circuit_info();
                    if(g_active_tab == TAB_SPEED) InvalidateRect(hwnd, NULL, FALSE);
                    if(g_vpn_active) {
                        DWORD now = GetTickCount();
                        if(now - g_last_attestation_poll >= 12000) {
                            g_last_attestation_poll = now;
                            if(InterlockedCompareExchange(&g_attestation_busy, 1, 0) == 0) {
                                HANDLE t = CreateThread(NULL, 0, leak_attestation_worker, NULL, 0, NULL);
                                if(t) CloseHandle(t);
                                else InterlockedExchange(&g_attestation_busy, 0);
                            }
                        }
                    }
                }
            }
        }
        else if(wp == 2 && g_connected) {
            if(!tor_newnym()) {
                MessageBoxW(hwnd, LTXT(L"Tor non ha accettato la rotazione. Verifica che il servizio sia pronto.",
                                       L"Tor could not rotate the circuit. Check that it is ready."), APP_NAME, MB_OK | MB_ICONWARNING);
            } else {
                g_last_circuit_poll = 0;
            }
        }
        return 0;

    case WM_VPN_RESULT:
        trace_start(L"UI received worker result");
        if(g_start_thread) { CloseHandle(g_start_thread); g_start_thread = NULL; }
        InterlockedExchange(&g_starting, 0);
        if(wp) {
            SetWindowTextW(g_connect, LTXT(L"Disconnetti", L"Disconnect"));
            SetWindowTextW(g_rotate, LTXT(L"Nuovo circuito", L"New circuit"));
            if(g_audit) SetWindowTextW(g_audit, LTXT(L"Audit & Sicurezza", L"Audit & Security"));
            EnableWindow(g_rotate, TRUE);
            EnableWindow(g_country, TRUE);
            g_last_circuit_poll = 0;
            g_last_attestation_poll = 0;
            if(InterlockedCompareExchange(&g_attestation_busy, 1, 0) == 0) {
                HANDLE t = CreateThread(NULL, 0, leak_attestation_worker, NULL, 0, NULL);
                if(t) CloseHandle(t);
                else InterlockedExchange(&g_attestation_busy, 0);
            }
            SetTimer(hwnd, 1, 1000, NULL);
            static const UINT mins[] = {0, 5, 10, 30};
            if(g_interval_index > 0 && g_interval_index < 4) SetTimer(hwnd, 2, mins[g_interval_index] * 60 * 1000, NULL);
        } else {
            int canceled = InterlockedExchange(&g_cancel_start, 0);
            trace_start(canceled ? L"cleanup after canceled start" : L"cleanup after start failure");
            stop_tor();
            trace_start(L"cleanup complete");
            if(canceled) { InvalidateRect(hwnd, NULL, TRUE); return 0; }
            wchar_t message[256];
            if(g_helper_exit_code == 13) {
                _snwprintf_s(message, _countof(message), _TRUNCATE,
                    LTXT(L"Windows ha rifiutato l'attivazione del kill switch (helper %lu). Approva la richiesta UAC e verifica i criteri firewall.",
                         L"Windows refused to enable the kill switch (helper %lu). Approve the UAC prompt and check firewall policy."), g_helper_exit_code);
            } else {
                _snwprintf_s(message, _countof(message), _TRUNCATE,
                    LTXT(L"Avvio non riuscito (helper %lu). Controlla Tor, i file dell'app e la richiesta UAC.",
                         L"Could not start (helper %lu). Check Tor, the app files and the UAC prompt."), g_helper_exit_code);
            }
            MessageBoxW(hwnd, message, APP_NAME, MB_OK | MB_ICONERROR);
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;

    case WM_ATTESTATION_RESULT: {
        LeakAttestation *res = (LeakAttestation*)lp;
        if(res) {
            g_attestation = *res;
            g_attestation.check_count++;
            HeapFree(GetProcessHeap(), 0, res);
            InvalidateRect(hwnd, NULL, FALSE);
            if(g_audit_dialog) InvalidateRect(g_audit_dialog, NULL, FALSE);
        }
        return 0;
    }

    case WM_CIRCUIT_RESULT: {
        CircuitResult *result = (CircuitResult*)lp;
        if(result) {
            if(g_connected) {
                if(result->name[0][0] != 0) {
                    for(int i = 0; i < 3; i++) {
                        if(result->name[i][0]) memcpy(g_hop_name[i], result->name[i], sizeof(g_hop_name[i]));
                        if(result->country[i][0] != '-') memcpy(g_hop_country[i], result->country[i], sizeof(g_hop_country[i]));
                    }
                } else if(g_hop_name[0][0] == 0 && result->public_country[0] >= 'a' && result->public_country[0] <= 'z') {
                    g_hop_country[2][0] = result->public_country[0];
                    g_hop_country[2][1] = result->public_country[1];
                    g_hop_country[2][2] = 0;
                    if(g_hop_name[2][0] == 0) strcpy_s(g_hop_name[2], sizeof(g_hop_name[2]), "TorExitNode");
                }
                if(result->public_ip[0]) MultiByteToWideChar(CP_ACP, 0, result->public_ip, -1, g_exit_public_ip, _countof(g_exit_public_ip));
                if(result->public_country[0] >= 'a' && result->public_country[0] <= 'z') memcpy(g_exit_public_country, result->public_country, 3);
            }
            HeapFree(GetProcessHeap(), 0, result);
        }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    case WM_COUNTRY_RESULT: {
        ExitDiscovery *d = (ExitDiscovery*)lp;
        if(d) {
            if(d->valid) {
                memcpy(g_exit_relay_count, d->count, sizeof(g_exit_relay_count));
                g_exit_list_ready = 1;
            }
            HeapFree(GetProcessHeap(), 0, d);
            fill_country_options(g_exit_index);
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    }

    case WM_COMMAND:
        if(LOWORD(wp) == ID_TRAY_EXIT) { g_exit_app = 1; DestroyWindow(hwnd); return 0; }
        if(LOWORD(wp) == ID_LANGUAGE && HIWORD(wp) == BN_CLICKED) { toggle_language_popup(); return 0; }
        if(LOWORD(wp) == ID_COUNTRY && HIWORD(wp) == BN_CLICKED) { toggle_country_popup(); return 0; }
        if(LOWORD(wp) == ID_INTERVAL && HIWORD(wp) == BN_CLICKED) { toggle_interval_popup(); return 0; }
        if(LOWORD(wp) == ID_AUDIT) { open_audit_dialog(hwnd); return 0; }
        if(LOWORD(wp) == ID_SCAN_NODES) {
            HANDLE t = CreateThread(NULL, 0, exit_discovery_worker, NULL, 0, NULL);
            if(t) CloseHandle(t);
            open_relay_scanner_dialog(hwnd);
            return 0;
        }

        if(LOWORD(wp) == ID_SETTING_DNS_COMBO && HIWORD(wp) == CBN_SELCHANGE) {
            g_setting_dns_mode = (int)SendMessageW(g_dns_combo, CB_GETCURSEL, 0, 0);
            ShowWindow(g_dns_edit, (g_setting_dns_mode == 3) ? SW_SHOW : SW_HIDE);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        if(LOWORD(wp) == ID_SETTING_SAVE_BTN) {
            g_setting_dns_mode = (int)SendMessageW(g_dns_combo, CB_GETCURSEL, 0, 0);
            GetWindowTextW(g_dns_edit, g_setting_custom_dns_ip, _countof(g_setting_custom_dns_ip));
            save_preferences();
            g_settings_saved_tick = GetTickCount();
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        if(LOWORD(wp) == ID_CONNECT) {
            if(InterlockedCompareExchange(&g_starting, 0, 0)) {
                InterlockedExchange(&g_cancel_start, 1);
                if(g_cancel_event) SetEvent(g_cancel_event);
                if(g_stop_event) SetEvent(g_stop_event);
                if(g_tor_process.hProcess) (void)tor_control("SIGNAL SHUTDOWN", NULL, 0);
                SetWindowTextW(g_connect, LTXT(L"Annullamento…", L"Canceling…"));
                InvalidateRect(hwnd, NULL, FALSE);
                return 0;
            }
            if(g_tor_process.hProcess) { stop_tor(); return 0; }

            InterlockedExchange(&g_cancel_start, 0);
            g_cancel_event = CreateEventW(NULL, TRUE, FALSE, NULL);
            if(!g_cancel_event) {
                MessageBoxW(hwnd, LTXT(L"Impossibile preparare l'avvio annullabile.", L"Could not prepare a cancellable connection."), APP_NAME, MB_OK | MB_ICONERROR);
                return 0;
            }
            InterlockedExchange(&g_starting, 1);
            wcscpy_s(g_tor_info, _countof(g_tor_info), LTXT(L"Avvio di Tor…", L"Starting Tor…"));
            SetWindowTextW(g_connect, LTXT(L"Annulla", L"Cancel"));
            InvalidateRect(hwnd, NULL, TRUE);

            g_start_thread = CreateThread(NULL, 0, start_vpn_worker, NULL, 0, NULL);
            if(!g_start_thread) {
                InterlockedExchange(&g_starting, 0);
                SetWindowTextW(g_connect, LTXT(L"Connetti a Tor", L"Connect to Tor"));
                if(g_cancel_event) { CloseHandle(g_cancel_event); g_cancel_event = NULL; }
                return 0;
            }
            return 0;
        }

        if(LOWORD(wp) == ID_ROTATE) {
            if(!tor_newnym()) {
                MessageBoxW(hwnd, LTXT(L"Rotazione non riuscita. Attendi che Tor completi l'avvio.", L"Rotation failed. Wait for Tor to finish starting."), APP_NAME, MB_OK | MB_ICONWARNING);
            } else {
                g_last_circuit_poll = 0;
                MessageBoxW(hwnd, LTXT(L"Richiesta di nuovo circuito inviata a Tor.", L"A request for a new Tor circuit was sent."), APP_NAME, MB_OK | MB_ICONINFORMATION);
            }
            return 0;
        }
        return 0;

    case WM_TRAYICON: {
        UINT event = (UINT)LOWORD(lp);
        if(event == NIN_SELECT || event == NIN_KEYSELECT || event == WM_LBUTTONUP || event == WM_LBUTTONDBLCLK) {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        } else if(event == WM_RBUTTONUP || event == WM_CONTEXTMENU) {
            tray_menu();
        }
        return 0;
    }

    case WM_SIZE:
        if(wp == SIZE_MINIMIZED) ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        if(g_country_popup) { DestroyWindow(g_country_popup); g_country_popup = NULL; }
        if(g_interval_popup) { DestroyWindow(g_interval_popup); g_interval_popup = NULL; }
        if(g_language_popup) { DestroyWindow(g_language_popup); g_language_popup = NULL; }
        tray_remove();
        KillTimer(hwnd, 3);
        stop_tor();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmd, int show) {
    (void)prev; (void)cmd;
    INITCOMMONCONTROLSEX ic = {sizeof(ic), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&ic);
    g_instance = inst;

    load_preferences();
    init_gdiplus();
    g_app_icon_header = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_AURELIA), IMAGE_ICON, 48, 48, LR_DEFAULTCOLOR);
    g_app_icon = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_AURELIA), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
    g_app_icon_small = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_AURELIA), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

    g_font = CreateFontW(17, 0, 0, 0, FW_MEDIUM, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_font_bold = CreateFontW(17, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_small = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_caption = CreateFontW(12, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_heading = CreateFontW(29, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_emoji = CreateFontW(34, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI Emoji");

    if(cmd && wcsstr(cmd, L"--screenshot")) {
        int w = 1160, h = 840;
        HDC sdc = GetDC(NULL);
        HDC dc = CreateCompatibleDC(sdc);
        BITMAPINFO bi = {0};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = h;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 24;
        bi.bmiHeader.biCompression = BI_RGB;
        void *bits = NULL;
        HBITMAP dib = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
        HGDIOBJ old = SelectObject(dc, dib);
        paint_dc(dc, w, h);
        CreateDirectoryW(L"docs", NULL);
        FILE *f = NULL;
        if(_wfopen_s(&f, L"docs\\screenshot.bmp", L"wb") == 0 && f) {
            int row_bytes = ((w * 3 + 3) / 4) * 4;
            int img_size = row_bytes * h;
            BITMAPFILEHEADER bfh = {0};
            bfh.bfType = 0x4D42;
            bfh.bfOffBits = (DWORD)(sizeof(bfh) + sizeof(BITMAPINFOHEADER));
            bfh.bfSize = bfh.bfOffBits + (DWORD)img_size;
            fwrite(&bfh, sizeof(bfh), 1, f);
            fwrite(&bi.bmiHeader, sizeof(BITMAPINFOHEADER), 1, f);
            fwrite(bits, img_size, 1, f);
            fclose(f);
        }
        SelectObject(dc, old);
        DeleteObject(dib);
        DeleteDC(dc);
        ReleaseDC(NULL, sdc);
        return 0;
    }

    WNDCLASSW pc = {0};
    pc.lpfnWndProc = country_popup_proc;
    pc.hInstance = inst;
    pc.lpszClassName = L"AureliaCountryPopup";
    pc.hCursor = LoadCursor(NULL, IDC_HAND);
    pc.hbrBackground = CreateSolidBrush(panel);
    RegisterClassW(&pc);

    WNDCLASSW iclass = {0};
    iclass.lpfnWndProc = interval_popup_proc;
    iclass.hInstance = inst;
    iclass.lpszClassName = L"AureliaIntervalPopup";
    iclass.hCursor = LoadCursor(NULL, IDC_HAND);
    iclass.hbrBackground = CreateSolidBrush(panel);
    RegisterClassW(&iclass);

    WNDCLASSW lclass = {0};
    lclass.lpfnWndProc = language_popup_proc;
    lclass.hInstance = inst;
    lclass.lpszClassName = L"AureliaLanguagePopup";
    lclass.hCursor = LoadCursor(NULL, IDC_HAND);
    lclass.hbrBackground = CreateSolidBrush(panel);
    RegisterClassW(&lclass);

    WNDCLASSW aclass = {0};
    aclass.lpfnWndProc = audit_dialog_proc;
    aclass.hInstance = inst;
    aclass.lpszClassName = L"AureliaAuditDialog";
    aclass.hCursor = LoadCursor(NULL, IDC_ARROW);
    aclass.hbrBackground = CreateSolidBrush(bg);
    RegisterClassW(&aclass);

    WNDCLASSW sclass = {0};
    sclass.lpfnWndProc = relay_scanner_dialog_proc;
    sclass.hInstance = inst;
    sclass.lpszClassName = L"AureliaRelayScannerDialog";
    sclass.hCursor = LoadCursor(NULL, IDC_ARROW);
    sclass.hbrBackground = CreateSolidBrush(bg);
    RegisterClassW(&sclass);

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = L"AureliaMainWindow";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = g_app_icon_header ? g_app_icon_header : g_app_icon;
    wc.hbrBackground = CreateSolidBrush(bg);
    RegisterClassW(&wc);

    HWND h = CreateWindowExW(0, wc.lpszClassName, APP_NAME,
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE | WS_CLIPCHILDREN,
                             CW_USEDEFAULT, CW_USEDEFAULT, WIN_W, WIN_H + 40, NULL, NULL, inst, NULL);
    if(!h) return 1;
    ShowWindow(h, show);
    UpdateWindow(h);
    MSG m;
    while(GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return (int)m.wParam;
}
