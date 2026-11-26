#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef COBJMACROS
#define COBJMACROS
#endif
#include <winsock2.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <shellapi.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#define STATE_MAGIC 0x41555234u
#define STATE_VERSION 3u
#define MAX_ROUTES 512
#define RULE_GROUP L"Aurelia Tor VPN"
#define RULE_TOR L"Aurelia Tor Egress"
#define RULE_TUN L"Aurelia Tunnel Egress"
#define RULE_LOOP L"Aurelia Local SOCKS"
#define RULE_CONTROL L"Aurelia Local Tor Control"
#define RULE_BLOCK_DNS_UDP L"Aurelia Block Physical DNS UDP"
#define RULE_BLOCK_DNS_TCP L"Aurelia Block Physical DNS TCP"
#define TUN_NAME L"Aurelia-Tor"

typedef struct {
    DWORD family;
    BYTE prefix;
    DWORD if_index;
    SOCKADDR_INET destination;
    SOCKADDR_INET next_hop;
} RouteRecord;

typedef struct {
    DWORD magic, version, bytes;
    DWORD profile_mask;
    DWORD old_action[3];
    BOOL old_enabled[3];
    DWORD route_count, tunnel_index;
    DWORD physical4_index, physical6_index;
    SOCKADDR_INET physical4_gateway, physical6_gateway;
    GUID tunnel_guid;
    BOOL dns_saved;
    ULONG old_tun_metric4, old_tun_metric6;
    BOOL old_tun_automatic4, old_tun_automatic6, tun_metric4_saved, tun_metric6_saved;
    WCHAR old_dns_servers[512];
    WCHAR tor_path[MAX_PATH];
    WCHAR connected_event[128];
    WCHAR stop_event[128];
    RouteRecord routes[MAX_ROUTES];
} NetState;

typedef int (__cdecl *HevMainFn)(const char *, int);
typedef void (__cdecl *HevQuitFn)(void);

static NetState state;
static wchar_t state_path[MAX_PATH];
static wchar_t helper_path[MAX_PATH];
static wchar_t stop_name[128], blocked_name[128], go_name[128], ready_name[128];
static wchar_t helper_tor_path[MAX_PATH];
static HANDLE state_mutex;
static HANDLE stop_event, blocked_event, go_event, ready_event;
static HANDLE parent_process;
static HANDLE tunnel_thread;
static HMODULE hev_module;
static HevMainFn hev_main_fn;
static HevQuitFn hev_quit_fn;
static char hev_config_path[MAX_PATH];
static wchar_t hev_config_wpath[MAX_PATH];
static DWORD parent_pid;

static void helper_trace(const wchar_t *stage) {
    wchar_t path[MAX_PATH];_snwprintf_s(path,MAX_PATH,_TRUNCATE,L"%s.helper.log",state_path);
    HANDLE f=CreateFileW(path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE)return;
    SYSTEMTIME t;GetLocalTime(&t);wchar_t row[256];
    int n=_snwprintf_s(row,_countof(row),_TRUNCATE,L"%04u-%02u-%02u %02u:%02u:%02u %s\r\n",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,stage);
    DWORD done=0;WriteFile(f,row,(DWORD)(n*sizeof(wchar_t)),&done,NULL);CloseHandle(f);
}

static int state_write_locked(void) {
    wchar_t tmp[MAX_PATH];
    _snwprintf_s(tmp, MAX_PATH, _TRUNCATE, L"%s.tmp", state_path);
    HANDLE f=CreateFileW(tmp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN,NULL);
    if(f==INVALID_HANDLE_VALUE)return 0;
    DWORD done=0; BOOL ok=WriteFile(f,&state,sizeof(state),&done,NULL)&&done==sizeof(state)&&FlushFileBuffers(f);
    CloseHandle(f);
    if(!ok){DeleteFileW(tmp);return 0;}
    if(!MoveFileExW(tmp,state_path,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){DeleteFileW(tmp);return 0;}
    return 1;
}
static int state_load(void) {
    HANDLE f=CreateFileW(state_path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE)return 0;
    DWORD got=0; BOOL ok=ReadFile(f,&state,sizeof(state),&got,NULL)&&got==sizeof(state); CloseHandle(f);
    return ok&&state.magic==STATE_MAGIC&&state.version==STATE_VERSION&&state.bytes==sizeof(state)&&state.route_count<=MAX_ROUTES;
}

static void remove_rules(void) {
    INetFwPolicy2 *policy=NULL; INetFwRules *rules=NULL;
    if(FAILED(CoCreateInstance(&CLSID_NetFwPolicy2,NULL,CLSCTX_INPROC_SERVER,&IID_INetFwPolicy2,(void**)&policy)))return;
    if(SUCCEEDED(INetFwPolicy2_get_Rules(policy,&rules))) {
        BSTR names[6]={SysAllocString(RULE_TOR),SysAllocString(RULE_TUN),SysAllocString(RULE_LOOP),SysAllocString(RULE_CONTROL),SysAllocString(RULE_BLOCK_DNS_UDP),SysAllocString(RULE_BLOCK_DNS_TCP)};
        for(int i=0;i<6;i++){if(names[i]){INetFwRules_Remove(rules,names[i]);SysFreeString(names[i]);}}
        INetFwRules_Release(rules);
    }
    INetFwPolicy2_Release(policy);
}

static int add_block_dns_rule(INetFwRules *rules,const wchar_t *name,long protocol) {
    INetFwRule *r=NULL; HRESULT hr=CoCreateInstance(&CLSID_NetFwRule,NULL,CLSCTX_INPROC_SERVER,&IID_INetFwRule,(void**)&r);
    if(FAILED(hr))return 0;
    BSTR bn=SysAllocString(name);
    BSTR group=SysAllocString(RULE_GROUP);
    BSTR bports=SysAllocString(L"53");
    BSTR btypes=SysAllocString(L"Lan,Wireless,RemoteAccess");
    hr=INetFwRule_put_Name(r,bn);
    if(SUCCEEDED(hr)) hr=INetFwRule_put_Grouping(r,group);
    if(SUCCEEDED(hr)) hr=INetFwRule_put_Protocol(r,protocol);
    if(SUCCEEDED(hr)) hr=INetFwRule_put_RemotePorts(r,bports);
    if(SUCCEEDED(hr)) hr=INetFwRule_put_Direction(r,NET_FW_RULE_DIR_OUT);
    if(SUCCEEDED(hr)) hr=INetFwRule_put_Action(r,NET_FW_ACTION_BLOCK);
    if(SUCCEEDED(hr)) hr=INetFwRule_put_InterfaceTypes(r,btypes);
    if(SUCCEEDED(hr)) hr=INetFwRule_put_Profiles(r,(long)NET_FW_PROFILE2_ALL);
    if(SUCCEEDED(hr)) hr=INetFwRule_put_Enabled(r,VARIANT_TRUE);
    if(SUCCEEDED(hr)) hr=INetFwRules_Add(rules,r);
    if(bn)SysFreeString(bn);if(group)SysFreeString(group);if(bports)SysFreeString(bports);if(btypes)SysFreeString(btypes);INetFwRule_Release(r);
    return SUCCEEDED(hr);
}

static void flush_dns_cache(void) {
    HMODULE m=LoadLibraryW(L"dnsapi.dll");
    if(m) {
        typedef BOOL (WINAPI *DnsFlushCacheFn)(void);
        DnsFlushCacheFn fn=(DnsFlushCacheFn)GetProcAddress(m,"DnsFlushResolverCache");
        if(fn) fn();
        FreeLibrary(m);
    }
}

static void apply_dns_leak_policy(int enable) {
    HKEY hk=NULL;
    if(enable) {
        if(RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
            DWORD one=1, zero=0;
            RegSetValueExW(hk, L"DisableSmartNameResolution", 0, REG_DWORD, (const BYTE*)&one, sizeof(one));
            RegSetValueExW(hk, L"EnableMulticast", 0, REG_DWORD, (const BYTE*)&zero, sizeof(zero));
            RegCloseKey(hk);
            helper_trace(L"Smart Multi-Homed Name Resolution disabled in registry");
        }
    } else {
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
            RegDeleteValueW(hk, L"DisableSmartNameResolution");
            RegDeleteValueW(hk, L"EnableMulticast");
            RegCloseKey(hk);
            helper_trace(L"Smart Multi-Homed Name Resolution restored in registry");
        }
    }
    flush_dns_cache();
}

static int add_rule(INetFwRules *rules,const wchar_t *name,const wchar_t *program,const wchar_t *remote,const wchar_t *ports,const wchar_t *interface_name,DWORD profiles) {
    INetFwRule *r=NULL; HRESULT hr=CoCreateInstance(&CLSID_NetFwRule,NULL,CLSCTX_INPROC_SERVER,&IID_INetFwRule,(void**)&r);
    if(FAILED(hr))return 0;
    const wchar_t *stage=L"set rule name";
    BSTR bn=SysAllocString(name), bp=program?SysAllocString(program):NULL;
    hr=INetFwRule_put_Name(r,bn);
    BSTR group=SysAllocString(RULE_GROUP), br=remote?SysAllocString(remote):NULL, bports=ports?SysAllocString(ports):NULL;
    if(SUCCEEDED(hr)){stage=L"set grouping";hr=INetFwRule_put_Grouping(r,group);}
    if(SUCCEEDED(hr)&&bp){stage=L"set application";hr=INetFwRule_put_ApplicationName(r,bp);}
    if(SUCCEEDED(hr)){stage=L"set protocol";hr=INetFwRule_put_Protocol(r,ports?IPPROTO_TCP:NET_FW_IP_PROTOCOL_ANY);}
    if(SUCCEEDED(hr)&&br){stage=L"set remote addresses";hr=INetFwRule_put_RemoteAddresses(r,br);}
    if(SUCCEEDED(hr)&&bports){stage=L"set remote ports";hr=INetFwRule_put_RemotePorts(r,bports);}
    if(SUCCEEDED(hr)){stage=L"set direction";hr=INetFwRule_put_Direction(r,NET_FW_RULE_DIR_OUT);}
    if(SUCCEEDED(hr)){stage=L"set action";hr=INetFwRule_put_Action(r,NET_FW_ACTION_ALLOW);}
    if(SUCCEEDED(hr)){stage=L"set profiles";hr=INetFwRule_put_Profiles(r,(long)profiles);}
    if(SUCCEEDED(hr)){stage=L"enable rule";hr=INetFwRule_put_Enabled(r,VARIANT_TRUE);}
    if(SUCCEEDED(hr)&&interface_name) {
        VARIANT v; VariantInit(&v); v.vt=VT_ARRAY|VT_VARIANT; v.parray=SafeArrayCreateVector(VT_VARIANT,0,1);
        if(!v.parray){hr=E_OUTOFMEMORY;stage=L"create interface array";}
        else {
            LONG i=0;VARIANT item;VariantInit(&item);item.vt=VT_BSTR;item.bstrVal=SysAllocString(interface_name);
            hr=SafeArrayPutElement(v.parray,&i,&item);VariantClear(&item);
            if(SUCCEEDED(hr)){stage=L"set interfaces";hr=INetFwRule_put_Interfaces(r,v);}
            VariantClear(&v);
        }
    }
    if(SUCCEEDED(hr)){stage=L"add rule";hr=INetFwRules_Add(rules,r);}
    if(FAILED(hr)){wchar_t m[256];_snwprintf_s(m,_countof(m),_TRUNCATE,L"firewall rule '%s' failed at %s HRESULT=0x%08lX",name,stage,(DWORD)hr);helper_trace(m);}
    if(bn)SysFreeString(bn);if(bp)SysFreeString(bp);if(group)SysFreeString(group);if(br)SysFreeString(br);if(bports)SysFreeString(bports);INetFwRule_Release(r);
    return SUCCEEDED(hr);
}

static int firewall_arm(const wchar_t *tor_path) {
    static const NET_FW_PROFILE_TYPE2 profiles[3]={NET_FW_PROFILE2_DOMAIN,NET_FW_PROFILE2_PRIVATE,NET_FW_PROFILE2_PUBLIC};
    INetFwPolicy2 *policy=NULL; INetFwRules *rules=NULL; HRESULT hr;
    hr=CoCreateInstance(&CLSID_NetFwPolicy2,NULL,CLSCTX_INPROC_SERVER,&IID_INetFwPolicy2,(void**)&policy);
    if(FAILED(hr)){wchar_t m[96];_snwprintf_s(m,_countof(m),_TRUNCATE,L"firewall COM create failed HRESULT=0x%08lX",(DWORD)hr);helper_trace(m);return 0;}
    LONG active=0; hr=INetFwPolicy2_get_CurrentProfileTypes(policy,&active);
    if(FAILED(hr)){INetFwPolicy2_Release(policy);helper_trace(L"firewall current-profile query failed");return 0;}(void)active;
    if(!state.magic) {
        state.magic=STATE_MAGIC; state.version=STATE_VERSION; state.bytes=sizeof(state); state.profile_mask=NET_FW_PROFILE2_ALL;
        for(int i=0;i<3;i++) {
            NET_FW_ACTION a=NET_FW_ACTION_ALLOW; VARIANT_BOOL enabled=VARIANT_FALSE;
            HRESULT h1=INetFwPolicy2_get_DefaultOutboundAction(policy,profiles[i],&a),h2=INetFwPolicy2_get_FirewallEnabled(policy,profiles[i],&enabled);
            if(FAILED(h1)||FAILED(h2)){wchar_t m[128];_snwprintf_s(m,_countof(m),_TRUNCATE,L"firewall profile query failed idx=%d h1=0x%08lX h2=0x%08lX",i,(DWORD)h1,(DWORD)h2);helper_trace(m);INetFwPolicy2_Release(policy);return 0;}
            state.old_action[i]=(DWORD)a; state.old_enabled[i]=enabled==VARIANT_TRUE;
        }
        wcscpy_s(state.tor_path,MAX_PATH,tor_path); wcscpy_s(state.connected_event,_countof(state.connected_event),ready_name);
        if(!state_write_locked()){helper_trace(L"firewall state save failed");INetFwPolicy2_Release(policy);return 0;}
    }
    remove_rules();
    hr=INetFwPolicy2_get_Rules(policy,&rules);
    int ok=SUCCEEDED(hr);
    if(!ok){wchar_t m[96];_snwprintf_s(m,_countof(m),_TRUNCATE,L"firewall rules query failed HRESULT=0x%08lX",(DWORD)hr);helper_trace(m);}
    if(ok&&!add_rule(rules,RULE_TOR,tor_path,NULL,NULL,NULL,NET_FW_PROFILE2_ALL)){helper_trace(L"adding Tor firewall rule failed");ok=0;}
    if(ok&&!add_rule(rules,RULE_LOOP,NULL,L"127.0.0.1",L"9050,9052",NULL,NET_FW_PROFILE2_ALL)){helper_trace(L"adding local SOCKS firewall rule failed");ok=0;}
    if(ok&&!add_rule(rules,RULE_CONTROL,NULL,L"127.0.0.1",L"9051",NULL,NET_FW_PROFILE2_ALL)){helper_trace(L"adding local control firewall rule failed");ok=0;}
    if(ok&&!add_block_dns_rule(rules,RULE_BLOCK_DNS_UDP,IPPROTO_UDP)){helper_trace(L"adding physical DNS UDP block rule failed");}
    if(ok&&!add_block_dns_rule(rules,RULE_BLOCK_DNS_TCP,IPPROTO_TCP)){helper_trace(L"adding physical DNS TCP block rule failed");}
    if(rules)INetFwRules_Release(rules);
    if(ok) {
        for(int i=0;i<3;i++) {
            HRESULT he=INetFwPolicy2_put_FirewallEnabled(policy,profiles[i],VARIANT_TRUE);
            HRESULT ha=SUCCEEDED(he)?INetFwPolicy2_put_DefaultOutboundAction(policy,profiles[i],NET_FW_ACTION_BLOCK):he;
            if(FAILED(he)||FAILED(ha)){wchar_t m[128];_snwprintf_s(m,_countof(m),_TRUNCATE,L"firewall block profile idx=%d enabled=0x%08lX action=0x%08lX",i,(DWORD)he,(DWORD)ha);helper_trace(m);ok=0;break;}
        }
    }
    INetFwPolicy2_Release(policy);
    if(!ok){helper_trace(L"firewall rule install or block-policy update failed");return 0;}
    if(!state_write_locked()){helper_trace(L"firewall state update failed");return 0;}
    helper_trace(L"firewall armed");return 1;
}

static int firewall_allow_tunnel(void) {
    INetFwPolicy2 *policy=NULL;INetFwRules *rules=NULL;
    HRESULT hr=CoCreateInstance(&CLSID_NetFwPolicy2,NULL,CLSCTX_INPROC_SERVER,&IID_INetFwPolicy2,(void**)&policy);
    if(FAILED(hr))return 0;
    hr=INetFwPolicy2_get_Rules(policy,&rules);int ok=SUCCEEDED(hr);
    if(ok) {
        BSTR name=SysAllocString(RULE_TUN);
        if(name){INetFwRules_Remove(rules,name);SysFreeString(name);}
        ok=add_rule(rules,RULE_TUN,NULL,NULL,NULL,TUN_NAME,NET_FW_PROFILE2_ALL);
    }
    if(rules)INetFwRules_Release(rules);INetFwPolicy2_Release(policy);
    if(!ok)helper_trace(L"adding tunnel firewall rule after adapter creation failed");
    else helper_trace(L"tunnel firewall allow rule installed");
    return ok;
}

static void firewall_restore(void) {
    static const NET_FW_PROFILE_TYPE2 profiles[3]={NET_FW_PROFILE2_DOMAIN,NET_FW_PROFILE2_PRIVATE,NET_FW_PROFILE2_PUBLIC};
    INetFwPolicy2 *policy=NULL;
    remove_rules();
    apply_dns_leak_policy(0);
    if(FAILED(CoCreateInstance(&CLSID_NetFwPolicy2,NULL,CLSCTX_INPROC_SERVER,&IID_INetFwPolicy2,(void**)&policy)))return;
    for(int i=0;i<3;i++) {
        INetFwPolicy2_put_DefaultOutboundAction(policy,profiles[i],(NET_FW_ACTION)state.old_action[i]);
        INetFwPolicy2_put_FirewallEnabled(policy,profiles[i],state.old_enabled[i]?VARIANT_TRUE:VARIANT_FALSE);
    }
    INetFwPolicy2_Release(policy);
    DeleteFileW(state_path);
}

static int add_route(const RouteRecord *rec) {
    MIB_IPFORWARD_ROW2 row; InitializeIpForwardEntry(&row);
    row.InterfaceIndex=rec->if_index; row.DestinationPrefix.Prefix=rec->destination; row.DestinationPrefix.PrefixLength=rec->prefix;
    row.NextHop=rec->next_hop; row.Metric=1; row.Protocol=MIB_IPPROTO_NETMGMT;
    DWORD e=CreateIpForwardEntry2(&row); return e==NO_ERROR?1:e==ERROR_OBJECT_ALREADY_EXISTS?2:0;
}
static void remove_routes(void) {
    for(DWORD i=0;i<state.route_count;i++) {
        RouteRecord *rec=&state.routes[i]; MIB_IPFORWARD_ROW2 row; InitializeIpForwardEntry(&row);
        row.InterfaceIndex=rec->if_index; row.DestinationPrefix.Prefix=rec->destination; row.DestinationPrefix.PrefixLength=rec->prefix; row.NextHop=rec->next_hop;
        DeleteIpForwardEntry2(&row);
    }
    state.route_count=0;
}
static int record_route(RouteRecord *rec) {
    if(state.route_count>=MAX_ROUTES)return 0;
    for(DWORD i=0;i<state.route_count;i++) {
        RouteRecord *x=&state.routes[i];
        if(x->family==rec->family&&x->if_index==rec->if_index&&x->prefix==rec->prefix&&memcmp(&x->destination,&rec->destination,sizeof(rec->destination))==0)return 1;
    }
    state.routes[state.route_count++]=*rec;
    if(!state_write_locked()){state.route_count--;return 0;}
    int added=add_route(rec);
    if(!added){wchar_t m[128];_snwprintf_s(m,_countof(m),_TRUNCATE,L"route install failed family=%lu prefix=%u if=%lu",rec->family,rec->prefix,rec->if_index);helper_trace(m);}
    if(added==2){state.route_count--;state_write_locked();return 1;}
    if(!added){state.route_count--;state_write_locked();return 0;}
    return 1;
}
static int route_from_gateway(DWORD family,const SOCKADDR_INET *destination,BYTE prefix,DWORD if_index,const SOCKADDR_INET *gateway) {
    RouteRecord r; ZeroMemory(&r,sizeof(r)); r.family=family;r.prefix=prefix;r.if_index=if_index;r.destination=*destination;r.next_hop=*gateway; return record_route(&r);
}
static void restore_tunnel_metrics(void) {
    MIB_IPINTERFACE_ROW row;
    if(state.tun_metric4_saved){InitializeIpInterfaceEntry(&row);row.Family=AF_INET;row.InterfaceIndex=state.tunnel_index;if(GetIpInterfaceEntry(&row)==NO_ERROR){row.Metric=state.old_tun_metric4;row.UseAutomaticMetric=(BOOLEAN)state.old_tun_automatic4;SetIpInterfaceEntry(&row);}}
    if(state.tun_metric6_saved){InitializeIpInterfaceEntry(&row);row.Family=AF_INET6;row.InterfaceIndex=state.tunnel_index;if(GetIpInterfaceEntry(&row)==NO_ERROR){row.Metric=state.old_tun_metric6;row.UseAutomaticMetric=(BOOLEAN)state.old_tun_automatic6;SetIpInterfaceEntry(&row);}}
    state.tun_metric4_saved=state.tun_metric6_saved=FALSE;
}
static int verify_tunnel_default_route(DWORD expected_index) {
    SOCKADDR_INET destination,source; MIB_IPFORWARD_ROW2 best; ZeroMemory(&destination,sizeof(destination)); ZeroMemory(&source,sizeof(source));
    destination.Ipv4.sin_family=AF_INET; InetPtonW(AF_INET,L"1.1.1.1",&destination.Ipv4.sin_addr);
    DWORD rc=GetBestRoute2(NULL,0,NULL,&destination,0,&best,&source);
    if(rc!=NO_ERROR || best.InterfaceIndex!=expected_index) {
        wchar_t message[160]; _snwprintf_s(message,_countof(message),_TRUNCATE,L"default route verification failed: error=%lu interface=%lu expected=%lu",rc,rc==NO_ERROR?best.InterfaceIndex:0,expected_index); helper_trace(message); return 0;
    }
    wchar_t message[128]; _snwprintf_s(message,_countof(message),_TRUNCATE,L"verified IPv4 default route uses tunnel interface %lu metric %lu",best.InterfaceIndex,best.Metric); helper_trace(message); return 1;
}
static int best_gateway(DWORD family,SOCKADDR_INET *gateway,DWORD *if_index) {
    SOCKADDR_INET dest; ZeroMemory(&dest,sizeof(dest));
    if(family==AF_INET){dest.Ipv4.sin_family=AF_INET;InetPtonW(AF_INET,L"1.1.1.1",&dest.Ipv4.sin_addr);}
    else {dest.Ipv6.sin6_family=AF_INET6;InetPtonW(AF_INET6,L"2606:4700:4700::1111",&dest.Ipv6.sin6_addr);}
    MIB_IPFORWARD_ROW2 best;SOCKADDR_INET best_source;ZeroMemory(&best_source,sizeof(best_source));
    DWORD rc=GetBestRoute2(NULL,0,NULL,&dest,0,&best,&best_source);
    if(rc!=NO_ERROR){wchar_t msg[128];_snwprintf_s(msg,_countof(msg),_TRUNCATE,L"GetBestRoute2 family=%lu error=%lu",family,rc);helper_trace(msg);return 0;}
    *gateway=best.NextHop;*if_index=best.InterfaceIndex;return 1;
}
static int ensure_tor_routes(void) {
    SOCKADDR_INET gw4,gw6;DWORD if4=0,if6=0;
    int have4=state.physical4_index!=0,have6=state.physical6_index!=0;
    if(!have4&&best_gateway(AF_INET,&gw4,&if4)){state.physical4_gateway=gw4;state.physical4_index=if4;have4=1;}
    if(!have6&&best_gateway(AF_INET6,&gw6,&if6)){state.physical6_gateway=gw6;state.physical6_index=if6;have6=1;}
    if(!have4&&!have6){helper_trace(L"Tor route: no physical gateway found");return 0;}
    if(!state_write_locked()){helper_trace(L"Tor route: could not persist physical gateway");return 0;}
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); if(snap==INVALID_HANDLE_VALUE){helper_trace(L"Tor route: process snapshot failed");return 0;}
    PROCESSENTRY32W pe={sizeof(pe)}; DWORD pid=0;
    if(Process32FirstW(snap,&pe))do { if(_wcsicmp(pe.szExeFile,L"tor.exe")==0){HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pe.th32ProcessID); if(p){wchar_t path[MAX_PATH];DWORD n=MAX_PATH;if(QueryFullProcessImageNameW(p,0,path,&n)&&_wcsicmp(path,state.tor_path)==0)pid=pe.th32ProcessID;CloseHandle(p);} if(pid)break;} }while(Process32NextW(snap,&pe));
    CloseHandle(snap); if(!pid){helper_trace(L"Tor route: matching tor.exe process not found");return 0;}
    DWORD size=0; GetExtendedTcpTable(NULL,&size,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0); PMIB_TCPTABLE_OWNER_PID table=(PMIB_TCPTABLE_OWNER_PID)HeapAlloc(GetProcessHeap(),0,size);
    if(table&&GetExtendedTcpTable(table,&size,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)==NO_ERROR) {
        for(DWORD i=0;i<table->dwNumEntries;i++)if(table->table[i].dwOwningPid==pid&&table->table[i].dwRemoteAddr&&have4) {
            RouteRecord r;ZeroMemory(&r,sizeof(r));r.family=AF_INET;r.prefix=32;r.if_index=state.physical4_index;r.destination.Ipv4.sin_family=AF_INET;r.destination.Ipv4.sin_addr.S_un.S_addr=table->table[i].dwRemoteAddr;r.next_hop=state.physical4_gateway;record_route(&r);
        }
    }
    if(table)HeapFree(GetProcessHeap(),0,table);
    size=0; GetExtendedTcpTable(NULL,&size,FALSE,AF_INET6,TCP_TABLE_OWNER_PID_ALL,0); PMIB_TCP6TABLE_OWNER_PID table6=(PMIB_TCP6TABLE_OWNER_PID)HeapAlloc(GetProcessHeap(),0,size);
    if(table6&&GetExtendedTcpTable(table6,&size,FALSE,AF_INET6,TCP_TABLE_OWNER_PID_ALL,0)==NO_ERROR) {
        for(DWORD i=0;i<table6->dwNumEntries;i++)if(table6->table[i].dwOwningPid==pid&&have6) {
            IN6_ADDR *d=(IN6_ADDR*)table6->table[i].ucRemoteAddr; if(IN6_IS_ADDR_UNSPECIFIED(d)||IN6_IS_ADDR_LOOPBACK(d))continue;
            RouteRecord r;ZeroMemory(&r,sizeof(r));r.family=AF_INET6;r.prefix=128;r.if_index=state.physical6_index;r.destination.Ipv6.sin6_family=AF_INET6;CopyMemory(&r.destination.Ipv6.sin6_addr,d,sizeof(*d));r.destination.Ipv6.sin6_scope_id=table6->table[i].dwRemoteScopeId;r.next_hop=state.physical6_gateway;record_route(&r);
        }
    }
    if(table6)HeapFree(GetProcessHeap(),0,table6);
    return 1;
}

static int find_tunnel_adapter(DWORD expected_index,GUID *guid) {
    ULONG size=16*1024; IP_ADAPTER_ADDRESSES *buf=(IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(),0,size); if(!buf)return 0;
    ULONG rc=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_INCLUDE_PREFIX,NULL,buf,&size);
    if(rc==ERROR_BUFFER_OVERFLOW){HeapFree(GetProcessHeap(),0,buf);buf=(IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(),0,size);if(!buf)return 0;rc=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_INCLUDE_PREFIX,NULL,buf,&size);}
    int found=0;
    if(rc==NO_ERROR)for(IP_ADAPTER_ADDRESSES *a=buf;a;a=a->Next)if(a->IfIndex==expected_index) {
        wchar_t msg[192];_snwprintf_s(msg,_countof(msg),_TRUNCATE,L"adapter index %lu name %s",a->IfIndex,a->FriendlyName?a->FriendlyName:L"(unnamed)");helper_trace(msg);
        if(ConvertInterfaceLuidToGuid(&a->Luid,guid)==NO_ERROR)found=1;
        break;
    }
    if(rc!=NO_ERROR){wchar_t msg[96];_snwprintf_s(msg,_countof(msg),_TRUNCATE,L"GetAdaptersAddresses failed %lu",rc);helper_trace(msg);}
    HeapFree(GetProcessHeap(),0,buf);return found;
}

static int route_up(DWORD tun_index) {
    helper_trace(L"route-up hook entered");
    if(WaitForSingleObject(state_mutex,5000)!=WAIT_OBJECT_0){helper_trace(L"route-up state mutex timeout");return 0;}
    if(state.tunnel_index) { ReleaseMutex(state_mutex);return 1; }
    GUID guid;ZeroMemory(&guid,sizeof(guid));
    int adapter_found=0;for(int retry=0;retry<20&&!adapter_found;retry++){adapter_found=find_tunnel_adapter(tun_index,&guid);if(!adapter_found)Sleep(250);}
    if(!adapter_found){helper_trace(L"route-up could not find Wintun adapter");ReleaseMutex(state_mutex);return 0;}
    helper_trace(L"route-up found Wintun adapter");
    if(!firewall_allow_tunnel()){ReleaseMutex(state_mutex);return 0;}
    state.tunnel_index=tun_index;state.tunnel_guid=guid;state_write_locked();
    if(!ensure_tor_routes()){helper_trace(L"route-up could not preserve Tor relay routes");restore_tunnel_metrics();state.tunnel_index=0;state_write_locked();ReleaseMutex(state_mutex);return 0;}
    /* Two /1 routes outrank every physical default route without relying on
       Windows accepting a metric change on the Wintun interface. Tor relay
       host routes (/32 and /128) remain more specific and bypass the tunnel. */
    SOCKADDR_INET v4a,v4b,v6a,v6b,zero4,zero6;ZeroMemory(&v4a,sizeof(v4a));ZeroMemory(&v4b,sizeof(v4b));ZeroMemory(&v6a,sizeof(v6a));ZeroMemory(&v6b,sizeof(v6b));ZeroMemory(&zero4,sizeof(zero4));ZeroMemory(&zero6,sizeof(zero6));
    v4a.Ipv4.sin_family=v4b.Ipv4.sin_family=AF_INET;v6a.Ipv6.sin6_family=v6b.Ipv6.sin6_family=AF_INET6;zero4.Ipv4.sin_family=AF_INET;zero6.Ipv6.sin6_family=AF_INET6;
    v4b.Ipv4.sin_addr.S_un.S_addr=htonl(0x80000000U);v6b.Ipv6.sin6_addr.u.Byte[0]=0x80;
    int ok=route_from_gateway(AF_INET,&v4a,1,tun_index,&zero4)&&route_from_gateway(AF_INET,&v4b,1,tun_index,&zero4)&&route_from_gateway(AF_INET6,&v6a,1,tun_index,&zero6)&&route_from_gateway(AF_INET6,&v6b,1,tun_index,&zero6);
    if(ok) {
        DNS_INTERFACE_SETTINGS old;ZeroMemory(&old,sizeof(old));old.Version=DNS_INTERFACE_SETTINGS_VERSION1;
        if(GetInterfaceDnsSettings(guid,&old)==NO_ERROR) {
            if(old.NameServer)wcsncpy_s(state.old_dns_servers,_countof(state.old_dns_servers),old.NameServer,_TRUNCATE);
            state.dns_saved=TRUE;
            FreeInterfaceDnsSettings(&old);
        }
        DNS_INTERFACE_SETTINGS set;ZeroMemory(&set,sizeof(set));set.Version=DNS_INTERFACE_SETTINGS_VERSION1;set.Flags=DNS_SETTING_NAMESERVER;set.NameServer=L"198.18.0.2";
        ok=SetInterfaceDnsSettings(guid,&set)==NO_ERROR;
        if(ok) apply_dns_leak_policy(1);
    }
    if(ok) ok=verify_tunnel_default_route(tun_index);
    if(!ok){helper_trace(L"route-up could not establish verified default routes or DNS");remove_routes();restore_tunnel_metrics();state.tunnel_index=0;state_write_locked();}
    else {
        state_write_locked();HANDLE event=OpenEventW(EVENT_MODIFY_STATE,FALSE,state.connected_event);if(event){SetEvent(event);CloseHandle(event);helper_trace(L"route-up tunnel ready event set");}else helper_trace(L"route-up could not open ready event");
    }
    ReleaseMutex(state_mutex);return ok;
}

static int route_down(void) {
    if(WaitForSingleObject(state_mutex,5000)!=WAIT_OBJECT_0)return 0;
    apply_dns_leak_policy(0);
    if(state.tunnel_index&&state.dns_saved) {
        DNS_INTERFACE_SETTINGS set;ZeroMemory(&set,sizeof(set));set.Version=DNS_INTERFACE_SETTINGS_VERSION1;set.Flags=DNS_SETTING_NAMESERVER;set.NameServer=state.old_dns_servers;
        SetInterfaceDnsSettings(state.tunnel_guid,&set);
    }
    remove_routes();restore_tunnel_metrics();state.tunnel_index=0;state.dns_saved=FALSE;state.old_dns_servers[0]=0;state.physical4_index=state.physical6_index=0;state_write_locked();
    ReleaseMutex(state_mutex);return 1;
}

static DWORD WINAPI tunnel_main(LPVOID p) {
    (void)p;int rc=hev_main_fn(hev_config_path,-1);
    wchar_t msg[128];_snwprintf_s(msg,_countof(msg),_TRUNCATE,L"Hev main returned %d",rc);helper_trace(msg);
    return (DWORD)rc;
}

static int helper_start(void) {
    helper_trace(L"helper start");
    wchar_t stderr_path[MAX_PATH];_snwprintf_s(stderr_path,MAX_PATH,_TRUNCATE,L"%s.stderr.log",state_path);
    FILE *stderr_file=NULL;_wfreopen_s(&stderr_file,stderr_path,L"a",stderr);
    HANDLE token=NULL;TOKEN_ELEVATION elevation;DWORD size=0;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)){if(GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&size))helper_trace(elevation.TokenIsElevated?L"process elevated":L"process not elevated");CloseHandle(token);}
    if(FAILED(CoInitializeEx(NULL,COINIT_APARTMENTTHREADED)))return 10;
    state_mutex=CreateMutexW(NULL,FALSE,L"Local\\AureliaTunnelState"); if(!state_mutex)return 11;
    HANDLE old=CreateFileW(state_path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(old!=INVALID_HANDLE_VALUE){CloseHandle(old);if(!state_load())return 12;route_down();}
    else ZeroMemory(&state,sizeof(state));
    wcscpy_s(state.tor_path,MAX_PATH,helper_tor_path);
    wcscpy_s(state.connected_event,_countof(state.connected_event),ready_name);
    wcscpy_s(state.stop_event,_countof(state.stop_event),stop_name);
    if(!firewall_arm(state.tor_path)){firewall_restore();helper_trace(L"helper exit 13 firewall arm failure");return 13;}
    SetEvent(blocked_event);helper_trace(L"blocked event set");
    HANDLE wait_go[3]={stop_event,parent_process,go_event};
    DWORD w=WaitForMultipleObjects(3,wait_go,FALSE,180000);
    if(w==WAIT_OBJECT_0||w==WAIT_OBJECT_0+1){firewall_restore();return 0;}
    if(w!=WAIT_OBJECT_0+2){firewall_restore();return 14;}
    helper_trace(L"Tor ready signal received");
    wchar_t module_dir[MAX_PATH];DWORD n=GetModuleFileNameW(NULL,module_dir,MAX_PATH);if(!n||n>=MAX_PATH){firewall_restore();return 15;}
    wchar_t *slash=wcsrchr(module_dir,L'\\');if(slash)*slash=0;
    wchar_t hev_path[MAX_PATH];_snwprintf_s(hev_path,MAX_PATH,_TRUNCATE,L"%s\\hev-socks5-tunnel.dll",module_dir);
    hev_module=LoadLibraryW(hev_path);if(!hev_module){wchar_t m[128];_snwprintf_s(m,_countof(m),_TRUNCATE,L"Hev DLL load failed error=%lu",GetLastError());helper_trace(m);firewall_restore();return 16;}
    hev_main_fn=(HevMainFn)GetProcAddress(hev_module,"hev_socks5_tunnel_main_from_file");hev_quit_fn=(HevQuitFn)GetProcAddress(hev_module,"hev_socks5_tunnel_quit");
    if(!hev_main_fn||!hev_quit_fn){helper_trace(L"Hev DLL exports missing");FreeLibrary(hev_module);firewall_restore();return 17;}
    int bytes=WideCharToMultiByte(CP_ACP,WC_NO_BEST_FIT_CHARS,hev_config_wpath,-1,hev_config_path,MAX_PATH,NULL,NULL);
    if(!bytes){helper_trace(L"tunnel config path conversion failed");FreeLibrary(hev_module);firewall_restore();return 18;}
    tunnel_thread=CreateThread(NULL,0,tunnel_main,NULL,0,NULL);if(!tunnel_thread){helper_trace(L"tunnel thread creation failed");FreeLibrary(hev_module);firewall_restore();return 19;}
    helper_trace(L"Hev tunnel thread started");
    HANDLE waiters[3]={stop_event,parent_process,tunnel_thread};
    for(;;){
        DWORD r=WaitForMultipleObjects(3,waiters,FALSE,1000);
        if(r==WAIT_OBJECT_0){helper_trace(L"helper stop event received");break;}
        if(r==WAIT_OBJECT_0+1){helper_trace(L"GUI parent process exited");break;}
        if(r==WAIT_OBJECT_0+2){DWORD code=0;GetExitCodeThread(tunnel_thread,&code);wchar_t m[128];_snwprintf_s(m,_countof(m),_TRUNCATE,L"Hev tunnel thread exited code=%lu",code);helper_trace(m);break;}
        if(r==WAIT_FAILED)break;
        if(WaitForSingleObject(ready_event,0)==WAIT_OBJECT_0&&WaitForSingleObject(state_mutex,1000)==WAIT_OBJECT_0){ensure_tor_routes();ReleaseMutex(state_mutex);}
    }
    if(WaitForSingleObject(tunnel_thread,0)==WAIT_TIMEOUT)hev_quit_fn();
    WaitForSingleObject(tunnel_thread,30000);
    if(WaitForSingleObject(tunnel_thread,0)==WAIT_TIMEOUT){TerminateThread(tunnel_thread,1);}
    CloseHandle(tunnel_thread);tunnel_thread=NULL;FreeLibrary(hev_module);hev_module=NULL;
    if(state.tunnel_index)route_down();
    helper_trace(L"restoring routes and firewall");firewall_restore();helper_trace(L"helper cleanup complete");return 0;
}

static void ensure_local_path(wchar_t out[MAX_PATH]) {
    wchar_t *local=_wgetenv(L"LOCALAPPDATA");if(!local)local=L"C:\\ProgramData";
    _snwprintf_s(out,MAX_PATH,_TRUNCATE,L"%s\\Aurelia\\Tor\\netstate.bin",local);
}

int WINAPI wWinMain(HINSTANCE inst,HINSTANCE prev,PWSTR cmd,int show) {
    (void)inst;(void)prev;(void)cmd;(void)show;
    int argc=0;LPWSTR *argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)return 2;
    ensure_local_path(state_path);
    if(argc==3&&argv[1][0]!=L'-'){
        if(!state_load()){helper_trace(L"route hook failed to load state");LocalFree(argv);return 3;}
        HRESULT com=CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);if(FAILED(com)){helper_trace(L"route hook COM initialization failed");LocalFree(argv);return 4;}
        state_mutex=CreateMutexW(NULL,FALSE,L"Local\\AureliaTunnelState");
        if(!state_mutex){CoUninitialize();LocalFree(argv);return 4;} DWORD index=wcstoul(argv[2],NULL,10);int ok=state.tunnel_index?route_down():route_up(index);
        if(!ok){helper_trace(L"route hook failed; requesting fail-closed cleanup");HANDLE ev=OpenEventW(EVENT_MODIFY_STATE,FALSE,state.stop_event);if(ev){SetEvent(ev);CloseHandle(ev);}}
        CloseHandle(state_mutex);CoUninitialize();LocalFree(argv);return ok?0:5;
    }
    if(argc==3&&_wcsicmp(argv[1],L"--recover")==0){
        wcscpy_s(state_path,MAX_PATH,argv[2]);if(!state_load()){LocalFree(argv);return 0;}CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);state_mutex=CreateMutexW(NULL,FALSE,L"Local\\AureliaTunnelState");route_down();firewall_restore();CloseHandle(state_mutex);LocalFree(argv);return 0;
    }
    if(argc!=10||_wcsicmp(argv[1],L"--start")!=0){LocalFree(argv);return 2;}
    wcscpy_s(state_path,MAX_PATH,argv[2]);wcscpy_s(hev_config_wpath,MAX_PATH,argv[3]);
    stop_name[0]=blocked_name[0]=go_name[0]=ready_name[0]=0;
    wcscpy_s(stop_name,_countof(stop_name),argv[5]);wcscpy_s(blocked_name,_countof(blocked_name),argv[6]);wcscpy_s(go_name,_countof(go_name),argv[7]);wcscpy_s(ready_name,_countof(ready_name),argv[8]);
    wcscpy_s(state.tor_path,MAX_PATH,argv[4]);wcscpy_s(helper_tor_path,MAX_PATH,argv[4]);parent_pid=wcstoul(argv[9],NULL,10);
    stop_event=OpenEventW(SYNCHRONIZE,FALSE,stop_name);blocked_event=OpenEventW(EVENT_MODIFY_STATE,FALSE,blocked_name);go_event=OpenEventW(SYNCHRONIZE,FALSE,go_name);ready_event=OpenEventW(EVENT_MODIFY_STATE,FALSE,ready_name);parent_process=OpenProcess(SYNCHRONIZE,FALSE,parent_pid);
    if(!stop_event||!blocked_event||!go_event||!ready_event||!parent_process){LocalFree(argv);return 20;}
    int res=helper_start();
    CloseHandle(stop_event);CloseHandle(blocked_event);CloseHandle(go_event);CloseHandle(ready_event);CloseHandle(parent_process);if(state_mutex)CloseHandle(state_mutex);CoUninitialize();LocalFree(argv);return res;
}
