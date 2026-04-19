/*
 * ptehookd.c — ptehook on-device auto-hook daemon.
 *
 * Reads JSON profiles from /data/adb/ptehook/profiles/, monitors target
 * processes, and automatically installs UXN hooks whenever a target app
 * starts. Hooks persist across app restarts and device reboots (via APatch
 * module service.sh).
 *
 * Build:
 *   aarch64-linux-android29-clang -O2 -static -o ptehookd ptehookd.c -DJSMN_STATIC
 *
 * Requires: ptehook_ctl and pte_scan in the same directory.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdarg.h>

#include "shellcode_patch.h"

/* ---- Minimal JSON parser (jsmn-style, inlined) ---- */
/* We only need to parse simple flat/1-level JSON profiles. Instead of pulling
   in a full JSON library (not available in NDK static builds), we use a
   purpose-built key-value extractor that handles our profile format. */

#define MAX_HOOKS        16
#define MAX_PROFILES     8
#define MAX_ADJACENT     8
#define MAX_PATCH_SLOTS  4
#define MAX_SHELLCODE    1024
#define MAX_PKG_LEN      128
#define MAX_CLASS_LEN    256
#define MAX_METHOD_LEN   128
#define MAX_SIG_LEN      256
#define CMD_BUF_SIZE     2048
#define OUT_BUF_SIZE     8192
#define MAX_CANDIDATES   32
#define LOG_BUF_SIZE     512
#define SUPERKEY_MAX     128

/* ---- Configuration ---- */
static char g_superkey[SUPERKEY_MAX];
static char g_profiles_dir[256]  = "/data/adb/ptehook/profiles";
static char g_bin_dir[256]       = "/data/adb/ptehook";
static char g_log_path[256]      = "/data/adb/ptehook/ptehookd.log";
static int  g_poll_ms            = 500;
static int  g_art_ready_delay_ms = 2000;
static int  g_foreground         = 0;
static volatile int g_stop       = 0;
static FILE *g_log_fp            = NULL;

/* ---- Data structures ---- */

typedef struct {
    int byte_offset;
    int reg;
} patch_slot_t;

typedef struct {
    char     id[64];
    int      type;              /* 0=java, 1=java_spray */
    char     class_desc[MAX_CLASS_LEN];
    char     method_name[MAX_METHOD_LEN];
    char     signature[MAX_SIG_LEN];
    uint32_t method_idx;
    int      adjacent_idxs[MAX_ADJACENT];
    int      n_adjacent;
    uint32_t access_flags_dex;
    int      deploy_mode;       /* 0=default, 1=wait_jit, 2=unsafe_bridge */
    int      warmup_timeout;

    char     action_type[32];
    int      action_value;

    uint8_t  shellcode[MAX_SHELLCODE];
    int      shellcode_len;
    patch_slot_t slot_expected;
    patch_slot_t slot_backup;

    /* ART layout (copied from profile) */
    int      art_size;
    int      art_off_af;
    int      art_off_midx;
    int      art_off_ep;
} hook_def_t;

typedef struct {
    char      package[MAX_PKG_LEN];
    char      apk_md5[64];
    int       art_size;
    int       art_off_decl;
    int       art_off_af;
    int       art_off_midx;
    int       art_off_ep;
    hook_def_t hooks[MAX_HOOKS];
    int       n_hooks;
} profile_t;

typedef enum {
    STATE_WAITING,
    STATE_ART_INIT,
    STATE_HOOKING,
    STATE_ACTIVE,
} proc_state_t;

typedef struct {
    profile_t   *profile;
    proc_state_t state;
    int          pid;
    uint64_t     ghosts[MAX_HOOKS];
    int          hook_ok[MAX_HOOKS];
} monitor_t;

static profile_t  g_profiles[MAX_PROFILES];
static int         g_n_profiles = 0;
static monitor_t   g_monitors[MAX_PROFILES];

/* ---- Logging ---- */

static void log_daemon(const char *fmt, ...)
{
    va_list ap;
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    FILE *fp = g_log_fp ? g_log_fp : stderr;
    fprintf(fp, "[%s] ", ts);
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fprintf(fp, "\n");
    fflush(fp);
}

/* ---- Shell command execution ---- */

static int run_cmd(const char *cmd, char *out, int out_max)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    int total = 0;
    while (total < out_max - 1) {
        int c = fgetc(fp);
        if (c == EOF) break;
        out[total++] = (char)c;
    }
    out[total] = '\0';
    int status = pclose(fp);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static char *ctl_raw(const char *args)
{
    static char result[OUT_BUF_SIZE];
    char cmd[CMD_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "%s/ptehook_ctl %s raw %s",
             g_bin_dir, g_superkey, args);
    if (run_cmd(cmd, result, sizeof(result)) < 0)
        return NULL;
    return result;
}

/* ---- KPM command wrappers ---- */

static uint64_t ctl_proc_read_u64(int pid, uint64_t addr)
{
    char args[128];
    snprintf(args, sizeof(args), "proc-read %d 0x%lx 8", pid, (unsigned long)addr);
    char *out = ctl_raw(args);
    if (!out) return 0;
    char *p = strstr(out, "bytes:");
    if (!p) p = strstr(out, "bytes :");
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ') p++;
    /* Parse 16-char hex as little-endian bytes */
    uint8_t bytes[8];
    for (int i = 0; i < 8 && p[i*2] && p[i*2+1]; i++) {
        char tmp[3] = { p[i*2], p[i*2+1], 0 };
        bytes[i] = (uint8_t)strtoul(tmp, NULL, 16);
    }
    uint64_t val = 0;
    for (int i = 7; i >= 0; i--)
        val = (val << 8) | bytes[i];
    return val;
}

static uint32_t ctl_proc_read_u32(int pid, uint64_t addr)
{
    char args[128];
    snprintf(args, sizeof(args), "proc-read %d 0x%lx 4", pid, (unsigned long)addr);
    char *out = ctl_raw(args);
    if (!out) return 0;
    char *p = strstr(out, "bytes");
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ') p++;
    uint8_t bytes[4];
    for (int i = 0; i < 4 && p[i*2] && p[i*2+1]; i++) {
        char tmp[3] = { p[i*2], p[i*2+1], 0 };
        bytes[i] = (uint8_t)strtoul(tmp, NULL, 16);
    }
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t ctl_ghost_alloc(int pid)
{
    /* Find a suitable gap first by reading maps */
    char cmd[CMD_BUF_SIZE], out[OUT_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", pid);
    if (run_cmd(cmd, out, sizeof(out)) < 0) return 0;

    /* Find libart r-xp base */
    uint64_t libart_rx = 0;
    char *line = strtok(out, "\n");
    while (line) {
        if (strstr(line, "libart.so") && strstr(line, "r-xp")) {
            sscanf(line, "%lx", (unsigned long *)&libart_rx);
            break;
        }
        line = strtok(NULL, "\n");
    }
    if (!libart_rx) return 0;

    /* Try ghost-alloc near libart */
    char args[256];
    snprintf(args, sizeof(args), "ghost-alloc %d 0x%lx 0x1000",
             pid, (unsigned long)libart_rx);
    char *r = ctl_raw(args);
    if (!r) return 0;
    char *gp = strstr(r, "ghost=0x");
    if (!gp) return 0;
    return strtoull(gp + 6, NULL, 16);
}

static uint64_t ctl_uxn_hook(int pid, uint64_t target, uint64_t replace)
{
    char args[256];
    snprintf(args, sizeof(args), "uxn-hook %d 0x%lx 0x%lx",
             pid, (unsigned long)target, (unsigned long)replace);

    char *out = ctl_raw(args);
    if (!out) return 0;

    /* Handle "already hooked" - unhook and retry */
    if (strstr(out, "already hooked")) {
        char uargs[256];
        snprintf(uargs, sizeof(uargs), "uxn-unhook %d 0x%lx",
                 pid, (unsigned long)target);
        ctl_raw(uargs);
        out = ctl_raw(args);
        if (!out) return 0;
    }

    char *bp = strstr(out, "backup=0x");
    if (!bp) return 0;
    return strtoull(bp + 7, NULL, 16);
}

static int ctl_ghost_write(int pid, uint64_t ghost, int offset,
                           const uint8_t *data, int len)
{
    /* Encode data as hex and send via ghost-write. Chunk to 1024 bytes. */
    for (int i = 0; i < len; i += 512) {
        int chunk = (len - i > 512) ? 512 : len - i;
        char hex[1025];
        hex_encode(data + i, chunk, hex);

        char args[CMD_BUF_SIZE];
        snprintf(args, sizeof(args), "ghost-write %d 0x%lx %d %s",
                 pid, (unsigned long)ghost, offset + i, hex);
        char *out = ctl_raw(args);
        if (!out || !strstr(out, "[OK]")) return -1;
    }
    return 0;
}

static void ctl_ghost_free(int pid, uint64_t ghost)
{
    char args[128];
    snprintf(args, sizeof(args), "ghost-free %d 0x%lx",
             pid, (unsigned long)ghost);
    ctl_raw(args);
}

static void ctl_uxn_unhook(int pid, uint64_t target)
{
    char args[128];
    snprintf(args, sizeof(args), "uxn-unhook %d 0x%lx",
             pid, (unsigned long)target);
    ctl_raw(args);
}

/* ---- Process utilities ---- */

static int pidof(const char *package)
{
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
        char path[64], cmdline[256];
        snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        int n = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);
        if (n <= 0) continue;
        cmdline[n] = '\0';
        if (strcmp(cmdline, package) == 0) {
            int pid = atoi(ent->d_name);
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    return -1;
}

static int proc_alive(int pid)
{
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    struct stat st;
    return stat(path, &st) == 0;
}

static int has_libart(int pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libart.so") && strstr(line, "r-xp")) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int is_in_libart(int pid, uint64_t addr)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "libart.so")) continue;
        uint64_t s, e;
        if (sscanf(line, "%lx-%lx", (unsigned long *)&s, (unsigned long *)&e) == 2) {
            if (addr >= s && addr < e) { found = 1; break; }
        }
    }
    fclose(f);
    return found;
}

/* ---- ArtMethod scanning ---- */

static int scan_artmethod(int pid, hook_def_t *hook, uint64_t *candidates, int max_cand)
{
    char adj_csv[256] = "";
    for (int i = 0; i < hook->n_adjacent; i++) {
        char tmp[16];
        snprintf(tmp, sizeof(tmp), "%s%d", i > 0 ? "," : "", hook->adjacent_idxs[i]);
        strncat(adj_csv, tmp, sizeof(adj_csv) - strlen(adj_csv) - 1);
    }

    char cmd[CMD_BUF_SIZE];
    snprintf(cmd, sizeof(cmd),
        "%s/pte_scan %d %u %s --size=0x%x --off-midx=0x%x",
        g_bin_dir, pid, hook->method_idx,
        hook->n_adjacent > 0 ? adj_csv : "0",
        hook->art_size, hook->art_off_midx);

    char out[OUT_BUF_SIZE];
    run_cmd(cmd, out, sizeof(out));

    int n = 0;
    char *line = strtok(out, "\n");
    while (line && n < max_cand) {
        while (*line == ' ') line++;
        if (line[0] == '0' && line[1] == 'x') {
            candidates[n++] = strtoull(line, NULL, 16);
        }
        line = strtok(NULL, "\n");
    }
    return n;
}

/* ---- Hook installation ---- */

static int install_java_hook(int pid, hook_def_t *hook, uint64_t *out_ghost)
{
    *out_ghost = 0;

    /* Step 1: Scan ArtMethod */
    uint64_t candidates[MAX_CANDIDATES];
    int n_cand = scan_artmethod(pid, hook, candidates, MAX_CANDIDATES);
    if (n_cand == 0) {
        log_daemon("  [%s] no ArtMethod candidates found", hook->id);
        return -1;
    }

    /* Step 2: Disambiguate by access_flags */
    uint64_t best = 0;
    int n_match = 0;
    for (int i = 0; i < n_cand; i++) {
        uint32_t af = ctl_proc_read_u32(pid, candidates[i] + hook->art_off_af);
        if ((af & 0xFFFF) == (hook->access_flags_dex & 0xFFFF)) {
            if (n_match == 0) best = candidates[i];
            n_match++;
        }
    }
    if (n_match == 0) {
        /* Fallback: use first candidate */
        best = candidates[0];
        log_daemon("  [%s] access_flags mismatch, using first candidate", hook->id);
    } else if (n_match > 1) {
        log_daemon("  [%s] %d candidates after af filter, using first", hook->id, n_match);
    }

    /* Step 3: Read entry_point */
    uint64_t ep = untag_ptr(ctl_proc_read_u64(pid, best + hook->art_off_ep));
    if (ep == 0) {
        log_daemon("  [%s] entry_point is NULL", hook->id);
        return -2;
    }

    /* Step 4: wait_jit if needed */
    if (hook->deploy_mode == 1 && is_in_libart(pid, ep)) {
        log_daemon("  [%s] entry_point in libart, waiting for JIT...", hook->id);
        int waited = 0;
        for (int t = 0; t < hook->warmup_timeout * 2; t++) {
            usleep(500 * 1000);
            if (!proc_alive(pid)) return -3;
            ep = untag_ptr(ctl_proc_read_u64(pid, best + hook->art_off_ep));
            if (!is_in_libart(pid, ep)) {
                log_daemon("  [%s] JIT done after %ds: ep=0x%lx", hook->id,
                           (t + 1) / 2, (unsigned long)ep);
                waited = 1;
                break;
            }
        }
        if (!waited) {
            if (hook->deploy_mode == 1) {
                /* Check deploy_strategy fallback: try unsafe_bridge */
                log_daemon("  [%s] JIT timeout, trying unsafe_bridge fallback", hook->id);
            } else {
                log_daemon("  [%s] JIT timeout, skipping", hook->id);
                return -3;
            }
        }
    }

    /* Step 5: Alloc ghost */
    uint64_t ghost = ctl_ghost_alloc(pid);
    if (!ghost) {
        log_daemon("  [%s] ghost_alloc failed", hook->id);
        return -4;
    }

    /* Step 6: UXN hook */
    uint64_t backup = ctl_uxn_hook(pid, ep, ghost);
    if (!backup) {
        log_daemon("  [%s] uxn_hook failed", hook->id);
        ctl_ghost_free(pid, ghost);
        return -5;
    }

    /* Step 7: Patch shellcode template */
    uint8_t code[MAX_SHELLCODE];
    memcpy(code, hook->shellcode, hook->shellcode_len);

    patch_movz_movk_fixed4(code, hook->slot_expected.byte_offset,
                           untag_ptr(best), hook->slot_expected.reg);
    patch_movz_movk_fixed4(code, hook->slot_backup.byte_offset,
                           backup, hook->slot_backup.reg);

    /* Step 8: Write shellcode to ghost */
    if (ctl_ghost_write(pid, ghost, 0, code, hook->shellcode_len) < 0) {
        log_daemon("  [%s] ghost_write failed", hook->id);
        ctl_uxn_unhook(pid, ep);
        ctl_ghost_free(pid, ghost);
        return -6;
    }

    *out_ghost = ghost;
    log_daemon("  [%s] OK artmethod=0x%lx ep=0x%lx ghost=0x%lx backup=0x%lx",
               hook->id, (unsigned long)best, (unsigned long)ep,
               (unsigned long)ghost, (unsigned long)backup);
    return 0;
}

static int install_all_hooks(monitor_t *mon)
{
    profile_t *prof = mon->profile;
    int ok_count = 0;

    log_daemon("installing %d hooks for %s (pid=%d)",
               prof->n_hooks, prof->package, mon->pid);

    for (int i = 0; i < prof->n_hooks; i++) {
        mon->hook_ok[i] = 0;
        mon->ghosts[i] = 0;

        /* Retry loop for class-not-yet-loaded */
        for (int attempt = 0; attempt < 6; attempt++) {
            int ret = install_java_hook(mon->pid, &prof->hooks[i], &mon->ghosts[i]);
            if (ret == 0) {
                mon->hook_ok[i] = 1;
                ok_count++;
                break;
            }
            if (ret == -1 && attempt < 5) {
                /* ArtMethod not found yet, class may not be loaded */
                usleep(500 * 1000);
                if (!proc_alive(mon->pid)) return 0;
                continue;
            }
            log_daemon("  [%s] install failed (err=%d)", prof->hooks[i].id, ret);
            break;
        }
    }

    log_daemon("%d/%d hooks installed for %s",
               ok_count, prof->n_hooks, prof->package);
    return ok_count > 0;
}

/* ---- JSON profile parsing ---- */

/* Simple JSON string value extractor: find "key": "value" */
static int json_get_str(const char *json, const char *key, char *out, int max)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < max - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i;
}

/* Simple JSON integer value extractor: find "key": 123 */
static int json_get_int(const char *json, const char *key, int *out)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == '"') {
        /* Quoted number */
        p++;
        *out = atoi(p);
    } else {
        *out = atoi(p);
    }
    return 0;
}

/* Extract integer array: "key": [1, 2, 3] */
static int json_get_int_array(const char *json, const char *key, int *arr, int max)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0;
    p = strchr(p + strlen(pattern), '[');
    if (!p) return 0;
    p++;
    int n = 0;
    while (*p && *p != ']' && n < max) {
        while (*p == ' ' || *p == ',') p++;
        if (*p == ']') break;
        arr[n++] = atoi(p);
        while (*p && *p != ',' && *p != ']') p++;
    }
    return n;
}

/* Find and extract the Nth JSON object in an array by counting braces */
static const char *json_array_nth(const char *json, const char *key, int idx,
                                   const char **end_out)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return NULL;
    p = strchr(p, '[');
    if (!p) return NULL;
    p++;

    int depth = 0, cur_idx = -1;
    const char *obj_start = NULL;
    while (*p) {
        if (*p == '{') {
            if (depth == 0) {
                cur_idx++;
                if (cur_idx == idx) obj_start = p;
            }
            depth++;
        } else if (*p == '}') {
            depth--;
            if (depth == 0 && cur_idx == idx) {
                if (end_out) *end_out = p + 1;
                return obj_start;
            }
        }
        p++;
    }
    return NULL;
}

/* Extract a nested JSON object as string: "key": { ... } */
static const char *json_get_obj(const char *json, const char *key, const char **end)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return NULL;
    p += strlen(pattern);
    while (*p && *p != '{') p++;
    if (*p != '{') return NULL;
    const char *start = p;
    int depth = 0;
    while (*p) {
        if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) { if (end) *end = p + 1; return start; } }
        p++;
    }
    return NULL;
}

static int load_profile(const char *path, profile_t *prof)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *json = malloc(sz + 1);
    if (!json) { fclose(f); return -1; }
    fread(json, 1, sz, f);
    json[sz] = '\0';
    fclose(f);

    memset(prof, 0, sizeof(*prof));
    json_get_str(json, "package", prof->package, MAX_PKG_LEN);
    json_get_str(json, "apk_md5", prof->apk_md5, sizeof(prof->apk_md5));

    /* art_layout */
    const char *art_end;
    const char *art = json_get_obj(json, "art_layout", &art_end);
    if (art) {
        char art_buf[512];
        int n = (art_end - art < (int)sizeof(art_buf)) ? (int)(art_end - art) : (int)sizeof(art_buf) - 1;
        memcpy(art_buf, art, n);
        art_buf[n] = '\0';
        json_get_int(art_buf, "artmethod_size", &prof->art_size);
        json_get_int(art_buf, "off_declaring_class", &prof->art_off_decl);
        json_get_int(art_buf, "off_access_flags", &prof->art_off_af);
        json_get_int(art_buf, "off_dex_method_index", &prof->art_off_midx);
        json_get_int(art_buf, "off_entry_point", &prof->art_off_ep);
    }
    if (prof->art_size == 0) prof->art_size = 0x20;
    if (prof->art_off_af == 0 && prof->art_off_ep == 0) {
        prof->art_off_af = 4;
        prof->art_off_midx = 8;
        prof->art_off_ep = 0x18;
    }

    /* Hooks array */
    for (int i = 0; i < MAX_HOOKS; i++) {
        const char *h_end;
        const char *h = json_array_nth(json, "hooks", i, &h_end);
        if (!h) break;

        int h_len = (int)(h_end - h);
        char *hbuf = malloc(h_len + 1);
        memcpy(hbuf, h, h_len);
        hbuf[h_len] = '\0';

        hook_def_t *hd = &prof->hooks[prof->n_hooks];
        memset(hd, 0, sizeof(*hd));

        json_get_str(hbuf, "id", hd->id, sizeof(hd->id));
        json_get_str(hbuf, "class_desc", hd->class_desc, MAX_CLASS_LEN);
        json_get_str(hbuf, "method_name", hd->method_name, MAX_METHOD_LEN);
        json_get_str(hbuf, "signature", hd->signature, MAX_SIG_LEN);

        int tmp;
        if (json_get_int(hbuf, "method_idx", &tmp) == 0)
            hd->method_idx = (uint32_t)tmp;
        if (json_get_int(hbuf, "access_flags_dex", &tmp) == 0)
            hd->access_flags_dex = (uint32_t)tmp;
        json_get_int(hbuf, "warmup_timeout", &hd->warmup_timeout);
        if (hd->warmup_timeout == 0) hd->warmup_timeout = 30;

        hd->n_adjacent = json_get_int_array(hbuf, "adjacent_idxs",
                                             hd->adjacent_idxs, MAX_ADJACENT);

        /* deploy_mode */
        char dm[32] = "";
        json_get_str(hbuf, "deploy_mode", dm, sizeof(dm));
        if (strcmp(dm, "wait_jit") == 0) hd->deploy_mode = 1;
        else if (strcmp(dm, "unsafe_bridge") == 0) hd->deploy_mode = 2;
        else hd->deploy_mode = 0;

        /* action */
        const char *act_end;
        const char *act = json_get_obj(hbuf, "action", &act_end);
        if (act) {
            int alen = (int)(act_end - act);
            char abuf[256];
            if (alen < (int)sizeof(abuf)) {
                memcpy(abuf, act, alen);
                abuf[alen] = '\0';
                json_get_str(abuf, "type", hd->action_type, sizeof(hd->action_type));
                json_get_int(abuf, "value", &hd->action_value);
            }
        }

        /* shellcode */
        char sc_hex[MAX_SHELLCODE * 2 + 1] = "";
        json_get_str(hbuf, "shellcode_hex", sc_hex, sizeof(sc_hex));
        if (sc_hex[0]) {
            hd->shellcode_len = hex_decode(sc_hex, hd->shellcode, MAX_SHELLCODE);
        }

        /* patch_slots */
        const char *ps_end;
        const char *ps = json_get_obj(hbuf, "patch_slots", &ps_end);
        if (ps) {
            int plen = (int)(ps_end - ps);
            char pbuf[512];
            if (plen < (int)sizeof(pbuf)) {
                memcpy(pbuf, ps, plen);
                pbuf[plen] = '\0';

                const char *emp_end;
                const char *emp = json_get_obj(pbuf, "expected_method_ptr", &emp_end);
                if (emp) {
                    char eb[128];
                    int en = (emp_end - emp < (int)sizeof(eb)) ? (int)(emp_end - emp) : (int)sizeof(eb) - 1;
                    memcpy(eb, emp, en); eb[en] = '\0';
                    json_get_int(eb, "byte_offset", &hd->slot_expected.byte_offset);
                    json_get_int(eb, "reg", &hd->slot_expected.reg);
                }
                const char *ba_end;
                const char *ba = json_get_obj(pbuf, "backup_addr", &ba_end);
                if (ba) {
                    char bb[128];
                    int bn = (ba_end - ba < (int)sizeof(bb)) ? (int)(ba_end - ba) : (int)sizeof(bb) - 1;
                    memcpy(bb, ba, bn); bb[bn] = '\0';
                    json_get_int(bb, "byte_offset", &hd->slot_backup.byte_offset);
                    json_get_int(bb, "reg", &hd->slot_backup.reg);
                }
            }
        }

        /* Copy ART layout to hook for convenience */
        hd->art_size = prof->art_size;
        hd->art_off_af = prof->art_off_af;
        hd->art_off_midx = prof->art_off_midx;
        hd->art_off_ep = prof->art_off_ep;

        prof->n_hooks++;
        free(hbuf);
    }

    free(json);
    return 0;
}

static int load_all_profiles(void)
{
    DIR *d = opendir(g_profiles_dir);
    if (!d) {
        log_daemon("cannot open profiles dir: %s", g_profiles_dir);
        return -1;
    }
    g_n_profiles = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && g_n_profiles < MAX_PROFILES) {
        int len = strlen(ent->d_name);
        if (len < 6 || strcmp(ent->d_name + len - 5, ".json") != 0)
            continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", g_profiles_dir, ent->d_name);
        if (load_profile(path, &g_profiles[g_n_profiles]) == 0) {
            log_daemon("loaded profile: %s (%s, %d hooks)",
                       ent->d_name,
                       g_profiles[g_n_profiles].package,
                       g_profiles[g_n_profiles].n_hooks);
            g_n_profiles++;
        } else {
            log_daemon("failed to load profile: %s", ent->d_name);
        }
    }
    closedir(d);
    return g_n_profiles;
}

/* ---- Monitor loop ---- */

static void monitor_loop(void)
{
    for (int i = 0; i < g_n_profiles; i++) {
        g_monitors[i].profile = &g_profiles[i];
        g_monitors[i].state = STATE_WAITING;
        g_monitors[i].pid = -1;
    }

    log_daemon("entering monitor loop (%d profiles, poll=%dms)",
               g_n_profiles, g_poll_ms);

    while (!g_stop) {
        for (int i = 0; i < g_n_profiles; i++) {
            monitor_t *mon = &g_monitors[i];
            profile_t *prof = mon->profile;

            switch (mon->state) {

            case STATE_WAITING: {
                int pid = pidof(prof->package);
                if (pid > 0) {
                    mon->pid = pid;
                    mon->state = STATE_ART_INIT;
                    log_daemon("[%s] process detected pid=%d", prof->package, pid);
                }
                break;
            }

            case STATE_ART_INIT: {
                if (!proc_alive(mon->pid)) {
                    mon->state = STATE_WAITING;
                    mon->pid = -1;
                    break;
                }
                if (has_libart(mon->pid)) {
                    log_daemon("[%s] libart ready, waiting %dms for ART init",
                               prof->package, g_art_ready_delay_ms);
                    usleep(g_art_ready_delay_ms * 1000);
                    if (!proc_alive(mon->pid)) {
                        mon->state = STATE_WAITING;
                        mon->pid = -1;
                        break;
                    }
                    mon->state = STATE_HOOKING;
                }
                break;
            }

            case STATE_HOOKING: {
                if (!proc_alive(mon->pid)) {
                    mon->state = STATE_WAITING;
                    mon->pid = -1;
                    break;
                }
                int ok = install_all_hooks(mon);
                if (ok) {
                    mon->state = STATE_ACTIVE;
                    log_daemon("[%s] hooks active", prof->package);
                } else {
                    log_daemon("[%s] hook installation failed, will retry on restart",
                               prof->package);
                    mon->state = STATE_WAITING;
                    mon->pid = -1;
                }
                break;
            }

            case STATE_ACTIVE: {
                if (!proc_alive(mon->pid)) {
                    log_daemon("[%s] process died, waiting for restart", prof->package);
                    mon->state = STATE_WAITING;
                    mon->pid = -1;
                    memset(mon->ghosts, 0, sizeof(mon->ghosts));
                    memset(mon->hook_ok, 0, sizeof(mon->hook_ok));
                }
                break;
            }
            }
        }
        usleep(g_poll_ms * 1000);
    }
}

/* ---- Signal handling ---- */

static void on_signal(int sig)
{
    if (sig == SIGTERM || sig == SIGINT) {
        log_daemon("received signal %d, stopping", sig);
        g_stop = 1;
    } else if (sig == SIGHUP) {
        log_daemon("received SIGHUP, reloading profiles");
        load_all_profiles();
    }
}

/* ---- Main ---- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "ptehookd - ptehook on-device auto-hook daemon\n\n"
        "Usage: %s [OPTIONS]\n\n"
        "Options:\n"
        "  --superkey-file=PATH  superkey path (default /data/adb/ptehook/superkey)\n"
        "  --profiles-dir=PATH   profiles directory (default /data/adb/ptehook/profiles)\n"
        "  --bin-dir=PATH        binary directory (default /data/adb/ptehook)\n"
        "  --log=PATH            log file path (default /data/adb/ptehook/ptehookd.log)\n"
        "  --poll-interval=MS    poll interval in ms (default 500)\n"
        "  --art-ready-delay=MS  ART init wait in ms (default 2000)\n"
        "  --foreground          run in foreground\n"
        "  --status              show daemon status and exit\n"
        "  --reload              send SIGHUP to running daemon\n"
        "  --stop                send SIGTERM to running daemon\n"
        "  -h, --help            show this help\n",
        prog);
}

static int read_superkey(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot read superkey: %s\n", path);
        return -1;
    }
    if (!fgets(g_superkey, sizeof(g_superkey), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    /* Trim trailing whitespace */
    int len = strlen(g_superkey);
    while (len > 0 && (g_superkey[len-1] == '\n' || g_superkey[len-1] == '\r'
                        || g_superkey[len-1] == ' '))
        g_superkey[--len] = '\0';
    return 0;
}

static int find_running_daemon(void)
{
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *ent;
    int my_pid = getpid();
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
        int pid = atoi(ent->d_name);
        if (pid == my_pid) continue;
        char path[64], cmdline[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        int n = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);
        if (n > 0) {
            cmdline[n] = '\0';
            if (strstr(cmdline, "ptehookd")) {
                closedir(d);
                return pid;
            }
        }
    }
    closedir(d);
    return -1;
}

int main(int argc, char **argv)
{
    char superkey_path[256] = "/data/adb/ptehook/superkey";
    int do_status = 0, do_reload = 0, do_stop = 0;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--superkey-file=", 16) == 0)
            strncpy(superkey_path, argv[i] + 16, sizeof(superkey_path) - 1);
        else if (strncmp(argv[i], "--profiles-dir=", 15) == 0)
            strncpy(g_profiles_dir, argv[i] + 15, sizeof(g_profiles_dir) - 1);
        else if (strncmp(argv[i], "--bin-dir=", 10) == 0)
            strncpy(g_bin_dir, argv[i] + 10, sizeof(g_bin_dir) - 1);
        else if (strncmp(argv[i], "--log=", 6) == 0)
            strncpy(g_log_path, argv[i] + 6, sizeof(g_log_path) - 1);
        else if (strncmp(argv[i], "--poll-interval=", 16) == 0)
            g_poll_ms = atoi(argv[i] + 16);
        else if (strncmp(argv[i], "--art-ready-delay=", 18) == 0)
            g_art_ready_delay_ms = atoi(argv[i] + 18);
        else if (strcmp(argv[i], "--foreground") == 0)
            g_foreground = 1;
        else if (strcmp(argv[i], "--status") == 0)
            do_status = 1;
        else if (strcmp(argv[i], "--reload") == 0)
            do_reload = 1;
        else if (strcmp(argv[i], "--stop") == 0)
            do_stop = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    /* Control commands: --status / --reload / --stop */
    if (do_status || do_reload || do_stop) {
        int dpid = find_running_daemon();
        if (dpid < 0) {
            fprintf(stderr, "ptehookd is not running\n");
            return 1;
        }
        if (do_status) {
            printf("ptehookd is running (pid=%d)\n", dpid);
            return 0;
        }
        if (do_reload) {
            kill(dpid, SIGHUP);
            printf("sent SIGHUP to pid %d\n", dpid);
            return 0;
        }
        if (do_stop) {
            kill(dpid, SIGTERM);
            printf("sent SIGTERM to pid %d\n", dpid);
            return 0;
        }
    }

    /* Read superkey */
    if (read_superkey(superkey_path) < 0)
        return 1;

    /* Open log */
    g_log_fp = fopen(g_log_path, "a");
    if (!g_log_fp) g_log_fp = stderr;

    log_daemon("ptehookd starting (pid=%d)", getpid());

    /* Load profiles */
    if (load_all_profiles() <= 0) {
        log_daemon("no profiles loaded, exiting");
        return 1;
    }

    /* Daemonize unless --foreground */
    if (!g_foreground) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid > 0) return 0;  /* Parent exits */
        setsid();
        /* Redirect stdio */
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
    }

    /* Setup signal handlers */
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGHUP, on_signal);
    signal(SIGPIPE, SIG_IGN);

    /* Enter monitor loop */
    monitor_loop();

    log_daemon("ptehookd stopped");
    if (g_log_fp && g_log_fp != stderr) fclose(g_log_fp);
    return 0;
}
