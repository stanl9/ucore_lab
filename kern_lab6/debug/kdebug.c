#include <defs.h>
#include <x86.h>
#include <stab.h>
#include <stdio.h>
#include <string.h>
#include <memlayout.h>
#include <sync.h>
#include <vmm.h>
#include <proc.h>
#include <kdebug.h>
#include <kmonitor.h>
#include <assert.h>

#define STACKFRAME_DEPTH 20

extern const struct stab __STAB_BEGIN__[];
extern const struct stab __STAB_END__[];
extern const char __STABSTR_BEGIN__[];
extern const char __STABSTR_END__[];

struct eipdebuginfo {
    const char *eip_file;
    int eip_line;
    const char *eip_fn_name;
    int eip_fn_namelen;
    uintptr_t eip_fn_addr;
    int eip_fn_narg;
};

struct userstabdata {
    const struct stab *stabs;
    const struct stab *stab_end;
    const char *stabstr;
    const char *stabstr_end;
};

static void
stab_binsearch(const struct stab *stabs, int *region_left, int *region_right,
           int type, uintptr_t addr) {
    int l = *region_left, r = *region_right, any_matches = 0;
    while (l <= r) {
        int true_m = (l + r) / 2, m = true_m;
        while (m >= l && stabs[m].n_type != type) {
            m --;
        }
        if (m < l) {
            l = true_m + 1;
            continue;
        }
        any_matches = 1;
        if (stabs[m].n_value < addr) {
            *region_left = m;
            l = true_m + 1;
        } else if (stabs[m].n_value > addr) {
            *region_right = m - 1;
            r = m - 1;
        } else {
            *region_left = m;
            l = m;
            addr ++;
        }
    }
    if (!any_matches) {
        *region_right = *region_left - 1;
    }
    else {
        l = *region_right;
        for (; l > *region_left && stabs[l].n_type != type; l --)
            /* do nothing */;
        *region_left = l;
    }
}

int
debuginfo_eip(uintptr_t addr, struct eipdebuginfo *info) {
    const struct stab *stabs, *stab_end;
    const char *stabstr, *stabstr_end;
    info->eip_file = "<unknown>";
    info->eip_line = 0;
    info->eip_fn_name = "<unknown>";
    info->eip_fn_namelen = 9;
    info->eip_fn_addr = addr;
    info->eip_fn_narg = 0;
    if (addr >= KERNBASE) {
        stabs = __STAB_BEGIN__;
        stab_end = __STAB_END__;
        stabstr = __STABSTR_BEGIN__;
        stabstr_end = __STABSTR_END__;
    }
    else {
        const struct userstabdata *usd = (struct userstabdata *)USTAB;
        struct mm_struct *mm;
        if (current == NULL || (mm = current->mm) == NULL) {
            return -1;
        }
        if (!user_mem_check(mm, (uintptr_t)usd, sizeof(struct userstabdata), 0)) {
            return -1;
        }
        stabs = usd->stabs;
        stab_end = usd->stab_end;
        stabstr = usd->stabstr;
        stabstr_end = usd->stabstr_end;
        if (!user_mem_check(mm, (uintptr_t)stabs, (uintptr_t)stab_end - (uintptr_t)stabs, 0)) {
            return -1;
        }
        if (!user_mem_check(mm, (uintptr_t)stabstr, stabstr_end - stabstr, 0)) {
            return -1;
        }
    }
    if (stabstr_end <= stabstr || stabstr_end[-1] != 0) {
        return -1;
    }
    int lfile = 0, rfile = (stab_end - stabs) - 1;
    stab_binsearch(stabs, &lfile, &rfile, N_SO, addr);
    if (lfile == 0)
        return -1;
    int lfun = lfile, rfun = rfile;
    int lline, rline;
    stab_binsearch(stabs, &lfun, &rfun, N_FUN, addr);
    if (lfun <= rfun) {
        if (stabs[lfun].n_strx < stabstr_end - stabstr) {
            info->eip_fn_name = stabstr + stabs[lfun].n_strx;
        }
        info->eip_fn_addr = stabs[lfun].n_value;
        addr -= info->eip_fn_addr;
        lline = lfun;
        rline = rfun;
    } else {
        info->eip_fn_addr = addr;
        lline = lfile;
        rline = rfile;
    }
    info->eip_fn_namelen = strfind(info->eip_fn_name, ':') - info->eip_fn_name;
    stab_binsearch(stabs, &lline, &rline, N_SLINE, addr);
    if (lline <= rline) {
        info->eip_line = stabs[rline].n_desc;
    } else {
        return -1;
    }
    while (lline >= lfile
           && stabs[lline].n_type != N_SOL
           && (stabs[lline].n_type != N_SO || !stabs[lline].n_value)) {
        lline --;
    }
    if (lline >= lfile && stabs[lline].n_strx < stabstr_end - stabstr) {
        info->eip_file = stabstr + stabs[lline].n_strx;
    }
    if (lfun < rfun) {
        for (lline = lfun + 1;
             lline < rfun && stabs[lline].n_type == N_PSYM;
             lline ++) {
            info->eip_fn_narg ++;
        }
    }
    return 0;
}

void
print_kerninfo(void) {
    extern char etext[], edata[], end[], kern_init[];
    cprintf("Special kernel symbols:
");
    cprintf("  entry  0x%08x (phys)
", kern_init);
    cprintf("  etext  0x%08x (phys)
", etext);
    cprintf("  edata  0x%08x (phys)
", edata);
    cprintf("  end    0x%08x (phys)
", end);
    cprintf("Kernel executable memory footprint: %dKB
", (end - kern_init + 1023)/1024);
}

void
print_debuginfo(uintptr_t eip) {
    struct eipdebuginfo info;
    if (debuginfo_eip(eip, &info) != 0) {
        cprintf("    <unknow>: -- 0x%08x --
", eip);
    }
    else {
        char fnname[256];
        int j;
        for (j = 0; j < info.eip_fn_namelen; j ++) {
            fnname[j] = info.eip_fn_name[j];
        }
        fnname[j] = '\0';
        cprintf("    %s:%d: %s+%d
", info.eip_file, info.eip_line,
                fnname, eip - info.eip_fn_addr);
    }
}

static inline uint32_t
read_ebp(void) {
    uint32_t ebp;
    asm volatile("movl %%ebp, %0" : "=r" (ebp));
    return ebp;
}

static __noinline uint32_t
read_eip(void) {
    uint32_t eip;
    asm volatile("movl 4(%%ebp), %0" : "=r" (eip));
    return eip;
}

void
print_stackframe(void) {
    uint32_t ebp = read_ebp(), eip = read_eip();
    int i, j;
    for (i = 0; i < STACKFRAME_DEPTH && ebp != 0; i ++) {
        cprintf("ebp:0x%08x eip:0x%08x args:", ebp, eip);
        uint32_t *args = (uint32_t *)ebp + 2;
        for (j = 0; j < 4; j ++) {
            cprintf("0x%08x ", args[j]);
        }
        cprintf("
");
        print_debuginfo(eip - 1);
        eip = ((uint32_t *)ebp)[1];
        ebp = ((uint32_t *)ebp)[0];
    }
}
