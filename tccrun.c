/*
 *  TCC - Tiny C Compiler - Support for -run switch
 *
 *  Copyright (c) 2001-2004 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "tcc.h"

/* only native compiler supports -run */
#ifdef TCC_IS_NATIVE


/* defined when included from lib/bt-exe.c */
#ifndef CONFIG_TCC_BACKTRACE_ONLY

#ifndef _WIN32
# include <sys/mman.h>
#endif

static void set_pages_executable(TCCState *s1, int mode, void *ptr, unsigned long length);
static int tcc_relocate_ex(TCCState *s1, void *ptr, addr_t ptr_diff);


/* ------------------------------------------------------------- */
/* Do all relocations (needed before using tcc_get_symbol())
   Returns -1 on error. */

LIBTCCAPI int tcc_relocate(TCCState *s1, void *ptr)
{
    int size;
    addr_t ptr_diff = 0;

    if (TCC_RELOCATE_AUTO != ptr)
        return tcc_relocate_ex(s1, ptr, 0);

    size = tcc_relocate_ex(s1, NULL, 0);
    if (size < 0)
        return -1;

#ifdef HAVE_SELINUX
{
    /* Using mmap instead of malloc */
    void *prx;
    char tmpfname[] = "/tmp/.tccrunXXXXXX";
    int fd = mkstemp(tmpfname);
    unlink(tmpfname);
    ftruncate(fd, size);

    size = (size + (PAGESIZE-1)) & ~(PAGESIZE-1);
    ptr = mmap(NULL, size * 2, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    /* mmap RX memory at a fixed distance */
    prx = mmap((char*)ptr + size, size, PROT_READ|PROT_EXEC, MAP_SHARED|MAP_FIXED, fd, 0);
    if (ptr == MAP_FAILED || prx == MAP_FAILED)
	tcc_error("tccrun: could not map memory");
    ptr_diff = (char*)prx - (char*)ptr;
    close(fd);
    //printf("map %p %p %p\n", ptr, prx, (void*)ptr_diff);
}
#else
    ptr = tcc_malloc(size);
#endif
    tcc_relocate_ex(s1, ptr, ptr_diff); /* no more errors expected */
    dynarray_add(&s1->runtime_mem, &s1->nb_runtime_mem, (void*)(addr_t)size);
    dynarray_add(&s1->runtime_mem, &s1->nb_runtime_mem, ptr);
    return 0;
}

ST_FUNC void tcc_run_free(TCCState *s1)
{
    int i;

    for (i = 0; i < s1->nb_runtime_mem; i += 2) {
        unsigned size = (unsigned)(addr_t)s1->runtime_mem[i];
        void *ptr = s1->runtime_mem[i+1];
#ifdef HAVE_SELINUX
        munmap(ptr, size * 2);
#else
        /* unprotect memory to make it usable for malloc again */
        set_pages_executable(s1, 2, ptr, size);
        tcc_free(ptr);
#endif
    }
    tcc_free(s1->runtime_mem);
}

static void run_cdtors(TCCState *s1, const char *start, const char *end,
                       int argc, char **argv, char **envp)
{
    void **a = (void **)get_sym_addr(s1, start, 0, 0);
    void **b = (void **)get_sym_addr(s1, end, 0, 0);
    while (a != b)
        ((void(*)(int, char **, char **))*a++)(argc, argv, envp);
}

/* launch the compiled program with the given arguments */
LIBTCCAPI int tcc_run(TCCState *s1, int argc, char **argv)
{
    int (*prog_main)(int, char **, char **), ret;
#if defined(__APPLE__) || defined(__FreeBSD__)
    char **envp = NULL;
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    extern char **environ;
    char **envp = environ;
#else
    char **envp = environ;
#endif

    s1->runtime_main = s1->nostdlib ? "_start" : "main";
    if ((s1->dflag & 16) && (addr_t)-1 == get_sym_addr(s1, s1->runtime_main, 1, 1))
        return 0;
    if (tcc_relocate(s1, TCC_RELOCATE_AUTO) < 0)
        return -1;
    
    prog_main = (void*)get_sym_addr(s1, s1->runtime_main, 1, 1);


    errno = 0; /* clean errno value */
    fflush(stdout);
    fflush(stderr);
    /* These aren't C symbols, so don't need leading underscore handling.  */
    run_cdtors(s1, "__init_array_start", "__init_array_end", argc, argv, envp);
    {
        ret = prog_main(argc, argv, envp);
    }
    run_cdtors(s1, "__fini_array_start", "__fini_array_end", 0, NULL, NULL);
    if ((s1->dflag & 16) && ret)
        fprintf(s1->ppfp, "[returns %d]\n", ret), fflush(s1->ppfp);
    return ret;
}

#define DEBUG_RUNMEN 0

/* enable rx/ro/rw permissions */
#define CONFIG_RUNMEM_RO 1

#if CONFIG_RUNMEM_RO
# define PAGE_ALIGN PAGESIZE
#elif defined TCC_TARGET_I386 || defined TCC_TARGET_X86_64
/* To avoid that x86 processors would reload cached instructions
   each time when data is written in the near, we need to make
   sure that code and data do not share the same 64 byte unit */
# define PAGE_ALIGN 64
#else
# define PAGE_ALIGN 1
#endif

/* relocate code. Return -1 on error, required size if ptr is NULL,
   otherwise copy code into buffer passed by the caller */
static int tcc_relocate_ex(TCCState *s1, void *ptr, addr_t ptr_diff)
{
    Section *s;
    unsigned offset, length, align, max_align, i, k, f;
    unsigned n, copy;
    addr_t mem, addr;

    if (NULL == ptr) {
        s1->nb_errors = 0;

        tcc_add_runtime(s1);
	    resolve_common_syms(s1);
        build_got_entries(s1, 0);
        if (s1->nb_errors)
            return -1;
    }

    offset = max_align = 0, mem = (addr_t)ptr;

    copy = 0;
redo:
    for (k = 0; k < 3; ++k) { /* 0:rx, 1:ro, 2:rw sections */
        n = 0; addr = 0;
        for(i = 1; i < s1->nb_sections; i++) {
            static const char shf[] = {
                SHF_ALLOC|SHF_EXECINSTR, SHF_ALLOC, SHF_ALLOC|SHF_WRITE
                };
            s = s1->sections[i];
            if (shf[k] != (s->sh_flags & (SHF_ALLOC|SHF_WRITE|SHF_EXECINSTR)))
                continue;
            length = s->data_offset;
            if (copy) {
                if (addr == 0)
                    addr = s->sh_addr;
                n = (s->sh_addr - addr) + length;
                ptr = (void*)s->sh_addr;
                if (k == 0)
                    ptr = (void*)(s->sh_addr - ptr_diff);
                if (NULL == s->data || s->sh_type == SHT_NOBITS)
                    memset(ptr, 0, length);
                else
                    memcpy(ptr, s->data, length);

                if (s->data) {
                    tcc_free(s->data);
                    s->data = NULL;
                    s->data_allocated = 0;
                }
                s->data_offset = 0;
                continue;
            }
            align = s->sh_addralign - 1;
            if (++n == 1 && align < (PAGE_ALIGN - 1))
                align = (PAGE_ALIGN - 1);
            if (max_align < align)
                max_align = align;
            addr = k ? mem : mem + ptr_diff;
            offset += -(addr + offset) & align;
            s->sh_addr = mem ? addr + offset : 0;
            offset += length;
#if DEBUG_RUNMEN
            if (mem)
                printf("%d: %-16s %p  len %04x  align %04x\n",
                    k, s->name, (void*)s->sh_addr, length, align + 1);
#endif
        }
        if (copy) { /* set permissions */
            if (k == 0 && ptr_diff)
                continue; /* not with HAVE_SELINUX */
            f = k;
#if !CONFIG_RUNMEM_RO
            if (f != 0)
                continue;
            f = 3; /* change only SHF_EXECINSTR to rwx */
#endif
#if DEBUG_RUNMEN
            printf("protect %d %p %04x\n", f, (void*)addr, n);
#endif
            if (n)
                set_pages_executable(s1, f, (void*)addr, n);
        }
    }

    if (copy)
        return 0;

    /* relocate symbols */
    relocate_syms(s1, s1->symtab, !(s1->nostdlib));
    if (s1->nb_errors)
        return -1;
    if (0 == mem)
        return offset + max_align;


    /* relocate sections */
    relocate_plt(s1);

    relocate_sections(s1);
    copy = 1;
    goto redo;
}

/* ------------------------------------------------------------- */
/* allow to run code in memory */

static void set_pages_executable(TCCState *s1, int mode, void *ptr, unsigned long length)
{
#ifdef _WIN32
    static const unsigned char protect[] = {
        PAGE_EXECUTE_READ,
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_EXECUTE_READWRITE
        };
    DWORD old;
    VirtualProtect(ptr, length, protect[mode], &old);
#else
    static const unsigned char protect[] = {
        PROT_READ | PROT_EXEC,
        PROT_READ,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE | PROT_EXEC
        };
    addr_t start, end;
    start = (addr_t)ptr & ~(PAGESIZE - 1);
    end = (addr_t)ptr + length;
    end = (end + PAGESIZE - 1) & ~(PAGESIZE - 1);
    if (mprotect((void *)start, end - start, protect[mode]))
        tcc_error("mprotect failed: did you mean to configure --with-selinux?");

/* XXX: BSD sometimes dump core with bad system call */
# if (defined TCC_TARGET_ARM && !TARGETOS_BSD) || defined TCC_TARGET_ARM64
    if (mode == 0 || mode == 3) {
        void __clear_cache(void *beginning, void *end);
        __clear_cache(ptr, (char *)ptr + length);
    }
# endif

#endif
}


#endif //ndef CONFIG_TCC_BACKTRACE_ONLY
/* ------------------------------------------------------------- */


#endif /* TCC_IS_NATIVE */
/* ------------------------------------------------------------- */
