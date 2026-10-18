/*
 * pagemap.h - writing kernel pages that are mapped read-only
 *
 * SbieDrv >= 1.18.7 declares KphpTrustedPublicKey const, which puts the key
 * into .rdata - mapped read-only.  The helper driver memmove has no SEH, so
 * a direct write there bugchecks the box (0xBE).  Such pages are written
 * through a writable alias of the same physical frame; the page tables
 * self-map at a base Windows randomizes per boot, which is read from
 * nt!MmPteBase and validated before it is used.
 */
#ifndef PAGEMAP_H
#define PAGEMAP_H

#include <windows.h>
#include "log.h"
#include "kdrv.h"
#include "kmod.h"
/* ------------------------------------------------------------------ */
/*  Writes into read-only image pages                                 */
/*                                                                    */
/*  SbieDrv >= 1.18.7 declares KphpTrustedPublicKey const, which puts */
/*  the key into .rdata - mapped read-only.  The helper driver's      */
/*  memmove has no SEH, so a direct write would bugcheck the box      */
/*  (ATTEMPTED_WRITE_TO_READONLY_MEMORY).  Such pages are written     */
/*  through a writable alias of the same physical frame instead.      */
/* ------------------------------------------------------------------ */

/* 4-level x64 paging self-maps the page tables, so the PTE of *va*
 * sits at base + 8 * (packed indices); only the low 36 bits of
 * (va >> 12) are indices, the bits above are the canonical sign
 * extension and must be masked off. */
#define KDRV_VA_INDEX_MASK 0xFFFFFFFFFULL

/* The self-map base is randomized per boot (Windows 10 RS1+), so it is
 * read from nt!MmPteBase.  The variable is not exported; it is located
 * by the code idiom `mov rax, [rip+MmPteBase]` / `shr r??, 9`.
 *
 * shortcut: the scan accepts exactly that idiom and only in sections that
 * are executable and not discardable.  A kernel that compiles it
 * differently makes the lookup find nothing and the unlock stop with a
 * controlled error - it never guesses a base.  Upgrade if a future build
 * no longer matches (the log says "no PTE-base reference found"). */
#define KDRV_MMPTE_PATTERN_LEN 11

/* Target of the 11-byte pattern at *p* (which lives at *va*), or 0 when
 * it is not a PTE-base reference: 48 8B 05 <disp32> 48 C1 E? 09. */
static ULONG64 kdrv_pte_ref_target(const BYTE *p, ULONG64 va)
{
    if (p[0] != 0x48 || p[1] != 0x8B || p[2] != 0x05)
        return 0;
    if (p[7] != 0x48 || p[8] != 0xC1 || (p[9] & 0xF8) != 0xE8 || p[10] != 9)
        return 0;
    return va + 7 + (LONG)*(const INT32 *)(p + 3);
}

/* Is *v* shaped like a 4-level self-map base (kernel-half PML4 entry,
 * everything below it zero)? */
static BOOL kdrv_is_pte_base(ULONG64 v)
{
    ULONG64 idx = (v >> 39) & 0x1FF;
    return (v & KDRV_VA_INDEX_MASK) == 0 &&
           (v >> 48) == 0xFFFF &&
           idx >= 0x100 && idx <= 0x1FF;
}

/* VA of the PTE that maps *va*. */
static ULONG64 kdrv_pte_va(ULONG64 pte_base, ULONG64 va)
{
    return pte_base + ((va >> 12) & KDRV_VA_INDEX_MASK) * 8;
}

/* Alias PTE for the frame described by *src_pte*: present, writable,
 * supervisor (US=0 keeps SMAP out of the way for the kernel-mode store)
 * and non-executable.  Windows' per-PTE software bits are dropped. */
static ULONG64 kdrv_alias_pte(ULONG64 src_pte)
{
    return (src_pte & 0x000FFFFFFFFFF000ULL) | 0x1ULL | 0x2ULL |
           0x8000000000000000ULL;
}

/* Distinct reference targets and how often the idiom pointed at each. */
#define KDRV_MAX_PTE_REFS 32

typedef struct {
    ULONG64 va;
    int hits;
} kdrv_pte_ref_t;

/* Scan one code chunk for PTE-base references; hits must stay inside the
 * ntoskrnl image, so every later read of a target is a mapped read.  The
 * idiom is not exclusive to MmPteBase, so targets are collected with
 * their hit counts and the value shape decides later. */
static void kdrv_pte_refs_in_chunk(const BYTE *code, ULONG64 chunk_va, ULONG len,
                                   ULONG64 img_base, ULONG64 img_size,
                                   kdrv_pte_ref_t *refs, int *ref_count)
{
    if (len < KDRV_MMPTE_PATTERN_LEN)
        return;

    for (ULONG i = 0; i + KDRV_MMPTE_PATTERN_LEN <= len; i++) {
        ULONG64 target = kdrv_pte_ref_target(code + i, chunk_va + i);
        if (!target || target < img_base || target >= img_base + img_size)
            continue;

        int k;
        for (k = 0; k < *ref_count; k++) {
            if (refs[k].va == target) {
                refs[k].hits++;
                break;
            }
        }
        if (k == *ref_count && *ref_count < KDRV_MAX_PTE_REFS) {
            refs[*ref_count].va = target;
            refs[*ref_count].hits = 1;
            (*ref_count)++;
        }
    }
}

/* Read nt!MmPteBase out of the loaded ntoskrnl image.  Returns the base
 * or 0; a failure is reported and leaves the unlock a controlled error,
 * never a fault in the helper driver. */
static ULONG64 kdrv_locate_pte_base(kdrv_t *d)
{
    ULONG img_size = 0;
    ULONG64 img_base = kmod_find("ntoskrnl", &img_size);
    if (!img_base || !img_size) {
        LOGE("kdrv_locate_pte_base: ntoskrnl not found in the module list");
        return 0;
    }

    /* Section table of the *loaded* image (its headers are mapped). */
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    if (kdrv_read(d, img_base, &dos, sizeof(dos)) != 0 ||
        dos.e_lfanew < 0 || dos.e_lfanew >= 0x1000 ||   /* NT headers live in the first page */
        kdrv_read(d, img_base + dos.e_lfanew, &nt, sizeof(nt)) != 0) {
        LOGE("kdrv_locate_pte_base: PE headers unreadable");
        return 0;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || nt.Signature != IMAGE_NT_SIGNATURE) {
        LOGE("kdrv_locate_pte_base: bad PE headers");
        return 0;
    }

    IMAGE_SECTION_HEADER sec[64];
    ULONG sec_count = nt.FileHeader.NumberOfSections;
    if (!sec_count || sec_count > 64) {
        LOGE("kdrv_locate_pte_base: implausible section count %lu", sec_count);
        return 0;
    }
    ULONG sec_off = 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    if (kdrv_read(d, img_base + sec_off, sec, sec_count * sizeof(sec[0])) != 0) {
        LOGE("kdrv_locate_pte_base: section table unreadable");
        return 0;
    }

    kdrv_pte_ref_t refs[KDRV_MAX_PTE_REFS];
    int ref_count = 0;

    /* Chunked so a large section costs a fixed allocation; the overlap
     * keeps a pattern that straddles a chunk boundary. */
    const ULONG CHUNK = 512 * 1024;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, CHUNK);
    if (!buf) {
        LOGE("kdrv_locate_pte_base: alloc failed");
        return 0;
    }

    for (ULONG s = 0; s < sec_count; s++) {
        if (!(sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) || !sec[s].SizeOfRawData)
            continue;
        /* Discarded sections (INIT) may already be unmapped - reading
         * them would fault the un-SEH'd helper driver. */
        if (sec[s].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
            continue;

        ULONG64 sec_base = img_base + sec[s].VirtualAddress;
        if (sec_base < img_base || sec_base >= img_base + img_size)
            continue;   /* bogus section header must not steer the reads */
        /* Never read padding past the mapping: the raw size can exceed
         * the virtual size and the image end. */
        ULONG span = sec[s].SizeOfRawData;
        if (sec[s].Misc.VirtualSize && span > sec[s].Misc.VirtualSize)
            span = sec[s].Misc.VirtualSize;
        if (sec_base + span > img_base + img_size)
            span = (ULONG)(img_base + img_size - sec_base);

        ULONG left = span;
        ULONG64 off = 0;
        while (left) {
            ULONG take = (left > CHUNK) ? CHUNK : left;
            if (kdrv_read(d, sec_base + off, buf, take) != 0) {
                LOGW("kdrv_locate_pte_base: section read failed at 0x%llX", sec_base + off);
                break;
            }
            kdrv_pte_refs_in_chunk(buf, sec_base + off, take, img_base, img_size,
                                   refs, &ref_count);
            if (take == left)
                break;   /* last chunk of this section: nothing left to overlap */
            off += take - (KDRV_MMPTE_PATTERN_LEN - 1);   /* keep a pattern that straddles */
            left -= take;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);

    if (!ref_count) {
        LOGE("kdrv_locate_pte_base: no PTE-base reference found (image size 0x%lX)", img_size);
        return 0;
    }
    if (ref_count == KDRV_MAX_PTE_REFS)
        LOGW("kdrv_locate_pte_base: reference table full, later targets skipped");

    /* The idiom is shared with other kernel globals, so the value shape
     * decides: read each distinct target (inside the image, hence mapped)
     * most-referenced first and take the first self-map shaped value. */
    ULONG64 base = 0;
    for (int i = 0; i < ref_count; i++) {
        int best = i;
        for (int j = i + 1; j < ref_count; j++) {
            if (refs[j].hits > refs[best].hits)
                best = j;
        }
        kdrv_pte_ref_t tmp = refs[i];
        refs[i] = refs[best];
        refs[best] = tmp;

        ULONG64 v = 0;
        if (kdrv_read(d, refs[i].va, &v, sizeof(v)) != 0) {
            LOGW("kdrv_locate_pte_base: target 0x%llX unreadable", refs[i].va);
            continue;
        }
        if (!kdrv_is_pte_base(v)) {
            LOGW("kdrv_locate_pte_base: target 0x%llX holds 0x%llX - not a self-map base",
                 refs[i].va, v);
            continue;
        }
        LOGI("nt!MmPteBase at RVA 0x%llX = 0x%llX (%d reference(s))",
             refs[i].va - img_base, v, refs[i].hits);
        base = v;
        break;
    }

    if (!base)
        LOGE("kdrv_locate_pte_base: no self-map base among %d distinct target(s)", ref_count);
    return base;
}

/* Validate a candidate base against a page this process owns: its PTE
 * must be a present, writable, user entry.  A wrong base cannot pass
 * this, and the check runs before any write - so a bad base ends as a
 * controlled failure, not as corrupt memory. */
static BOOL kdrv_validate_pte_base(kdrv_t *d, ULONG64 base)
{
    BYTE *probe = (BYTE *)VirtualAlloc(NULL, 0x1000,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!probe) {
        /* An unvalidated base must not be used: refuse instead. */
        LOGE("kdrv_validate_pte_base: probe alloc failed: %lu", GetLastError());
        return FALSE;
    }

    *(volatile BYTE *)probe = 1;   /* fault the page in */
    ULONG64 probe_pte = 0;
    BOOL ok = kdrv_read(d, kdrv_pte_va(base, (ULONG64)(ULONG_PTR)probe),
                        &probe_pte, sizeof(probe_pte)) == 0 &&
              (probe_pte & 0x1) && (probe_pte & 0x2) && (probe_pte & 0x4);
    if (ok)
        LOGI("PTE base 0x%llX validated against an owned page", base);
    else
        LOGE("kdrv_validate_pte_base: base 0x%llX failed validation "
             "(own page PTE 0x%llX)", base, probe_pte);

    VirtualFree(probe, 0, MEM_RELEASE);
    return ok;
}

/* The page-table base, or 0 when this OS cannot be handled: 5-level
 * paging (LA57) uses another layout, and guessing a base would fault
 * the un-SEH'd helper driver into a bugcheck. */
static BOOL kdrv_pte_supported(void)
{
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return (ULONG64)(ULONG_PTR)si.lpMaximumApplicationAddress <= 0x00007FFFFFFEFFFFULL;
}

/* Pre-RS1 kernels (every Windows before 10 1607) have no nt!MmPteBase
 * to find: their self-map base is the fixed classic constant.  Newer
 * builds must never fall back to it - there it is unmapped and reading
 * a PTE through it would bugcheck the box. */
#define KDRV_PTE_BASE_FIXED 0xFFFFF68000000000ULL
#define KDRV_OS_RS1_BUILD   14393

static ULONG64 kdrv_pte_base_fixed(void)
{
    typedef LONG (WINAPI *fn_getver)(RTL_OSVERSIONINFOW *);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    fn_getver getver = ntdll
        ? (fn_getver)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    if (!getver) return 0;

    RTL_OSVERSIONINFOW vi;
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (getver(&vi) != 0) return 0;

    if (vi.dwMajorVersion > 10) return 0;
    if (vi.dwMajorVersion == 10 && vi.dwBuildNumber >= KDRV_OS_RS1_BUILD) return 0;

    LOGI("Pre-RS1 kernel (build %lu.%lu.%lu): fixed self-map base",
         vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    return KDRV_PTE_BASE_FIXED;
}

static ULONG64 kdrv_pte_base(kdrv_t *d)
{
    if (!kdrv_pte_supported()) {
        LOGE("kdrv: 5-level paging detected, no PTE alias - unlock unsupported here");
        return 0;
    }

    ULONG64 base = kdrv_locate_pte_base(d);
    if (!base)
        base = kdrv_pte_base_fixed();
    if (!base) {
        LOGE("kdrv: no page-table base found - unlock unsupported on this kernel");
        return 0;
    }
    return kdrv_validate_pte_base(d, base) ? base : 0;
}

/* Write *size* bytes to kernel VA *va*, which may live in a read-only
 * image section.  A writable page takes the direct path; a read-only
 * page is written through a fresh alias of its physical frame, so the
 * store never touches a read-only mapping (a stale read-only TLB entry
 * on the original VA would fault again).  Every failure is detected
 * before any store, so a read-only page can never reach the driver's
 * un-SEH'd memmove.  Returns 0 on success. */
static int kdrv_page_write(kdrv_t *d, ULONG64 va, const void *data, ULONG size)
{
    if ((va & 0xFFF) + size > 0x1000) {
        LOGE("kdrv_page_write: %lu bytes at 0x%llX cross a page boundary", size, va);
        return 1;
    }

    ULONG64 pte_base = kdrv_pte_base(d);
    if (!pte_base) return 1;

    ULONG64 target_pte = 0;
    ULONG64 pte_va = kdrv_pte_va(pte_base, va);
    if (kdrv_read(d, pte_va, &target_pte, sizeof(target_pte)) != 0) {
        LOGE("kdrv_page_write: PTE read failed at 0x%llX", pte_va);
        return 2;
    }
    if (!(target_pte & 0x1) || (target_pte & 0x80)) {
        LOGE("kdrv_page_write: no 4K present mapping for 0x%llX (PTE 0x%llX)",
             va, target_pte);
        return 3;
    }
    if (target_pte & 0x2) {
        LOGI("Target page is writable - direct write");
        return kdrv_write(d, va, data, size);
    }

    /* Three committed pages, never touched by user code: their PTE page
     * is materialised by touching the neighbour that shares the 2MB
     * region, and the alias page itself stays out of the TLB.  The 2MB
     * boundary can cross at most one of the two neighbour boundaries. */
    BYTE *pages = (BYTE *)VirtualAlloc(NULL, 3 * 0x1000,
                                       MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pages) {
        LOGE("kdrv_page_write: VirtualAlloc failed: %lu", GetLastError());
        return 4;
    }

    BYTE *alias = pages + 0x1000;
    BYTE *anchor = ((ULONG_PTR)alias >> 21) == ((ULONG_PTR)pages >> 21)
                   ? pages : pages + 0x2000;
    if (((ULONG_PTR)alias >> 21) != ((ULONG_PTR)anchor >> 21)) {
        /* Cannot happen: contiguous pages, one 2MB boundary at most. */
        VirtualFree(pages, 0, MEM_RELEASE);
        LOGE("kdrv_page_write: no neighbour page in the alias 2MB region");
        return 5;
    }
    *(volatile BYTE *)anchor = 0;   /* materialise the PTE page, not the alias */

    ULONG64 alias_va = (ULONG64)(ULONG_PTR)alias;
    ULONG64 alias_pte_va = kdrv_pte_va(pte_base, alias_va);
    ULONG64 saved_pte = 0;
    int rc = 0;
    BOOL restored = TRUE;

    if (kdrv_read(d, alias_pte_va, &saved_pte, sizeof(saved_pte)) != 0) {
        LOGE("kdrv_page_write: alias PTE read failed at 0x%llX", alias_pte_va);
        rc = 6;
        goto out;
    }

    ULONG64 alias_pte = kdrv_alias_pte(target_pte);
    if (kdrv_write(d, alias_pte_va, &alias_pte, sizeof(alias_pte)) != 0) {
        LOGE("kdrv_page_write: alias PTE write failed at 0x%llX", alias_pte_va);
        rc = 7;
        goto out;
    }

    LOGI("Target page is read-only - writing via page alias 0x%llX", alias_va);
    if (kdrv_write(d, alias_va + (va & 0xFFF), data, size) != 0) {
        LOGE("kdrv_page_write: alias write failed");
        rc = 8;
    }

    /* The alias mapping must not outlive this call. */
    if (kdrv_write(d, alias_pte_va, &saved_pte, sizeof(saved_pte)) != 0) {
        LOGE("kdrv_page_write: alias PTE restore failed at 0x%llX", alias_pte_va);
        restored = FALSE;
        if (!rc) rc = 9;
    }

out:
    /* Freeing the pages while their PTE still points at the target frame
     * would hand that frame back to the allocator - leak them instead. */
    if (restored)
        VirtualFree(pages, 0, MEM_RELEASE);
    else
        LOGW("kdrv_page_write: alias PTE left in place, pages leaked on purpose");
    return rc;
}


#endif /* PAGEMAP_H */
