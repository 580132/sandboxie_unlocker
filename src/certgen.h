/*
 * certgen.h - Certificate.dat generation and .sig re-signing
 *
 * Builds a UTF-8 Certificate.dat with an ECDSA P-256 signature that
 * the driver's KphValidateCertificate will accept.  Also re-signs
 * all .exe.sig files in the Sandboxie directory with our key.
 */
#ifndef CERTGEN_H
#define CERTGEN_H

#include <windows.h>
#include "log.h"
#include "ecrypto.h"
#include "fileio.h"
#include "pesearch.h"

/* Certificate tags that produce:
 *   type  = eCertEternal (4)
 *   level = eCertMaxLevel (7)
 *   opts  = opt_sec + opt_enc + opt_net + opt_desk
 *   expiration = -1 (never expires)
 */
static const char *CERT_TAGS[] = {
    "NAME: HardTest",
    "DATE: 25.06.2026",
    "TYPE: ETERNAL",
    "SOFTWARE: Sandboxie-Plus",
    "OPTIONS: SBOX,EBOX,NETI,DESK",
    NULL
};

/* SHA-256 a file. Returns 0 on success, writes 32 bytes into out. */
static int sha256_file(const char *path, BYTE *out)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("sha256_file: open failed: %lu path=%s", GetLastError(), path);
        return 1;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, L"SHA256", NULL, 0)) return 2;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 3;
    }

    /* 64KB on the unlock thread's stack would be reckless; the file
     * hashing is single-threaded, so a static buffer is safe. */
    static BYTE buf[65536];
    DWORD bytesRead;
    BOOL readOk = TRUE;
    BOOL hashOk = TRUE;
    DWORD readErr = 0;
    NTSTATUS hashSt = 0;
    for (;;) {
        if (!ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL)) {
            readOk = FALSE;
            readErr = GetLastError();  /* capture now - BCrypt/CloseHandle calls below clobber it */
            break;
        }
        if (bytesRead == 0) break;
        hashSt = BCryptHashData(hHash, buf, bytesRead, 0);
        if (hashSt) { hashOk = FALSE; break; }
    }

    NTSTATUS finSt = BCryptFinishHash(hHash, out, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    /* An unfed hash still finishes cleanly, so each failure class keeps
     * its own diagnosis: finish, hash feed, then file read. */
    if (finSt) { LOGE("sha256_file: BCryptFinishHash failed: 0x%lX", (unsigned long)finSt); return 6; }
    if (!hashOk) { LOGE("sha256_file: BCryptHashData failed: 0x%lX", (unsigned long)hashSt); return 6; }
    if (!readOk) { LOGE("sha256_file: ReadFile failed: %lu path=%s", readErr, path); return 5; }
    return 0;
}

/* SHA-256 of name:value pairs from CERT_TAGS (excludes SIGNATURE).
 * Matches verify.c's hashing: hash(utf8(name)) then hash(utf8(value)).
 * Returns 0 on success; on failure out32 is zeroed. */
static int cert_hash_body(BYTE *out32)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, L"SHA256", NULL, 0)) { memset(out32, 0, 32); return 1; }
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        memset(out32, 0, 32);
        return 2;
    }

    int r = 0;
    for (int i = 0; CERT_TAGS[i]; i++) {
        const char *colon = strchr(CERT_TAGS[i], ':');
        if (!colon) continue;
        const char *name = CERT_TAGS[i];
        const char *value = colon + 1;
        while (*name == ' ') name++;
        while (*value == ' ') value++;
        if (BCryptHashData(hHash, (PUCHAR)name, (ULONG)(colon - name), 0) ||
            BCryptHashData(hHash, (PUCHAR)value, (ULONG)strlen(value), 0)) {
            r = 3;
            break;
        }
    }

    if (!r && BCryptFinishHash(hHash, out32, 32, 0))
        r = 4;

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (r) memset(out32, 0, 32);
    return r;
}

/* Write Certificate.dat to sbie_dir. Returns 0 on success. */
static int cert_write(const char *sbie_dir, const ec_keypair_t *kp)
{
    BYTE hash[32];
    if (cert_hash_body(hash)) { LOGE("cert_hash_body failed"); return 5; }

    BYTE sig[64];
    int r = ec_sign_hash(kp, hash, sig);
    if (r) { LOGE("ec_sign_hash failed: %d", r); return 1; }

    char sig_b64[256];
    r = ec_base64_encode(sig, 64, sig_b64, sizeof(sig_b64));
    if (r) { LOGE("ec_base64_encode failed: %d", r); return 2; }

    char content[2048];
    content[0] = 0;
    for (int i = 0; CERT_TAGS[i]; i++) {
        strcat_s(content, sizeof(content), CERT_TAGS[i]);
        strcat_s(content, sizeof(content), "\n");
    }
    strcat_s(content, sizeof(content), "SIGNATURE: ");
    strcat_s(content, sizeof(content), sig_b64);
    strcat_s(content, sizeof(content), "\n");

    char path[MAX_PATH];
    strcpy_s(path, MAX_PATH, sbie_dir);
    strcat_s(path, MAX_PATH, "\\Certificate.dat");

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("CreateFile failed: %lu path=%s", GetLastError(), path);
        return 3;
    }

    DWORD written;
    BOOL ok = WriteFile(hFile, content, (DWORD)strlen(content), &written, NULL);
    CloseHandle(hFile);
    if (!ok || written != (DWORD)strlen(content)) {
        LOGE("cert_write: WriteFile failed: %lu written=%lu", GetLastError(), written);
        return 4;
    }
    return 0;
}

/* Re-sign a single .exe.sig file.  .sig = 64-byte raw ECDSA of SHA-256(exe).
 * Returns 0 on success; failures are logged. */
static int cert_resign_one(const char *exe_path, const char *sig_path,
                           const ec_keypair_t *kp)
{
    BYTE hash[32];
    if (sha256_file(exe_path, hash) != 0) return 1;

    BYTE sig[64];
    if (ec_sign_hash(kp, hash, sig) != 0) { LOGE("resign: ec_sign_hash failed: %s", exe_path); return 2; }

    HANDLE hSig = CreateFileA(sig_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSig == INVALID_HANDLE_VALUE) {
        LOGE("resign: create %s failed: %lu", sig_path, GetLastError());
        return 3;
    }

    DWORD written;
    BOOL ok = WriteFile(hSig, sig, 64, &written, NULL);
    CloseHandle(hSig);
    if (!ok || written != 64) {
        LOGE("resign: write %s failed: %lu", sig_path, GetLastError());
        return 4;
    }
    return 0;
}

/* Does *sig_path* hold the vendor signature for *exe_path*, verified with
 * *trusted_pub*?  Returns 1 (valid), 0 (not this key) or -1 (unreadable). */
static int cert_sig_is_vendor(const char *exe_path, const char *sig_path,
                              const BYTE *trusted_pub)
{
    BYTE hash[32];
    if (sha256_file(exe_path, hash) != 0) return -1;

    BYTE *sig = NULL;
    DWORD sigSize = 0;
    if (!read_file_all(sig_path, &sig, &sigSize, 4096) || sigSize != SIG_SIZE) {
        if (sig) HeapFree(GetProcessHeap(), 0, sig);
        return -1;
    }

    int ok = (ec_verify_pub(trusted_pub, hash, sig) == 0) ? 1 : 0;
    HeapFree(GetProcessHeap(), 0, sig);
    return ok;
}

/* Backup original .sig files.
 *
 * A backup is only useful when it holds the *vendor* signature of the
 * installed executables: "copy once and never look again" kept a stale
 * backup alive across a Sandboxie update, and restoring it afterwards
 * left .exe and .sig mismatched.  So:
 *   - the installed .sig verifies under *trusted_pub* (fresh install or
 *     reinstall/repair): refresh the backup, stale or not;
 *   - it does not: the installed pair is already our re-signed one (or
 *     something else) - keep an existing valid backup, and say loudly
 *     when there is none or when the one we have does not match the
 *     installed executable (only a Sandboxie repair can fix that).
 * The trusted key is a parameter so the policy is testable without the
 * vendor's private key. */
static void cert_backup_sigs_ex(const char *sbie_dir, const char *backup_dir,
                                const BYTE *trusted_pub)
{
    if (!CreateDirectoryA(backup_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        LOGW("sig backup: CreateDirectoryA failed: %lu - originals will be lost on re-sign", GetLastError());
        return;
    }

    char pattern[MAX_PATH];
    strcpy_s(pattern, MAX_PATH, sbie_dir);
    strcat_s(pattern, MAX_PATH, "\\*.exe.sig");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    int refreshed = 0, kept = 0, warned = 0;

    do {
        char src[MAX_PATH], dst[MAX_PATH], exe[MAX_PATH];
        strcpy_s(src, MAX_PATH, sbie_dir);
        strcat_s(src, MAX_PATH, "\\");
        strcat_s(src, MAX_PATH, fd.cFileName);
        strcpy_s(dst, MAX_PATH, backup_dir);
        strcat_s(dst, MAX_PATH, "\\");
        strcat_s(dst, MAX_PATH, fd.cFileName);

        strcpy_s(exe, MAX_PATH, sbie_dir);
        strcat_s(exe, MAX_PATH, "\\");
        size_t nameLen = strlen(fd.cFileName);
        if (nameLen > 4)
            strncat_s(exe, MAX_PATH, fd.cFileName, nameLen - 4);

        int vendor_now = cert_sig_is_vendor(exe, src, trusted_pub);
        BOOL have_backup = (GetFileAttributesA(dst) != INVALID_FILE_ATTRIBUTES);

        if (vendor_now == 1) {
            if (!CopyFileA(src, dst, FALSE)) {
                LOGW("sig backup: refresh failed: %s -> %s err=%lu", src, dst, GetLastError());
                warned++;
            } else {
                refreshed++;
            }
        } else if (!have_backup) {
            if (!CopyFileA(src, dst, FALSE))
                LOGW("sig backup: copy failed: %s -> %s err=%lu", src, dst, GetLastError());
            LOGW("sig backup: %s is not vendor-signed and had no backup - removing the "
                 "hook cannot restore it, repair Sandboxie to refresh", fd.cFileName);
            warned++;
        } else if (cert_sig_is_vendor(exe, dst, trusted_pub) != 1) {
            LOGW("sig backup: %s does not match %s - stale after a Sandboxie update; "
                 "removing the hook would restore a mismatched .sig, repair Sandboxie first",
                 fd.cFileName, fd.cFileName);
            warned++;
        } else {
            kept++;   /* valid vendor backup already in place */
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);

    if (refreshed || kept || warned)
        LOGI("sig backup: refreshed %d, kept %d, warnings %d", refreshed, kept, warned);
}

/* Production policy: the vendor key of this SbieDrv generation. */
static void cert_backup_sigs(const char *sbie_dir, const char *backup_dir)
{
    cert_backup_sigs_ex(sbie_dir, backup_dir, ORIGINAL_KEY);
}

/* Re-sign all .exe.sig files in the Sandboxie directory. */
static int cert_resign_all(const char *sbie_dir, const ec_keypair_t *kp)
{
    char pattern[MAX_PATH];
    strcpy_s(pattern, MAX_PATH, sbie_dir);
    strcat_s(pattern, MAX_PATH, "\\*.exe.sig");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    int count = 0;
    do {
        char sigPath[MAX_PATH], exePath[MAX_PATH];
        strcpy_s(sigPath, MAX_PATH, sbie_dir);
        strcat_s(sigPath, MAX_PATH, "\\");
        strcat_s(sigPath, MAX_PATH, fd.cFileName);

        strcpy_s(exePath, MAX_PATH, sbie_dir);
        strcat_s(exePath, MAX_PATH, "\\");
        size_t nameLen = strlen(fd.cFileName);
        if (nameLen > 4)
            strncat_s(exePath, MAX_PATH, fd.cFileName, nameLen - 4);

        if (GetFileAttributesA(exePath) != INVALID_FILE_ATTRIBUTES) {
            if (cert_resign_one(exePath, sigPath, kp) == 0)
                count++;
            else
                LOGW("resign: FAILED for %s (exe untouched, .sig may be stale)", sigPath);
        } else {
            LOGW("resign: exe missing for %s - skipped", sigPath);
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return count;
}

#endif /* CERTGEN_H */
