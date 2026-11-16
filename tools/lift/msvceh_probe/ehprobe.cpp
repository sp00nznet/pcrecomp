// Every MSVC exception shape a lift has to survive; prints one line each.
#include <windows.h>
#include <stdio.h>

struct Tracker { const char* n; Tracker(const char* s) : n(s) {} ~Tracker() { printf("  ~%s\n", n); } };
struct Err { int code; };

__declspec(noinline) void thrower(int v) { Tracker t("thrower"); if (v) throw Err{ v }; }
__declspec(noinline) int fpo_catch(int v) {        // /O2: frame pointer omitted
    try { thrower(v); } catch (const Err& e) { return e.code + 1; }
    return 0;
}
__declspec(noinline) int nested(int v) {
    Tracker t("nested");
    try { try { thrower(v); } catch (int) { return -1; } } catch (Err& e) { return e.code * 10; }
    return 0;
}
__declspec(noinline) int rethrow(int v) {
    try { try { thrower(v); } catch (...) { throw; } } catch (Err& e) { return e.code + 100; }
    return 0;
}
__declspec(noinline) int seh_raise(DWORD code) {
    __try { RaiseException(code, 0, 0, NULL); return 0; } __except (EXCEPTION_EXECUTE_HANDLER) { return (int)(GetExceptionCode() & 0xFF); }
}
static int g_fin;
__declspec(noinline) void seh_finally_inner(DWORD code) { __try { RaiseException(code, 0, 0, NULL); } __finally { g_fin++; } }
__declspec(noinline) int seh_finally(DWORD code) {
    __try { seh_finally_inner(code); } __except (EXCEPTION_EXECUTE_HANDLER) { return g_fin; }
    return -1;
}

static volatile int g_one = 1;
int main() {
    int argc = g_one;   /* not the real argc: a host may pass its own arguments */
    int pass = 0, n = 0;
#define T(name, expr, want) do { int r_ = (expr); n++; pass += r_ == (want); \
    printf("%s %s = %d (want %d)\n", r_ == (want) ? "PASS" : "FAIL", name, r_, want); } while (0)
    T("fpo_catch", fpo_catch(argc + 4), 6);
    T("nested", nested(argc + 1), 20);
    T("rethrow", rethrow(argc), 101);
    T("seh_raise", seh_raise(0xE0000042), 0x42);
    T("seh_finally", seh_finally(0xE0000043), 1);
    printf("%d/%d\n", pass, n);
    return pass == n ? 0 : 1;
}
