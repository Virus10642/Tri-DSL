/* Tri DSL compiler */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define MAXL 512
#define LNSZ 80
#define MAXLB 128
#define MAXS 16

typedef struct { char name[16]; uint32_t addr; } Label;
typedef struct { int bm, bi; } BorrowFrame;
static char src[MAXL][LNSZ], asm1[MAXL][LNSZ];
static int sl, al, asmSrcLine[MAXL];
static char *lines2[MAXL];
static int lines2AsmIdx[MAXL], ln2;
static BorrowFrame bstack[MAXS];
static int sp;
static Label labels[MAXLB];
static int nlabels;
static FILE *out;

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr); exit(EXIT_FAILURE);
}
static char *trim(char *s) {
    if (!s || !*s) return s;
    while (*s == ' ' || *s == '\t') ++s;
    char *e = s + strlen(s) - 1;
    while (e >= s && (*e == ' ' || *e == '\t' || *e == '\r' || *e == '\n')) *e-- = 0;
    return s;
}
static void dieSrc(int idx, const char *fmt, ...) {
    if (idx < 0) idx = 0;
    fprintf(stderr, "Error at source line %d: ", idx + 1);
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fprintf(stderr, "\n    %s\n", src[idx]); exit(EXIT_FAILURE);
}
static void dieAsm(int aidx, const char *fmt, ...) {
    int sidx = asmSrcLine[lines2AsmIdx[aidx]];
    fprintf(stderr, "Error at source line %d: ", sidx + 1);
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fprintf(stderr, "\n    %s\n", src[sidx]); exit(EXIT_FAILURE);
}
static void lowerCopy(char *dst, const char *s) {
    size_t n = strlen(s); if (n >= LNSZ) n = LNSZ - 1;
    for (size_t i = 0; i < n; ++i) dst[i] = (char)tolower((unsigned char)s[i]);
    dst[n] = 0;
}
static void formatAsm(int line, char *dst, size_t size, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); int n = vsnprintf(dst, size, fmt, ap); va_end(ap);
    if (n < 0 || (size_t)n >= size) dieSrc(line, "generated assembly line is too long");
}
static void emitAsm(int line, const char *text) {
    if (strlen(text) >= LNSZ) dieSrc(line, "generated assembly line is too long");
    if (al >= MAXL) dieSrc(line, "asm1 overflow");
    asmSrcLine[al] = line; strcpy(asm1[al++], text);
}
static unsigned parseImm(const char *s, int aidx) {
    if (!s || !*s || s[0] == '-') dieAsm(aidx, "invalid immediate '%s'", s ? s : "");
    errno = 0; char *end = NULL; int base = 10;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) base = 16;
    unsigned long v = strtoul(s, &end, base);
    if (errno == ERANGE || end == s || *end || v > UINT_MAX)
        dieAsm(aidx, "malformed or out-of-range immediate '%s'", s);
    return (unsigned)v;
}
static void readSrc(const char *fn) {
    FILE *f = fopen(fn, "r"); if (!f) die("cannot open source '%s'", fn);
    char buf[LNSZ];
    while (fgets(buf, sizeof buf, f)) {
        if (strlen(buf) == sizeof buf - 1 && buf[sizeof buf - 2] != '\n')
            die("source line is longer than %d characters", LNSZ - 1);
        char *t = trim(buf);
        if (*t && *t != ';') { if (sl >= MAXL) die("too many source lines (> %d)", MAXL); strcpy(src[sl++], t); }
    }
    fclose(f);
}
static void requireEnd(char **save, int i, const char *what) {
    if (strtok_r(NULL, " \t,", save)) dieAsm(i, "%s has too many arguments", what);
}
static uint32_t lineSize(const char *line, int i) {
    char tmp[LNSZ]; strcpy(tmp, line); char *save = NULL, *tok = strtok_r(tmp, " \t,", &save);
    if (!tok) return 0;
    if (tok[strlen(tok)-1] == ':') return 0;
    if (!strcmp(tok, "ORG")) { parseImm(strtok_r(NULL, " \t,", &save), i); requireEnd(&save, i, "ORG"); return 0; }
    if (!strcmp(tok, "DB")) { uint32_t n = 0; while (strtok_r(NULL, " \t,", &save)) ++n; if (!n) dieAsm(i, "DB needs at least one byte"); return n; }
    if (!strcmp(tok, "FILL")) { char *n = strtok_r(NULL, " \t,", &save), *v = strtok_r(NULL, " \t,", &save); unsigned count = parseImm(n, i); parseImm(v, i); requireEnd(&save, i, "FILL"); return count; }
    if (!strcmp(tok, "INT")) { parseImm(strtok_r(NULL, " \t,", &save), i); requireEnd(&save, i, "INT"); return 2; }
    if (!strcmp(tok, "JMP") || !strcmp(tok, "CALL")) { if (!strtok_r(NULL, " \t,", &save)) dieAsm(i, "%s needs a label", tok); requireEnd(&save, i, tok); return 5; }
    if (!strcmp(tok, "LJMP")) { char *p = strtok_r(NULL, " \t,", &save); if (!p || !strchr(p, ':')) dieAsm(i, "LJMP needs offset:segment"); requireEnd(&save, i, "LJMP"); return 6; }
    dieAsm(i, "unknown directive '%s'", tok); return 0;
}
static void recordLabel(const char *name, uint32_t pc, int i) {
    if (!name || !*name || strlen(name) >= sizeof labels[0].name) dieAsm(i, "label must contain 1 to 15 characters");
    for (int n = 0; n < nlabels; ++n) if (!strcmp(labels[n].name, name)) dieAsm(i, "duplicate label '%s'", name);
    if (nlabels >= MAXLB) dieAsm(i, "too many labels (> %d)", MAXLB);
    strcpy(labels[nlabels].name, name); labels[nlabels++].addr = pc;
}
static uint32_t findLabel(const char *name, int i) {
    if (!name || !*name) dieAsm(i, "missing label");
    for (int n = 0; n < nlabels; ++n) if (!strcmp(labels[n].name, name)) return labels[n].addr;
    dieAsm(i, "undefined label '%s'", name); return 0;
}
static int simpleCall(char *line, const char *lower, const char *prefix, const char *op, int i) {
    size_t p = strlen(prefix), n = strlen(line);
    if (strncmp(lower, prefix, p) || n < p + 1 || line[n-1] != ')') return 0;
    line[n-1] = 0; if (!line[p]) dieSrc(i, "%s needs an argument", op);
    char tmp[LNSZ]; formatAsm(i, tmp, sizeof tmp, "%s %s", op, line + p); strcpy(line, tmp); return 1;
}
static void pass1(void) {
    sp = 0; bstack[0].bm = bstack[0].bi = 0;
    for (int i = 0; i < sl; ++i) {
        char line[LNSZ], lower[LNSZ], tmp[LNSZ]; strcpy(line, src[i]); lowerCopy(lower, line);
        const char *prefixes[][2] = {{"org(","ORG"},{"db(","DB"},{"fill(","FILL"},{"int(","INT"},{"jmp(","JMP"},{"call(","CALL"}};
        int converted = 0;
        for (size_t k = 0; k < sizeof prefixes / sizeof prefixes[0]; ++k) if (simpleCall(line, lower, prefixes[k][0], prefixes[k][1], i)) { converted = 1; break; }
        if (!converted && !strncmp(lower, "ljmp(", 5) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = 0; char *c = strchr(line + 5, ','); if (!c) dieSrc(i, "ljmp() needs two arguments");
            *c = 0; if (!*trim(line + 5) || !*trim(c + 1)) dieSrc(i, "ljmp() needs two arguments");
            formatAsm(i, tmp, sizeof tmp, "LJMP %s:%s", trim(line + 5), trim(c + 1)); strcpy(line, tmp); converted = 1;
        }
        if (!strcmp(lower, "{") ) { if (sp + 1 >= MAXS) dieSrc(i, "scope overflow"); ++sp; bstack[sp].bm = bstack[sp].bi = 0; continue; }
        if (!strcmp(lower, "}")) { if (!sp) dieSrc(i, "unmatched scope close"); --sp; continue; }
        if (!strncmp(lower, "let &mut", 8)) { if (bstack[sp].bm || bstack[sp].bi) dieSrc(i, "borrow error"); bstack[sp].bm = 1; continue; }
        if (!strncmp(lower, "let &", 5)) { if (bstack[sp].bm) dieSrc(i, "borrow error"); bstack[sp].bi = 1; continue; }
        if (!strcmp(lower, "tape_start()")) { emitAsm(i, "ORG 0x500"); emitAsm(i, "DB 0xBE,0x00,0x05"); continue; }
        if (!strcmp(lower, "load()")) { emitAsm(i, "DB 0x8A,0x04"); continue; }
        if (!strcmp(lower, "store()")) { emitAsm(i, "DB 0x88,0x04"); continue; }
        if (!strncmp(lower, "head +=", 7)) {
            char *end; errno = 0; long v = strtol(lower + 7, &end, 0);
            if (errno || end == lower + 7 || *trim(end) || v < 0 || v > 255) dieSrc(i, "head offset must be an integer from 0 to 255");
            formatAsm(i, tmp, sizeof tmp, "DB 0x83,0xC6,%ld", v); emitAsm(i, tmp); continue;
        }
        struct { const char *name; const char *intop; } special[] = {{"fold_mode(","0x01"},{"bist_start(","0x10"},{"mme(","0x30"},{"patch_commit(","0x04"},{"perf_sample(","0x40"},{"link_config(","0x50"},{"org_set(","0x05"}};
        int handled = 0;
        for (size_t k = 0; k < sizeof special / sizeof special[0]; ++k) if (!strncmp(lower, special[k].name, strlen(special[k].name)) && line[strlen(line)-1] == ')') {
            size_t p = strlen(special[k].name); line[strlen(line)-1] = 0; if (!*trim(line + p)) dieSrc(i, "%s needs arguments", special[k].name);
            formatAsm(i, tmp, sizeof tmp, "INT %s", special[k].intop); emitAsm(i, tmp); formatAsm(i, tmp, sizeof tmp, "DB %s", line + p); emitAsm(i, tmp); handled = 1; break;
        }
        if (handled) continue;
        struct { const char *name; const char *intop; } pairs[] = {{"power_gate(","0x02"},{"smt_weight(","0x20"},{"patch_bank(","0x03"}};
        for (size_t k = 0; k < sizeof pairs / sizeof pairs[0]; ++k) if (!strncmp(lower, pairs[k].name, strlen(pairs[k].name)) && line[strlen(line)-1] == ')') {
            size_t p = strlen(pairs[k].name); line[strlen(line)-1] = 0; char *c = strchr(line + p, ','); if (!c || !*trim(line + p) || !*trim(c + 1)) dieSrc(i, "%s needs two arguments", pairs[k].name);
            *c = 0; formatAsm(i, tmp, sizeof tmp, "INT %s", pairs[k].intop); emitAsm(i, tmp); formatAsm(i, tmp, sizeof tmp, "DB %s,%s", trim(line + p), trim(c + 1)); emitAsm(i, tmp); handled = 1; break;
        }
        if (handled) continue;
        emitAsm(i, line);
    }
    if (sp) dieSrc(sl ? sl - 1 : 0, "unclosed scope(s)");
}
static void asmPassA(void) {
    for (int i = 0; i < al; ++i) {
        if (ln2 >= MAXL) dieAsm(i, "lines2 overflow");
        lines2[ln2] = (char *)malloc(LNSZ); if (!lines2[ln2]) dieAsm(i, "out of memory");
        strcpy(lines2[ln2], asm1[i]); lines2AsmIdx[ln2++] = i;
    }
    uint32_t pc = 0;
    for (int i = 0; i < ln2; ++i) {
        char tmp[LNSZ]; strcpy(tmp, trim(lines2[i])); char *save = NULL, *tok = strtok_r(tmp, " \t,", &save); if (!tok) continue;
        if (tok[strlen(tok)-1] == ':') { tok[strlen(tok)-1] = 0; recordLabel(tok, pc, i); }
        else if (!strcmp(tok, "ORG")) pc = parseImm(strtok_r(NULL, " \t,", &save), i);
        else pc += lineSize(lines2[i], i);
    }
}
static void e8(uint8_t b) { fputc(b, out); }
static void e16(uint16_t w) { e8((uint8_t)w); e8((uint8_t)(w >> 8)); }
static void e32(uint32_t w) { e16((uint16_t)w); e16((uint16_t)(w >> 16)); }
static void asmPassB(void) {
    out = fopen("out.bin", "wb"); if (!out) die("cannot create output file"); uint32_t pc = 0;
    for (int i = 0; i < ln2; ++i) {
        char tmp[LNSZ]; strcpy(tmp, lines2[i]); char *save = NULL, *tok = strtok_r(tmp, " \t,", &save); if (!tok) { free(lines2[i]); continue; }
        if (!strcmp(tok, "ORG")) { pc = parseImm(strtok_r(NULL, " \t,", &save), i); requireEnd(&save, i, "ORG"); if (fseek(out, (long)pc, SEEK_SET)) dieAsm(i, "invalid ORG address"); }
        else if (!strcmp(tok, "DB")) { char *v; int count = 0; while ((v = strtok_r(NULL, " \t,", &save))) { unsigned b = parseImm(v, i); if (b > 255) dieAsm(i, "DB byte out of range: %u", b); e8((uint8_t)b); ++pc; ++count; } if (!count) dieAsm(i, "DB needs at least one byte"); }
        else if (!strcmp(tok, "FILL")) { unsigned count = parseImm(strtok_r(NULL, " \t,", &save), i), value = parseImm(strtok_r(NULL, " \t,", &save), i); requireEnd(&save, i, "FILL"); if (value > 255) dieAsm(i, "FILL byte out of range: %u", value); for (unsigned j = 0; j < count; ++j) e8((uint8_t)value); pc += count; }
        else if (!strcmp(tok, "INT")) { unsigned imm = parseImm(strtok_r(NULL, " \t,", &save), i); requireEnd(&save, i, "INT"); if (imm > 255) dieAsm(i, "INT immediate out of range: %u", imm); e8(0xCD); e8((uint8_t)imm); pc += 2; }
        else if (!strcmp(tok, "JMP") || !strcmp(tok, "CALL")) { uint32_t dest = findLabel(strtok_r(NULL, " \t,", &save), i); requireEnd(&save, i, tok); int64_t rel = (int64_t)dest - ((int64_t)pc + 5); if (rel < INT32_MIN || rel > INT32_MAX) dieAsm(i, "relative jump is out of range"); e8(!strcmp(tok, "JMP") ? 0xE9 : 0xE8); e32((uint32_t)(int32_t)rel); pc += 5; }
        else if (!strcmp(tok, "LJMP")) { char *p = strtok_r(NULL, " \t,", &save); if (!p) dieAsm(i, "LJMP needs offset:segment"); char *c = strchr(p, ':'); if (!c) dieAsm(i, "LJMP needs offset:segment"); *c++ = 0; unsigned off = parseImm(p, i), seg = parseImm(c, i); requireEnd(&save, i, "LJMP"); if (seg > UINT16_MAX || off > UINT32_MAX) dieAsm(i, "LJMP operand out of range"); e8(0xEA); e32(off); e16((uint16_t)seg); pc += 6; }
        else if (tok[strlen(tok)-1] != ':') dieAsm(i, "unknown directive '%s'", tok);
        free(lines2[i]);
    }
    fclose(out);
}
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "Usage: %s <source.asm>\n", argv[0]); return EXIT_FAILURE; }
    readSrc(argv[1]); pass1(); asmPassA(); asmPassB(); return EXIT_SUCCESS;
}
