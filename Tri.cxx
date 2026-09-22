/* Tri DSL compiler. */
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

static char src[MAXL][LNSZ];
static int sl;
static char asm1[MAXL][LNSZ];
static int asmSrcLine[MAXL];
static int al;
static char *lines2[MAXL];
static int lines2AsmIdx[MAXL];
static int ln2;
static BorrowFrame bstack[MAXS];
static int sp;
static Label labels[MAXLB];
static int nlabels;
static FILE *out;

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

static char *trim(char *s) {
    if (!s || !*s) return s;
    while (*s == ' ' || *s == '\t') ++s;
    char *e = s + strlen(s) - 1;
    while (e >= s && (*e == ' ' || *e == '\t' || *e == '\r' || *e == '\n'))
        *e-- = '\0';
    return s;
}

static void dieSrc(int idx, const char *fmt, ...) {
    if (idx < 0) idx = 0;
    fprintf(stderr, "Error at source line %d: ", idx + 1);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n    %s\n", src[idx]);
    exit(EXIT_FAILURE);
}

static void dieAsm(int aidx, const char *fmt, ...) {
    int sidx = asmSrcLine[lines2AsmIdx[aidx]];
    fprintf(stderr, "Error at source line %d: ", sidx + 1);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n    %s\n", src[sidx]);
    exit(EXIT_FAILURE);
}

static unsigned parseImm(const char *s, int aidx) {
    if (!s || !*s) dieAsm(aidx, "missing immediate");
    if (s[0] == '-') dieAsm(aidx, "negative immediate '%s'", s);

    errno = 0;
    char *end = NULL;
    unsigned long v;
    int base = 10;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) base = 16;
    v = strtoul(s, &end, base);
    if (errno == ERANGE || end == s || *end != '\0' || v > UINT_MAX)
        dieAsm(aidx, "malformed or out-of-range immediate '%s'", s);
    return (unsigned)v;
}

static void read_src(const char *fn) {
    FILE *f = fopen(fn, "r");
    if (!f) die("cannot open source '%s'", fn);

    char buf[LNSZ];
    while (fgets(buf, sizeof buf, f)) {
        if (strlen(buf) == sizeof buf - 1 && buf[sizeof buf - 2] != '\n')
            die("source line is longer than %d characters", LNSZ - 1);
        char *t = trim(buf);
        if (*t && *t != ';') {
            if (sl >= MAXL) die("too many source lines (> %d)", MAXL);
            strcpy(src[sl++], t);
        }
    }
    fclose(f);
}

static void emitAsm(int sourceLine, const char *text) {
    if (al >= MAXL) dieSrc(sourceLine, "asm1 overflow");
    if (strlen(text) >= LNSZ) dieSrc(sourceLine, "generated assembly line is too long");
    asmSrcLine[al] = sourceLine;
    strcpy(asm1[al++], text);
}

static void lower_copy(char *dst, const char *srcText) {
    size_t n = strlen(srcText);
    if (n >= LNSZ) n = LNSZ - 1;
    for (size_t i = 0; i < n; ++i)
        dst[i] = (char)tolower((unsigned char)srcText[i]);
    dst[n] = '\0';
}

static int transform_call(char *line, const char *lower, const char *prefix,
                          const char *opcode) {
    size_t n = strlen(line), p = strlen(prefix);
    if (strncmp(lower, prefix, p) || n < p + 1 || line[n - 1] != ')') return 0;
    char tmp[LNSZ];
    line[n - 1] = '\0';
    int written = snprintf(tmp, sizeof tmp, "%s %s", opcode, line + p);
    if (written < 0 || (size_t)written >= sizeof tmp) return -1;
    strcpy(line, tmp);
    return 1;
}

static uint32_t line_sz(const char *line, int aidx) {
    char tmp[LNSZ];
    strcpy(tmp, line);
    char *save = NULL;
    char *tok = strtok_r(tmp, " \t,", &save);
    if (!tok) return 0;
    if (tok[strlen(tok) - 1] == ':') return 0;
    if (!strcmp(tok, "ORG")) return 0;
    if (!strcmp(tok, "DB")) {
        uint32_t count = 0;
        while (strtok_r(NULL, " \t,", &save)) ++count;
        return count;
    }
    if (!strcmp(tok, "FILL")) {
        char *count = strtok_r(NULL, " \t,", &save);
        return parseImm(count, aidx);
    }
    if (!strcmp(tok, "INT")) return 2;
    if (!strcmp(tok, "JMP") || !strcmp(tok, "CALL")) return 5;
    if (!strcmp(tok, "LJMP")) return 6;
    dieAsm(aidx, "unknown directive '%s'", tok);
    return 0;
}

static void recordLabel(const char *name, uint32_t pc, int aidx) {
    if (!name || !*name || strlen(name) >= sizeof labels[0].name)
        dieAsm(aidx, "label must contain 1 to 15 characters");
    for (int i = 0; i < nlabels; ++i)
        if (!strcmp(labels[i].name, name)) dieAsm(aidx, "duplicate label '%s'", name);
    if (nlabels >= MAXLB) dieAsm(aidx, "too many labels (> %d)", MAXLB);
    strcpy(labels[nlabels].name, name);
    labels[nlabels++].addr = pc;
}

static uint32_t findLabel(const char *name, int aidx) {
    if (!name || !*name) dieAsm(aidx, "missing label");
    for (int i = 0; i < nlabels; ++i)
        if (!strcmp(labels[i].name, name)) return labels[i].addr;
    dieAsm(aidx, "undefined label '%s'", name);
    return 0;
}

static void pass1(void) {
    sp = 0;
    bstack[0].bm = bstack[0].bi = 0;

    for (int i = 0; i < sl; ++i) {
        char line[LNSZ], lower[LNSZ], tmp[LNSZ];
        strcpy(line, src[i]);
        lower_copy(lower, line);

        const char *simple[][2] = {
            {"org(", "ORG"}, {"db(", "DB"}, {"fill(", "FILL"},
            {"int(", "INT"}, {"jmp(", "JMP"}, {"call(", "CALL"}
        };
        int transformed = 0;
        for (size_t k = 0; k < sizeof simple / sizeof simple[0]; ++k) {
            int r = transform_call(line, lower, simple[k][0], simple[k][1]);
            if (r < 0) dieSrc(i, "generated assembly line is too long");
            if (r > 0) { transformed = 1; break; }
        }
        if (!transformed && !strncmp(lower, "ljmp(", 5) &&
            line[strlen(line) - 1] == ')') {
            line[strlen(line) - 1] = '\0';
            char *comma = strchr(line + 5, ',');
            if (!comma) dieSrc(i, "ljmp() needs two arguments");
            *comma = '\0';
            int n = snprintf(tmp, sizeof tmp, "LJMP %s:%s", line + 5, comma + 1);
            if (n < 0 || (size_t)n >= sizeof tmp) dieSrc(i, "generated line is too long");
            strcpy(line, tmp);
            transformed = 1;
        }

        if (!strcmp(line, "{")) {
            if (sp + 1 >= MAXS) dieSrc(i, "scope overflow");
            ++sp; bstack[sp].bm = bstack[sp].bi = 0; continue;
        }
        if (!strcmp(line, "}")) {
            if (!sp) dieSrc(i, "unmatched scope close");
            --sp; continue;
        }
        if (!strncmp(line, "let &mut", 8)) {
            if (bstack[sp].bm || bstack[sp].bi) dieSrc(i, "borrow error");
            bstack[sp].bm = 1; continue;
        }
        if (!strncmp(line, "let &", 5)) {
            if (bstack[sp].bm) dieSrc(i, "borrow error");
            bstack[sp].bi = 1; continue;
        }

        if (!strcmp(line, "tape_start()")) {
            emitAsm(i, "ORG 0x500"); emitAsm(i, "DB 0xBE,0x00,0x05"); continue;
        }
        if (!strcmp(line, "load()")) { emitAsm(i, "DB 0x8A,0x04"); continue; }
        if (!strcmp(line, "store()")) { emitAsm(i, "DB 0x88,0x04"); continue; }
        if (!strncmp(line, "head +=", 7)) {
            char *end = NULL;
            errno = 0;
            long v = strtol(line + 7, &end, 0);
            if (errno || end == line + 7 || *trim(end) || v < 0 || v > 255)
                dieSrc(i, "head offset must be an integer from 0 to 255");
            snprintf(tmp, sizeof tmp, "DB 0x83,0xC6,%ld", v);
            emitAsm(i, tmp); continue;
        }

        if (!strncmp(lower, "fold_mode(", 10) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0';
            emitAsm(i, "INT 0x01");
            snprintf(tmp, sizeof tmp, "DB %s", line + 10); emitAsm(i, tmp); continue;
        }
        if (!strncmp(lower, "power_gate(", 11) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0'; char *c = strchr(line + 11, ',');
            if (!c) dieSrc(i, "power_gate(unit,op) needs two arguments");
            *c = '\0'; emitAsm(i, "INT 0x02");
            snprintf(tmp, sizeof tmp, "DB %s,%s", line + 11, trim(c + 1)); emitAsm(i, tmp); continue;
        }
        if (!strncmp(lower, "bist_start(", 11) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0'; emitAsm(i, "INT 0x10");
            snprintf(tmp, sizeof tmp, "DB %s", line + 11); emitAsm(i, tmp); continue;
        }
        if (!strncmp(lower, "smt_weight(", 11) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0'; char *c = strchr(line + 11, ',');
            if (!c) dieSrc(i, "smt_weight(t,w) needs two arguments");
            *c = '\0'; emitAsm(i, "INT 0x20");
            snprintf(tmp, sizeof tmp, "DB %s,%s", line + 11, trim(c + 1)); emitAsm(i, tmp); continue;
        }
        if (!strncmp(lower, "mme(", 4) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0'; emitAsm(i, "INT 0x30");
            snprintf(tmp, sizeof tmp, "DB %s", line + 4); emitAsm(i, tmp); continue;
        }
        if (!strncmp(lower, "patch_bank(", 11) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0'; char *c = strchr(line + 11, ',');
            if (!c) dieSrc(i, "patch_bank(bank,flags) needs two arguments");
            *c = '\0'; emitAsm(i, "INT 0x03");
            snprintf(tmp, sizeof tmp, "DB %s,%s", line + 11, trim(c + 1)); emitAsm(i, tmp); continue;
        }
        if (!strncmp(lower, "patch_commit(", 13) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0'; emitAsm(i, "INT 0x04");
            snprintf(tmp, sizeof tmp, "DB %s", line + 13); emitAsm(i, tmp); continue;
        }
        if (!strncmp(lower, "perf_sample(", 12) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0'; emitAsm(i, "INT 0x40");
            snprintf(tmp, sizeof tmp, "DB %s", line + 12); emitAsm(i, tmp); continue;
        }
        if (!strncmp(lower, "link_config(", 12) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0'; emitAsm(i, "INT 0x50");
            snprintf(tmp, sizeof tmp, "DB %s", line + 12); emitAsm(i, tmp); continue;
        }
        if (!strncmp(lower, "org_set(", 8) && line[strlen(line)-1] == ')') {
            line[strlen(line)-1] = '\0'; emitAsm(i, "INT 0x05");
            snprintf(tmp, sizeof tmp, "DB %s", line + 8); emitAsm(i, tmp); continue;
        }
        emitAsm(i, line);
    }
    if (sp) dieSrc(sl ? sl - 1 : 0, "unclosed scope(s)");
}

static void asm_passA(void) {
    for (int i = 0; i < al; ++i) {
        if (ln2 >= MAXL) dieAsm(i, "lines2 overflow");
        lines2[ln2] = static_cast<char *>(malloc(LNSZ));
        if (!lines2[ln2]) dieAsm(i, "out of memory");
        strcpy(lines2[ln2], asm1[i]);
        lines2AsmIdx[ln2++] = i;
    }

    uint32_t pc = 0;
    for (int i = 0; i < ln2; ++i) {
        char tmp[LNSZ]; strcpy(tmp, trim(lines2[i]));
        char *save = NULL, *tok = strtok_r(tmp, " \t,", &save);
        if (!tok) continue;
        if (tok[strlen(tok) - 1] == ':') {
            tok[strlen(tok) - 1] = '\0';
            recordLabel(tok, pc, i);
        } else if (!strcmp(tok, "ORG")) {
            pc = parseImm(strtok_r(NULL, " \t,", &save), i);
        } else {
            pc += line_sz(lines2[i], i);
        }
    }
}

static void e8(uint8_t b) { fputc(b, out); }
static void e16(uint16_t w) { e8((uint8_t)w); e8((uint8_t)(w >> 8)); }
static void e32(uint32_t w) { e16((uint16_t)w); e16((uint16_t)(w >> 16)); }

static void asm_passB(void) {
    out = fopen("out.bin", "wb");
    if (!out) die("cannot create output file");
    uint32_t pc = 0;

    for (int i = 0; i < ln2; ++i) {
        char tmp[LNSZ]; strcpy(tmp, lines2[i]);
        char *save = NULL, *tok = strtok_r(tmp, " \t,", &save);
        if (!tok) { free(lines2[i]); continue; }

        if (!strcmp(tok, "ORG")) {
            pc = parseImm(strtok_r(NULL, " \t,", &save), i);
            if (fseek(out, (long)pc, SEEK_SET) != 0) dieAsm(i, "invalid ORG address");
        } else if (!strcmp(tok, "DB")) {
            char *v;
            while ((v = strtok_r(NULL, " \t,", &save))) {
                unsigned b = parseImm(v, i);
                if (b > 255) dieAsm(i, "DB byte out of range: %u", b);
                e8((uint8_t)b); ++pc;
            }
        } else if (!strcmp(tok, "FILL")) {
            unsigned count = parseImm(strtok_r(NULL, " \t,", &save), i);
            unsigned value = parseImm(strtok_r(NULL, " \t,", &save), i);
            if (value > 255) dieAsm(i, "FILL byte out of range: %u", value);
            for (unsigned j = 0; j < count; ++j) e8((uint8_t)value);
            pc += count;
        } else if (!strcmp(tok, "INT")) {
            unsigned imm = parseImm(strtok_r(NULL, " \t,", &save), i);
            if (imm > 255) dieAsm(i, "INT immediate out of range: %u", imm);
            e8(0xCD); e8((uint8_t)imm); pc += 2;
        } else if (!strcmp(tok, "JMP") || !strcmp(tok, "CALL")) {
            uint32_t dest = findLabel(strtok_r(NULL, " \t,", &save), i);
            int32_t rel = (int32_t)dest - (int32_t)(pc + 5);
            e8(!strcmp(tok, "JMP") ? 0xE9 : 0xE8); e32((uint32_t)rel); pc += 5;
        } else if (!strcmp(tok, "LJMP")) {
            char *p = strtok_r(NULL, " \t,", &save);
            if (!p) dieAsm(i, "LJMP needs offset:segment");
            char *colon = strchr(p, ':');
            if (!colon) dieAsm(i, "LJMP needs offset:segment");
            *colon++ = '\0';
            unsigned off = parseImm(p, i), seg = parseImm(colon, i);
            e8(0xEA); e32(off); e16((uint16_t)seg); pc += 6;
        } else if (tok[strlen(tok) - 1] != ':') {
            dieAsm(i, "unknown directive '%s'", tok);
        }
        free(lines2[i]);
    }
    fclose(out);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <source.asm>\n", argv[0]);
        return EXIT_FAILURE;
    }
    read_src(argv[1]);
    pass1();
    asm_passA();
    asm_passB();
    return EXIT_SUCCESS;
}
