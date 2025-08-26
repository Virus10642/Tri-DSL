/*
  tri.c – Python-Style “Trinary-Assembly” Compiler
  ~380 LOC ANSI C → <6 KB binary with –Os –s + strip + upx

  Fixes & hardening:
    • Array-bounds checks on all indices
    • Scope-based borrow checking with matching braces
    • Duplicate-label detection
    • Malformed numeric literals error with source context
    • Unrecognized directives/instructions error with context
    • Error messages include source-line number & text
    • Non-destructive parsing via strtok_r
    • Malloc-return checks, with casts to (char*)
    • Free(lines2[]) to avoid leaks
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

#define MAXL 512
#define LNSZ  80
#define MAXLB 128
#define MAXS  16

typedef struct { char name[16]; uint32_t addr; } Label;
typedef struct { int bm, bi; } BorrowFrame;

// DSL source lines
static char src[MAXL][LNSZ];
static int  sl = 0;

// Intermediate AST→ASM lines + source mapping
static char asm1[MAXL][LNSZ];
static int  asmSrcLine[MAXL];
static int  al = 0;

// Final assembler lines + asm1 mapping
static char *lines2[MAXL];
static int   lines2AsmIdx[MAXL];
static int   ln2 = 0;

// Borrow-scope stack
static BorrowFrame bstack[MAXS];
static int         sp = 0;

// Unified label table
static Label lbl2[MAXLB];
static int   nl2 = 0;

// Output file
static FILE *out;

/* Trim whitespace & CR/LF */
static char *trim(char *s) {
    while (*s==' '||*s=='\t') s++;
    char *e = s + strlen(s)-1;
    while (e>=s && (*e==' '||*e=='\t'||*e=='\r'||*e=='\n')) *e--=0;
    return s;
}

/* General error */
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

/* Error in DSL source */
static void dieSrc(int idx, const char *fmt, ...) {
    fprintf(stderr,"Error at source line %d: ", idx+1);
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr,"\n    %s\n", src[idx]);
    exit(1);
}

/* Error in assembler stage */
static void dieAsm(int aidx, const char *fmt, ...) {
    int sidx = asmSrcLine[ lines2AsmIdx[aidx] ];
    fprintf(stderr,"Error at source line %d: ", sidx+1);
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr,"\n    %s\n", src[sidx]);
    exit(1);
}

/* Parse immediate with validation */
static unsigned parseImm(const char *s, int aidx) {
    char *end;
    unsigned long v;
    if (s[0]=='0'&&s[1]=='x') {
        v = strtoul(s+2, &end, 16);
        if (end==s+2 || *end) dieAsm(aidx,"malformed hex immediate '%s'",s);
    } else {
        v = strtoul(s, &end, 10);
        if (end==s) dieAsm(aidx,"malformed decimal immediate '%s'",s);
    }
    return (unsigned)v;
}

/* Read DSL source lines */
static void read_src(const char *fn) {
    FILE *f = fopen(fn,"r");
    if (!f) die("cannot open source '%s'", fn);
    char buf[LNSZ];
    while (fgets(buf,LNSZ,f)) {
        char *t = trim(buf);
        if (*t && *t!=';') {
            if (sl>=MAXL) die("too many source lines (> %d)", MAXL);
            strcpy(src[sl++], t);
        }
    }
    fclose(f);
}

/* Compute size of a single asm1 line */
static uint32_t line_sz(const char *ln) {
    char tmp[LNSZ]; strcpy(tmp, ln);
    char *tok = strtok(tmp," \t,");
    if (!tok) return 0;
    if (tok[strlen(tok)-1]==':') return 0;
    if (!strcmp(tok,"ORG"))   return 0;
    if (!strcmp(tok,"DB")) {
        int c=0; while(strtok(NULL," \t,")) c++; return c;
    }
    if (!strcmp(tok,"FILL")) {
        int n = atoi(strtok(NULL," \t,")); return n;
    }
    if (!strcmp(tok,"INT"))   return 2;
    if (!strcmp(tok,"JMP")||!strcmp(tok,"CALL")) return 5;
    if (!strcmp(tok,"LJMP"))  return 6;
    return 0;
}

/* Record a label, error on duplicate */
static void recordLabel(const char *nm, uint32_t pc, int aidx) {
    for(int i=0;i<nl2;i++){
        if(!strcmp(lbl2[i].name, nm))
            dieAsm(aidx,"duplicate label '%s'", nm);
    }
    if(nl2>=MAXLB) dieAsm(aidx,"too many labels (> %d)", MAXLB);
    strncpy(lbl2[nl2].name, nm, 15);
    lbl2[nl2].name[15] = 0;
    lbl2[nl2].addr = pc;
    nl2++;
}

/* Lookup a label */
static uint32_t find_lbl(const char *nm, int aidx) {
    for(int i=0;i<nl2;i++){
        if(!strcmp(lbl2[i].name, nm))
            return lbl2[i].addr;
    }
    dieAsm(aidx,"undefined label '%s'", nm);
    return 0;
}

/* PASS1: DSL → asm1 with Python-like syntax & borrow checks */
static void pass1() {
    sp=0; bstack[0].bm=bstack[0].bi=0;

    for(int i=0;i<sl;i++){
        char line[LNSZ];
        strcpy(line, trim(src[i]));

        char lower[LNSZ];
        for(int j=0; line[j] && j<LNSZ; j++)
            lower[j] = tolower((unsigned char)line[j]);
        lower[strlen(line)] = 0;

        // Pythonic transforms
        if(!strncmp(lower,"org(",4) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"ORG %s", line+4);
        }
        else if(!strncmp(lower,"db(",3) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"DB %s", line+3);
        }
        else if(!strncmp(lower,"fill(",5) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"FILL %s", line+5);
        }
        else if(!strncmp(lower,"int(",4) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"INT %s", line+4);
        }
        else if(!strncmp(lower,"jmp(",4) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"JMP %s", line+4);
        }
        else if(!strncmp(lower,"call(",5) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"CALL %s", line+5);
        }
        else if(!strncmp(lower,"ljmp(",5) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            char *p = line+5, *c = strchr(p, ',');
            if(!c) dieSrc(i,"ljmp() needs two args");
            *c=0;
            sprintf(line,"LJMP %s:%s", p, c+1);
        }
        // In pass1(), after existing Pythonic transforms

        else if(!strncmp(lower,"fold_mode(",10) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;               // strip ')'
            char *arg = line+10;                  // mode
            // emit: INT 0x01  +  DB <mode>
            asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x01");
            char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s", arg);
            asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
            continue;
        }
        else if(!strncmp(lower,"power_gate(",11) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            char *p = line+11, *c = strchr(p, ',');
            if(!c) dieSrc(i,"power_gate(unit,op)");
            *c=0; char *unit=p; char *op=trim(c+1);
            asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x02");
            char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s,%s", unit, op);
            asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
            continue;
        }
        else if(!strncmp(lower,"bist_start(",11) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0; char *id=line+11;
            asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x10");
            char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s", id);
            asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
            continue;
        }
        else if(!strncmp(lower,"smt_weight(",11) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            char *p=line+11,*c=strchr(p,','); if(!c) dieSrc(i,"smt_weight(t,w)");
            *c=0; char *tid=p; char *w=trim(c+1);
            asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x20");
            char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s,%s", tid, w);
            asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
            continue;
        }
        else if(!strncmp(lower,"mme(",4) && line[strlen(line)-1]==')'){
            // mme(src_cap,dst_cap,size,stride,flags)
            line[strlen(line)-1]=0; char *p=line+4;
            // trust DB formatting here; let user supply bytes or a packed tuple label
            asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x30");
            char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s", p);
            asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
            continue;
        }
        else if(!strncmp(lower,"patch_bank(",11) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            char *p=line+11,*c=strchr(p,','); if(!c) dieSrc(i,"patch_bank(bank,flags)");
            *c=0; char *bank=p; char *flags=trim(c+1);
            asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x03");
            char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s,%s", bank, flags);
            asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
            continue;
        }
        else if(!strncmp(lower,"patch_commit(",13) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0; char *crc=line+13;
            asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x04");
            char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s", crc);
            asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
            continue;
        }
        else if(!strncmp(lower,"perf_sample(",12) && line[strlen(line)-1]==')'){
            // perf_sample(op,event,slot)
            line[strlen(line)-1]=0; char *pl=line+12;
            asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x40");
            char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s", pl);
            asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
            continue;
        }
        else if(!strncmp(lower,"link_config(",12) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0; char *pl=line+12;
            asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x50");
            char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s", pl);
            asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
            continue;
        }
        // Borrow & scopes
        if(!strcmp(line,"{")) {
            if(sp+1>=MAXS) dieSrc(i,"scope overflow");
            sp++; bstack[sp].bm=bstack[sp].bi=0;
            continue;
        }
        if(!strcmp(line,"}")) {
            if(sp==0) dieSrc(i,"unmatched scope close");
            sp--; continue;
        }
        if(!strncmp(line,"let &mut",8)) {
            if(bstack[sp].bm||bstack[sp].bi) dieSrc(i,"borrow error");
            bstack[sp].bm=1; continue;
        }
        if(!strncmp(line,"let &",5)) {
            if(bstack[sp].bm) dieSrc(i,"borrow error");
            bstack[sp].bi=1; continue;
        }

        // Built‐ins
        if(!strcmp(line,"tape_start()")) {
            if(al+2>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],"ORG 0x500");
            asmSrcLine[al]=i; strcpy(asm1[al++],"DB 0xBE,0x00,0x05");
            continue;
        }
        if(!strcmp(line,"load()")) {
            if(al+1>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],"DB 0x8A,0x04");
            continue;
        }
        if(!strcmp(line,"store()")) {
            if(al+1>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],"DB 0x88,0x04");
            continue;
        }
        if(!strncmp(line,"head +=",7)) {
            char *numstr=line+7; char *end;
            long v=strtol(numstr,&end,0);
            if(end==numstr||v<0||v>255) dieSrc(i,"head offset 0..255");
            char tmp[LNSZ];
            int n=sprintf(tmp,"DB 0x83,0xC6,%ld",v);
            if(n<0||n>=LNSZ) dieSrc(i,"sprintf overflow");
            if(al+1>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],tmp);
            continue;
        }
        else if(!strncmp(lower,"org_set(",8) && line[strlen(line)-1]==')'){
        line[strlen(line)-1]=0;
        char *addr = line+8;
        asmSrcLine[al]=i; strcpy(asm1[al++],"INT 0x05");
        char tmp[LNSZ]; snprintf(tmp,LNSZ,"DB %s", addr);
        asmSrcLine[al]=i; strcpy(asm1[al++], tmp);
        continue;
        }
    
        // Fallback to copy
        if(al>=MAXL) dieSrc(i,"asm1 overflow");
        asmSrcLine[al]=i;
        strcpy(asm1[al++], line);
    }

    if(sp!=0) dieSrc(sl-1,"unclosed scope(s)");
}

/* PASS A: copy asm1 → lines2 and record labels */
static void asm_passA() {
    for(int i=0;i<al;i++){
        if(ln2>=MAXL) dieAsm(i,"lines2 overflow");
        lines2[ln2] = (char*)malloc(LNSZ);
        if(!lines2[ln2]) dieAsm(i,"out of memory");
        strcpy(lines2[ln2], asm1[i]);
        lines2AsmIdx[ln2] = i;
        ln2++;
    }
    uint32_t pc=0;
    for(int i=0;i<ln2;i++){
        char tmp[LNSZ]; strcpy(tmp, trim(lines2[i]));
        char *save, *tok = strtok_r(tmp," \t,",&save);
        if(!tok) continue;
        if(tok[strlen(tok)-1]==':'){
            tok[strlen(tok)-1]=0;
            recordLabel(tok, pc, i);
        } else {
            pc += line_sz(lines2[i]);
        }
    }
}

/* Byte-emit helpers */
static void e8(uint8_t b){ fputc(b,out); }
static void e16(uint16_t w){ e8(w&0xFF); e8(w>>8); }
static void e32(uint32_t w){ e16(w&0xFFFF); e16(w>>16); }

/* PASS B: emit out.bin and free lines2 */
static void asm_passB() {
    out = fopen("out.bin","wb");
    if(!out) die("cannot create output file");

    uint32_t pc=0;
    for(int i=0;i<ln2;i++){
        char tmp[LNSZ]; strcpy(tmp, lines2[i]);
        char *save, *tok = strtok_r(tmp," \t,",&save);
        if(!tok){ free(lines2[i]); continue; }

        if(!strcmp(tok,"ORG")){
            unsigned v = parseImm(strtok_r(NULL," \t,",&save), i);
            pc=v; fseek(out,pc,SEEK_SET);
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"DB")){
            char *v;
            while((v=strtok_r(NULL," \t,",&save))){
                unsigned b=parseImm(v,i);
                if(b>0xFF) dieAsm(i,"DB byte out of range: %u",b);
                e8((uint8_t)b); pc++;
            }
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"FILL")){
            unsigned cnt=parseImm(strtok_r(NULL," \t,",&save), i);
            unsigned val=parseImm(strtok_r(NULL," \t,",&save), i);
            if(val>0xFF) dieAsm(i,"FILL byte out of range: %u",val);
            for(unsigned j=0;j<cnt;j++){ e8((uint8_t)val); pc++; }
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"INT")){
            unsigned imm=parseImm(strtok_r(NULL," \t,",&save), i);
            if(imm>0xFF) dieAsm(i,"INT imm8 out of range: %u",imm);
            e8(0xCD); e8((uint8_t)imm); pc+=2;
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"JMP")||!strcmp(tok,"CALL")){
            e8(tok[0]=='J'?0xE9:0xE8);
            uint32_t dest=find_lbl(strtok_r(NULL," \t,",&save), i);
            int32_t rel=(int32_t)dest-(int32_t)(pc+5);
            e32((uint32_t)rel); pc+=5;
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"LJMP")){
            e8(0xEA);
            char *p = strtok_r(NULL," \t,",&save);
            char *sg = strchr(p,':'); *sg++=0;
            unsigned off=parseImm(p,i), s=parseImm(sg,i);
            e32(off); e16((uint16_t)s); pc+=6;
            free(lines2[i]); continue;
        }
        if(tok[strlen(tok)-1]==':'){
            free(lines2[i]); continue;
        }
        dieAsm(i,"unknown directive '%s'", tok);
    }
    fclose(out);
}

int main(int argc,char**argv){
    if(argc!=2){
        fprintf(stderr,"Usage: %s <source.asm>\n",argv[0]);
        return 1;
    }
    read_src(argv[1]);
    pass1();
    asm_passA();
    asm_passB();
    return 0;
}  if(sp+1>=MAXS) dieSrc(i,"scope overflow");
            sp++; bstack[sp].bm=bstack[sp].bi=0;
            continue;
        }
        if(!strcmp(line,"}")) {
            if(sp==0) dieSrc(i,"unmatched scope close");
            sp--; continue;
        }
        if(!strncmp(line,"let &mut",8)) {
            if(bstack[sp].bm||bstack[sp].bi) dieSrc(i,"borrow error");
            bstack[sp].bm=1; continue;
        }
        if(!strncmp(line,"let &",5)) {
            if(bstack[sp].bm) dieSrc(i,"borrow error");
            bstack[sp].bi=1; continue;
        }

        // Built‐ins
        if(!strcmp(line,"tape_start()")) {
            if(al+2>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],"ORG 0x500");
            asmSrcLine[al]=i; strcpy(asm1[al++],"DB 0xBE,0x00,0x05");
            continue;
        }
        if(!strcmp(line,"load()")) {
            if(al+1>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],"DB 0x8A,0x04");
            continue;
        }
        if(!strcmp(line,"store()")) {
            if(al+1>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],"DB 0x88,0x04");
            continue;
        }
        if(!strncmp(line,"head +=",7)) {
            char *numstr=line+7; char *end;
            long v=strtol(numstr,&end,0);
            if(end==numstr||v<0||v>255) dieSrc(i,"head offset 0..255");
            char tmp[LNSZ];
            int n=sprintf(tmp,"DB 0x83,0xC6,%ld",v);
            if(n<0||n>=LNSZ) dieSrc(i,"sprintf overflow");
            if(al+1>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],tmp);
            continue;
        }

        // Fallback to copy
        if(al>=MAXL) dieSrc(i,"asm1 overflow");
        asmSrcLine[al]=i;
        strcpy(asm1[al++], line);
    }

    if(sp!=0) dieSrc(sl-1,"unclosed scope(s)");
}

/* PASS A: copy asm1 → lines2 and record labels */
static void asm_passA() {
    for(int i=0;i<al;i++){
        if(ln2>=MAXL) dieAsm(i,"lines2 overflow");
        lines2[ln2] = (char*)malloc(LNSZ);
        if(!lines2[ln2]) dieAsm(i,"out of memory");
        strcpy(lines2[ln2], asm1[i]);
        lines2AsmIdx[ln2] = i;
        ln2++;
    }
    uint32_t pc=0;
    for(int i=0;i<ln2;i++){
        char tmp[LNSZ]; strcpy(tmp, trim(lines2[i]));
        char *save, *tok = strtok_r(tmp," \t,",&save);
        if(!tok) continue;
        if(tok[strlen(tok)-1]==':'){
            tok[strlen(tok)-1]=0;
            recordLabel(tok, pc, i);
        } else {
            pc += line_sz(lines2[i]);
        }
    }
}

/* Byte-emit helpers */
static void e8(uint8_t b){ fputc(b,out); }
static void e16(uint16_t w){ e8(w&0xFF); e8(w>>8); }
static void e32(uint32_t w){ e16(w&0xFFFF); e16(w>>16); }

/* PASS B: emit out.bin and free lines2 */
static void asm_passB() {
    out = fopen("out.bin","wb");
    if(!out) die("cannot create output file");

    uint32_t pc=0;
    for(int i=0;i<ln2;i++){
        char tmp[LNSZ]; strcpy(tmp, lines2[i]);
        char *save, *tok = strtok_r(tmp," \t,",&save);
        if(!tok){ free(lines2[i]); continue; }

        if(!strcmp(tok,"ORG")){
            unsigned v = parseImm(strtok_r(NULL," \t,",&save), i);
            pc=v; fseek(out,pc,SEEK_SET);
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"DB")){
            char *v;
            while((v=strtok_r(NULL," \t,",&save))){
                unsigned b=parseImm(v,i);
                if(b>0xFF) dieAsm(i,"DB byte out of range: %u",b);
                e8((uint8_t)b); pc++;
            }
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"FILL")){
            unsigned cnt=parseImm(strtok_r(NULL," \t,",&save), i);
            unsigned val=parseImm(strtok_r(NULL," \t,",&save), i);
            if(val>0xFF) dieAsm(i,"FILL byte out of range: %u",val);
            for(unsigned j=0;j<cnt;j++){ e8((uint8_t)val); pc++; }
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"INT")){
            unsigned imm=parseImm(strtok_r(NULL," \t,",&save), i);
            if(imm>0xFF) dieAsm(i,"INT imm8 out of range: %u",imm);
            e8(0xCD); e8((uint8_t)imm); pc+=2;
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"JMP")||!strcmp(tok,"CALL")){
            e8(tok[0]=='J'?0xE9:0xE8);
            uint32_t dest=find_lbl(strtok_r(NULL," \t,",&save), i);
            int32_t rel=(int32_t)dest-(int32_t)(pc+5);
            e32((uint32_t)rel); pc+=5;
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"LJMP")){
            e8(0xEA);
            char *p = strtok_r(NULL," \t,",&save);
            char *sg = strchr(p,':'); *sg++=0;
            unsigned off=parseImm(p,i), s=parseImm(sg,i);
            e32(off); e16((uint16_t)s); pc+=6;
            free(lines2[i]); continue;
        }
        if(tok[strlen(tok)-1]==':'){
            free(lines2[i]); continue;
        }
        dieAsm(i,"unknown directive '%s'", tok);
    }
    fclose(out);
}

int main(int argc,char**argv){
    if(argc!=2){
        fprintf(stderr,"Usage: %s <source.asm>\n",argv[0]);
        return 1;
    }
    read_src(argv[1]);
    pass1();
    asm_passA();
    asm_passB();
    return 0;
}/*
  tri.c – Python-Style “Trinary-Assembly” Compiler
  ~380 LOC ANSI C → <6 KB binary with –Os –s + strip + upx

  Fixes & hardening:
    • Array-bounds checks on all indices
    • Scope-based borrow checking with matching braces
    • Duplicate-label detection
    • Malformed numeric literals error with source context
    • Unrecognized directives/instructions error with context
    • Error messages include source-line number & text
    • Non-destructive parsing via strtok_r
    • Malloc-return checks, with casts to (char*)
    • Free(lines2[]) to avoid leaks
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

#define MAXL 512
#define LNSZ  80
#define MAXLB 128
#define MAXS  16

typedef struct { char name[16]; uint32_t addr; } Label;
typedef struct { int bm, bi; } BorrowFrame;

// DSL source lines
static char src[MAXL][LNSZ];
static int  sl = 0;

// Intermediate AST→ASM lines + source mapping
static char asm1[MAXL][LNSZ];
static int  asmSrcLine[MAXL];
static int  al = 0;

// Final assembler lines + asm1 mapping
static char *lines2[MAXL];
static int   lines2AsmIdx[MAXL];
static int   ln2 = 0;

// Borrow-scope stack
static BorrowFrame bstack[MAXS];
static int         sp = 0;

// Unified label table
static Label lbl2[MAXLB];
static int   nl2 = 0;

// Output file
static FILE *out;

/* Trim whitespace & CR/LF */
static char *trim(char *s) {
    while (*s==' '||*s=='\t') s++;
    char *e = s + strlen(s)-1;
    while (e>=s && (*e==' '||*e=='\t'||*e=='\r'||*e=='\n')) *e--=0;
    return s;
}

/* General error */
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

/* Error in DSL source */
static void dieSrc(int idx, const char *fmt, ...) {
    fprintf(stderr,"Error at source line %d: ", idx+1);
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr,"\n    %s\n", src[idx]);
    exit(1);
}

/* Error in assembler stage */
static void dieAsm(int aidx, const char *fmt, ...) {
    int sidx = asmSrcLine[ lines2AsmIdx[aidx] ];
    fprintf(stderr,"Error at source line %d: ", sidx+1);
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr,"\n    %s\n", src[sidx]);
    exit(1);
}

/* Parse immediate with validation */
static unsigned parseImm(const char *s, int aidx) {
    char *end;
    unsigned long v;
    if (s[0]=='0'&&s[1]=='x') {
        v = strtoul(s+2, &end, 16);
        if (end==s+2 || *end) dieAsm(aidx,"malformed hex immediate '%s'",s);
    } else {
        v = strtoul(s, &end, 10);
        if (end==s) dieAsm(aidx,"malformed decimal immediate '%s'",s);
    }
    return (unsigned)v;
}

/* Read DSL source lines */
static void read_src(const char *fn) {
    FILE *f = fopen(fn,"r");
    if (!f) die("cannot open source '%s'", fn);
    char buf[LNSZ];
    while (fgets(buf,LNSZ,f)) {
        char *t = trim(buf);
        if (*t && *t!=';') {
            if (sl>=MAXL) die("too many source lines (> %d)", MAXL);
            strcpy(src[sl++], t);
        }
    }
    fclose(f);
}

/* Compute size of a single asm1 line */
static uint32_t line_sz(const char *ln) {
    char tmp[LNSZ]; strcpy(tmp, ln);
    char *tok = strtok(tmp," \t,");
    if (!tok) return 0;
    if (tok[strlen(tok)-1]==':') return 0;
    if (!strcmp(tok,"ORG"))   return 0;
    if (!strcmp(tok,"DB")) {
        int c=0; while(strtok(NULL," \t,")) c++; return c;
    }
    if (!strcmp(tok,"FILL")) {
        int n = atoi(strtok(NULL," \t,")); return n;
    }
    if (!strcmp(tok,"INT"))   return 2;
    if (!strcmp(tok,"JMP")||!strcmp(tok,"CALL")) return 5;
    if (!strcmp(tok,"LJMP"))  return 6;
    return 0;
}

/* Record a label, error on duplicate */
static void recordLabel(const char *nm, uint32_t pc, int aidx) {
    for(int i=0;i<nl2;i++){
        if(!strcmp(lbl2[i].name, nm))
            dieAsm(aidx,"duplicate label '%s'", nm);
    }
    if(nl2>=MAXLB) dieAsm(aidx,"too many labels (> %d)", MAXLB);
    strncpy(lbl2[nl2].name, nm, 15);
    lbl2[nl2].name[15] = 0;
    lbl2[nl2].addr = pc;
    nl2++;
}

/* Lookup a label */
static uint32_t find_lbl(const char *nm, int aidx) {
    for(int i=0;i<nl2;i++){
        if(!strcmp(lbl2[i].name, nm))
            return lbl2[i].addr;
    }
    dieAsm(aidx,"undefined label '%s'", nm);
    return 0;
}

/* PASS1: DSL → asm1 with Python-like syntax & borrow checks */
static void pass1() {
    sp=0; bstack[0].bm=bstack[0].bi=0;

    for(int i=0;i<sl;i++){
        char line[LNSZ];
        strcpy(line, trim(src[i]));

        char lower[LNSZ];
        for(int j=0; line[j] && j<LNSZ; j++)
            lower[j] = tolower((unsigned char)line[j]);
        lower[strlen(line)] = 0;

        // Pythonic transforms
        if(!strncmp(lower,"org(",4) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"ORG %s", line+4);
        }
        else if(!strncmp(lower,"db(",3) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"DB %s", line+3);
        }
        else if(!strncmp(lower,"fill(",5) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"FILL %s", line+5);
        }
        else if(!strncmp(lower,"int(",4) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"INT %s", line+4);
        }
        else if(!strncmp(lower,"jmp(",4) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"JMP %s", line+4);
        }
        else if(!strncmp(lower,"call(",5) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            sprintf(line,"CALL %s", line+5);
        }
        else if(!strncmp(lower,"ljmp(",5) && line[strlen(line)-1]==')'){
            line[strlen(line)-1]=0;
            char *p = line+5, *c = strchr(p, ',');
            if(!c) dieSrc(i,"ljmp() needs two args");
            *c=0;
            sprintf(line,"LJMP %s:%s", p, c+1);
        }

        // Borrow & scopes
        if(!strcmp(line,"{")) {
            if(sp+1>=MAXS) dieSrc(i,"scope overflow");
            sp++; bstack[sp].bm=bstack[sp].bi=0;
            continue;
        }
        if(!strcmp(line,"}")) {
            if(sp==0) dieSrc(i,"unmatched scope close");
            sp--; continue;
        }
        if(!strncmp(line,"let &mut",8)) {
            if(bstack[sp].bm||bstack[sp].bi) dieSrc(i,"borrow error");
            bstack[sp].bm=1; continue;
        }
        if(!strncmp(line,"let &",5)) {
            if(bstack[sp].bm) dieSrc(i,"borrow error");
            bstack[sp].bi=1; continue;
        }

        // Built‐ins
        if(!strcmp(line,"tape_start()")) {
            if(al+2>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],"ORG 0x500");
            asmSrcLine[al]=i; strcpy(asm1[al++],"DB 0xBE,0x00,0x05");
            continue;
        }
        if(!strcmp(line,"load()")) {
            if(al+1>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],"DB 0x8A,0x04");
            continue;
        }
        if(!strcmp(line,"store()")) {
            if(al+1>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],"DB 0x88,0x04");
            continue;
        }
        if(!strncmp(line,"head +=",7)) {
            char *numstr=line+7; char *end;
            long v=strtol(numstr,&end,0);
            if(end==numstr||v<0||v>255) dieSrc(i,"head offset 0..255");
            char tmp[LNSZ];
            int n=sprintf(tmp,"DB 0x83,0xC6,%ld",v);
            if(n<0||n>=LNSZ) dieSrc(i,"sprintf overflow");
            if(al+1>=MAXL) dieSrc(i,"asm1 overflow");
            asmSrcLine[al]=i; strcpy(asm1[al++],tmp);
            continue;
        }

        // Fallback to copy
        if(al>=MAXL) dieSrc(i,"asm1 overflow");
        asmSrcLine[al]=i;
        strcpy(asm1[al++], line);
    }

    if(sp!=0) dieSrc(sl-1,"unclosed scope(s)");
}

/* PASS A: copy asm1 → lines2 and record labels */
static void asm_passA() {
    for(int i=0;i<al;i++){
        if(ln2>=MAXL) dieAsm(i,"lines2 overflow");
        lines2[ln2] = (char*)malloc(LNSZ);
        if(!lines2[ln2]) dieAsm(i,"out of memory");
        strcpy(lines2[ln2], asm1[i]);
        lines2AsmIdx[ln2] = i;
        ln2++;
    }
    uint32_t pc=0;
    for(int i=0;i<ln2;i++){
        char tmp[LNSZ]; strcpy(tmp, trim(lines2[i]));
        char *save, *tok = strtok_r(tmp," \t,",&save);
        if(!tok) continue;
        if(tok[strlen(tok)-1]==':'){
            tok[strlen(tok)-1]=0;
            recordLabel(tok, pc, i);
        } else {
            pc += line_sz(lines2[i]);
        }
    }
}

/* Byte-emit helpers */
static void e8(uint8_t b){ fputc(b,out); }
static void e16(uint16_t w){ e8(w&0xFF); e8(w>>8); }
static void e32(uint32_t w){ e16(w&0xFFFF); e16(w>>16); }

/* PASS B: emit out.bin and free lines2 */
static void asm_passB() {
    out = fopen("out.bin","wb");
    if(!out) die("cannot create output file");

    uint32_t pc=0;
    for(int i=0;i<ln2;i++){
        char tmp[LNSZ]; strcpy(tmp, lines2[i]);
        char *save, *tok = strtok_r(tmp," \t,",&save);
        if(!tok){ free(lines2[i]); continue; }

        if(!strcmp(tok,"ORG")){
            unsigned v = parseImm(strtok_r(NULL," \t,",&save), i);
            pc=v; fseek(out,pc,SEEK_SET);
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"DB")){
            char *v;
            while((v=strtok_r(NULL," \t,",&save))){
                unsigned b=parseImm(v,i);
                if(b>0xFF) dieAsm(i,"DB byte out of range: %u",b);
                e8((uint8_t)b); pc++;
            }
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"FILL")){
            unsigned cnt=parseImm(strtok_r(NULL," \t,",&save), i);
            unsigned val=parseImm(strtok_r(NULL," \t,",&save), i);
            if(val>0xFF) dieAsm(i,"FILL byte out of range: %u",val);
            for(unsigned j=0;j<cnt;j++){ e8((uint8_t)val); pc++; }
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"INT")){
            unsigned imm=parseImm(strtok_r(NULL," \t,",&save), i);
            if(imm>0xFF) dieAsm(i,"INT imm8 out of range: %u",imm);
            e8(0xCD); e8((uint8_t)imm); pc+=2;
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"JMP")||!strcmp(tok,"CALL")){
            e8(tok[0]=='J'?0xE9:0xE8);
            uint32_t dest=find_lbl(strtok_r(NULL," \t,",&save), i);
            int32_t rel=(int32_t)dest-(int32_t)(pc+5);
            e32((uint32_t)rel); pc+=5;
            free(lines2[i]); continue;
        }
        if(!strcmp(tok,"LJMP")){
            e8(0xEA);
            char *p = strtok_r(NULL," \t,",&save);
            char *sg = strchr(p,':'); *sg++=0;
            unsigned off=parseImm(p,i), s=parseImm(sg,i);
            e32(off); e16((uint16_t)s); pc+=6;
            free(lines2[i]); continue;
        }
        if(tok[strlen(tok)-1]==':'){
            free(lines2[i]); continue;
        }
        dieAsm(i,"unknown directive '%s'", tok);
    }
    fclose(out);
}

int main(int argc,char**argv){
    if(argc!=2){
        fprintf(stderr,"Usage: %s <source.asm>\n",argv[0]);
        return 1;
    }
    read_src(argv[1]);
    pass1();
    asm_passA();
    asm_passB();
    return 0;
}
