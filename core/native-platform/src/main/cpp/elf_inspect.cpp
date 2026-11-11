#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <vector>

// 任务 2.3：ELF 自解析 —— 从磁盘读取共享库的 .dynsym/.dynstr，解析符号 → st_value。
// 不经过 dlsym（dlsym 结果可被 hook 篡改），供 C7 的 GOT/PLT 完整性比对：
//   期望地址 = 磁盘 st_value + 进程内该库的加载基址（由 /proc/self/maps 求得）。
// 支持 ELF32/ELF64，仅处理本机字节序。

namespace {

struct SymbolHit {
    unsigned long st_value = 0;
    unsigned char st_info = 0;
    bool found = false;
};

template <typename Ehdr, typename Shdr, typename Sym>
bool parse_dynsym(int fd, const std::string &want, SymbolHit *out) {
    Ehdr ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != static_cast<ssize_t>(sizeof(ehdr))) return false;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return false;

    std::vector<Shdr> shdrs(ehdr.e_shnum);
    if (ehdr.e_shnum == 0 ||
        pread(fd, shdrs.data(), sizeof(Shdr) * ehdr.e_shnum, ehdr.e_shoff) !=
            static_cast<ssize_t>(sizeof(Shdr) * ehdr.e_shnum)) {
        return false;
    }

    for (const Shdr &sh : shdrs) {
        if (sh.sh_type != SHT_DYNSYM) continue;
        // 2026-11-10 审计修复：sh_link 为磁盘字段，恶意/损坏 ELF 可任意置值——
        // maps 被 hook 时 C7 解析的是攻击者可控文件，越界下标 = UB/崩溃
        // （用崩溃规避检测的攻击面）。负值/超界一律跳过。
        if (sh.sh_link >= shdrs.size()) continue;
        const Shdr &strsec = shdrs[sh.sh_link];

        std::vector<char> strtab(strsec.sh_size);
        if (pread(fd, strtab.data(), strsec.sh_size, strsec.sh_offset) !=
            static_cast<ssize_t>(strsec.sh_size)) {
            continue;
        }

        const size_t count = sh.sh_size / sizeof(Sym);
        std::vector<Sym> syms(count);
        if (pread(fd, syms.data(), sh.sh_size, sh.sh_offset) != static_cast<ssize_t>(sh.sh_size)) {
            continue;
        }

        for (const Sym &sym : syms) {
            if (sym.st_name >= strsec.sh_size) continue;
            const char *name = strtab.data() + sym.st_name;
            if (name == want) {
                out->st_value = static_cast<unsigned long>(sym.st_value);
                out->st_info = sym.st_info;
                out->found = true;
                return true;
            }
        }
    }
    return true;  // 解析成功但没有命中
}

}  // namespace

// 返回：0 = 未命中/失败；>0 = 磁盘上的 st_value（vaddr）。
unsigned long da_elf_export_value(const char *path, const char *symbol) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    unsigned char class_byte = 0;
    if (pread(fd, &class_byte, 1, EI_CLASS) != 1) {
        close(fd);
        return 0;
    }
    SymbolHit hit;
    bool ok = false;
    if (class_byte == ELFCLASS64) {
        ok = parse_dynsym<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym>(fd, symbol, &hit);
    } else if (class_byte == ELFCLASS32) {
        ok = parse_dynsym<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym>(fd, symbol, &hit);
    }
    close(fd);
    return (ok && hit.found) ? hit.st_value : 0;
}

// ---- C7 支持：按 vaddr 读磁盘字节（PT_LOAD 换算）+ 重定位表枚举 ----

struct PhdrRange {
    unsigned long p_vaddr = 0;
    unsigned long p_offset = 0;
    unsigned long p_filesz = 0;
};

template <typename Ehdr, typename Phdr>
bool collect_loads(int fd, std::vector<PhdrRange> *out) {
    Ehdr ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != static_cast<ssize_t>(sizeof(ehdr))) return false;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return false;
    if (ehdr.e_phnum == 0 || ehdr.e_phoff == 0) return false;
    std::vector<Phdr> phdrs(ehdr.e_phnum);
    if (pread(fd, phdrs.data(), sizeof(Phdr) * ehdr.e_phnum, ehdr.e_phoff) !=
        static_cast<ssize_t>(sizeof(Phdr) * ehdr.e_phnum)) {
        return false;
    }
    for (const Phdr &p : phdrs) {
        if (p.p_type == PT_LOAD) {
            out->push_back({static_cast<unsigned long>(p.p_vaddr),
                            static_cast<unsigned long>(p.p_offset),
                            static_cast<unsigned long>(p.p_filesz)});
        }
    }
    return !out->empty();
}

// 读磁盘 ELF 中 [vaddr, vaddr+len) 的原始字节（.text prologue 比对用）。
// 返回实际读取字节数；0 = vaddr 不在任何 PT_LOAD。
long da_elf_read_at_vaddr(const char *path, unsigned long vaddr, unsigned char *buf, size_t len) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    unsigned char class_byte = 0;
    if (pread(fd, &class_byte, 1, EI_CLASS) != 1) {
        close(fd);
        return 0;
    }
    std::vector<PhdrRange> loads;
    bool ok = false;
    if (class_byte == ELFCLASS64) {
        ok = collect_loads<Elf64_Ehdr, Elf64_Phdr>(fd, &loads);
    } else if (class_byte == ELFCLASS32) {
        ok = collect_loads<Elf32_Ehdr, Elf32_Phdr>(fd, &loads);
    }
    if (!ok) {
        close(fd);
        return 0;
    }
    for (const PhdrRange &r : loads) {
        if (vaddr >= r.p_vaddr && vaddr < r.p_vaddr + r.p_filesz) {
            const size_t avail = static_cast<size_t>(r.p_vaddr + r.p_filesz - vaddr);
            const size_t want = len < avail ? len : avail;
            const ssize_t n = pread(fd, buf, want, static_cast<off_t>(r.p_offset + (vaddr - r.p_vaddr)));
            close(fd);
            return n > 0 ? static_cast<long>(n) : 0;
        }
    }
    close(fd);
    return 0;
}

// 枚举动态重定位：输出 "symbolName\tgot_vaddr"（JUMP_SLOT/GLOB_DAT，C7 GOT 完整性用）。
template <typename Ehdr, typename Shdr, typename Sym, typename Rel>
int relocs_common(int fd, std::vector<std::string> *out) {
    Ehdr ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != static_cast<ssize_t>(sizeof(ehdr))) return -1;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return -1;
    std::vector<Shdr> shdrs(ehdr.e_shnum);
    if (ehdr.e_shnum == 0 ||
        pread(fd, shdrs.data(), sizeof(Shdr) * ehdr.e_shnum, ehdr.e_shoff) !=
            static_cast<ssize_t>(sizeof(Shdr) * ehdr.e_shnum)) {
        return -1;
    }
    // 找 .dynsym/.dynstr
    size_t dynsym_idx = 0, dynstr_idx = 0;
    for (size_t i = 0; i < shdrs.size(); i++) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            dynsym_idx = i;
            dynstr_idx = shdrs[i].sh_link;
            break;
        }
    }
    if (dynsym_idx == 0) return 0;
    // 同 parse_dynsym：sh_link 磁盘字段不可信（2026-11-10 审计修复）
    if (dynstr_idx >= shdrs.size()) return -1;
    const Shdr &symsec = shdrs[dynsym_idx];
    const Shdr &strsec = shdrs[dynstr_idx];
    std::vector<char> strtab(strsec.sh_size);
    if (pread(fd, strtab.data(), strsec.sh_size, strsec.sh_offset) != static_cast<ssize_t>(strsec.sh_size)) return -1;
    const size_t sym_count = symsec.sh_size / sizeof(Sym);
    std::vector<Sym> syms(sym_count);
    if (pread(fd, syms.data(), symsec.sh_size, symsec.sh_offset) != static_cast<ssize_t>(symsec.sh_size)) return -1;

    for (const Shdr &sh : shdrs) {
        const bool isRela = sh.sh_type == SHT_RELA;
        const bool isRel = sh.sh_type == SHT_REL;
        if (!isRela && !isRel) continue;
        const size_t ent = isRela ? sizeof(Rel) : sizeof(Rel);
        const size_t count = sh.sh_size / ent;
        std::vector<unsigned char> raw(sh.sh_size);
        if (pread(fd, raw.data(), sh.sh_size, sh.sh_offset) != static_cast<ssize_t>(sh.sh_size)) continue;
        for (size_t i = 0; i < count; i++) {
            const Rel *rel = reinterpret_cast<const Rel *>(raw.data() + i * ent);
            const unsigned long r_offset = static_cast<unsigned long>(rel->r_offset);
            const unsigned long sym_idx = isRela
                ? static_cast<unsigned long>(reinterpret_cast<const Elf64_Rela *>(rel)->r_info) >> 32
                : static_cast<unsigned long>(reinterpret_cast<const Elf32_Rel *>(rel)->r_info) >> 8;
            const unsigned long type = isRela
                ? (static_cast<unsigned long>(reinterpret_cast<const Elf64_Rela *>(rel)->r_info) & 0xFFFFFFFFL)
                : (static_cast<unsigned long>(reinterpret_cast<const Elf32_Rel *>(rel)->r_info) & 0xFFL);
            // arm64: JUMP_SLOT=1026, GLOB_DAT=1025；arm32: JUMP_SLOT=22, GLOB_DAT=21
#if defined(__aarch64__)
            const bool wanted = (type == 1026 || type == 1025);
#else
            const bool wanted = (type == 22 || type == 21);
#endif
            if (!wanted || sym_idx == 0 || sym_idx >= sym_count) continue;
            const Sym &sym = syms[sym_idx];
            if (sym.st_name >= strsec.sh_size) continue;
            char line[640];
            snprintf(line, sizeof(line), "%s\t%lu", strtab.data() + sym.st_name, r_offset);
            out->emplace_back(line);
        }
    }
    return 0;
}

int da_elf_relocations(const char *path, std::vector<std::string> *out) {
    out->clear();
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    unsigned char class_byte = 0;
    if (pread(fd, &class_byte, 1, EI_CLASS) != 1) {
        close(fd);
        return -1;
    }
    int rc = -1;
    if (class_byte == ELFCLASS64) {
        rc = relocs_common<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym, Elf64_Rela>(fd, out);
    } else if (class_byte == ELFCLASS32) {
        rc = relocs_common<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym, Elf32_Rel>(fd, out);
    }
    close(fd);
    return rc;
}

// 从 /proc/self/maps 求指定库文件在本进程的加载基址（首个可执行映射的起始地址）。
// 供「期望地址 = st_value + 基址」与 dlsym 实测交叉（任务 2.3 验证）。
unsigned long da_maps_base(const char *path) {
    FILE *f = fopen("/proc/self/maps", "re");
    if (f == nullptr) return 0;
    char line[1024];
    unsigned long best = 0;
    const size_t path_len = strlen(path);
    while (fgets(line, sizeof(line), f) != nullptr) {
        const size_t len = strlen(line);
        if (len < path_len + 1) continue;
        const char *candidate = line + (len - path_len - 1);
        if (candidate[0] != '/' || memcmp(candidate, path, path_len) != 0 || candidate[path_len] != '\n') {
            // 允许行尾就是路径（换行已被 fgets 保留）——上面已按 '\n' 对齐校验
            continue;
        }
        unsigned long start = strtoul(line, nullptr, 16);
        if (best == 0 || start < best) best = start;
    }
    fclose(f);
    return best;
}
