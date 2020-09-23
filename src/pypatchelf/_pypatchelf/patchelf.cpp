/*
 *  PatchELF is a utility to modify properties of ELF executables and libraries
 *  Copyright (C) 2004-2016  Eelco Dolstra <edolstra@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf.h"

static bool debugMode = false;

static bool forceRPath = false;

static std::string outputFileName;
#ifdef DEFAULT_PAGESIZE
static int forcedPageSize = DEFAULT_PAGESIZE;
#else
static int forcedPageSize = -1;
#endif

typedef std::shared_ptr<std::vector<unsigned char>> FileContents;

#define ElfFileParams                                                                                   \
    class Elf_Ehdr, class Elf_Phdr, class Elf_Shdr, class Elf_Addr, class Elf_Off, class Elf_Dyn,       \
            class Elf_Sym, class Elf_Verneed, class Elf_Versym
#define ElfFileParamNames                                                                               \
    Elf_Ehdr, Elf_Phdr, Elf_Shdr, Elf_Addr, Elf_Off, Elf_Dyn, Elf_Sym, Elf_Verneed, Elf_Versym

static std::vector<std::string>
splitColonDelimitedString(const char* s)
{
    std::vector<std::string> parts;
    const char* pos = s;
    while (*pos) {
        const char* end = strchr(pos, ':');
        if (!end) end = strchr(pos, 0);

        parts.emplace_back(pos, end - pos);
        if (*end == ':') ++end;
        pos = end;
    }

    return parts;
}

static bool
hasAllowedPrefix(const std::string& s, const std::vector<std::string>& allowedPrefixes)
{
    return std::any_of(allowedPrefixes.cbegin(), allowedPrefixes.cend(), [&](const std::string& i) {
        return !s.compare(0, i.size(), i);
    });
}

template<ElfFileParams>
class ElfFile
{
  public:
    const FileContents fileContents;

  private:
    unsigned char* contents;

    Elf_Ehdr* hdr;
    std::vector<Elf_Phdr> phdrs;
    std::vector<Elf_Shdr> shdrs;

    bool littleEndian;

    bool changed = false;

    bool isExecutable = false;

    typedef std::string SectionName;
    typedef std::map<SectionName, std::string> ReplacedSections;

    ReplacedSections replacedSections;

    std::string sectionNames; /* content of the .shstrtab section */

    /* Align on 4 or 8 bytes boundaries on 32- or 64-bit platforms
       respectively. */
    size_t sectionAlignment = sizeof(Elf_Off);

    std::vector<SectionName> sectionsByOldIndex;

  public:
    explicit ElfFile(const FileContents& fileContents);

    bool isChanged()
    {
        return changed;
    }

  private:
    struct CompPhdr
    {
        ElfFile* elfFile;

        bool operator()(const Elf_Phdr& x, const Elf_Phdr& y)
        {
            // A PHDR comes before everything else.
            if (y.p_type == PT_PHDR) return false;
            if (x.p_type == PT_PHDR) return true;

            // Sort non-PHDRs by address.
            return elfFile->rdi(x.p_paddr) < elfFile->rdi(y.p_paddr);
        }
    };

    friend struct CompPhdr;

    void sortPhdrs();

    struct CompShdr
    {
        ElfFile* elfFile;

        bool operator()(const Elf_Shdr& x, const Elf_Shdr& y)
        {
            return elfFile->rdi(x.sh_offset) < elfFile->rdi(y.sh_offset);
        }
    };

    friend struct CompShdr;

    unsigned int getPageSize() const;

    void sortShdrs();

    void shiftFile(unsigned int extraPages, Elf_Addr startPage);

    std::string getSectionName(const Elf_Shdr& shdr) const;

    Elf_Shdr& findSection(const SectionName& sectionName);

    Elf_Shdr* findSection2(const SectionName& sectionName);

    unsigned int findSection3(const SectionName& sectionName);

    std::string& replaceSection(const SectionName& sectionName, unsigned int size);

    bool haveReplacedSection(const SectionName& sectionName) const;

    void writeReplacedSections(Elf_Off& curOff, Elf_Addr startAddr, Elf_Off startOffset);

    void rewriteHeaders(Elf_Addr phdrAddress);

    void rewriteSectionsLibrary();

    void rewriteSectionsExecutable();

    void normalizeNoteSegments();

  public:
    void rewriteSections();

    typedef enum { rpPrint, rpShrink, rpSet, rpRemove } RPathOp;

    void
    modifyRPath(RPathOp op, const std::vector<std::string>& allowedRpathPrefixes, std::string newRPath);

  private:
    /* Convert an integer in big or little endian representation (as
       specified by the ELF header) to this platform's integer
       representation. */
    template<class I>
    I rdi(I i) const;

    /* Convert back to the ELF representation. */
    template<class I>
    I wri(I& t, unsigned long long i) const
    {
        t = rdi((I)i);
        return i;
    }
};

/* !!! G++ creates broken code if this function is inlined, don't know
   why... */
template<ElfFileParams>
template<class I>
I
ElfFile<ElfFileParamNames>::rdi(I i) const
{
    I r = 0;
    if (littleEndian) {
        for (unsigned int n = 0; n < sizeof(I); ++n) {
            r |= ((I) * (((unsigned char*)&i) + n)) << (n * 8);
        }
    } else {
        for (unsigned int n = 0; n < sizeof(I); ++n) {
            r |= ((I) * (((unsigned char*)&i) + n)) << ((sizeof(I) - n - 1) * 8);
        }
    }
    return r;
}

static void
debug(const char* format, ...)
{
    if (debugMode) {
        va_list ap;
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);
    }
}

void
fmt2(std::ostringstream& out)
{
}

template<typename T, typename... Args>
void
fmt2(std::ostringstream& out, T x, Args... args)
{
    out << x;
    fmt2(out, args...);
}

template<typename... Args>
std::string
fmt(Args... args)
{
    std::ostringstream out;
    fmt2(out, args...);
    return out.str();
}

struct SysError : std::runtime_error
{
    int errNo;

    explicit SysError(const std::string& msg)
    : std::runtime_error(fmt(msg + ": " + strerror(errno)))
    , errNo(errno)
    {
    }
};

__attribute__((noreturn)) static void
error(const std::string& msg)
{
    if (errno)
        throw SysError(msg);
    else
        throw std::runtime_error(msg);
}

static void
growFile(const FileContents& contents, size_t newSize)
{
    if (newSize > contents->capacity()) error("maximum file size exceeded");
    if (newSize <= contents->size()) return;
    contents->resize(newSize, 0);
}

static FileContents
readFile(const std::string& fileName, size_t cutOff = std::numeric_limits<size_t>::max())
{
    struct stat st
    {
    };
    if (stat(fileName.c_str(), &st) != 0) throw SysError(fmt("getting info about '", fileName, "'"));

    if ((uint64_t)st.st_size > (uint64_t)std::numeric_limits<size_t>::max())
        throw SysError(fmt("cannot read file of size ", st.st_size, " into memory"));

    size_t size = std::min(cutOff, (size_t)st.st_size);

    FileContents contents = std::make_shared<std::vector<unsigned char>>();
    contents->reserve(size + 32 * 1024 * 1024);
    contents->resize(size, 0);

    int fd = open(fileName.c_str(), O_RDONLY);
    if (fd == -1) throw SysError(fmt("opening '", fileName, "'"));

    size_t bytesRead = 0;
    ssize_t portion;
    while ((portion = read(fd, contents->data() + bytesRead, size - bytesRead)) > 0)
        bytesRead += portion;

    if (bytesRead != size) throw SysError(fmt("reading '", fileName, "'"));

    close(fd);

    return contents;
}

struct ElfType
{
    bool is32Bit;
    int machine;  // one of EM_*
};

ElfType
getElfType(const FileContents& fileContents)
{
    /* Check the ELF header for basic validity. */
    if (fileContents->size() < (off_t)sizeof(Elf32_Ehdr)) error("missing ELF header");

    auto contents = fileContents->data();

    if (memcmp(contents, ELFMAG, SELFMAG) != 0) error("not an ELF executable");

    if (contents[EI_VERSION] != EV_CURRENT) error("unsupported ELF version");

    if (contents[EI_CLASS] != ELFCLASS32 && contents[EI_CLASS] != ELFCLASS64)
        error("ELF executable is not 32 or 64 bit");

    bool is32Bit = contents[EI_CLASS] == ELFCLASS32;

    // FIXME: endianness
    return ElfType{
            is32Bit,
            is32Bit ? ((Elf32_Ehdr*)contents)->e_machine : ((Elf64_Ehdr*)contents)->e_machine};
}

static void
checkPointer(const FileContents& contents, void* p, unsigned int size)
{
    assert((unsigned char*)p >= contents->data()
           && (unsigned char*)p + size <= contents->data() + contents->size());
}

template<ElfFileParams>
ElfFile<ElfFileParamNames>::ElfFile(const FileContents& fileContents)
: fileContents(fileContents)
, contents(fileContents->data())
{
    /* Check the ELF header for basic validity. */
    if (fileContents->size() < (off_t)sizeof(Elf_Ehdr)) error("missing ELF header");

    hdr = (Elf_Ehdr*)fileContents->data();

    if (memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0) error("not an ELF executable");

    littleEndian = hdr->e_ident[EI_DATA] == ELFDATA2LSB;

    if (rdi(hdr->e_type) != ET_EXEC && rdi(hdr->e_type) != ET_DYN) error("wrong ELF type");

    if ((rdi(hdr->e_phoff) + rdi(hdr->e_phnum) * rdi(hdr->e_phentsize)) > fileContents->size())
        error("program header table out of bounds");

    if (rdi(hdr->e_shnum) == 0)
        error("no section headers. The input file is probably a statically linked, self-decompressing "
              "binary");

    if ((rdi(hdr->e_shoff) + rdi(hdr->e_shnum) * rdi(hdr->e_shentsize)) > fileContents->size())
        error("section header table out of bounds");

    if (rdi(hdr->e_phentsize) != sizeof(Elf_Phdr)) error("program headers have wrong size");

    /* Copy the program and section headers. */
    for (int i = 0; i < rdi(hdr->e_phnum); ++i) {
        phdrs.push_back(*((Elf_Phdr*)(contents + rdi(hdr->e_phoff)) + i));
        if (rdi(phdrs[i].p_type) == PT_INTERP) isExecutable = true;
    }

    for (int i = 0; i < rdi(hdr->e_shnum); ++i)
        shdrs.push_back(*((Elf_Shdr*)(contents + rdi(hdr->e_shoff)) + i));

    /* Get the section header string table section (".shstrtab").  Its
       index in the section header table is given by e_shstrndx field
       of the ELF header. */
    unsigned int shstrtabIndex = rdi(hdr->e_shstrndx);
    assert(shstrtabIndex < shdrs.size());
    unsigned int shstrtabSize = rdi(shdrs[shstrtabIndex].sh_size);
    char* shstrtab = (char*)contents + rdi(shdrs[shstrtabIndex].sh_offset);
    checkPointer(fileContents, shstrtab, shstrtabSize);

    assert(shstrtabSize > 0);
    assert(shstrtab[shstrtabSize - 1] == 0);

    sectionNames = std::string(shstrtab, shstrtabSize);

    sectionsByOldIndex.resize(hdr->e_shnum);
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
        sectionsByOldIndex[i] = getSectionName(shdrs[i]);
}

template<ElfFileParams>
unsigned int
ElfFile<ElfFileParamNames>::getPageSize() const
{
    if (forcedPageSize > 0) return forcedPageSize;

    // Architectures (and ABIs) can have different minimum section alignment
    // requirements. There is no authoritative list of these values. The
    // current list is extracted from GNU gold's source code (abi_pagesize).
    switch (hdr->e_machine) {
        case EM_SPARC:
        case EM_MIPS:
        case EM_PPC:
        case EM_PPC64:
        case EM_AARCH64:
        case EM_TILEGX:
            return 0x10000;
        default:
            return 0x1000;
    }
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::sortPhdrs()
{
    /* Sort the segments by offset. */
    CompPhdr comp{};
    comp.elfFile = this;
    stable_sort(phdrs.begin(), phdrs.end(), comp);
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::sortShdrs()
{
    /* Translate sh_link mappings to section names, since sorting the
       sections will invalidate the sh_link fields. */
    std::map<SectionName, SectionName> linkage;
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
        if (rdi(shdrs[i].sh_link) != 0)
            linkage[getSectionName(shdrs[i])] = getSectionName(shdrs[rdi(shdrs[i].sh_link)]);

    /* Idem for sh_info on certain sections. */
    std::map<SectionName, SectionName> info;
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
        if (rdi(shdrs[i].sh_info) != 0
            && (rdi(shdrs[i].sh_type) == SHT_REL || rdi(shdrs[i].sh_type) == SHT_RELA))
            info[getSectionName(shdrs[i])] = getSectionName(shdrs[rdi(shdrs[i].sh_info)]);

    /* Idem for the index of the .shstrtab section in the ELF header. */
    Elf_Shdr shstrtab = shdrs[rdi(hdr->e_shstrndx)];

    /* Sort the sections by offset. */
    CompShdr comp{};
    comp.elfFile = this;
    stable_sort(shdrs.begin() + 1, shdrs.end(), comp);

    /* Restore the sh_link mappings. */
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
        if (rdi(shdrs[i].sh_link) != 0)
            wri(shdrs[i].sh_link, findSection3(linkage[getSectionName(shdrs[i])]));

    /* And the st_info mappings. */
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
        if (rdi(shdrs[i].sh_info) != 0
            && (rdi(shdrs[i].sh_type) == SHT_REL || rdi(shdrs[i].sh_type) == SHT_RELA))
            wri(shdrs[i].sh_info, findSection3(info[getSectionName(shdrs[i])]));

    /* And the .shstrtab index. Note: the match here is done by checking the offset as searching
     * by name can yield incorrect results in case there are multiple sections with the same
     * name as the one initially pointed by hdr->e_shstrndx */
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i) {
        if (shdrs[i].sh_offset == shstrtab.sh_offset) {
            wri(hdr->e_shstrndx, i);
        }
    }
}

static void
writeFile(const std::string& fileName, const FileContents& contents)
{
    debug("writing %s\n", fileName.c_str());

    int fd = open(fileName.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0777);
    if (fd == -1) error("open");

    size_t bytesWritten = 0;
    ssize_t portion;
    while ((portion = write(fd, contents->data() + bytesWritten, contents->size() - bytesWritten)) > 0)
        bytesWritten += portion;

    if (bytesWritten != contents->size()) error("write");

    if (close(fd) != 0) error("close");
}

static uint64_t
roundUp(uint64_t n, uint64_t m)
{
    return ((n - 1) / m + 1) * m;
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::shiftFile(unsigned int extraPages, Elf_Addr startPage)
{
    /* Move the entire contents of the file 'extraPages' pages
       further. */
    unsigned int oldSize = fileContents->size();
    unsigned int shift = extraPages * getPageSize();
    growFile(fileContents, fileContents->size() + extraPages * getPageSize());
    memmove(contents + extraPages * getPageSize(), contents, oldSize);
    memset(contents + sizeof(Elf_Ehdr), 0, shift - sizeof(Elf_Ehdr));

    /* Adjust the ELF header. */
    wri(hdr->e_phoff, sizeof(Elf_Ehdr));
    wri(hdr->e_shoff, rdi(hdr->e_shoff) + shift);

    /* Update the offsets in the section headers. */
    for (int i = 1; i < rdi(hdr->e_shnum); ++i)
        wri(shdrs[i].sh_offset, rdi(shdrs[i].sh_offset) + shift);

    /* Update the offsets in the program headers. */
    for (int i = 0; i < rdi(hdr->e_phnum); ++i) {
        wri(phdrs[i].p_offset, rdi(phdrs[i].p_offset) + shift);
        if (rdi(phdrs[i].p_align) != 0
            && (rdi(phdrs[i].p_vaddr) - rdi(phdrs[i].p_offset)) % rdi(phdrs[i].p_align) != 0)
        {
            debug("changing alignment of program header %d from %d to %d\n",
                  i,
                  rdi(phdrs[i].p_align),
                  getPageSize());
            wri(phdrs[i].p_align, getPageSize());
        }
    }

    /* Add a segment that maps the new program/section headers and
       PT_INTERP segment into memory.  Otherwise glibc will choke. */
    phdrs.resize(rdi(hdr->e_phnum) + 1);
    wri(hdr->e_phnum, rdi(hdr->e_phnum) + 1);
    Elf_Phdr& phdr = phdrs[rdi(hdr->e_phnum) - 1];
    wri(phdr.p_type, PT_LOAD);
    wri(phdr.p_offset, 0);
    wri(phdr.p_vaddr, wri(phdr.p_paddr, startPage));
    wri(phdr.p_filesz, wri(phdr.p_memsz, shift));
    wri(phdr.p_flags, PF_R | PF_W);
    wri(phdr.p_align, getPageSize());
}

template<ElfFileParams>
std::string
ElfFile<ElfFileParamNames>::getSectionName(const Elf_Shdr& shdr) const
{
    return std::string(sectionNames.c_str() + rdi(shdr.sh_name));
}

template<ElfFileParams>
Elf_Shdr&
ElfFile<ElfFileParamNames>::findSection(const SectionName& sectionName)
{
    auto shdr = findSection2(sectionName);
    if (!shdr) {
        std::string extraMsg;
        if (sectionName == ".interp" || sectionName == ".dynamic" || sectionName == ".dynstr")
            extraMsg = ". The input file is most likely statically linked";
        error("cannot find section '" + sectionName + "'" + extraMsg);
    }
    return *shdr;
}

template<ElfFileParams>
Elf_Shdr*
ElfFile<ElfFileParamNames>::findSection2(const SectionName& sectionName)
{
    auto i = findSection3(sectionName);
    return i ? &shdrs[i] : nullptr;
}

template<ElfFileParams>
unsigned int
ElfFile<ElfFileParamNames>::findSection3(const SectionName& sectionName)
{
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
        if (getSectionName(shdrs[i]) == sectionName) return i;
    return 0;
}

template<ElfFileParams>
bool
ElfFile<ElfFileParamNames>::haveReplacedSection(const SectionName& sectionName) const
{
    return (replacedSections.find(sectionName) != replacedSections.end());
}

template<ElfFileParams>
std::string&
ElfFile<ElfFileParamNames>::replaceSection(const SectionName& sectionName, unsigned int size)
{
    auto i = replacedSections.find(sectionName);
    std::string s;

    if (i != replacedSections.end()) {
        s = std::string(i->second);
    } else {
        auto shdr = findSection(sectionName);
        s = std::string((char*)contents + rdi(shdr.sh_offset), rdi(shdr.sh_size));
    }

    s.resize(size);
    replacedSections[sectionName] = s;

    return replacedSections[sectionName];
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::writeReplacedSections(
        Elf_Off& curOff,
        Elf_Addr startAddr,
        Elf_Off startOffset)
{
    /* Overwrite the old section contents with 'X's.  Do this
       *before* writing the new section contents (below) to prevent
       clobbering previously written new section contents. */
    for (auto& i : replacedSections) {
        std::string sectionName = i.first;
        Elf_Shdr& shdr = findSection(sectionName);
        if (shdr.sh_type != SHT_NOBITS) memset(contents + rdi(shdr.sh_offset), 'X', rdi(shdr.sh_size));
    }

    for (auto& i : replacedSections) {
        std::string sectionName = i.first;
        auto& shdr = findSection(sectionName);
        Elf_Shdr orig_shdr = shdr;
        debug("rewriting section '%s' from offset 0x%x (size %d) to offset 0x%x (size %d)\n",
              sectionName.c_str(),
              rdi(shdr.sh_offset),
              rdi(shdr.sh_size),
              curOff,
              i.second.size());

        memcpy(contents + curOff, (unsigned char*)i.second.c_str(), i.second.size());

        /* Update the section header for this section. */
        wri(shdr.sh_offset, curOff);
        wri(shdr.sh_addr, startAddr + (curOff - startOffset));
        wri(shdr.sh_size, i.second.size());
        wri(shdr.sh_addralign, sectionAlignment);

        /* If this is the .interp section, then the PT_INTERP segment
           must be sync'ed with it. */
        if (sectionName == ".interp") {
            for (unsigned int j = 0; j < phdrs.size(); ++j)
                if (rdi(phdrs[j].p_type) == PT_INTERP) {
                    phdrs[j].p_offset = shdr.sh_offset;
                    phdrs[j].p_vaddr = phdrs[j].p_paddr = shdr.sh_addr;
                    phdrs[j].p_filesz = phdrs[j].p_memsz = shdr.sh_size;
                }
        }

        /* If this is the .dynamic section, then the PT_DYNAMIC segment
           must be sync'ed with it. */
        if (sectionName == ".dynamic") {
            for (unsigned int j = 0; j < phdrs.size(); ++j)
                if (rdi(phdrs[j].p_type) == PT_DYNAMIC) {
                    phdrs[j].p_offset = shdr.sh_offset;
                    phdrs[j].p_vaddr = phdrs[j].p_paddr = shdr.sh_addr;
                    phdrs[j].p_filesz = phdrs[j].p_memsz = shdr.sh_size;
                }
        }

        /* If this is a note section, there might be a PT_NOTE segment that
           must be sync'ed with it. Note that normalizeNoteSegments() will have
           already taken care of PT_NOTE segments containing multiple note
           sections. At this point, we can assume that the segment will map to
           exactly one section.

           Note sections also have particular alignment constraints: the
           data inside the section is formatted differently depending on the
           section alignment. Keep the original alignment if possible. */
        if (rdi(shdr.sh_type) == SHT_NOTE) {
            if (orig_shdr.sh_addralign < sectionAlignment) shdr.sh_addralign = orig_shdr.sh_addralign;

            for (unsigned int j = 0; j < phdrs.size(); ++j)
                if (rdi(phdrs[j].p_type) == PT_NOTE) {
                    Elf_Off p_start = rdi(phdrs[j].p_offset);
                    Elf_Off p_end = p_start + rdi(phdrs[j].p_filesz);
                    Elf_Off s_start = rdi(orig_shdr.sh_offset);
                    Elf_Off s_end = s_start + rdi(orig_shdr.sh_size);

                    /* Skip if no overlap. */
                    if (!(s_start >= p_start && s_start < p_end) && !(s_end > p_start && s_end <= p_end))
                        continue;

                    /* We only support exact matches. */
                    if (p_start != s_start || p_end != s_end)
                        error("unsupported overlap of SHT_NOTE and PT_NOTE");

                    phdrs[j].p_offset = shdr.sh_offset;
                    phdrs[j].p_vaddr = phdrs[j].p_paddr = shdr.sh_addr;
                    phdrs[j].p_filesz = phdrs[j].p_memsz = shdr.sh_size;
                }
        }

        curOff += roundUp(i.second.size(), sectionAlignment);
    }

    replacedSections.clear();
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::rewriteSectionsLibrary()
{
    /* For dynamic libraries, we just place the replacement sections
       at the end of the file.  They're mapped into memory by a
       PT_LOAD segment located directly after the last virtual address
       page of other segments. */
    Elf_Addr startPage = 0;
    for (unsigned int i = 0; i < phdrs.size(); ++i) {
        Elf_Addr thisPage = roundUp(rdi(phdrs[i].p_vaddr) + rdi(phdrs[i].p_memsz), getPageSize());
        if (thisPage > startPage) startPage = thisPage;
    }

    debug("last page is 0x%llx\n", (unsigned long long)startPage);

    /* When normalizing note segments we will in the worst case be adding
       1 program header for each SHT_NOTE section. */
    unsigned int num_notes = 0;
    for (const auto& shdr : shdrs)
        if (rdi(shdr.sh_type) == SHT_NOTE) num_notes++;

    /* Because we're adding a new section header, we're necessarily increasing
       the size of the program header table.  This can cause the first section
       to overlap the program header table in memory; we need to shift the first
       few segments to someplace else. */
    /* Some sections may already be replaced so account for that */
    unsigned int i = 1;
    Elf_Addr pht_size = sizeof(Elf_Ehdr) + (phdrs.size() + num_notes + 1) * sizeof(Elf_Phdr);
    while (shdrs[i].sh_addr <= pht_size && i < rdi(hdr->e_shnum)) {
        if (not haveReplacedSection(getSectionName(shdrs[i])))
            replaceSection(getSectionName(shdrs[i]), shdrs[i].sh_size);
        i++;
    }

    /* Compute the total space needed for the replaced sections */
    off_t neededSpace = 0;
    for (auto& section : replacedSections)
        neededSpace += roundUp(section.second.size(), sectionAlignment);
    debug("needed space is %d\n", neededSpace);

    size_t startOffset = roundUp(fileContents->size(), getPageSize());

    growFile(fileContents, startOffset + neededSpace);

    /* Even though this file is of type ET_DYN, it could actually be
       an executable.  For instance, Gold produces executables marked
       ET_DYN as does LD when linking with pie. If we move PT_PHDR, it
       has to stay in the first PT_LOAD segment or any subsequent ones
       if they're continuous in memory due to linux kernel constraints
       (see BUGS). Since the end of the file would be after bss, we can't
       move PHDR there, we therefore choose to leave PT_PHDR where it is but
       move enough following sections such that we can add the extra PT_LOAD
       section to it. This PT_LOAD segment ensures the sections at the end of
       the file are mapped into memory for ld.so to process.
       We can't use the approach in rewriteSectionsExecutable()
       since DYN executables tend to start at virtual address 0, so
       rewriteSectionsExecutable() won't work because it doesn't have
       any virtual address space to grow downwards into. */
    if (isExecutable && startOffset > startPage) {
        debug("shifting new PT_LOAD segment by %d bytes to work around a Linux kernel bug\n",
              startOffset - startPage);
        startPage = startOffset;
    }

    /* Add a segment that maps the replaced sections into memory. */
    wri(hdr->e_phoff, sizeof(Elf_Ehdr));
    phdrs.resize(rdi(hdr->e_phnum) + 1);
    wri(hdr->e_phnum, rdi(hdr->e_phnum) + 1);
    Elf_Phdr& phdr = phdrs[rdi(hdr->e_phnum) - 1];
    wri(phdr.p_type, PT_LOAD);
    wri(phdr.p_offset, startOffset);
    wri(phdr.p_vaddr, wri(phdr.p_paddr, startPage));
    wri(phdr.p_filesz, wri(phdr.p_memsz, neededSpace));
    wri(phdr.p_flags, PF_R | PF_W);
    wri(phdr.p_align, getPageSize());

    normalizeNoteSegments();

    /* Write out the replaced sections. */
    Elf_Off curOff = startOffset;
    writeReplacedSections(curOff, startPage, startOffset);
    assert(curOff == startOffset + neededSpace);

    /* Write out the updated program and section headers */
    rewriteHeaders(hdr->e_phoff);
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::rewriteSectionsExecutable()
{
    /* Sort the sections by offset, otherwise we won't correctly find
       all the sections before the last replaced section. */
    sortShdrs();

    /* What is the index of the last replaced section? */
    unsigned int lastReplaced = 0;
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i) {
        std::string sectionName = getSectionName(shdrs[i]);
        if (replacedSections.find(sectionName) != replacedSections.end()) {
            debug("using replaced section '%s'\n", sectionName.c_str());
            lastReplaced = i;
        }
    }

    assert(lastReplaced != 0);

    debug("last replaced is %d\n", lastReplaced);

    /* Try to replace all sections before that, as far as possible.
       Stop when we reach an irreplacable section (such as one of type
       SHT_PROGBITS).  These cannot be moved in virtual address space
       since that would invalidate absolute references to them. */
    assert(lastReplaced + 1 < shdrs.size()); /* !!! I'm lazy. */
    size_t startOffset = rdi(shdrs[lastReplaced + 1].sh_offset);
    Elf_Addr startAddr = rdi(shdrs[lastReplaced + 1].sh_addr);
    std::string prevSection;
    for (unsigned int i = 1; i <= lastReplaced; ++i) {
        Elf_Shdr& shdr(shdrs[i]);
        std::string sectionName = getSectionName(shdr);
        debug("looking at section '%s'\n", sectionName.c_str());
        /* !!! Why do we stop after a .dynstr section? I can't
           remember! */
        if ((rdi(shdr.sh_type) == SHT_PROGBITS && sectionName != ".interp") || prevSection == ".dynstr")
        {
            startOffset = rdi(shdr.sh_offset);
            startAddr = rdi(shdr.sh_addr);
            lastReplaced = i - 1;
            break;
        } else {
            if (replacedSections.find(sectionName) == replacedSections.end()) {
                debug("replacing section '%s' which is in the way\n", sectionName.c_str());
                replaceSection(sectionName, rdi(shdr.sh_size));
            }
        }
        prevSection = sectionName;
    }

    debug("first reserved offset/addr is 0x%x/0x%llx\n", startOffset, (unsigned long long)startAddr);

    assert(startAddr % getPageSize() == startOffset % getPageSize());
    Elf_Addr firstPage = startAddr - startOffset;
    debug("first page is 0x%llx\n", (unsigned long long)firstPage);

    if (rdi(hdr->e_shoff) < startOffset) {
        /* The section headers occur too early in the file and would be
           overwritten by the replaced sections. Move them to the end of the file
           before proceeding. */
        off_t shoffNew = fileContents->size();
        off_t shSize = rdi(hdr->e_shoff) + rdi(hdr->e_shnum) * rdi(hdr->e_shentsize);
        growFile(fileContents, fileContents->size() + shSize);
        wri(hdr->e_shoff, shoffNew);

        /* Rewrite the section header table.  For neatness, keep the
           sections sorted. */
        assert(rdi(hdr->e_shnum) == shdrs.size());
        sortShdrs();
        for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
            *((Elf_Shdr*)(contents + rdi(hdr->e_shoff)) + i) = shdrs[i];
    }

    normalizeNoteSegments();

    /* Compute the total space needed for the replaced sections, the
       ELF header, and the program headers. */
    size_t neededSpace = sizeof(Elf_Ehdr) + phdrs.size() * sizeof(Elf_Phdr);
    for (auto& i : replacedSections)
        neededSpace += roundUp(i.second.size(), sectionAlignment);

    debug("needed space is %d\n", neededSpace);

    /* If we need more space at the start of the file, then grow the
       file by the minimum number of pages and adjust internal
       offsets. */
    if (neededSpace > startOffset) {
        /* We also need an additional program header, so adjust for that. */
        neededSpace += sizeof(Elf_Phdr);
        debug("needed space is %d\n", neededSpace);

        unsigned int neededPages = roundUp(neededSpace - startOffset, getPageSize()) / getPageSize();
        debug("needed pages is %d\n", neededPages);
        if (neededPages * getPageSize() > firstPage) error("virtual address space underrun!");

        firstPage -= neededPages * getPageSize();
        startOffset += neededPages * getPageSize();

        shiftFile(neededPages, firstPage);
    }

    /* Clear out the free space. */
    Elf_Off curOff = sizeof(Elf_Ehdr) + phdrs.size() * sizeof(Elf_Phdr);
    debug("clearing first %d bytes\n", startOffset - curOff);
    memset(contents + curOff, 0, startOffset - curOff);

    /* Write out the replaced sections. */
    writeReplacedSections(curOff, firstPage, 0);
    assert(curOff == neededSpace);

    rewriteHeaders(firstPage + rdi(hdr->e_phoff));
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::normalizeNoteSegments()
{
    /* Break up PT_NOTE segments containing multiple SHT_NOTE sections. This
       is to avoid having to deal with moving multiple sections together if
       one of them has to be replaced. */

    /* We don't need to do anything if no note segments were replaced. */
    bool replaced_note = false;
    for (const auto& i : replacedSections) {
        if (rdi(findSection(i.first).sh_type) == SHT_NOTE) replaced_note = true;
    }
    if (!replaced_note) return;

    size_t orig_count = phdrs.size();
    for (size_t i = 0; i < orig_count; ++i) {
        auto& phdr = phdrs[i];
        if (rdi(phdr.p_type) != PT_NOTE) continue;

        size_t start_off = rdi(phdr.p_offset);
        size_t curr_off = start_off;
        size_t end_off = start_off + rdi(phdr.p_filesz);
        while (curr_off < end_off) {
            /* Find a section that starts at the current offset. If we can't
               find one, it means the SHT_NOTE sections weren't contiguous
               within the segment. */
            size_t size = 0;
            for (const auto& shdr : shdrs) {
                if (rdi(shdr.sh_type) != SHT_NOTE) continue;
                if (rdi(shdr.sh_offset) != curr_off) continue;
                size = rdi(shdr.sh_size);
                break;
            }
            if (size == 0) error("cannot normalize PT_NOTE segment: non-contiguous SHT_NOTE sections");
            if (curr_off + size > end_off)
                error("cannot normalize PT_NOTE segment: partially mapped SHT_NOTE section");

            /* Build a new phdr for this note section. */
            Elf_Phdr new_phdr = phdr;
            wri(new_phdr.p_offset, curr_off);
            wri(new_phdr.p_vaddr, rdi(phdr.p_vaddr) + (curr_off - start_off));
            wri(new_phdr.p_paddr, rdi(phdr.p_paddr) + (curr_off - start_off));
            wri(new_phdr.p_filesz, size);
            wri(new_phdr.p_memsz, size);

            /* If we haven't yet, reuse the existing phdr entry. Otherwise add
               a new phdr to the table. */
            if (curr_off == start_off)
                phdr = new_phdr;
            else
                phdrs.push_back(new_phdr);

            curr_off += size;
        }
    }
    wri(hdr->e_phnum, phdrs.size());
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::rewriteSections()
{
    if (replacedSections.empty()) return;

    for (auto& i : replacedSections)
        debug("replacing section '%s' with size %d\n", i.first.c_str(), i.second.size());

    if (rdi(hdr->e_type) == ET_DYN) {
        debug("this is a dynamic library\n");
        rewriteSectionsLibrary();
    } else if (rdi(hdr->e_type) == ET_EXEC) {
        debug("this is an executable\n");
        rewriteSectionsExecutable();
    } else
        error("unknown ELF type");
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::rewriteHeaders(Elf_Addr phdrAddress)
{
    /* Rewrite the program header table. */

    /* If there is a segment for the program header table, update it.
       (According to the ELF spec, there can only be one.) */
    for (unsigned int i = 0; i < phdrs.size(); ++i) {
        if (rdi(phdrs[i].p_type) == PT_PHDR) {
            phdrs[i].p_offset = hdr->e_phoff;
            wri(phdrs[i].p_vaddr, wri(phdrs[i].p_paddr, phdrAddress));
            wri(phdrs[i].p_filesz, wri(phdrs[i].p_memsz, phdrs.size() * sizeof(Elf_Phdr)));
            break;
        }
    }

    sortPhdrs();

    for (unsigned int i = 0; i < phdrs.size(); ++i)
        *((Elf_Phdr*)(contents + rdi(hdr->e_phoff)) + i) = phdrs[i];

    /* Rewrite the section header table.  For neatness, keep the
       sections sorted. */
    assert(rdi(hdr->e_shnum) == shdrs.size());
    sortShdrs();
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
        *((Elf_Shdr*)(contents + rdi(hdr->e_shoff)) + i) = shdrs[i];

    /* Update all those nasty virtual addresses in the .dynamic
       section.  Note that not all executables have .dynamic sections
       (e.g., those produced by klibc's klcc). */
    auto shdrDynamic = findSection2(".dynamic");
    if (shdrDynamic) {
        auto* dyn = (Elf_Dyn*)(contents + rdi(shdrDynamic->sh_offset));
        unsigned int d_tag;
        for (; (d_tag = rdi(dyn->d_tag)) != DT_NULL; dyn++)
            if (d_tag == DT_STRTAB)
                dyn->d_un.d_ptr = findSection(".dynstr").sh_addr;
            else if (d_tag == DT_STRSZ)
                dyn->d_un.d_val = findSection(".dynstr").sh_size;
            else if (d_tag == DT_SYMTAB)
                dyn->d_un.d_ptr = findSection(".dynsym").sh_addr;
            else if (d_tag == DT_HASH)
                dyn->d_un.d_ptr = findSection(".hash").sh_addr;
            else if (d_tag == DT_GNU_HASH)
                dyn->d_un.d_ptr = findSection(".gnu.hash").sh_addr;
            else if (d_tag == DT_JMPREL) {
                auto shdr = findSection2(".rel.plt");
                if (!shdr) shdr = findSection2(".rela.plt"); /* 64-bit Linux, x86-64 */
                if (!shdr) shdr = findSection2(".rela.IA_64.pltoff"); /* 64-bit Linux, IA-64 */
                if (!shdr) error("cannot find section corresponding to DT_JMPREL");
                dyn->d_un.d_ptr = shdr->sh_addr;
            } else if (d_tag == DT_REL) { /* !!! hack! */
                auto shdr = findSection2(".rel.dyn");
                /* no idea if this makes sense, but it was needed for some
                   program */
                if (!shdr) shdr = findSection2(".rel.got");
                /* some programs have neither section, but this doesn't seem
                   to be a problem */
                if (!shdr) continue;
                dyn->d_un.d_ptr = shdr->sh_addr;
            } else if (d_tag == DT_RELA) {
                auto shdr = findSection2(".rela.dyn");
                /* some programs lack this section, but it doesn't seem to
                   be a problem */
                if (!shdr) continue;
                dyn->d_un.d_ptr = shdr->sh_addr;
            } else if (d_tag == DT_VERNEED)
                dyn->d_un.d_ptr = findSection(".gnu.version_r").sh_addr;
            else if (d_tag == DT_VERSYM)
                dyn->d_un.d_ptr = findSection(".gnu.version").sh_addr;
    }

    /* Rewrite the .dynsym section.  It contains the indices of the
       sections in which symbols appear, so these need to be
       remapped. */
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i) {
        if (rdi(shdrs[i].sh_type) != SHT_SYMTAB && rdi(shdrs[i].sh_type) != SHT_DYNSYM) continue;
        debug("rewriting symbol table section %d\n", i);
        for (size_t entry = 0; (entry + 1) * sizeof(Elf_Sym) <= rdi(shdrs[i].sh_size); entry++) {
            auto* sym = (Elf_Sym*)(contents + rdi(shdrs[i].sh_offset) + entry * sizeof(Elf_Sym));
            unsigned int shndx = rdi(sym->st_shndx);
            if (shndx != SHN_UNDEF && shndx < SHN_LORESERVE) {
                if (shndx >= sectionsByOldIndex.size()) {
                    fprintf(stderr,
                            "warning: entry %d in symbol table refers to a non-existent section, "
                            "skipping\n",
                            shndx);
                    continue;
                }
                std::string section = sectionsByOldIndex.at(shndx);
                assert(!section.empty());
                auto newIndex = findSection3(section);  // inefficient
                // debug("rewriting symbol %d: index = %d (%s) -> %d\n", entry, shndx, section.c_str(),
                // newIndex);
                wri(sym->st_shndx, newIndex);
                /* Rewrite st_value.  FIXME: we should do this for all
                   types, but most don't actually change. */
                if (ELF32_ST_TYPE(rdi(sym->st_info)) == STT_SECTION)
                    wri(sym->st_value, rdi(shdrs[newIndex].sh_addr));
            }
        }
    }
}

static void
setSubstr(std::string& s, unsigned int pos, const std::string& t)
{
    assert(pos + t.size() <= s.size());
    copy(t.begin(), t.end(), s.begin() + pos);
}

static void
concatToRPath(std::string& rpath, const std::string& path)
{
    if (!rpath.empty()) rpath += ":";
    rpath += path;
}

template<ElfFileParams>
void
ElfFile<ElfFileParamNames>::modifyRPath(
        RPathOp op,
        const std::vector<std::string>& allowedRpathPrefixes,
        std::string newRPath)
{
    auto shdrDynamic = findSection(".dynamic");

    /* !!! We assume that the virtual address in the DT_STRTAB entry
       of the dynamic section corresponds to the .dynstr section. */
    auto shdrDynStr = findSection(".dynstr");
    char* strTab = (char*)contents + rdi(shdrDynStr.sh_offset);

    /* Walk through the dynamic section, look for the RPATH/RUNPATH
       entry.

       According to the ld.so docs, DT_RPATH is obsolete, we should
       use DT_RUNPATH.  DT_RUNPATH has two advantages: it can be
       overriden by LD_LIBRARY_PATH, and it's scoped (the DT_RUNPATH
       for an executable or library doesn't affect the search path for
       libraries used by it).  DT_RPATH is ignored if DT_RUNPATH is
       present.  The binutils 'ld' still generates only DT_RPATH,
       unless you use its '--enable-new-dtag' option, in which case it
       generates a DT_RPATH and DT_RUNPATH pointing at the same
       string. */
    std::vector<std::string> neededLibs;
    auto* dyn = (Elf_Dyn*)(contents + rdi(shdrDynamic.sh_offset));
    Elf_Dyn *dynRPath = nullptr, *dynRunPath = nullptr;
    char* rpath = nullptr;
    for (; rdi(dyn->d_tag) != DT_NULL; dyn++) {
        if (rdi(dyn->d_tag) == DT_RPATH) {
            dynRPath = dyn;
            /* Only use DT_RPATH if there is no DT_RUNPATH. */
            if (!dynRunPath) rpath = strTab + rdi(dyn->d_un.d_val);
        } else if (rdi(dyn->d_tag) == DT_RUNPATH) {
            dynRunPath = dyn;
            rpath = strTab + rdi(dyn->d_un.d_val);
        } else if (rdi(dyn->d_tag) == DT_NEEDED)
            neededLibs.push_back(std::string(strTab + rdi(dyn->d_un.d_val)));
    }

    if (op == rpPrint) {
        printf("%s\n", rpath ? rpath : "");
        return;
    }

    if (op == rpShrink && !rpath) {
        debug("no RPATH to shrink\n");
        return;
    }

    /* For each directory in the RPATH, check if it contains any
       needed library. */
    if (op == rpShrink) {
        std::vector<bool> neededLibFound(neededLibs.size(), false);

        newRPath = "";

        for (auto& dirName : splitColonDelimitedString(rpath)) {
            /* Non-absolute entries are allowed (e.g., the special
               "$ORIGIN" hack). */
            if (dirName[0] != '/') {
                concatToRPath(newRPath, dirName);
                continue;
            }

            /* If --allowed-rpath-prefixes was given, reject directories
               not starting with any of the (colon-delimited) prefixes. */
            if (!allowedRpathPrefixes.empty() && !hasAllowedPrefix(dirName, allowedRpathPrefixes)) {
                debug("removing directory '%s' from RPATH because of non-allowed prefix\n",
                      dirName.c_str());
                continue;
            }

            /* For each library that we haven't found yet, see if it
               exists in this directory. */
            bool libFound = false;
            for (unsigned int j = 0; j < neededLibs.size(); ++j)
                if (!neededLibFound[j]) {
                    std::string libName = dirName + "/" + neededLibs[j];
                    try {
                        if (getElfType(readFile(libName, sizeof(Elf32_Ehdr))).machine
                            == rdi(hdr->e_machine)) {
                            neededLibFound[j] = true;
                            libFound = true;
                        } else
                            debug("ignoring library '%s' because its machine type differs\n",
                                  libName.c_str());
                    } catch (SysError& e) {
                        if (e.errNo != ENOENT) throw;
                    }
                }

            if (!libFound)
                debug("removing directory '%s' from RPATH\n", dirName.c_str());
            else
                concatToRPath(newRPath, dirName);
        }
    }

    if (op == rpRemove) {
        if (!rpath) {
            debug("no RPATH to delete\n");
            return;
        }

        auto* dynamic = (Elf_Dyn*)(contents + rdi(shdrDynamic.sh_offset));
        Elf_Dyn* last = dynamic;
        for (; rdi(dynamic->d_tag) != DT_NULL; dynamic++) {
            if (rdi(dynamic->d_tag) == DT_RPATH) {
                debug("removing DT_RPATH entry\n");
                changed = true;
            } else if (rdi(dynamic->d_tag) == DT_RUNPATH) {
                debug("removing DT_RUNPATH entry\n");
                changed = true;
            } else {
                *last++ = *dynamic;
            }
        }
        memset(last, 0, sizeof(Elf_Dyn) * (dynamic - last));
        return;
    }

    if (!forceRPath && dynRPath && !dynRunPath) { /* convert DT_RPATH to DT_RUNPATH */
        wri(dynRPath->d_tag, DT_RUNPATH);
        dynRunPath = dynRPath;
        dynRPath = nullptr;
        changed = true;
    } else if (forceRPath && dynRunPath) { /* convert DT_RUNPATH to DT_RPATH */
        wri(dynRunPath->d_tag, DT_RPATH);
        dynRPath = dynRunPath;
        dynRunPath = nullptr;
        changed = true;
    }

    if (std::string(rpath ? rpath : "") == newRPath) {
        return;
    }

    changed = true;

    /* Zero out the previous rpath to prevent retained dependencies in
       Nix. */
    unsigned int rpathSize = 0;
    if (rpath) {
        rpathSize = strlen(rpath);
        memset(rpath, 'X', rpathSize);
    }

    debug("new rpath is '%s'\n", newRPath.c_str());

    if (newRPath.size() <= rpathSize) {
        strcpy(rpath, newRPath.c_str());
        return;
    }

    /* Grow the .dynstr section to make room for the new RPATH. */
    debug("rpath is too long, resizing...\n");

    std::string& newDynStr = replaceSection(".dynstr", rdi(shdrDynStr.sh_size) + newRPath.size() + 1);
    setSubstr(newDynStr, rdi(shdrDynStr.sh_size), newRPath + '\0');

    /* Update the DT_RUNPATH and DT_RPATH entries. */
    if (dynRunPath || dynRPath) {
        if (dynRunPath) dynRunPath->d_un.d_val = shdrDynStr.sh_size;
        if (dynRPath) dynRPath->d_un.d_val = shdrDynStr.sh_size;
    } else {
        /* There is no DT_RUNPATH entry in the .dynamic section, so we
           have to grow the .dynamic section. */
        std::string& newDynamic = replaceSection(".dynamic", rdi(shdrDynamic.sh_size) + sizeof(Elf_Dyn));

        unsigned int idx = 0;
        for (; rdi(((Elf_Dyn*)newDynamic.c_str())[idx].d_tag) != DT_NULL; idx++)
            ;
        debug("DT_NULL index is %d\n", idx);

        /* Shift all entries down by one. */
        setSubstr(newDynamic, sizeof(Elf_Dyn), std::string(newDynamic, 0, sizeof(Elf_Dyn) * (idx + 1)));

        /* Add the DT_RUNPATH entry at the top. */
        Elf_Dyn newDyn{};
        wri(newDyn.d_tag, forceRPath ? DT_RPATH : DT_RUNPATH);
        newDyn.d_un.d_val = shdrDynStr.sh_size;
        setSubstr(newDynamic, 0, std::string((char*)&newDyn, sizeof(Elf_Dyn)));
    }
}

template<class ElfFile>
static void
changeRPath(
        ElfFile&& elfFile,
        const FileContents& fileContents,
        const std::string& fileName,
        const std::string& RPath)
{
    elfFile.modifyRPath(elfFile.rpSet, {}, RPath);

    if (elfFile.isChanged()) {
        elfFile.rewriteSections();
        writeFile(fileName, elfFile.fileContents);
    }
}

using ElfFile32 =
        ElfFile<Elf32_Ehdr,
                Elf32_Phdr,
                Elf32_Shdr,
                Elf32_Addr,
                Elf32_Off,
                Elf32_Dyn,
                Elf32_Sym,
                Elf32_Verneed,
                Elf32_Versym>;
using ElfFile64 =
        ElfFile<Elf64_Ehdr,
                Elf64_Phdr,
                Elf64_Shdr,
                Elf64_Addr,
                Elf64_Off,
                Elf64_Dyn,
                Elf64_Sym,
                Elf64_Verneed,
                Elf64_Versym>;

void
patchElf(const std::string& fileName, const std::string& RPath)
{
    auto fileContents = readFile(fileName);
    std::string outputFileName2 = outputFileName.empty() ? fileName : outputFileName;

    if (getElfType(fileContents).is32Bit) {
        changeRPath(ElfFile32(fileContents), fileContents, outputFileName2, RPath);
    } else {
        changeRPath(ElfFile64(fileContents), fileContents, outputFileName2, RPath);
    }
}
