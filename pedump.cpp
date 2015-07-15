#include <iostream>
#include <cstdlib>

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

using namespace std;

struct IMAGE_DOS_HEADER
{
    unsigned short e_magic;
    unsigned short e_cblp;
    unsigned short e_cp;
    unsigned short e_crlc;
    unsigned short e_cparhdr;
    unsigned short e_minalloc;
    unsigned short e_maxalloc;
    unsigned short e_ss;
    unsigned short e_sp;
    unsigned short e_csum;
    unsigned short e_ip;
    unsigned short e_cs;
    unsigned short e_lfarlc;
    unsigned short e_ovno;
    unsigned short e_res[4];
    unsigned short e_oemid;
    unsigned short e_oeminfo;
    unsigned short e_res2[10];
    unsigned int   e_lfanew;
};

struct IMAGE_FILE_HEADER
{
    unsigned short Machine;
    unsigned short NumberOfSections;
    unsigned int   TimeDateStamp;
    unsigned int   PointerToSymbolTable;
    unsigned int   NumberOfSymbols;
    unsigned short SizeOfOptionalHeader;
    unsigned short Characteristics;
};

struct IMAGE_DATA_DIRECTORY
{
    unsigned int VirtualAddress;
    unsigned int Size;
};

struct IMAGE_OPTIONAL_HEADER
{
    unsigned short Magic;
    unsigned char  MajorLinkerVersion;
    unsigned char  MinorLinkerVersion;
    unsigned int   SizeOfCode;
    unsigned int   SizeOfInitializedData;
    unsigned int   SizeOfUninitializedData;
    unsigned int   AddressOfEntryPoint;
    unsigned int   BaseOfCode;
    unsigned int   BaseOfData;
    unsigned int   ImageBase;
    unsigned int   SectionAlignment;
    unsigned int   FileAlignment;
    unsigned short MajorOperatingSystemVersion;
    unsigned short MinorOperatingSystemVersion;
    unsigned short MajorImageVersion;
    unsigned short MinorImageVersion;
    unsigned short MajorSubsystemVersion;
    unsigned short MinorSubsystemVersion;
    unsigned int   Win32VersionValue;
    unsigned int   SizeOfImage;
    unsigned int   SizeOfHeaders;
    unsigned int   CheckSum;
    unsigned short Subsystem;
    unsigned short DllCharacteristics;
    unsigned int   SizeOfStackReserve;
    unsigned int   SizeOfStackCommit;
    unsigned int   SizeOfHeapReserve;
    unsigned int   SizeOfHeapCommit;
    unsigned int   LoaderFlags;
    unsigned int   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS
{
    unsigned int Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
};

#define OPTIONAL_HEADER_OFFSET ((unsigned int)(&((IMAGE_NT_HEADERS *) nullptr)->OptionalHeader))

struct IMAGE_SECTION_HEADER
{
    unsigned char  Name[8];
    unsigned int   Misc;
    unsigned int   VirtualAddress;
    unsigned int   SizeOfRawData;
    unsigned int   PointerToRawData;
    unsigned int   PointerToRelocations;
    unsigned int   PointerToLinenumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLinenumbers;
    unsigned int   Characteristics;
};

struct IMAGE_EXPORT_DIRECTORY
{
    unsigned int Characteristics;
    unsigned int TimeDateStamp;
    unsigned short MajorVersion;
    unsigned short MinorVersion;
    unsigned int Name;
    unsigned int Base;
    unsigned int NumberOfFunctions;
    unsigned int NumberOfNames;
    unsigned int AddressOfFunctions;     // RVA from base of image
    unsigned int AddressOfNames;         // RVA from base of image
    unsigned int AddressOfNameOrdinals;  // RVA from base of image
};

struct IMAGE_IMPORT_DESCRIPTOR
{
    unsigned int OriginalFirstThunk; // RVA to original unbound IAT
    unsigned int TimeDateStamp; // 0 if not bound,
    unsigned int ForwarderChain; // -1 if no forwarders
    unsigned int Name;
    unsigned int FirstThunk; // RVA to IAT
};

struct IMAGE_IMPORT_BY_NAME
{
    unsigned short Hint;
    char Name[1];
};

#define COFF_SYMBOL_ENTRY_SIZE 18
struct COFF_SYMBOL_ENTRY
{
  union
  {
      char e_name[8];
      struct
      {
          unsigned int e_zeroes;
          unsigned int e_offset;
      } e;
  } e;
  unsigned int e_value;
  short e_scnum;
  unsigned short e_type;
  unsigned char e_sclass;
  unsigned char e_numaux;
};

void
do_read(int fd, void *ptr, size_t size)
{
    char *cur = (char*) ptr;
    while (size > 0) {
        ssize_t r = read(fd, cur, size);
        if (r < 0) {
            cerr << "input error: " << strerror(errno) << endl;
            exit(1);
        }
        if (!r) {
            cerr << "unexpected EOF" << endl;
            exit(1);
        }
        size -= r;
        cur += r;
    }
}

void
do_seek(int fd, long long pos)
{
    if (lseek(fd, pos, SEEK_SET) < 0) {
        cerr << "lseek error" << endl;
        exit(1);
    }
}

const char * const dd_names[16] =
{
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "CERT",
    "RELOC",
    "DEBUG",
    "ARCH",
    "GP",
    "TLS",
    "LOAD",
    "BOUND",
    "IAT",
    "DELAY",
    "CLR",
    "RESERVED"
};

int
main(int argc, char **argv)
{
    if (argc != 2) {
        cerr << "wrong number of args" << endl;
        exit(1);
    }

    int fd = open(argv[1], O_RDONLY, 0);
    if (fd < 0) {
        cerr << "cannot open input file" << endl;
        exit(1);
    }

    IMAGE_DOS_HEADER dos_header;
    do_read(fd, &dos_header, sizeof(dos_header));
    printf("DOS header\n");
    printf("  e_magic: %04x\n", dos_header.e_magic);
    printf("  e_lfanew: %08x\n", dos_header.e_lfanew);

    long long nt_header_offset = dos_header.e_lfanew;
    IMAGE_NT_HEADERS nt_header;
    do_seek(fd, nt_header_offset);
    do_read(fd, &nt_header, sizeof(nt_header));
    printf("NT header\n");
    printf("  Signature: %08x\n", nt_header.Signature);

    printf("  FileHeader.Machine: %04x\n", nt_header.FileHeader.Machine);
    printf("  FileHeader.NumberOfSections: %04x\n", nt_header.FileHeader.NumberOfSections);
    printf("  FileHeader.PointerToSymbolTable: %08x\n", nt_header.FileHeader.PointerToSymbolTable);
    printf("  FileHeader.NumberOfSymbols: %08x\n", nt_header.FileHeader.NumberOfSymbols);
    printf("  FileHeader.SizeOfOptionalHeader: %04x\n", nt_header.FileHeader.SizeOfOptionalHeader);
    printf("  FileHeader.Characteristics: %04x\n", nt_header.FileHeader.Characteristics);

    printf("  OptionalHeader.Magic: %04x\n", nt_header.OptionalHeader.Magic);
    printf("  OptionalHeader.MajorLinkerVersion: %02x\n", nt_header.OptionalHeader.MajorLinkerVersion);
    printf("  OptionalHeader.MinorLinkerVersion: %02x\n", nt_header.OptionalHeader.MinorLinkerVersion);
    printf("  OptionalHeader.SizeOfCode: %08x\n", nt_header.OptionalHeader.SizeOfCode);
    printf("  OptionalHeader.SizeOfInitializedData: %08x\n", nt_header.OptionalHeader.SizeOfInitializedData);
    printf("  OptionalHeader.SizeOfUninitializedData: %08x\n", nt_header.OptionalHeader.SizeOfUninitializedData);
    printf("  OptionalHeader.AddressOfEntryPoint: %08x\n", nt_header.OptionalHeader.AddressOfEntryPoint);
    printf("  OptionalHeader.BaseOfCode: %08x\n", nt_header.OptionalHeader.BaseOfCode);
    printf("  OptionalHeader.BaseOfData: %08x\n", nt_header.OptionalHeader.BaseOfData);
    printf("  OptionalHeader.ImageBase: %08x\n", nt_header.OptionalHeader.ImageBase);
    printf("  OptionalHeader.SectionAlignment: %08x\n", nt_header.OptionalHeader.SectionAlignment);
    printf("  OptionalHeader.FileAlignment: %08x\n", nt_header.OptionalHeader.FileAlignment);
    printf("  OptionalHeader.SizeOfImage: %08x\n", nt_header.OptionalHeader.SizeOfImage);
    printf("  OptionalHeader.SizeOfHeaders: %08x\n", nt_header.OptionalHeader.SizeOfHeaders);
    printf("  OptionalHeader.NumberOfRvaAndSizes: %08x\n", nt_header.OptionalHeader.NumberOfRvaAndSizes);
    for (int i = 0; i < int(nt_header.OptionalHeader.NumberOfRvaAndSizes); ++i) {
        if (nt_header.OptionalHeader.DataDirectory[i].VirtualAddress && nt_header.OptionalHeader.DataDirectory[i].Size) {
            printf("  OptionalHeader.DataDirectory[%d(%s)].VirtualAddress: %08x\n", i, dd_names[i], nt_header.OptionalHeader.DataDirectory[i].VirtualAddress);
            printf("  OptionalHeader.DataDirectory[%d(%s)].Size: %08x\n", i, dd_names[i], nt_header.OptionalHeader.DataDirectory[i].Size);
        }
    }

    long long section_offset = nt_header_offset + nt_header.FileHeader.SizeOfOptionalHeader + OPTIONAL_HEADER_OFFSET;
    printf("SectionOffset: %016llx\n", section_offset);

    char *strings = nullptr;
    if (nt_header.FileHeader.PointerToSymbolTable) {
        long long strings_offset = nt_header.FileHeader.PointerToSymbolTable + nt_header.FileHeader.NumberOfSymbols * COFF_SYMBOL_ENTRY_SIZE;
        unsigned int strings_size = 0;
        do_seek(fd, strings_offset);
        do_read(fd, &strings_size, sizeof(strings_size));
        printf("StringTable size: %d\n", strings_size);
        strings = new char[strings_size];
        do_seek(fd, strings_offset);
        do_read(fd, strings, strings_size);
    }

    IMAGE_SECTION_HEADER *section_headers = new IMAGE_SECTION_HEADER[nt_header.FileHeader.NumberOfSections];
    do_seek(fd, section_offset);
    do_read(fd, section_headers, sizeof(section_headers[0]) * nt_header.FileHeader.NumberOfSections);

    for (int i = 0; i < int(nt_header.FileHeader.NumberOfSections); ++i) {
        if (section_headers[i].Name[0] == '/') {
            int name_offset = 0;
            sscanf((char*) &section_headers[i].Name[1], "%d", &name_offset);
            printf("  Section[%d].Name: %.8s (%s)\n", i, section_headers[i].Name, strings + name_offset);
        } else {
            printf("  Section[%d].Name: %.8s\n", i, section_headers[i].Name);
        }
        printf("  Section[%d].Misc: %08x\n", i, section_headers[i].Misc);
        printf("  Section[%d].VirtualAddress: %08x\n", i, section_headers[i].VirtualAddress);
        printf("  Section[%d].SizeOfRawData: %08x\n", i, section_headers[i].SizeOfRawData);
        printf("  Section[%d].PointerToRawData: %08x\n", i, section_headers[i].PointerToRawData);
        /*
        printf("  Section[%d].PointerToRelocations: %08x\n", i, section_headers[i].PointerToRelocations);
        printf("  Section[%d].PointerToLinenumbers: %08x\n", i, section_headers[i].PointerToLinenumbers);
        */
        printf("  Section[%d].Characteristics: %08x\n", i, section_headers[i].Characteristics);
    }

    // load the sections into memory
    char **section_data = new char*[nt_header.FileHeader.NumberOfSections];
    for (int i = 0; i < int(nt_header.FileHeader.NumberOfSections); ++i) {
        //cerr << "Loading section " << i << endl;
        section_data[i] = nullptr;
        unsigned int sz = section_headers[i].Misc;
        if (section_headers[i].SizeOfRawData > sz) sz = section_headers[i].SizeOfRawData;
        sz = (sz + 0xfff) & ~0xfff;
        if (sz > 0) {
            section_data[i] = new char[sz];
            if (section_headers[i].PointerToRawData && section_headers[i].SizeOfRawData) {
                do_seek(fd, section_headers[i].PointerToRawData);
                do_read(fd, section_data[i], section_headers[i].SizeOfRawData);
            }
        }
    }

    // process exports
    unsigned export_rva = nt_header.OptionalHeader.DataDirectory[0].VirtualAddress;
    unsigned export_size = nt_header.OptionalHeader.DataDirectory[0].Size;
    if (export_rva && export_size) {
        char *export_ptr = nullptr;
        int export_index = -1;
        const IMAGE_SECTION_HEADER *export_section = nullptr;
        for (int i = 0; i < int(nt_header.FileHeader.NumberOfSections); ++i) {
            if (section_headers[i].VirtualAddress <= export_rva
                && export_rva + export_size < section_headers[i].VirtualAddress + section_headers[i].Misc) {
                export_ptr = section_data[i] + (export_rva - section_headers[i].VirtualAddress);
                export_index = i;
                export_section = &section_headers[i];
            }
        }
        if (!export_ptr) abort();
        const IMAGE_EXPORT_DIRECTORY *expdir = (const IMAGE_EXPORT_DIRECTORY*) export_ptr;
        printf("  ExportDir.Characteristics: %08x\n", expdir->Characteristics);
        printf("  ExportDir.TimeDateStamp: %08x\n", expdir->TimeDateStamp);
        printf("  ExportDir.MajorVersion: %04x\n", expdir->MajorVersion);
        printf("  ExportDir.MinorVersion: %04x\n", expdir->MinorVersion);
        const char *name_ptr = nullptr;
        if (expdir->Name) {
            name_ptr = section_data[export_index] + (expdir->Name - export_section->VirtualAddress);
        }
        printf("  ExportDir.Name: %08x (%s)\n", expdir->Name, name_ptr);
        printf("  ExportDir.Base: %08x\n", expdir->Base);
        printf("  ExportDir.NumberOfFunctions: %08x\n", expdir->NumberOfFunctions);
        printf("  ExportDir.NumberOfNames: %08x\n", expdir->NumberOfNames);
        printf("  ExportDir.AddressOfFunctions: %08x\n", expdir->AddressOfFunctions);
        printf("  ExportDir.AddressOfNames: %08x\n", expdir->AddressOfNames);
        printf("  ExportDir.AddressOfNameOrdinals: %08x\n", expdir->AddressOfNameOrdinals);
        const unsigned *addresses = (const unsigned*) (section_data[export_index] + (expdir->AddressOfFunctions - export_section->VirtualAddress));
        for (int i = 0; i < int(expdir->NumberOfFunctions); ++i) {
            printf("    Function[%d]: %08x\n", expdir->Base + i, addresses[i]);
        }
        const unsigned *names = (const unsigned*) (section_data[export_index] + (expdir->AddressOfNames - export_section->VirtualAddress));
        const unsigned short *ordinals = (const unsigned short *) (section_data[export_index] + (expdir->AddressOfNameOrdinals - export_section->VirtualAddress));
        for (int i = 0; i < int(expdir->NumberOfNames); ++i) {
            name_ptr = nullptr;
            if (names[i]) {
                name_ptr = section_data[export_index] + (names[i] - export_section->VirtualAddress);
            }
            printf("    Name[%d]: %08x, %s, %d\n", i, names[i], name_ptr, ordinals[i]);
        }
    }

    unsigned import_rva = nt_header.OptionalHeader.DataDirectory[1].VirtualAddress;
    unsigned import_size = nt_header.OptionalHeader.DataDirectory[1].Size;
    if (import_rva && import_size) {
        char *import_ptr = nullptr;
        int import_index = -1;
        const IMAGE_SECTION_HEADER *import_section = nullptr;
        for (int i = 0; i < int(nt_header.FileHeader.NumberOfSections); ++i) {
            if (section_headers[i].VirtualAddress <= import_rva
                && import_rva + import_size < section_headers[i].VirtualAddress + section_headers[i].Misc) {
                import_ptr = section_data[i] + (import_rva - section_headers[i].VirtualAddress);
                import_index = i;
                import_section = &section_headers[i];
            }
        }
        if (!import_ptr) abort();
        unsigned import_count = import_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (import_size % sizeof(IMAGE_IMPORT_DESCRIPTOR) != 0) abort();
        const IMAGE_IMPORT_DESCRIPTOR *imports = (const IMAGE_IMPORT_DESCRIPTOR*) import_ptr;
        for (int i = 0; i < int(import_count); ++i) {
            printf("  ImportDesc[%d].OriginalFirstThunk: %08x\n", i, imports[i].OriginalFirstThunk);
            printf("  ImportDesc[%d].TimeDateStamp: %08x\n", i, imports[i].TimeDateStamp);
            printf("  ImportDesc[%d].ForwarderChain: %08x\n", i, imports[i].ForwarderChain);
            const char *name_ptr = "";
            if (imports[i].Name) {
                name_ptr = section_data[import_index] + (imports[i].Name - import_section->VirtualAddress);
            }
            printf("  ImportDesc[%d].Name: %08x (%s)\n", i, imports[i].Name, name_ptr);
            printf("  ImportDesc[%d].FirstThunk: %08x\n", i, imports[i].FirstThunk);
            if (imports[i].OriginalFirstThunk) {
                unsigned int *thunks = (unsigned int*) (section_data[import_index] + (imports[i].OriginalFirstThunk - import_section->VirtualAddress));
                for (int j = 0; ; ++j) {
                    printf("    OFT[%d]: %08x\n", j, thunks[j]);
                    if (!thunks[j]) break;
                    const IMAGE_IMPORT_BY_NAME *ibn = (const IMAGE_IMPORT_BY_NAME*)(section_data[import_index] + (thunks[j] - import_section->VirtualAddress));
                    printf("      %d %s\n", ibn->Hint, ibn->Name);
                }
            }
            if (imports[i].FirstThunk) {
                unsigned int *thunks = (unsigned int*) (section_data[import_index] + (imports[i].FirstThunk - import_section->VirtualAddress));
                for (int j = 0; ; ++j) {
                    printf("    FT[%d]: %08x\n", j, thunks[j]);
                    if (!thunks[j]) break;
                }
            }
        }
    }

    unsigned reloc_rva = nt_header.OptionalHeader.DataDirectory[5].VirtualAddress;
    unsigned reloc_size = nt_header.OptionalHeader.DataDirectory[5].Size;
    if (reloc_rva && reloc_size) {
        char *reloc_ptr = nullptr;
        int reloc_index = -1;
        const IMAGE_SECTION_HEADER *reloc_section = nullptr;
        for (int i = 0; i < int(nt_header.FileHeader.NumberOfSections); ++i) {
            if (section_headers[i].VirtualAddress <= reloc_rva
                && reloc_rva + reloc_size <= section_headers[i].VirtualAddress + section_headers[i].Misc) {
                reloc_ptr = section_data[i] + (reloc_rva - section_headers[i].VirtualAddress);
                reloc_index = i;
                reloc_section = &section_headers[i];
            }
        }
        if (!reloc_ptr) abort();
        printf("RelocationSection: %d\n", reloc_index);
        char *cur_ptr = reloc_ptr;
        while (1) {
            unsigned page_rva = *(const unsigned*) cur_ptr;
            unsigned block_size = *(const unsigned*) (cur_ptr + 4);
            printf("  PageRVA: %08x\n", page_rva);
            printf("  BlockSize: %08x\n", block_size);

            int count = (block_size - 8) / 2;
            unsigned short *page_relocs = (unsigned short*) (cur_ptr + 8);
            for (int j = 0; j < count; ++j) {
                printf("    %d %04x\n", (page_relocs[j] >> 12), page_relocs[j] & 0xfff);
            }

            cur_ptr += block_size;
            if (cur_ptr - reloc_ptr >= int(reloc_size)) break;
        }
    }

    close(fd); fd = -1;

    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
