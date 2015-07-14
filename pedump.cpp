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
            cerr << "input error" << endl;
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


    close(fd); fd = -1;

    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
