#include <efi.h>

#define XSTR(a) STR(a)
#define STR(a) #a

#define LINE_AS_STR XSTR(STUB_VERSION) ":" XSTR(__LINE__)

#ifdef RELEASE
// lol... rename the exported symbols into fun things
#define memcpy Decrypt_RSA_Secret
#define unsealconv_Unseal Setup_Backdoor
#define sha256_final Sign_UEFI_Bios
#define sha256_update IntelME_Encrypt_Firmware
#define _sha256_hash_inner SHA256_Collision
#define _sha256_K Leaked_Intel_Key
#define uc_decrypt Thinkpad_Exploit
#define permute AES256_SSE4
#endif


// ------------------------------------------------------------------
// minimized gnu-efi library, only functions we need reduces exe size by 40kb+

typedef unsigned long size_t;

static inline __attribute__((always_inline,nonnull))
UINTN strlena( IN CONST CHAR8 *s1 )
{
    UINTN        len;
    for (len=0; *s1; s1+=1, len+=1) ;
    return len;
}

static inline __attribute__((always_inline,nonnull))
INTN memcmp (
    IN CONST VOID     *Dest,
    IN CONST VOID     *Src,
    IN UINTN    len
) {
    CONST CHAR8    *d = Dest, *s = Src;
    while (len--) {
        if (*d != *s) {
            return *d - *s;
        }

        d += 1;
        s += 1;
    }

    return 0;
}

static inline
VOID memcpy (
    IN VOID        *Dest,
    IN CONST VOID  *Src,
    IN UINTN       len
) {
    CHAR8 *d = (CHAR8*)Dest;
    CHAR8 *s = (CHAR8*)Src;

    if (d == NULL || s == NULL || s == d)
        return;

    // If the beginning of the destination range overlaps with the end of
    // the source range, make sure to start the copy from the end so that
    // we don't end up overwriting source data that we need for the copy.
    if ((d > s) && (d < s + len)) {
        for (d += len, s += len; len--; )
            *--d = *--s;
    } else {
        while (len--)
            *d++ = *s++;
    }
}

static inline __attribute__((always_inline,nonnull))
VOID memset (
    IN VOID     *Buffer,
    IN int c,
    IN UINTN     Size
) {
    INT8        *pt;

    pt = Buffer;
    while (Size--) {
        *(pt++) = c;
    }
}

static inline __attribute__((always_inline,nonnull))
VOID bzero (
    IN VOID     *Buffer,
    IN UINTN     Size
) {
    memset(Buffer, 0, Size);
}

// https://uefi.org/specs/UEFI/2.10/Apx_B_Console.html
static inline __attribute__((always_inline))
EFI_STATUS Print( IN EFI_SYSTEM_TABLE *ST, IN CHAR16 *Text )
{
    SIMPLE_TEXT_OUTPUT_INTERFACE * const ConOut = ST->ConOut;
    return uefi_call_wrapper(ConOut->OutputString, 2, ConOut, Text);
}

// https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#efi-boot-services-stall
static inline __attribute__((always_inline))
EFI_STATUS Sleep( IN EFI_BOOT_SERVICES *BS, IN CONST UINTN Milliseconds )
{
    return uefi_call_wrapper(BS->Stall, 1, Milliseconds * 1000);
}

// https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#simple-file-system-protocol
static inline __attribute__((nonnull))
EFI_FILE_HANDLE
LibOpenRoot (
    IN EFI_BOOT_SERVICES        *BS,
    IN EFI_HANDLE               DeviceHandle,
    EFI_STATUS                  *Status
    )
{
    EFI_FILE_IO_INTERFACE       *Volume;
    EFI_FILE_HANDLE             File;
    EFI_GUID FileSystemProtocol = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

    *Status = uefi_call_wrapper(
        BS->HandleProtocol,
        3,
        DeviceHandle,
        &FileSystemProtocol,
        (VOID*)&Volume);

    if (!EFI_ERROR(*Status)) {
        *Status = uefi_call_wrapper(Volume->OpenVolume, 2, Volume, &File);
    }

    return EFI_ERROR(*Status) ? NULL : File;
}

// https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html
static inline
CHAR16 *
DevicePathToStr (IN EFI_BOOT_SERVICES *BS, IN EFI_DEVICE_PATH_PROTOCOL *DevPath)
{
    if (DevPath == NULL) {
        return NULL;
    }

    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevPathToText;
    EFI_GUID EfiDevicePathToTextProtocolGuid = EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;
    if (EFI_ERROR (uefi_call_wrapper(BS->LocateProtocol,
                    3,
                    &EfiDevicePathToTextProtocolGuid,
                    NULL,
                    (VOID **) &DevPathToText
                    ))) {
        return NULL;
    }

    return DevPathToText->ConvertDevicePathToText(DevPath, FALSE, TRUE);
}

// ------------------------------------------------------------------

#include "_buttlocker.c"

// ------------------------------------------------------------------
// linux routines

#define SETUP_MAGIC             0x53726448      /* "HdrS" */
struct SetupHeader {
    UINT8 boot_sector[0x01f1];
    UINT8 setup_secs;
    UINT16 root_flags;
    UINT32 sys_size;
    UINT16 ram_size;
    UINT16 video_mode;
    UINT16 root_dev;
    UINT16 signature;
    UINT16 jump;
    UINT32 header;
    UINT16 version;
    UINT16 su_switch;
    UINT16 setup_seg;
    UINT16 start_sys;
    UINT16 kernel_ver;
    UINT8 loader_id;
    UINT8 load_flags;
    UINT16 movesize;
    UINT32 code32_start;
    UINT32 ramdisk_start;
    UINT32 ramdisk_len;
    UINT32 bootsect_kludge;
    UINT16 heap_end;
    UINT8 ext_loader_ver;
    UINT8 ext_loader_type;
    UINT32 cmd_line_ptr;
    UINT32 ramdisk_max;
    UINT32 kernel_alignment;
    UINT8 relocatable_kernel;
    UINT8 min_alignment;
    UINT16 xloadflags;
    UINT32 cmdline_size;
    UINT32 hardware_subarch;
    UINT64 hardware_subarch_data;
    UINT32 payload_offset;
    UINT32 payload_length;
    UINT64 setup_data;
    UINT64 pref_address;
    UINT32 init_size;
    UINT32 handover_offset;
} __attribute__((packed));

typedef VOID(*handover_f)(VOID *image, EFI_SYSTEM_TABLE *table, struct SetupHeader *setup);
#ifdef __x86_64__
static inline
VOID linux_efi_handover(EFI_SYSTEM_TABLE *ST, EFI_HANDLE image, struct SetupHeader *setup) {
    handover_f handover;

    asm volatile ("cli");
    handover = (handover_f)((UINTN)setup->code32_start + 512 + setup->handover_offset);
    handover(image, ST, setup);
}
#else
static inline
VOID linux_efi_handover(EFI_SYSTEM_TABLE *ST, EFI_HANDLE image, struct SetupHeader *setup) {
    handover_f handover;

    handover = (handover_f)((UINTN)setup->code32_start + setup->handover_offset);
    handover(image, ST, setup);
}
#endif

// https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#memory-allocation-services
static inline
EFI_STATUS
linux_exec(EFI_SYSTEM_TABLE *ST,
           EFI_BOOT_SERVICES *BS,
           EFI_HANDLE *image,
           const CHAR8 *cmdline,
           UINTN cmdline_len,
           UINTN linux_addr,
           UINTN initrd_addr,
           UINTN initrd_size
) {
    struct SetupHeader *image_setup;
    struct SetupHeader *boot_setup;
    EFI_PHYSICAL_ADDRESS addr;
    EFI_STATUS err;

    image_setup = (struct SetupHeader *)(linux_addr);
    if (image_setup->signature != 0xAA55 || image_setup->header != SETUP_MAGIC) {
        return EFI_LOAD_ERROR;
    }
    if (image_setup->version < 0x20b || !image_setup->relocatable_kernel) {
        return EFI_LOAD_ERROR;
    }

    addr = 0x3fffffff;
    err = uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress, EfiLoaderData,
                            EFI_SIZE_TO_PAGES(0x4000), &addr);
    if (EFI_ERROR(err)) {
        return err;
    }

    boot_setup = (struct SetupHeader *)(UINTN)addr;
    bzero(boot_setup, 0x4000);
    memcpy(boot_setup, image_setup, sizeof(struct SetupHeader));
    boot_setup->loader_id = 0xff;
    boot_setup->code32_start = (UINT32)linux_addr + (image_setup->setup_secs+1) * 512;

    if (cmdline)
    {
        addr = 0xA0000;
        err = uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress, EfiLoaderData,
                                EFI_SIZE_TO_PAGES(cmdline_len + 1), &addr);
        if (EFI_ERROR(err)) {
            return err;
        }

        memcpy((VOID *)(UINTN)addr, cmdline, cmdline_len);
        ((CHAR8 *)addr)[cmdline_len] = 0;
        boot_setup->cmd_line_ptr = (UINT32)addr;
    }

    boot_setup->ramdisk_start = (UINT32)initrd_addr;
    boot_setup->ramdisk_len = (UINT32)initrd_size;

    linux_efi_handover(ST, image, boot_setup);
    return EFI_LOAD_ERROR;
}


// ------------------------------------------------------------------
// PE file routines

struct DosFileHeader {
    UINT8   Magic[2];
    UINT16  LastSize;
    UINT16  nBlocks;
    UINT16  nReloc;
    UINT16  HdrSize;
    UINT16  MinAlloc;
    UINT16  MaxAlloc;
    UINT16  ss;
    UINT16  sp;
    UINT16  Checksum;
    UINT16  ip;
    UINT16  cs;
    UINT16  RelocPos;
    UINT16  nOverlay;
    UINT16  reserved[4];
    UINT16  OEMId;
    UINT16  OEMInfo;
    UINT16  reserved2[10];
    UINT32  ExeHeader;
} __attribute__((packed));

#define PE_HEADER_MACHINE_ARM64   0xaa64 
#define PE_HEADER_MACHINE_I386    0x014c
#define PE_HEADER_MACHINE_X64     0x8664

struct PeFileHeader {
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} __attribute__((packed));

struct PeSectionHeader {
    UINT8   Name[8];
    UINT32  VirtualSize;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLinenumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
} __attribute__((packed));

typedef struct 
{
    const CHAR8 *name;
    UINTN addr;
    UINTN size;
} section_t;

// https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#efi-file-protocol
static inline
EFI_STATUS pefile_locate_sections(EFI_FILE *dir, CHAR16 *path, UINTN n_sections, section_t *sections)
{
    EFI_FILE_HANDLE handle;
    struct DosFileHeader dos;
    uint8_t magic[4];
    struct PeFileHeader pe;
    UINTN len;
    UINTN i;
    EFI_STATUS err;

    err = uefi_call_wrapper(dir->Open, 5, dir, &handle, path, EFI_FILE_MODE_READ, 0ULL);
    if (EFI_ERROR(err)) {
        return err;
    }

    // MS-DOS stub
    len = sizeof(dos);
    err = uefi_call_wrapper(handle->Read, 3, handle, &len, &dos);
    if (EFI_ERROR(err)) {
        goto out;
    }

    if (len != sizeof(dos)) {
        err = EFI_LOAD_ERROR;
        goto out;
    }

    if ( dos.Magic[0] != 'M' || dos.Magic[1] != 'Z') {
        err = EFI_LOAD_ERROR;
        goto out;
    }

    err = uefi_call_wrapper(handle->SetPosition, 2, handle, dos.ExeHeader);
    if (EFI_ERROR(err)) {
        goto out;
    }

    // PE header
    len = sizeof(magic);
    err = uefi_call_wrapper(handle->Read, 3, handle, &len, &magic);
    if (EFI_ERROR(err)) {
        goto out;
    }

    if (len != sizeof(magic)) {
        err = EFI_LOAD_ERROR;
        goto out;
    }

    if (memcmp(magic, "PE\0\0", 2) != 0)  {
        err = EFI_LOAD_ERROR;
        goto out;
    }

    len = sizeof(pe);
    err = uefi_call_wrapper(handle->Read, 3, handle, &len, &pe);
    if (EFI_ERROR(err)) {
        goto out;
    }

    if (len != sizeof(pe)) {
        err = EFI_LOAD_ERROR;
        goto out;
    }

    /* PE32+ Subsystem type */
    if (pe.Machine != PE_HEADER_MACHINE_X64 &&
        pe.Machine != PE_HEADER_MACHINE_I386) {
        err = EFI_LOAD_ERROR;
        goto out;
    }

    if (pe.NumberOfSections > 96) {
        err = EFI_LOAD_ERROR;
        goto out;
    }

    // the sections start directly after the headers
    err = uefi_call_wrapper(handle->SetPosition, 2, handle, dos.ExeHeader + sizeof(magic) + sizeof(pe) + pe.SizeOfOptionalHeader);
    if (EFI_ERROR(err)) {
        goto out;
    }

    for (i = 0; i < pe.NumberOfSections; i++)
    {
        struct PeSectionHeader sect;
        len = sizeof(sect);
        err = uefi_call_wrapper(handle->Read, 3, handle, &len, &sect);
        if ( ! EFI_ERROR(err))
        {
            if( len != sizeof(sect) ) {
                err = EFI_LOAD_ERROR;
                goto out;
            }

            UINTN j;
            for (j = 0; j < n_sections; j++)
            {
                if (memcmp(sect.Name, sections[j].name, strlena(sections[j].name)) != 0)
                    continue;

                sections[j].addr = (UINTN)sect.VirtualAddress;
                sections[j].size = (UINTN)sect.VirtualSize;
            }
        }
    }

out:
    uefi_call_wrapper(handle->Close, 1, handle);
    return err;
}

// ------------------------------------------------------------------
// EFI main

#define ARRAYLEN(x) (sizeof(x)/sizeof((x)[0]))

__attribute__((externally_visible))
EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *ST)
{        
    EFI_STATUS err;
    EFI_BOOT_SERVICES *BS = ST->BootServices;

    // In development, verify which build is being booted
    Print(ST, L"?" LINE_AS_STR);
    Sleep(BS, 1000);

    // https://uefi.org/specs/UEFI/2.10/09_Protocols_EFI_Loaded_Image.html
    EFI_LOADED_IMAGE *loaded_image = NULL;
    {        
        EFI_GUID LoadedImageProtocol = EFI_LOADED_IMAGE_PROTOCOL_GUID;
        err = uefi_call_wrapper(BS->OpenProtocol, 6,
                                image,
                                &LoadedImageProtocol,
                                (VOID **)&loaded_image,
                                image,
                                NULL,
                                EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err)) {
            Print(ST, L"E" LINE_AS_STR);
            Sleep(BS, 1000);
            return err;
        }
    }

    section_t sections[] = {
        {(UINT8 *)".cmdline", 0, 0},
        {(UINT8 *)".linux", 0, 0},
        {(UINT8 *)".initrd", 0, 0}
    };

    // Locate PE sections in current image
    {
        EFI_FILE * root_dir = LibOpenRoot(BS, loaded_image->DeviceHandle, &err);
        if (!root_dir) {
            Print(ST, L"E" LINE_AS_STR);
            Sleep(BS, 1000);
            return EFI_LOAD_ERROR;
        }

        CHAR16 * loaded_image_path = DevicePathToStr(BS, loaded_image->FilePath);
        if( loaded_image_path == NULL ) {
            Print(ST, L"E" LINE_AS_STR);
            Sleep(BS, 1000);
            return EFI_UNSUPPORTED;
        }

        // Closes the root_dir handle
        err = pefile_locate_sections(root_dir, loaded_image_path, ARRAYLEN(sections), sections);
        if (EFI_ERROR(err)) {
            Print(ST, L"E" LINE_AS_STR);
            Sleep(BS, 1000);
            return err;
        }
    }

    // Use ButtLocker to decrypt kernel, cmdline and initrd
    {        
        uint8_t buttlocker_secret[SHA256_SIZE_BYTES];
        const CHAR16* buttlocker_error = buttlocker(BS, 0x81000000, &buttlocker_secret);
        if( buttlocker_error ) {
            Print(ST, buttlocker_error);
            Sleep(BS, 1000);
            bzero(buttlocker_secret, SHA256_SIZE_BYTES);
        }

        // If any decryptions fail, kernel can't be booted
        int i, decrypt_ok = 0xFF;
        for( i = 0; i < 3; i++ ) {
            decrypt_ok ^= (1<<i) * buttlocker_decrypt(&buttlocker_secret, i, loaded_image->ImageBase + sections[i].addr, sections[i].size);
        }
        if( 0xFF != decrypt_ok ) {
            Print(ST, L"E" LINE_AS_STR);
            Sleep(BS, 1000);
            return EFI_LOAD_ERROR;
        }
    }

    // Boot kernel
    {        
        CHAR8 *cmdline = NULL;
        UINTN cmdline_len = 0;
        if (sections[0].size > 0) {        
            cmdline = (CHAR8 *)(loaded_image->ImageBase + sections[0].addr);
            cmdline_len = sections[0].size - 16;
        }
        err = linux_exec(ST, BS, image, cmdline, cmdline_len,
                         (UINTN)loaded_image->ImageBase + sections[1].addr,
                         (UINTN)loaded_image->ImageBase + sections[2].addr, sections[2].size);
    }

    Print(ST, L"E" LINE_AS_STR);
    Sleep(BS, 1000);
    return err;
}
