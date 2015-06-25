// Tools for DECO Cassette System
// by @ocornut for Game Preservation Society ( http://gamepres.org )
// code is quick & dirty to do the job, sorry for anyone who has to look into this..

// Input: raw cassette dump (.bin) + PROM key (.rom)
// Output: decrypted file (.decoded.bin)

// Brute-forcing type 1 dongle settings (4^8 combination) instead of parsing the silly .txt file..
// Brute-forcing type 3 swap settings (11 combinations from mame) instead of parsing the silly .txt file..
// MAY BE MISSING SOME COMBINATION
// MAY BE BUGGY. I have just butchered some code from MAME.
// HEURISTIC ISN'T GOOD ENOUGH, CHECK IF GAME WORKS ON REAL HARDWARE (OR EMULATOR)
// Heuristic is: require "HDRA" "HDRB" "HDRC" or "HDRD", from byte 0001 + score with count of alphanumeric character in the 0000..0020 range. Best score wins.

// Using info/code borrowed from MAME - defacto we are the same license as MAME
// see machine/decocass.c, drivers/decocass.c, etc.
// https://github.com/mamedev/mame/blob/bf4f1beaa2cd03b4362e52599ddcf4c4a9c32f13/src/mame/machine/decocass.c#L363

#define VERSION     "v0.4x (2015/06/25)"

// v0.1 - initial release (type 1 only, not much tested)
// v0.2 - fixes, early support for type 3
// v0.3 - additional type 1 dongle bit remapping maps, more brute force options
// v0.4x - encrypt type 1 + find correct decryption setting for type 1 based on encryption match

//-------------------------------------
// USAGE
//-------------------------------------
// Decrypt type 1 deco cassette data:
// - decocase_tools decrypt1 DT-1010-A-0.bin DE-0061-A-0.rom DT-1010-A-0.decoded.bin

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef unsigned char u8;

enum DecoCaseType
{
    DecoCaseType_1,
    DecoCaseType_2,
    DecoCaseType_3,
    DecoCaseType_4,
};

// MAME types
typedef unsigned char UINT8;
typedef int INT32;
typedef unsigned int UINT32;
typedef UINT32 offs_t;
#define BIT(x,n) (((x)>>(n))&1)

#define T1DIRECT 0
#define T1PROM 1
#define T1LATCH 2
#define T1LATCHINV 3
#define T1PROMINV 4 // <-- not in MAME
#define T1DIRECTINV 5 // <-- not in MAME

//const int T1_COMB_BIT_TYPES = 4+2;

/* dongle type #1: jumpers C and D assignments */
#define MAKE_MAP(m0,m1,m2,m3,m4,m5,m6,m7)   \
    ((UINT32)(m0)) | \
    ((UINT32)(m1) << 3) | \
    ((UINT32)(m2) << 6) | \
    ((UINT32)(m3) << 9) | \
    ((UINT32)(m4) << 12) | \
    ((UINT32)(m5) << 15) | \
    ((UINT32)(m6) << 18) | \
    ((UINT32)(m7) << 21)

enum {
    TYPE3_SWAP_01,
    TYPE3_SWAP_12,
    TYPE3_SWAP_13,
    TYPE3_SWAP_24,
    TYPE3_SWAP_25,
    TYPE3_SWAP_34_0,
    TYPE3_SWAP_34_7,
    TYPE3_SWAP_45,
    TYPE3_SWAP_23_56,
    TYPE3_SWAP_56,
    TYPE3_SWAP_67,
    TYPE3_SWAP_COUNT
};

#define TYPE1_IO_MAPS_COUNT 7
const UINT32 TYPE1_IO_MAPS[TYPE1_IO_MAPS_COUNT] =
{
    MAKE_MAP(0,1,2,3,4,5,6,7),
    MAKE_MAP(0,1,2,3,5,4,6,7), // csuperas
    MAKE_MAP(0,1,3,2,4,5,6,7), // clocknch
    MAKE_MAP(1,0,2,3,4,5,6,7), // cprogolf, cprogolfj
    MAKE_MAP(0,3,2,1,4,5,6,7), // cluckypo
    MAKE_MAP(2,1,0,3,4,5,6,7), // ctisland
    MAKE_MAP(0,1,2,4,3,5,6,7), // explorer  // not in mame

};

#define E5XX_MASK   0x02    /* use 0x0e for old style board */

static UINT32 Crc32(const void* data, size_t data_size, UINT32 seed = 0) 
{ 
    static UINT32 crc32_lut[256] = { 0 };
    if (!crc32_lut[1])
    {
        const UINT32 polynomial = 0xEDB88320;
        for (UINT32 i = 0; i < 256; i++) 
        { 
            UINT32 crc = i; 
            for (UINT32 j = 0; j < 8; j++) 
                crc = (crc >> 1) ^ (UINT32(-int(crc & 1)) & polynomial); 
            crc32_lut[i] = crc; 
        }
    }

    seed = ~seed;
    UINT32 crc = seed; 
    const unsigned char* current = (const unsigned char*)data;

    // Known size
    while (data_size--) 
        crc = (crc >> 8) ^ crc32_lut[(crc & 0xFF) ^ *current++]; 
    return ~crc; 
} 

static bool ReadFile(const char* filename, const char* mode, u8** out_data, int* out_len)
{
    FILE* f = fopen(filename, mode);
    if (!f)
    {
        printf("Error: failed to open '%s', aborting.\n", filename);
        return false;
    }
    fseek(f, 0, SEEK_END);
    int len = (int)ftell(f);
    fseek(f, 0, SEEK_SET);
    u8* data = new u8[len+1];
    fread(data, 1, len, f);
    fclose(f);
    data[len] = 0; // Convenient for loading text, unnecessary for binaries

    printf("Input: CRC32: %08X, %d bytes, File: %s\n", Crc32(data, len), len, filename);
    *out_data = data;
    *out_len = len;
    return true;
}

static bool WriteFile(const char* filename, const u8* data, int len)
{
    FILE* f = fopen(filename, "wb");
    if (!f)
    {
        printf("Error: failed to open '%s' to writing, aborting.\n", filename);
        return false;
    }
    fwrite(data, 1, len, f);
    fclose(f);
    printf("Output: CRC32: %08X, %d bytes, File: %s\n", Crc32(data, len), len, filename);
    return true;
}

#define LOG(unknown,args)        printf(args)

struct decocass_state
{
    UINT8*     m_bin;
    UINT8*     m_prom;
    UINT32     m_prom_mask;
    UINT8 (decocass_state::*m_dongle_r)(offs_t);

    INT32     m_firsttime;
    UINT8     m_latch1;

    DecoCaseType    m_type;

    /* dongle type #1 */
    UINT8     m_type1_map[8];
    UINT32    m_type1_inmap;
    UINT32    m_type1_outmap;

    /* dongle type #3: status and patches */
    INT32     m_type3_ctrs;         /* 12 bit counter stage */
    INT32     m_type3_d0_latch;     /* latched 8041-D0 value */
    INT32     m_type3_pal_19;       /* latched 1 for PAL input pin-19 */
    INT32     m_type3_swap;

    decocass_state()
    {
        m_bin = NULL;
        m_prom = NULL;
        m_prom_mask = 0;
        m_firsttime = 0;
        m_latch1 = 0;

        m_type = DecoCaseType_1;

        //m_type1_map = NULL;
        m_type1_inmap = MAKE_MAP(0,1,2,3,4,5,6,7);
        m_type1_outmap = MAKE_MAP(0,1,2,3,4,5,6,7);

        m_type3_ctrs = 0;
        m_type3_d0_latch = 0;
        m_type3_pal_19 = 0;
        m_type3_swap = 0;
    }

    void reset()
    {
        switch (m_type)
        {
        case DecoCaseType_1:
            //LOG(0,("dongle type #1 (DE-0061 own PROM)\n"));
            m_dongle_r = &decocass_state::decocass_type1_r;
            //m_type1_map = NULL;//type1_chwy;//type1_latch_27_pass_3_inv_2_table;
            m_latch1 = 0;
            break;
        case DecoCaseType_3:
            m_dongle_r = &decocass_state::decocass_type3_r;
            m_type3_ctrs = 0;
            m_type3_d0_latch = 0;
            m_type3_pal_19 = 0;
            m_type3_swap = TYPE3_SWAP_67;
            break;
        }
    }

    UINT8 decocass_type1_r(offs_t offset);
    UINT8 decocass_type3_r(offs_t offset);

    bool decocass_type1_encrypt(const UINT8* bin_src_decoded, UINT8* bin_dst_encoded, const UINT8* bin_ref_encoded, int bin_len);
};

UINT8 decocass_state::decocass_type3_r(offs_t offset)
{
    UINT8 data, save;

    save = m_bin[offset];//m_mcu->upi41_master_r(space,0);
    switch (m_type3_swap)
    {
    case TYPE3_SWAP_01:
        data =
            (BIT(save, 1) << 0) |
            (m_type3_d0_latch << 1) |
            (BIT(save, 2) << 2) |
            (BIT(save, 3) << 3) |
            (BIT(save, 4) << 4) |
            (BIT(save, 5) << 5) |
            (BIT(save, 6) << 6) |
            (BIT(save, 7) << 7);
        break;
    case TYPE3_SWAP_12:
        data =
            (m_type3_d0_latch << 0) |
            (BIT(save, 2) << 1) |
            (BIT(save, 1) << 2) |
            (BIT(save, 3) << 3) |
            (BIT(save, 4) << 4) |
            (BIT(save, 5) << 5) |
            (BIT(save, 6) << 6) |
            (BIT(save, 7) << 7);
        break;
    case TYPE3_SWAP_13:
        data =
            (m_type3_d0_latch << 0) |
            (BIT(save, 3) << 1) |
            (BIT(save, 2) << 2) |
            (BIT(save, 1) << 3) |
            (BIT(save, 4) << 4) |
            (BIT(save, 5) << 5) |
            (BIT(save, 6) << 6) |
            (BIT(save, 7) << 7);
        break;
    case TYPE3_SWAP_24:
        data =
            (m_type3_d0_latch << 0) |
            (BIT(save, 1) << 1) |
            (BIT(save, 4) << 2) |
            (BIT(save, 3) << 3) |
            (BIT(save, 2) << 4) |
            (BIT(save, 5) << 5) |
            (BIT(save, 6) << 6) |
            (BIT(save, 7) << 7);
        break;
    case TYPE3_SWAP_25:
        data =
            (m_type3_d0_latch << 0) |
            (BIT(save, 1) << 1) |
            (BIT(save, 5) << 2) |
            (BIT(save, 3) << 3) |
            (BIT(save, 4) << 4) |
            (BIT(save, 2) << 5) |
            (BIT(save, 6) << 6) |
            (BIT(save, 7) << 7);
        break;
    case TYPE3_SWAP_34_0:
        data =
            (m_type3_d0_latch << 0) |
            (BIT(save, 1) << 1) |
            (BIT(save, 2) << 2) |
            (BIT(save, 3) << 4) |
            (BIT(save, 4) << 3) |
            (BIT(save, 5) << 5) |
            (BIT(save, 6) << 6) |
            (BIT(save, 7) << 7);
        break;
    case TYPE3_SWAP_34_7:
        data =
            (BIT(save, 7) << 0) |
            (BIT(save, 1) << 1) |
            (BIT(save, 2) << 2) |
            (BIT(save, 4) << 3) |
            (BIT(save, 3) << 4) |
            (BIT(save, 5) << 5) |
            (BIT(save, 6) << 6) |
            (m_type3_d0_latch << 7);
        break;
    case TYPE3_SWAP_45:
        data =
            m_type3_d0_latch |
            (BIT(save, 1) << 1) |
            (BIT(save, 2) << 2) |
            (BIT(save, 3) << 3) |
            (BIT(save, 5) << 4) |
            (BIT(save, 4) << 5) |
            (BIT(save, 6) << 6) |
            (BIT(save, 7) << 7);
        break;
    case TYPE3_SWAP_23_56:
        data =
            (m_type3_d0_latch << 0) |
            (BIT(save, 1) << 1) |
            (BIT(save, 3) << 2) |
            (BIT(save, 2) << 3) |
            (BIT(save, 4) << 4) |
            (BIT(save, 6) << 5) |
            (BIT(save, 5) << 6) |
            (BIT(save, 7) << 7);
        break;
    case TYPE3_SWAP_56:
        data =
            m_type3_d0_latch |
            (BIT(save, 1) << 1) |
            (BIT(save, 2) << 2) |
            (BIT(save, 3) << 3) |
            (BIT(save, 4) << 4) |
            (BIT(save, 6) << 5) |
            (BIT(save, 5) << 6) |
            (BIT(save, 7) << 7);
        break;
    case TYPE3_SWAP_67:
        data =
            m_type3_d0_latch |
            (BIT(save, 1) << 1) |
            (BIT(save, 2) << 2) |
            (BIT(save, 3) << 3) |
            (BIT(save, 4) << 4) |
            (BIT(save, 5) << 5) |
            (BIT(save, 7) << 6) |
            (BIT(save, 6) << 7);
        break;
    default:
        data =
            m_type3_d0_latch |
            (BIT(save, 1) << 1) |
            (BIT(save, 2) << 2) |
            (BIT(save, 3) << 3) |
            (BIT(save, 4) << 4) |
            (BIT(save, 5) << 5) |
            (BIT(save, 6) << 6) |
            (BIT(save, 7) << 7);
    }
    m_type3_d0_latch = save & 1;
    //LOG(3,("%10s 6502-PC: %04x decocass_type3_r(%02x): $%02x '%c' <- 8041-DATA\n", space.machine().time().as_string(6), space.device().safe_pcbase(), offset, data, (data >= 32) ? data : '.'));

    return data;
}

UINT8 decocass_state::decocass_type1_r(offs_t offset)
{
    if (!m_type1_map)
        return 0x00;

    UINT8 data = m_bin[offset];
    UINT8 *prom = m_prom;//space.machine().root_device().memregion("dongle")->base();
    UINT8 save = data;    /* save the unmodifed data for the latch */

    offs_t promaddr = 0;
    offs_t prommask = m_prom_mask;
    int promshift = 0;

    #define T1MAP(x, m) (((m)>>(x*3))&7)
    for (int i=0;i<8;i++)
    {
        if (m_type1_map[i] == T1PROM || m_type1_map[i] == T1PROMINV) { promaddr |= (((data >> T1MAP(i,m_type1_inmap)) & 1) << promshift); promshift++; }
    }

    //if (promshift!=5)
    //    printf("promshift != 5? (you specified more/less than 5 prom source bits)\n");

    data = 0;
    promshift = 0;

    // PROM, LATCHINV, PROM, DIRECT, PROM, PROM, LATCH, PROM

    for (int i=0;i<8;i++)
    {
        if (m_type1_map[i] == T1PROM)     { data |= (((prom[promaddr] >> promshift) & 1)                << T1MAP(i,m_type1_outmap)); promshift++; }
        if (m_type1_map[i] == T1PROMINV)  { data |= ((1 - ((prom[promaddr] >> promshift) & 1))          << T1MAP(i,m_type1_outmap)); promshift++; }
        if (m_type1_map[i] == T1LATCHINV) { data |= ((1 - ((m_latch1 >> T1MAP(i,m_type1_inmap)) & 1))   << T1MAP(i,m_type1_outmap)); }
        if (m_type1_map[i] == T1LATCH)    { data |= (((m_latch1 >> T1MAP(i,m_type1_inmap)) & 1)         << T1MAP(i,m_type1_outmap)); }
        if (m_type1_map[i] == T1DIRECT)   { data |= (((save >> T1MAP(i,m_type1_inmap)) & 1)             << T1MAP(i,m_type1_outmap)); }
        if (m_type1_map[i] == T1DIRECTINV){ data |= ((1 - ((save >> T1MAP(i,m_type1_inmap)) & 1))       << T1MAP(i,m_type1_outmap)); }
    }

    //LOG(3,("%10s 6502-PC: %04x decocass_type1_r(%02x): $%02x\n",
    //    space.machine().time().as_string(6), space.device().safe_pcbase(), offset, data));

    m_latch1 = save;        /* latch the data for the next A0 == 0 read */

    return data;
}

bool decocass_state::decocass_type1_encrypt(const UINT8* bin_src_decoded, UINT8* bin_dst_encoded, const UINT8* bin_ref_encoded, int bin_len)
{
    UINT8 prom_lut[32];
    memset(prom_lut, -1, 32);
    for (int i = 0; i < 32; i++)
        prom_lut[m_prom[i] & 0x1f] = i;

    UINT8 latch = 0;

    for (int addr = 0; addr < bin_len; addr++)
    {
        UINT8 src = bin_src_decoded[addr];
        UINT8 src_next = (addr+1 < bin_len) ? bin_src_decoded[addr+1] : 0x00; // FIXME: final byte undefined
        UINT8 dst = 0;

        offs_t promval = 0;
        int promshift = 0;
        for (int i=0;i<8;i++)
        {
            if (m_type1_map[i] == T1PROM)   { promval |= (((src >> T1MAP(i,m_type1_outmap))) & 1) << promshift; promshift++; }
        }
        //printf("%04x: promval: %02x @ lut %02x\n", addr, promval, prom_lut[promval]);

        promshift = 0;
        for (int i=0;i<8;i++)
        {
            if (m_type1_map[i] == T1PROM)     { dst |= (((prom_lut[promval] >> promshift) & 1))             << T1MAP(i,m_type1_inmap); promshift++; }
            if (m_type1_map[i] == T1DIRECT)   { dst |= ((src >> T1MAP(i,m_type1_outmap)) & 1)               << T1MAP(i,m_type1_inmap); }
            if (m_type1_map[i] == T1LATCHINV) { dst |= ((1 - (src_next >> T1MAP(i,m_type1_outmap)) & 1))    << T1MAP(i,m_type1_inmap); }
            if (m_type1_map[i] == T1LATCH)    { dst |= ((src_next>> T1MAP(i,m_type1_outmap)) & 1)           << T1MAP(i,m_type1_inmap); } 
        }

        bin_dst_encoded[addr] = dst;
        latch = dst;

        // re-encode mismatch
        if (bin_ref_encoded && bin_ref_encoded[addr] != dst)
            return false;
    }

    return true;
}

void DumpMemory(const u8* data, int len, int columns = 16, int addr_offset = 0)
{
    for (int i = 0; i < len; i += columns)
    {
        printf("%04X: ", i+addr_offset);
        for (int c = 0; c < columns; c++)
            if (i+c < len)
                printf("%02X ", data[i+c]);
            else
                printf("   ");
        printf(" ; ");
        for (int c = 0; c < columns; c++)
            if (i+c < len)
                printf("%c", isprint(data[i+c]) ? data[i+c] : ' ');
        printf("\n");
    }
}

int decocase_decrypt(DecoCaseType type, int argc, char** argv)
{
    int arg = 0;

    u8* bin_data;
    int bin_len;
    const char* bin_name = argv[arg++];
    if (const char* p = strrchr(bin_name, '/')) bin_name = p+1;
    else if (const char* p = strrchr(bin_name, '\\')) bin_name = p+1;
    if (!ReadFile(bin_name, "rb", &bin_data, &bin_len))
        return 1;

    //u8* txt_data;
    //int txt_len;
    //if (!ReadFile(argv[arg++], "rt", &txt_data, &txt_len))
    //    return 1;

    u8* prom_data;
    int prom_len;
    const char* prom_name = argv[arg++];
    if (const char* p = strrchr(prom_name, '/')) prom_name = p+1;
    else if (const char* p = strrchr(prom_name, '\\')) prom_name = p+1;
    if (!ReadFile(prom_name, "rb", &prom_data, &prom_len))
        return 1;

    u8* bin_recoded = new u8[bin_len];
    memset(bin_recoded, 0, bin_len * sizeof(u8));

    decocass_state state;
    state.m_type = type;
    state.m_bin = bin_data;
    state.m_prom = prom_data;
    state.m_prom_mask = prom_len-1; // assume power of two
    state.reset();

    bool found = false;

    // bruteforce the 8-bit map
    // each bit can be either: 
    // we HAVE the information in the text file but it's been stored in an awkward way
    // rather than parsing it I am trying all 4^8 = 64K combinations..

    if (0)
    {
        //{ T1PROM, T1PROM, T1LATCHINV, T1PROM, T1PROM, T1DIRECT, T1LATCH, T1PROM };
        //UINT8 known_map[8] = { T1PROM,T1LATCHINV,T1PROM,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Astro Fantasia DT-1074-C-0
        //UINT8 known_map[8] = { T1PROM,T1DIRECT,T1PROM,T1DIRECT,T1PROM,T1PROM,T1DIRECT,T1PROM }; // Ninja DT-1021-D-0
        //UINT8 known_map[8] = { T1LATCHINV,T1PROM,T1PROM,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Treasure Island DT-1160-A-0
        //UINT8 known_map[8] = { T1LATCHINV,T1PROM,T1PROM,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Treasure Island DT-1160-A-0     // MOD
        //UINT8 known_map[8] = { T1LATCHINV,T1PROM,T1PROM,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Treasure Island DT-1160-B-0
        //UINT8 known_map[8] = { T1PROM, T1LATCHINV, T1PROM, T1DIRECT, T1PROM, T1PROM, T1LATCH, T1PROM }; // Astro Fantasia DT-1070-A-0
        

        //UINT8 known_map[8] = { T1PROM,T1PROM,T1LATCHINV,T1PROM,T1PROM,T1DIRECT,T1LATCH,T1PROM }; // Explorer DT-1180-A-0
        //UINT8 known_map[8] = { T1PROM,T1PROM,T1LATCHINV,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Explorer DT-2181-A-S

        //UINT8 known_map[8] = { T1PROM, T1DIRECT, T1PROM, T1PROM, T1DIRECT, T1PROM, T1DIRECT, T1PROM }; //  (0, 1, 2, 4, 3, 5, 6, 7) // 00-System DT-1902-B-0
        //UINT8 known_map[8] = { T1PROM,T1DIRECT,T1PROM,T1DIRECT,T1PROM,T1PROM,T1DIRECT,T1PROM };
        UINT8 known_map[8] = { T1PROM,T1PROM,T1LATCH,T1DIRECT,T1PROM,T1PROM,T1PROM,T1LATCH }; // 00-System DT-1914-B-0

        state.reset();
        memcpy(state.m_type1_map, known_map, sizeof(known_map));
        found = false;

        //state.m_type1_inmap = state.m_type1_outmap = MAKE_MAP(2,1,0,3,4,5,6,7);
    }

    // explorer encoded
    //  5D 43 5D 4F

    // explorer out (fail)
    //  04 50 44 41 - 1010000, 1000100, 01000001

    // _HDR
    //  ?? 48 44 52 - 1001000, 1000100, 01010010
    //                  xx                 x  x

    enum CrackFlags
    {
        CrackFlags_InOutList                 = 1 << 0,  // <10
        CrackFlags_InOutAll                  = 1 << 1,  // 8^8 = 16777216
        CrackFlags_InOutOneSwap              = 1 << 2,  // 8*2 = 64
        CrackFlags_InOutOneSwapSeparateInOut = 1 << 3,  // 8*4 = 64*64 = 4096
        CrackFlags_Map4                      = 1 << 4,  // 4^8 = 65536
        CrackFlags_Map6                      = 1 << 5,  // 6^8 = 1679616 (two extra settings not in mame, may no exist)
        CrackFlags_DisplayNewBestScore       = 1 << 6,
    };

    struct f
    {
        static void SetupComb(decocass_state& state, unsigned long long comb_no, int flags)
        {
            // in/out mame combinations
            if (flags & CrackFlags_InOutList)
            {
                state.m_type1_inmap = TYPE1_IO_MAPS[comb_no % TYPE1_IO_MAPS_COUNT];
                //comb_no /= TYPE1_IO_MAPS_COUNT;
                state.m_type1_outmap = TYPE1_IO_MAPS[comb_no % TYPE1_IO_MAPS_COUNT];
                comb_no /= TYPE1_IO_MAPS_COUNT;
            }
            
            // in/out all combination
            if (flags & CrackFlags_InOutAll)
            {
                state.m_type1_inmap = state.m_type1_outmap = MAKE_MAP(comb_no&7, (comb_no>>3)&7, (comb_no>>6)&7, (comb_no>>9)&7, (comb_no>>12)&7, (comb_no>>15)&7, (comb_no>>18)&7, (comb_no>>21)&7);
                comb_no /= 8*8*8*8*8*8*8*8;
            }

            // in/out 8*8 (swap two bits)
            if ((flags & CrackFlags_InOutOneSwap) || (flags & CrackFlags_InOutOneSwapSeparateInOut))
            {
                int o[8] = { 0,1,2,3,4,5,6,7 };
                int b0 = comb_no & 7; comb_no /= 8;
                int b1 = comb_no & 7; comb_no /= 8;
                int tmp = o[b0];
                o[b0] = o[b1];
                o[b1] = tmp;
                state.m_type1_inmap = MAKE_MAP(o[0],o[1],o[2],o[3],o[4],o[5],o[6],o[7]);

                if (flags & CrackFlags_InOutOneSwapSeparateInOut)
                {
                    int o[8] = { 0,1,2,3,4,5,6,7 };
                    int b0 = comb_no & 7; comb_no /= 8;
                    int b1 = comb_no & 7; comb_no /= 8;
                    int tmp = o[b0];
                    o[b0] = o[b1];
                    o[b1] = tmp;
                    state.m_type1_outmap = MAKE_MAP(o[0],o[1],o[2],o[3],o[4],o[5],o[6],o[7]);
                }
                else
                {
                    state.m_type1_outmap = state.m_type1_inmap;
                }
            }

            if (flags & CrackFlags_Map4)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    state.m_type1_map[bit] = comb_no % 4;
                    comb_no /= 4;
                }
            }
            if (flags & CrackFlags_Map6)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    state.m_type1_map[bit] = comb_no % 6;
                    comb_no /= 6;
                }
            }

        }

        static UINT8 GetMaskForType(decocass_state& state, UINT8 type)
        {
            UINT8 mask = 0;
            for (int bit = 0; bit < 8; bit++)
                if (state.m_type1_map[bit] == type)
                    mask |= 1 << bit;
            return mask;
        }
    };

    if (!found && type == DecoCaseType_1)
    {
        int flags = 0;
        flags |= CrackFlags_InOutList;
        //flags |= CrackFlags_InOutAll;
        //flags |= CrackFlags_InOutOneSwap;             
        //flags |= CrackFlags_InOutOneSwapSeparateInOut;
        flags |= CrackFlags_Map4;                      
        //flags |= CrackFlags_Map6;                      

        unsigned long long comb_count = 1;
        if (flags & CrackFlags_InOutList)
            comb_count *= TYPE1_IO_MAPS_COUNT;
        if (flags & CrackFlags_InOutAll)
            comb_count *= 8*8*8*8*8*8*8*8; // 8*7*6*5*4*3*2*1;
        if (flags & CrackFlags_InOutOneSwapSeparateInOut)
            comb_count *= 8*8*8*8;
        else if (flags & CrackFlags_InOutOneSwap)
            comb_count *= 8*8;
        if (flags & CrackFlags_Map4)
            comb_count *= (4*4*4*4)*(4*4*4*4);
        else if (flags & CrackFlags_Map6)
            comb_count *= (6*6*6*6)*(6*6*6*6);
        
        unsigned long long comb_best_no = -1;
        int comb_best_score = -1;

        printf("\n");
        printf("Searching %lld combinations...\n", comb_count);
        for (unsigned long long comb_no = 0; comb_no < comb_count; comb_no++)
        {
            if (comb_count > 5000000)
                if ((comb_no % 1000000) == 0)
                    printf("%lld/%lld...\n", comb_no, comb_count);

            state.reset();
            f::SetupComb(state, comb_no, flags);

            UINT8 hdr[96];
            for (int i = 0; i < 5; i++)
                hdr[i] = (state.*state.m_dongle_r)(i);

            //if (memcmp(hdr+1, "HDRA", 4) == 0 || memcmp(hdr+1, "HDRB", 4) == 0 || memcmp(hdr+1, "HDRC", 4) == 0 || memcmp(hdr+1, "HDRD", 4) == 0)
            if (memcmp(hdr+1, "HDR", 3) == 0)
            //if (memcmp(hdr+7, "DEC", 3) == 0)
            {
                found = true;
                for (int i = 5; i < 96; i++)
                    hdr[i] = (state.*state.m_dongle_r)(i);

                int score = 0;
                for (int i = 0; i < 16; i++)
                    score += isalnum(hdr[i]) ? 2 : 0; 
                for (int i = 16; i < 32; i++)
                    score += isdigit(hdr[i]) ? 2 : 0; 
                for (int i = 32; i < 96; i++)
                    score += (hdr[i] == ' ') ? 1 : 0; 

                bool reencode_ok = state.decocass_type1_encrypt(hdr, bin_recoded, bin_data, 96);
                if (!reencode_ok)
                    continue;

                if (comb_best_score <= score)
                {
                    //printf("new best score %d\n", score);
                    //if (flags & CrackFlags_DisplayNewBestScore)
                      //  DumpMemory(hdr, 96, 16);
                    comb_best_score = score;
                    comb_best_no = comb_no;
                }
                //break;
            }
        }
        if (found)
        {
            state.reset();
            f::SetupComb(state, comb_best_no, flags);
        }

        if (!found)
        {
            printf("Error: couldn't find a suitable bit mapping.\n");
            return 1;
        }
    }
    if (!found && type == DecoCaseType_3)
    {
        unsigned long long comb_count = TYPE3_SWAP_COUNT;
        unsigned long long comb_best_no = -1;
        int comb_best_score = -1;

        printf("Searching %lld combinations...\n", comb_count);
        for (unsigned long long comb_no = 0; comb_no < comb_count; comb_no++)
        {
            state.reset();
            state.m_type3_swap = (INT32)comb_no;

            UINT8 hdr[64];
            for (int i = 0; i < 5; i++)
                hdr[i] = (state.*state.m_dongle_r)(i);

            if (memcmp(hdr+1, "HDR", 3) == 0)// || memcmp(hdr+1, "HDRB", 4) == 0 || memcmp(hdr+1, "HDRC", 4) == 0 || memcmp(hdr+1, "HDRD", 4) == 0)
            {
                found = true;
                for (int i = 5; i < 64; i++)
                    hdr[i] = (state.*state.m_dongle_r)(i);

                int score = 0;
                for (int i = 0; i < 64; i++)
                    score += isalnum(hdr[i]) ? 1 : 0; 
                if (comb_best_score < score)
                {
                    //printf("new best score %d for comb %d\n", score, comb_no);
                    comb_best_score = score;
                    comb_best_no = comb_no;
                }
                //break;
            }
        }
        if (!found)
        {
            printf("Error: couldn't find a suitable bit swap mapping.\n");
            return 1;
        }
        state.reset();
        state.m_type3_swap = (INT32)comb_best_no;

        printf("Using swap mode: %d\n", state.m_type3_swap);
    }

    if (type == DecoCaseType_1)
    {
        printf("------------------------------------------------\n");
        printf("Type1 cas '%s' (CRC %08X) prom '%s' (CRC %08X)\ndongle (", bin_name, Crc32(bin_data, bin_len), prom_name, Crc32(prom_data, prom_len));
        for (int bit = 0; bit < 8; bit++)
        {
            const char* names[] = { "DIRECT", "PROM", "LATCH", "LATCHINV", "PROMINV", "DIRECTINV" };
            printf(bit < 7 ? "%s," : "%s", names[state.m_type1_map[bit]]);
        }
        printf(") remap (");
        for (int bit = 0; bit < 8; bit++)
            printf(bit < 7 ? "%d," : "%d", (state.m_type1_inmap >> (bit*3)) & 7);
        printf(")\n");
        printf("------------------------------------------------\n");

        printf("Latched bits                          = $%02X\n", f::GetMaskForType(state, T1LATCH) | f::GetMaskForType(state, T1LATCHINV));
        printf("Latched bits uninverted               = $%02X\n", f::GetMaskForType(state, T1LATCH));
        printf("Latched bits inverted                 = $%02X\n", f::GetMaskForType(state, T1LATCHINV));
        printf("Input bits that are passed uninverted = $%02X\n", f::GetMaskForType(state, T1DIRECT));
        printf("Input bits that are passed inverted   = $00\n");
        printf("Remaining bits for addressing PROM    = $%02X\n", f::GetMaskForType(state, T1PROM));

        printf("Input map                             = (");
        for (int bit = 0; bit < 8; bit++)
            printf(bit < 7 ? "%d," : "%d", (state.m_type1_inmap >> (bit*3)) & 7);
        printf(")\n");
        printf("Output map                            = (");
        for (int bit = 0; bit < 8; bit++)
            printf(bit < 7 ? "%d," : "%d", (state.m_type1_outmap >> (bit*3)) & 7);
        printf(")\n");
    }

    // Decode
    u8* bin_decoded = new u8[bin_len];
    for (int i = 0; i < bin_len; i++)
        bin_decoded[i] = (state.*state.m_dongle_r)(i);

    if (type == DecoCaseType_1)
    {
        printf("\nInput PROM:\n");
        DumpMemory(prom_data, prom_len <= 256 ? prom_len : 256);

        unsigned int prom_cover = 0x00;
        for (int i = 0; i < 32; i++)
        {
            UINT8 d = state.m_prom[i];
            prom_cover |= (1 << (d & 0x1f));
            //printf("PROM[$%02x] = $%02x masked $%02x / (%d%d%d) %d%d%d%d%d\n", i, d, d&0x1f, (d>>7)&1, (d>>6)&1, (d>>5)&1, (d>>4)&1, (d>>3)&1, (d>>2)&1, (d>>1)&1, (d>>0)&1);
        }
        printf("PROM type1 bit coverage $%08X: %s\n", prom_cover, prom_cover == 0xffffffff ? "OK" : "Error");

        if (prom_len > 256)
            printf("[...]\n");
    }

    // Dump header for reference
    //printf("\nINPUT BIN:\n");
    printf("\nInput Cassette: CRC32: %08X, %d bytes\n", Crc32(bin_data, bin_len), bin_len);
    DumpMemory(bin_data, 128);
    printf("[...]\n");

    // Write
    printf("\n");
    if (arg < argc)
        WriteFile(argv[arg++], bin_decoded, bin_len);
    else
        printf("Output: CRC32: %08X, %d bytes\n", Crc32(bin_decoded, bin_len), bin_len);

    //printf("\nOUTPUT BIN (DECODED):\n");
    DumpMemory(bin_decoded, 128);
    printf("[...]\n");

    // Re-encrypt with same key
    if (type == DecoCaseType_1)
    {
        state.decocass_type1_encrypt(bin_decoded, bin_recoded, NULL, bin_len);
        if (memcmp(bin_data, bin_recoded, bin_len) != 0)
        {
            printf("\nReencrypted: CRC32: %08X, %d bytes\n", Crc32(bin_recoded, bin_len), bin_len);
            printf("Error: Reencryption mismatch!\n");
            DumpMemory(bin_recoded, 128);//bin_len);
        }
        else
        {
            printf("\nReencrypted: CRC32: %08X, %d bytes, OK\n", Crc32(bin_recoded, bin_len), bin_len);
        }
    }

    return 0;
}

int main(int argc, char** argv)
{
    printf("------------------------------------------------\n");
    printf(" DECO Cassette System Tools %s\n", VERSION);
    printf(" http://gamepres.org\n");
    printf("------------------------------------------------\n");

    if (argc < 4)
    {
        printf("Decrypt Type 1:\n");
        printf("  decocase_tools decrypt1 <input_bin> <input_prom> [<output_bin>]\n");
        printf("\n");
        //printf("Encrypt Type 1:\n");
        //printf("  decocase_tools encrypt1 <input_bin> <input_prom> [<output_bin>]\n");
        //printf("\n");
        printf("Decrypt Type 3:\n");
        printf("  decocase_tools decrypt3 <input_bin> <input_prom> [<output_bin>]\n");
        return 0;
    }

    if (strcmp(argv[1], "decrypt1") == 0)
    {
        printf("Command: Decrypt Type 1\n");
        int ret = decocase_decrypt(DecoCaseType_1, argc-2, argv+2);
        //getc(stdin);
        return ret;
    }
    else if (strcmp(argv[1], "decrypt3") == 0)
    {
        printf("Command: Decrypt Type 3\n");
        int ret = decocase_decrypt(DecoCaseType_3, argc-2, argv+2);
        //getc(stdin);
        return ret;
    }
    else
    {
        fprintf(stderr, "Unknown command: '%s'\n", argv[1]);
        //getc(stdin);
    }

    return 0;
}
