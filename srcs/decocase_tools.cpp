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

#define VERSION     "v0.3 (2015/06/25)"

// v0.1 - initial release (type 1 only, not much tested)
// v0.2 - fixes, early support for type 3
// v0.3 - additional type 1 dongle bit remapping maps

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

const int T1_COMB_BIT_TYPES = 4;

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

#define TYPE1_IO_MAPS_COUNT 6
const UINT32 TYPE1_IO_MAPS[TYPE1_IO_MAPS_COUNT] =
{
    MAKE_MAP(0,1,2,3,4,5,6,7),
    MAKE_MAP(0,1,2,3,5,4,6,7), // csuperas
    MAKE_MAP(0,1,3,2,4,5,6,7), // clocknch
    MAKE_MAP(1,0,2,3,4,5,6,7), // cprogolf, cprogolfj
    MAKE_MAP(0,3,2,1,4,5,6,7), // cluckypo
    MAKE_MAP(2,1,0,3,4,5,6,7), // ctisland

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
};

UINT8 decocass_state::decocass_type3_r(offs_t offset)
{
    UINT8 data, save;

    if (0)//if (1 == (offset & 1))
    {
        if (1 == m_type3_pal_19)
        {
            UINT8 *prom = m_prom;//("dongle")->base();
            data = prom[m_type3_ctrs];
            //LOG(3,("%10s 6502-PC: %04x decocass_type3_r(%02x): $%02x <- prom[$%03x]\n", space.machine().time().as_string(6), space.device().safe_pcbase(), offset, data, m_type3_ctrs));
            if (++m_type3_ctrs == 4096)
                m_type3_ctrs = 0;
        }
        else
        {
            if (0 == (offset & E5XX_MASK))
            {
                data = m_bin[offset];//m_mcu->upi41_master_r(space,1);
                //LOG(4,("%10s 6502-PC: %04x decocass_type3_r(%02x): $%02x <- 8041 STATUS\n", space.machine().time().as_string(6), space.device().safe_pcbase(), offset, data));
            }
            else
            {
                data = 0xff;    /* open data bus? */
                //LOG(4,("%10s 6502-PC: %04x decocass_type3_r(%02x): $%02x <- open bus\n", space.machine().time().as_string(6), space.device().safe_pcbase(), offset, data));
            }
        }
    }
    else
    {
        /*
        if (1 == m_type3_pal_19)
        {
            save = data = 0xff;    // open data bus? 
            //LOG(3,("%10s 6502-PC: %04x decocass_type3_r(%02x): $%02x <- open bus", space.machine().time().as_string(6), space.device().safe_pcbase(), offset, data));
        }
        else
        */
        {
            if (1)//if (0 == (offset & E5XX_MASK))
            {
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
            }
            else
            {
                save = 0xff;    /* open data bus? */
                data =
                    m_type3_d0_latch |
                    (BIT(save, 1) << 1) |
                    (BIT(save, 2) << 2) |
                    (BIT(save, 3) << 3) |
                    (BIT(save, 4) << 4) |
                    (BIT(save, 5) << 5) |
                    (BIT(save, 6) << 7) |
                    (BIT(save, 7) << 6);
                //LOG(3,("%10s 6502-PC: %04x decocass_type3_r(%02x): $%02x '%c' <- open bus (D0 replaced with latch)\n", space.machine().time().as_string(6), space.device().safe_pcbase(), offset, data, (data >= 32) ? data : '.'));
                m_type3_d0_latch = save & 1;
            }
        }
    }

    return data;
}

UINT8 decocass_state::decocass_type1_r(offs_t offset)
{
    if (!m_type1_map)
        return 0x00;

    UINT8 data = m_bin[offset];

    if (0)//if (1 == (offset & 1))
    {
        /*
        if (0 == (offset & E5XX_MASK))
            data = m_mcu->upi41_master_r(space,1);
        else
            data = 0xff;
            */
        data = (BIT(data, 0) << 0) | (BIT(data, 1) << 1) | 0x7c;
        //LOG(4,("%10s 6502-PC: %04x decocass_type1_r(%02x): $%02x <- (%s %s)\n",
        //    space.machine().time().as_string(6), space.device().safe_pcbase(), offset, data,
        //    (data & 1) ? "OBF" : "-",
        //    (data & 2) ? "IBF" : "-"));
    }
    else
    {
        UINT8 save;
        UINT8 *prom = m_prom;//space.machine().root_device().memregion("dongle")->base();

        /*
        if (m_firsttime)
        {
            LOG(3,("prom data:\n"));
            for (int promaddr = 0; promaddr < 32; promaddr++)
            {
                if (promaddr % 8 == 0)
                    LOG(3,("  %02x:", promaddr));
                LOG(3,(" %02x%s", prom[promaddr], (promaddr % 8) == 7 ? "\n" : ""));
            }
            m_firsttime = 0;
            m_latch1 = 0;    // reset latch (??)
        }
        */

 /*
        if (0 == (offset & E5XX_MASK))
            data = m_mcu->upi41_master_r(space,0);
        else
            data = 0xff;
*/

        save = data;    /* save the unmodifed data for the latch */

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
    }

    return data;
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
    if (!ReadFile(argv[arg++], "rb", &bin_data, &bin_len))
        return 1;

    //u8* txt_data;
    //int txt_len;
    //if (!ReadFile(argv[arg++], "rt", &txt_data, &txt_len))
    //    return 1;

    u8* prom_data;
    int prom_len;
    if (!ReadFile(argv[arg++], "rb", &prom_data, &prom_len))
        return 1;

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
        //{ T1PROM,T1PROM,T1LATCHINV,T1PROM,T1PROM,T1DIRECT,T1LATCH,T1PROM }; // Explorer
        //UINT8 known_map[8] = { T1PROM,T1LATCHINV,T1PROM,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Astro Fantasia DT-1074-C-0
        //UINT8 known_map[8] = { T1PROM,T1DIRECT,T1PROM,T1DIRECT,T1PROM,T1PROM,T1DIRECT,T1PROM }; // Ninja DT-1021-D-0
        UINT8 known_map[8] = { T1LATCHINV,T1PROM,T1PROM,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Treasure Island DT-1160-A-0
        //UINT8 known_map[8] = { T1LATCHINV,T1PROM,T1PROM,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Treasure Island DT-1160-A-0     // MOD
        //UINT8 known_map[8] = { T1LATCHINV,T1PROM,T1PROM,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Treasure Island DT-1160-B-0
        //UINT8 known_map[8] = { T1PROM, T1LATCHINV, T1PROM, T1DIRECT, T1PROM, T1PROM, T1LATCH, T1PROM }; // Astro Fantasia DT-1070-A-0

        state.reset();
        memcpy(state.m_type1_map, known_map, sizeof(known_map));
        found = true;
    }

    struct f
    {
        static void SetupComb(decocass_state& state, unsigned int comb_no)
        {
            state.m_type1_inmap = TYPE1_IO_MAPS[comb_no % TYPE1_IO_MAPS_COUNT];
            state.m_type1_outmap = TYPE1_IO_MAPS[comb_no % TYPE1_IO_MAPS_COUNT];
            comb_no /= TYPE1_IO_MAPS_COUNT;

            for (int bit = 0; bit < 8; bit++)
            {
                state.m_type1_map[bit] = comb_no % T1_COMB_BIT_TYPES;
                comb_no /= T1_COMB_BIT_TYPES;
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
        //int comb_count = 1024*64;
        int comb_count = (T1_COMB_BIT_TYPES*T1_COMB_BIT_TYPES*T1_COMB_BIT_TYPES*T1_COMB_BIT_TYPES)*(T1_COMB_BIT_TYPES*T1_COMB_BIT_TYPES*T1_COMB_BIT_TYPES*T1_COMB_BIT_TYPES);
        comb_count *= TYPE1_IO_MAPS_COUNT;

        int comb_best_no = -1;
        int comb_best_score = -1;

        printf("Bruteforce bit mapping looking for 'HDR' string (%d combinations)...\n", comb_count);
        for (int comb_no = 0; comb_no < comb_count; comb_no++)
        {
            state.reset();
            f::SetupComb(state, comb_no);

            UINT8 hdr[64];
            for (int i = 0; i < 5; i++)
                hdr[i] = (state.*state.m_dongle_r)(i);

            if (memcmp(hdr+1, "HDRA", 4) == 0 || memcmp(hdr+1, "HDRB", 4) == 0 || memcmp(hdr+1, "HDRC", 4) == 0 || memcmp(hdr+1, "HDRD", 4) == 0)
            {
                found = true;
                for (int i = 5; i < 64; i++)
                    hdr[i] = (state.*state.m_dongle_r)(i);

                int score = 0;
                for (int i = 0; i < 64; i++)
                    score += isalnum(hdr[i]) ? 1 : 0; 
                if (comb_best_score < score)
                {
                    //printf("new best score %d\n", score);
                    comb_best_score = score;
                    comb_best_no = comb_no;
                }
                //break;
            }
        }
        if (found)
            f::SetupComb(state, comb_best_no);
        if (!found)
        {
            printf("Error: couldn't find a suitable bit mapping.\n");
            return 1;
        }
    }
    if (!found && type == DecoCaseType_3)
    {
        int comb_count = TYPE3_SWAP_COUNT;
        int comb_best_no = -1;
        int comb_best_score = -1;

        printf("Bruteforce bit swap mode looking for 'HDR' string (%d combinations)...\n", comb_count);
        for (int comb_no = 0; comb_no < comb_count; comb_no++)
        {
            state.reset();
            state.m_type3_swap = comb_no;

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
        state.m_type3_swap = comb_best_no;

        printf("Using swap mode: %d\n", state.m_type3_swap);
    }

    if (type == DecoCaseType_1)
    {
        printf("Found combination: ");
        for (int bit = 0; bit < 8; bit++)
        {
            const char* names[] = { "DIRECT", "PROM", "LATCH", "LATCHINV", "PROMINV", "DIRECTINV" };
            printf(bit < 7 ? "%s, " : "%s\n", names[state.m_type1_map[bit]]);
        }

        printf("Latched bits                          = $%02X\n", f::GetMaskForType(state, T1LATCH) | f::GetMaskForType(state, T1LATCHINV));
        printf("Latched bits uninverted               = $%02X\n", f::GetMaskForType(state, T1LATCH));
        printf("Latched bits inverted                 = $%02X\n", f::GetMaskForType(state, T1LATCHINV));
        printf("Input bits that are passed uninverted = $%02X\n", f::GetMaskForType(state, T1DIRECT));
        printf("Input bits that are passed inverted   = $00\n");
        printf("Remaining bits for addressing PROM    = $%02X\n", f::GetMaskForType(state, T1PROM));

        printf("Input map                             = (");
        for (int bit = 0; bit < 8; bit++)
            printf(bit < 7 ? "%d, " : "%d", (state.m_type1_inmap >> (bit*3)) & 7);
        printf(")\n");
        printf("Output map                            = (");
        for (int bit = 0; bit < 8; bit++)
            printf(bit < 7 ? "%d, " : "%d", (state.m_type1_outmap >> (bit*3)) & 7);
        printf(")\n");
    }

    /*
    Latched bits                          = $24 (2 latch bits)
    Input bits that are passed uninverted = $08 (1 true bits)
    Input bits that are passed inverted   = $00 (0 inverted bits)
    Remaining bits for addressing PROM    = $D3 (5 bits)
    Latched bit #0:
    - Input bit position  = 2
    - Output bit position = 2
    - Type                = Inverting latch
    Latched bit #1:
    - Input bit position  = 5
    - Output bit position = 5
    - Type                = Non-inverting latch
    */

    // Decode
    u8* bin_decoded = new u8[bin_len];
    for (int i = 0; i < bin_len; i++)
        bin_decoded[i] = (state.*state.m_dongle_r)(i);

    if (type == DecoCaseType_1)
    {
        printf("\nInput PROM:\n");
        DumpMemory(prom_data, prom_len);
    }

    // Dump header for reference
    //printf("\nINPUT BIN:\n");
    printf("\nInput Cassette:\n");
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

    // PROM, LATCHINV, PROM, DIRECT, PROM, PROM, LATCH, PROM

    //   $02 : 0000.0010 --->      0        = $73 (latch = 0)
    //         plpp dpip      plpp dpip
    //   $48 : 0100.1000           1        = $7b (latch = $7b)
    //         plpp dpip      plpp dpip


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
