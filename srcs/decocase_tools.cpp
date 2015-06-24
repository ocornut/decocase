// Tools for DECO Cassette System
// by @ocornut for Game Preservation Society ( http://gamepres.org )
// code is quick & dirty to do the job, sorry for anyone who has to look into this..

// Input: raw cassette dump (.bin) + PROM key (.rom)
// Output: decrypted file (.decoded.bin)

// Brute-forcing dongle settings (4^8 combination) instead of parsing the silly .txt file..
// Heuristic is: require "HDRA" or "HDRB" or "HDRC", from byte 0001 + score with count of alphanumeric character in the 0000..0020 range

// Using info/code borrowed from MAME - defacto we are the same license as MAME
// see machine/decocass.c, drivers/decocass.c, etc.
// https://github.com/mamedev/mame/blob/bf4f1beaa2cd03b4362e52599ddcf4c4a9c32f13/src/mame/machine/decocass.c#L363

#define VERSION     "v0.1 (2015/06/24)"

// v0.1 - initial release (type 1 only, not much tested)

//-------------------------------------
// USAGE
//-------------------------------------
// Decrypt type 1 deco cassette data:
// - decocase_tools decrypt DT-1010-A-0.bin DE-0061-A-0.rom DT-1010-A-0.decoded.bin

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef unsigned char u8;

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
#define T1DIRECTINV 4 // <-- not in MAME

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


#define T1MAP(x, m) (((m)>>(x*3))&7)

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

//static UINT8 type1_latch_27_pass_3_inv_2_table[8] = { T1PROM,T1PROM,T1LATCHINV,T1DIRECT,T1PROM,T1PROM,T1PROM,T1LATCH };
//static UINT8 type1_chwy[8] = { T1PROM,T1PROM,T1DIRECT,T1DIRECT,T1PROM,T1PROM,T1DIRECT,T1PROM };

struct decocass_state
{
    UINT8*     m_bin;
    UINT8*    m_prom;
    UINT8 (decocass_state::*m_dongle_r)(offs_t);

    INT32     m_firsttime;
    UINT8     m_latch1;

    /* dongle type #1 */
    UINT8*    m_type1_map;
    UINT32    m_type1_inmap;
    UINT32    m_type1_outmap;

    decocass_state()
    {
        m_bin = NULL;
        m_prom = NULL;
        m_firsttime = 0;
        m_latch1 = 0;

        m_type1_map = NULL;
        m_type1_inmap = MAKE_MAP(0,1,2,3,4,5,6,7);
        m_type1_outmap = MAKE_MAP(0,1,2,3,4,5,6,7);
    }
    UINT8 decocass_type1_r(offs_t offset);

    void reset_type1()
    {
        //LOG(0,("dongle type #1 (DE-0061 own PROM)\n"));
        m_dongle_r = &decocass_state::decocass_type1_r;
        m_type1_map = NULL;//type1_chwy;//type1_latch_27_pass_3_inv_2_table;
        m_latch1 = 0;
    }
};

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
        offs_t promaddr;
        UINT8 save;
        UINT8 *prom = m_prom;//space.machine().root_device().memregion("dongle")->base();

        /*
        if (m_firsttime)
        {
            LOG(3,("prom data:\n"));
            for (promaddr = 0; promaddr < 32; promaddr++)
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

        promaddr = 0;
        int promshift = 0;

        for (int i=0;i<8;i++)
        {
            if (m_type1_map[i] == T1PROM) { promaddr |= (((data >> T1MAP(i,m_type1_inmap)) & 1) << promshift); promshift++; }
        }

        //if (promshift!=5)
        //    printf("promshift != 5? (you specified more/less than 5 prom source bits)\n");

        data = 0;
        promshift = 0;

        for (int i=0;i<8;i++)
        {
            if (m_type1_map[i] == T1PROM)     { data |= (((prom[promaddr] >> promshift) & 1)                << T1MAP(i,m_type1_outmap)); promshift++; }
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

int decocase_decrypt(int argc, char** argv)
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
    state.m_bin = bin_data;
    state.m_prom = prom_data;
    state.reset_type1();

    bool found = false;

    // bruteforce the 8-bit map
    // each bit can be either: 
    // we HAVE the information in the text file but it's been stored in an awkward way
    // rather than parsing it I am trying all 4^8 = 64K combinations..

    UINT8 type1_map[8];

    if (0)
    {
        //{ T1PROM, T1PROM, T1LATCHINV, T1PROM, T1PROM, T1DIRECT, T1LATCH, T1PROM };
        //{ T1PROM,T1PROM,T1LATCHINV,T1PROM,T1PROM,T1DIRECT,T1LATCH,T1PROM }; // Explorer
        UINT8 known_map[8] = { T1PROM,T1LATCHINV,T1PROM,T1DIRECT,T1PROM,T1PROM,T1LATCH,T1PROM }; // Astro Fantasia DT-1074-C-0
        //10110101

        memcpy(type1_map, known_map, sizeof(type1_map));

        state.reset_type1();
        state.m_type1_map = type1_map;
        found = true;
    }

    struct f
    {
        static void WriteMask(UINT8 type1_map[8], unsigned int comb_no)
        {
            for (int bit = 0; bit < 8; bit++)
            {
                type1_map[bit] = comb_no % 4;
                comb_no /= 4;
            }
        }

        static UINT8 GetMaskForType(UINT8 type1_map[8], UINT8 type)
        {
            UINT8 mask = 0;
            for (int bit = 0; bit < 8; bit++)
                if (type1_map[bit] == type)
                    mask |= 1 << bit;
            return mask;
        }
    };

    if (!found)
    {
        int comb_count = 1024*64;
        //int comb_count = (5*5*5*5)*(5*5*5*5);

        int comb_best_no = -1;
        int comb_best_score = -1;

        printf("Bruteforce bit mapping looking for 'HDR' string (%d combinations)...\n", comb_count);
        for (int comb_no = 0; comb_no < comb_count; comb_no++)
        {
            f::WriteMask(type1_map, comb_no);

            state.reset_type1();
            state.m_type1_map = type1_map;
            UINT8 hdr[64];
            for (int i = 0; i < 5; i++)
                hdr[i] = state.decocass_type1_r(i);

            if (memcmp(hdr+1, "HDRA", 4) == 0 || memcmp(hdr+1, "HDRB", 4) == 0 || memcmp(hdr+1, "HDRC", 4) == 0)
            {
                found = true;
                for (int i = 5; i < 64; i++)
                    hdr[i] = state.decocass_type1_r(i);

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
            f::WriteMask(type1_map, comb_best_no);
    }

    if (!found)
    {
        printf("Error: couldn't find a suitable bit mapping.\n");
        return 1;
    }

    printf("Found combination: ");
    for (int bit = 0; bit < 8; bit++)
    {
        const char* names[] = { "DIRECT", "PROM", "LATCH", "LATCHINV", "DIRECTINV" };
        printf(bit < 7 ? "%s, " : "%s\n", names[type1_map[bit]]);
    }

    printf("Latched bits                          = $%02X\n", f::GetMaskForType(type1_map, T1LATCH) | f::GetMaskForType(type1_map, T1LATCHINV));
    printf("Latched bits uninverted               = $%02X\n", f::GetMaskForType(type1_map, T1LATCH));
    printf("Latched bits inverted                 = $%02X\n", f::GetMaskForType(type1_map, T1LATCHINV));
    printf("Input bits that are passed uninverted = $%02X\n", f::GetMaskForType(type1_map, T1DIRECT));
    printf("Input bits that are passed inverted   = $00\n");
    printf("Remaining bits for addressing PROM    = $%02X\n", f::GetMaskForType(type1_map, T1PROM));

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
        bin_decoded[i] = state.decocass_type1_r(i);

    // Dump header for reference
    //printf("\nINPUT BIN:\n");
    DumpMemory(bin_data, 256);
    printf("[...]\n");

    // Write
    printf("\n");
    if (arg < argc)
        WriteFile(argv[arg++], bin_decoded, bin_len);
    else
        printf("Output: CRC32: %08X, %d bytes\n", Crc32(bin_decoded, bin_len), bin_len);

    //printf("\nOUTPUT BIN (DECODED):\n");
    DumpMemory(bin_decoded, 256);
    printf("[...]\n");

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
        printf("Usage:\n\n");
        printf("- Decrypt Type 1:\n");
        printf("decocase_tools decrypt <input_bin> <input_prom> [<output_bin>]\n");
        return 0;
    }

    if (strcmp(argv[1], "decrypt") == 0)
    {
        printf("Command: Decrypt\n");
        int ret = decocase_decrypt(argc-2, argv+2);
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
