Tools for DECO Cassette System

for Game Preservation Society ( http://gamepres.org )

https://en.wikipedia.org/wiki/DECO_Cassette_System
"The DECO Cassette System was introduced in December 1980 by Data East. It was the first standardised arcade system that allowed arcade owners to change games."

Current status:

**Decrypt type 1 game data**
- Input: raw cassette dump (.bin) + PROM key (.rom)
- Output: decrypted file (.decoded.bin)
- Brute-forcing dongle settings, verify correct settings by re-encrypting

**Decrypt type 3 game data**
- Input: raw cassette dump (.bin) + PROM key (.rom)
- Output: decrypted file (.decoded.bin)
- Brute-forcing bit swap settings (among 11 combinations supported by MAME - perhaps some are missing? seems ok now. some brute-force bigger space)

