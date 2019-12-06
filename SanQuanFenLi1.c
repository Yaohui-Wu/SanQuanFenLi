// Usage (encryption): SanQuanFenLi -C/-c plaintext.file ciphertext.file password
// Usage (decryption): SanQuanFenLi -P/-p ciphertext.file plaintext.file password
// Compiled on MacOS, Linux and *BSD.
// Talk is so easy, show you my GOD. WOW!

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// The data of 256 values of key table that you can set randomly,
// yet you can freely to change to key table of 65536 values that you can set randomly,
// you can also freely to change to key table of 4294967296 values that you can set randomly,
// even if to change to key table of 18446744073709551616 values is no problem, which is only limited by the memory of your machine. WOW!
unsigned char aucKeyTable[256] = {
    44, 34, 24, 14, 4, 42, 32, 22, 12, 2, 19, 7, 47, 17, 5, 43, 37, 29, 13, 3, 41, 31, 23, 11, 0, 1, 6, 8, 9, 10, 15, 16, 18, 20, 21, 25, 26, 27, 28, 30, 33, 35, 36, 38, 39, 40, 45, 46, 48, 49,
    94, 84, 74, 64, 54, 92, 82, 72, 62, 52, 79, 59, 97, 89, 73, 67, 53, 91, 83, 71, 61, 51, 50, 55, 56, 57, 58, 60, 63, 65, 66, 68, 69, 70, 75, 76, 77, 78, 80, 81, 85, 86, 87, 88, 90, 93, 95, 96, 98, 99,
    144, 134, 124, 114, 104, 142, 132, 122, 112, 102, 139, 107, 137, 127, 103, 149, 131, 123, 113, 101, 100, 105, 106, 108, 109, 110, 111, 115, 116, 117, 118, 119, 120, 121, 125, 126, 128, 129, 130, 133, 135, 136, 138, 140, 141, 143, 145, 146, 147, 148,
    194, 184, 174, 164, 154, 192, 182, 172, 162, 152, 199, 197, 193, 179, 167, 157, 191, 181, 173, 163, 151, 150, 153, 155, 156, 158, 159, 160, 161, 165, 166, 168, 169, 170, 171, 175, 176, 177, 178, 180, 183, 185, 186, 187, 188, 189, 190, 195, 196, 198,
    254, 244, 234, 224, 214, 204, 252, 242, 232, 222, 212, 202, 239, 227, 251, 241, 233, 223, 211, 209, 200, 201, 203, 205, 206, 207, 208, 210, 213, 215, 216, 217, 218, 219, 220, 221, 225, 226, 228, 229, 230, 231, 235, 236, 237, 238, 240, 243, 245, 246, 247, 248, 249, 250, 253, 255
};

// The data of 256 values of avalanche table that you can set randomly.
// The number of bytes of the value of the avalanche table can be larger with you, such as 8 bytes, 16 bytes, 32 bytes, and so on.
// It can even be extended to infinity, which is just subject to your machine's memory. WOW!
// The capacity of avalanche tables can grow with you, such as 65536, 4294967296, 184467440737095516, etc.
// It can even be extended to infinity, which is just subject to your machine's memory. WOW!
unsigned int auiAvalancheTable[256] = {
    0x46733436, 0x59763833, 0x50673432, 0x44623937, 0x41783435, 0x42663438, 0x43713135, 0x51743039, 0x4C7a3737, 0x577a3635, 0x58693139, 0x59753336, 0x46733733, 0x45683235, 0x42753730, 0x55743235,
    0x55643533, 0x47653334, 0x55623237, 0x50673036, 0x54653739, 0x42643331, 0x4E6c3738, 0x58633838, 0x56673733, 0x41763032, 0x4F633934, 0x4C613136, 0x456c3935, 0x566e3232, 0x4A713730, 0x49753538,
    0x4A623333, 0x58623832, 0x4B753039, 0x436b3731, 0x51703736, 0x4E773836, 0x5A753137, 0x57713232, 0x4A663630, 0x4D783439, 0x54663832, 0x54793136, 0x4B793238, 0x4E6d3731, 0x4D763638, 0x4C6e3233,
    0x536d3631, 0x506d3530, 0x54693738, 0x53683735, 0x42683036, 0x4C6b3231, 0x44673239, 0x4C6d3736, 0x497a3939, 0x46633336, 0x58733131, 0x4F703636, 0x5A683232, 0x417a3135, 0x43643434, 0x55753734,
    0x42683131, 0x45613830, 0x57673537, 0x42773137, 0x596b3134, 0x54673135, 0x4D793639, 0x48783032, 0x4E683734, 0x4F6d3037, 0x446c3233, 0x4B743631, 0x5A613137, 0x4F763737, 0x4B773937, 0x566f3939,
    0x54683131, 0x4C753237, 0x46613837, 0x486b3230, 0x56633534, 0x5A703834, 0x546b3031, 0x486b3939, 0x54703037, 0x56653036, 0x4C7a3338, 0x47793136, 0x44633534, 0x4A6a3737, 0x46723237, 0x58683936,
    0x53723533, 0x5A613237, 0x53653435, 0x4D6b3032, 0x45763139, 0x4B703936, 0x4C653332, 0x456d3934, 0x4D643532, 0x4C753231, 0x486f3833, 0x43633034, 0x54763833, 0x47753837, 0x506a3831, 0x43783532,
    0x4D6e3936, 0x54683333, 0x55753934, 0x51753235, 0x466d3838, 0x57643235, 0x59793135, 0x56653033, 0x4E723134, 0x5A7a3939, 0x52633138, 0x41673139, 0x4A6f3633, 0x56713936, 0x58683032, 0x49783133,
    0x49653438, 0x57683331, 0x4D6d3631, 0x56653130, 0x41693039, 0x55713336, 0x4F623836, 0x48683738, 0x4B723937, 0x53793631, 0x47693936, 0x50753033, 0x42713039, 0x586f3934, 0x4B6d3835, 0x53793836,
    0x42793530, 0x54743439, 0x487a3531, 0x41753830, 0x416a3334, 0x50653231, 0x466d3330, 0x476b3938, 0x596b3232, 0x55723437, 0x4F733832, 0x43763736, 0x5A6a3034, 0x54773130, 0x46673830, 0x45763337,
    0x56733834, 0x45663737, 0x4C7a3138, 0x556a3932, 0x566e3632, 0x48683536, 0x56633131, 0x59763532, 0x576f3835, 0x4E673231, 0x586b3534, 0x41763734, 0x4A7a3332, 0x47703735, 0x4A673132, 0x56793137,
    0x57623436, 0x49703038, 0x4F6c3538, 0x567a3531, 0x446d3333, 0x486d3334, 0x586e3935, 0x47723837, 0x55783338, 0x4D763939, 0x54773632, 0x4A623938, 0x48643832, 0x47793033, 0x4E663437, 0x4D6c3834,
    0x566c3239, 0x55653231, 0x4F663732, 0x45703833, 0x586e3832, 0x4C633130, 0x55713831, 0x4D623632, 0x586d3833, 0x47703732, 0x52673438, 0x5A7a3739, 0x46773130, 0x42753130, 0x58783832, 0x4D613630,
    0x4D763234, 0x41733630, 0x4A703537, 0x4A633335, 0x45763832, 0x47663332, 0x4B633335, 0x41623632, 0x4C6d3132, 0x546b3436, 0x42713834, 0x466e3135, 0x556a3838, 0x41733831, 0x55623839, 0x5A6a3332,
    0x5A743533, 0x55703932, 0x50693330, 0x4A783931, 0x556b3933, 0x516c3133, 0x53693132, 0x42643437, 0x566f3835, 0x53743434, 0x5A6a3635, 0x55713238, 0x58683537, 0x5A783234, 0x4D6f3030, 0x506e3730,
    0x44643938, 0x55663038, 0x45623338, 0x4F723835, 0x46653635, 0x4D6f3530, 0x496b3934, 0x44673331, 0x53703730, 0x45643832, 0x426d3635, 0x43663936, 0x45723234, 0x43753537, 0x47713130, 0x55713733
};

// generate random number of "JunTai" distribution
void JunTai(char *pucPassword)
{
// any password length
    unsigned long ulPasswordLength = -1;

// get password length
    while(pucPassword[++ulPasswordLength]);

// key table convert 8 * 32 = 256 bytes of data at a time in order to generate the random number of "JunTai" distribution
    for(unsigned long i = 0; i < 32; ++i)
    {
        unsigned long *pulKeySwap1 = (unsigned long*)aucKeyTable, *pulKeySwap2 = (unsigned long*)aucKeyTable, ulKeyTemp, ulKeyIndex;

        ulKeyIndex = pucPassword[i % ulPasswordLength] % 32;

        ulKeyTemp = pulKeySwap1[i];

        pulKeySwap1[i] = pulKeySwap2[ulKeyIndex];

        pulKeySwap2[ulKeyIndex] = ulKeyTemp;
    }
}

void Encrypt(char *argv[])
{
    JunTai(argv[2]);

    struct stat statFileSize;

// get plaintext file size
    stat(argv[0], &statFileSize);

    unsigned long ulFileSize = statFileSize.st_size;

// open plaintext file descriptor
    int iPlaintextFD = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

    unsigned char *pucCiphertext = (unsigned char*)malloc(ulFileSize);

// read data from plaintext file
    read(iPlaintextFD, pucCiphertext, ulFileSize);

    close(iPlaintextFD);

// process plaintext data if the plaintext size is greater than 256 bytes
    for(unsigned long k = ulFileSize / 256 * 256; 0 < k && k < ulFileSize; k -= 256)
    {
        for(unsigned long l = 0; l < 256 && k + l < ulFileSize; ++l)
        {
            pucCiphertext[k + l] ^= pucCiphertext[k + l - 256];
        }
    }

// Use XOR to process the first 256 bytes of plaintext data, which may be less than 256 bytes.
    for(unsigned long j = 0; j < 256 && j < ulFileSize; ++j)
    {
        pucCiphertext[j] ^= aucKeyTable[j];
    }

    unsigned int *puiCiphertext = (unsigned int*)malloc(4 * ulFileSize);

// process avalanche
    for(unsigned long n = 0; n < ulFileSize; ++n)
    {
        puiCiphertext[n] = auiAvalancheTable[pucCiphertext[n]];
    }
    
// open ciphertext file descriptor
    int iCiphertextFD = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to ciphertext file
    write(iCiphertextFD, puiCiphertext, 4 * ulFileSize);

    close(iCiphertextFD);

    free(puiCiphertext);

    free(pucCiphertext);
}

void Decrypt(char *argv[])
{
    JunTai(argv[2]);

    struct stat statFileSize;

// get ciphertext file size
    stat(argv[0], &statFileSize);

    unsigned long ulFileSize = statFileSize.st_size;

// open ciphertext file descriptor
    int iCiphertextFD = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

    unsigned int *puiPlaintext = (unsigned int*)malloc(ulFileSize);

// read data from ciphertext file
    read(iCiphertextFD, puiPlaintext, ulFileSize);

    close(iCiphertextFD);

    ulFileSize /= 4;

    unsigned char *pucPlaintext = (unsigned char*)malloc(ulFileSize);

// process avalanche
    for(unsigned long i = 0; i < ulFileSize; ++i)
    {
        for(unsigned long j = 0; j < 256; ++j)
        {
            if(puiPlaintext[i] == auiAvalancheTable[j])
            {
                pucPlaintext[i] = j;

                break;
            }
        }
    }

    free(puiPlaintext);

// Use XOR to process the first 256 bytes of ciphertext data, which may be less than 256 bytes.
    for(unsigned long j = 0; j < 256 && j < ulFileSize; ++j)
    {
        pucPlaintext[j] ^= aucKeyTable[j];
    }

// process ciphertext data if the ciphertext size is greater than 256 bytes
    for(unsigned long k = 256; k < ulFileSize; k += 256)
    {
        for(unsigned long l = 0; l < 256 && k + l < ulFileSize; ++l)
        {
            pucPlaintext[k + l] ^= pucPlaintext[k + l - 256];
        }
    }

// open plaintext file descriptor
    int iPlaintextFD = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to plaintext file
    write(iPlaintextFD, pucPlaintext, ulFileSize);

    close(iPlaintextFD);

    free(pucPlaintext);
}

int main(int argc, char *argv[])
{
    if(argv[1][0] == '-')
    {
        if(argv[1][1] == 'C' || argv[1][1] == 'c')
        {
            Encrypt(argv + 2);
        }

        if(argv[1][1] == 'P' || argv[1][1] == 'p')
        {
            Decrypt(argv + 2);
        }
    }

    return 0;
}
