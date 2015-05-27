#include <cstdio>
#include <cstring>
/*base64 code table*/
static char table[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
/*Extend 3 byte of stream to 4 byte base64 code*/
/*First byte*/
inline char extendA(const char *txt){
    return table[(txt[0] & 0xfc)>>2];
}
/*Second byte*/
inline char extendB(const char *txt){
    return table[((txt[0] & 0x03)<<6 | (txt[1] & 0xf0)>>2)>>2];
}
/*Third byte*/
inline char extendC(const char *txt){
    return table[(txt[1] & 0x0f)<<2 | (txt[2] & 0xc0)>>6];
}
/*Forth byte*/
inline char extendD(const char *txt){
    return table[(txt[2] & 0x3f)];
}
/*base64 encode,convert text to ciphertext*/
void encode(const char* txt, char*& out){
    int iLen = strlen(txt);
    int count = iLen/3;
    int flag = iLen%3;
    out = new char[(flag ? count * 4 + 4 : count * 4) + 1];
    int i = 0;
    while(count--){
        out[i++] = extendA(txt);
        out[i++] = extendB(txt);
        out[i++] = extendC(txt);
        out[i++] = extendD(txt);
        txt+=3;
    }
    if(flag){
        out[i++] = extendA(txt);
        out[i++] = extendB(txt);
        switch (flag){
            case 1:out[i++] = out[i++] = '=';
                break;
            case 2:
                out[i++] = extendC(txt);
                out[i++] = '=';
                break;
        }
    }
    out[i] = 0;
};
/*Get the index from a base64 code*/
char invertTable(char c){
    switch (c & 0xf0){
        case 0b00100000:
            switch (c & 0x0f){
                case 0b00001011:
                    return 62;
                case 0b00001111:
                    return 63;
            }
            break;
        case 0b00110000:
            return (c & 0x0f) + 52;
        case 0b01000000:
            return (c & 0x0f) - 1;
        case 0b01010000:
            return (c & 0x0f) + 15;
        case 0b01100000:
            return (c & 0x0f) + 25;
        case 0b01110000:
            return (c & 0x0f) + 41;
    }
}
/*Zip 4 byte of base64 code to 3 byte stream*/
/*First byte*/
inline char zipA(const char* base){
    return invertTable(base[0])<<2 | (invertTable(base[1]) & 0x30) >>4;
}
/*Secind byte*/
inline char zipB(const char* base){
    return ( invertTable(base[1]) << 4 ) | ( (invertTable(base[2]) & 0x3c) >>2);
}
/*Third byte*/
inline char zipC(const char* base){
    return ((invertTable(base[2]) & 0x03) << 6) | (invertTable(base[3]) & 0x3f);
}
/*Deciphering ciphertext to plain text*/
void decode(const char* base, char*& out){
    int iLen = strlen(base);
    int count = iLen / 4 - 1;
    out = new char[base[iLen - 1] == '='? base[iLen - 2] == '='? count* 3 + 2: count * 3 + 3:count*3 + 1];
    int i = 0;
    while(count--){
        out[i++] = zipA(base);
        out[i++] = zipB(base);
        out[i++] = zipC(base);
        base+=4;
    }
    if(base[3] == '='){
        out[i++] = zipA(base);
        if(base[2] != '='){
            out[i++] = zipB(base);
        }
    }
    out[i] = 0;
}
int main() {
    return 0;
}