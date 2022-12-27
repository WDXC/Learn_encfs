#ifndef _base64_incl_
#define _base64_incl_

#include <string>   // for string
#include <vector>   // for vector

namespace encfs {
    inline int B64ToB256Bytes(int numB64Bytes) {
        return (numB64Bytes * 6) / 8;   // round down
    }

    inline int B32ToB256Bytes(int numB32Bytes) {
        return (numB32Bytes * 5) / 8;   // round down
    }
    inline int B256ToB64Bytes(int numB256Bytes) {
        return (numB256Bytes * 8 + 5) / 6;  // round up
    }
    inline int B256To32Bytes(int numB256Bytes) {
        return (numB256Bytes * 8 + 4) / 5;  // round up
    }

    /*
        convert data between different bases - each being a power of 2.
     */
    void changeBase2(unsigned char* src, int srcLength, int srcPow2,
                     unsigned char* dst, int dstLength, int dstPow2);

    /*
        same as changeBase2, but writes output over the top of input data
     */
    void changeBase2Inline(unsigned char* buf, int srcLength, int srcPow2,
                           int dstPow, bool outputPartialLastByte);

    // implace translation from values [0, 2^6] => base64 ASCII
    void B64ToAscii(unsigned char* buf, int length);
    // implace translation from values [0, 2^5] => base32 ASCII
    void B32ToAscii(unsigned char* buf, int length);

    // implace translation from values base64 ASCII => [0, 2^6]
    void AsciiToB64(unsigned char* buf, int length);
    void AsciiToB64(unsigned char* out, const unsigned char* in, int length);

    // implace translation from values base32 ASCII => [0, 2^5]
    void AsciiToB32(unsigned char* buf, int length);
    void AsciiToB32(unsigned char* out, const unsigned char* in, int length);

    // Decode standard B64 into the output array.
    // Used only to decode legacy Boost XML serialized config format.
    // The output size must be at least B64ToB256Bytes(inputLen).
    bool B64StandardDecode(unsigned char* out, const unsigned char* in,
                           int inputLen);
    std::string B64StandardEncode(const std::vector<unsigned char>& input);
}

#endif
