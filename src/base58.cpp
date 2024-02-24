// Copyright (c) 2014-2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <hash.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <vector>
#include <cassert>
#include <cstring>

// The Base58 character set excluding "0", "I", "O", and "l" for clarity.
static constexpr auto pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// Each ASCII character and its Base58 value, with -1 indicating an invalid character for Base58.
static constexpr int8_t mapBase58[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};

static constexpr int base{58};
static constexpr int64_t baseScale{1000LL};
static constexpr int64_t log58_256Ratio =  733LL;  // Approximation of log(base)/log(256), scaled by baseScale.
static constexpr int64_t log256_58Ratio = 1366LL; // Approximation of log(256)/log(base), scaled by baseScale.

[[nodiscard]] static bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch, int max_ret_len)
{
    // Skip leading spaces.
    while (*psz && IsSpace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '1') {
        zeroes++;
        if (zeroes > max_ret_len) return false;
        psz++;
    }
    const int size = 1 + strlen(psz) * log58_256Ratio / baseScale;
    std::vector<unsigned char> b256(size);
    // Process the characters.
    static_assert(std::size(mapBase58) == 256, "mapBase58.size() should be 256"); // guarantee not out of range
    while (*psz && !IsSpace(*psz)) {
        // Decode base58 character
        int carry = mapBase58[(uint8_t)*psz];
        if (carry == -1)  // Invalid b58 character
            return false;
        int i = 0;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += base * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        if (length + zeroes > max_ret_len) return false;
        psz++;
    }
    // Skip trailing spaces.
    while (IsSpace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

auto BatchInput(const Span<const unsigned char>& input, const int start) -> std::vector<unsigned char>
{
    return std::vector(input.begin() + start, input.end());
}

std::string EncodeBase58(const Span<const unsigned char> input)
{
    auto leading{0U};
    while (leading < input.size() && input[leading] == 0)
        ++leading;

    const auto size = 1 + input.size() * log256_58Ratio / baseScale;
    std::string result;
    result.reserve(leading + size);
    result.assign(leading, '1'); // Fill in leading '1's for each zero byte in input.

    auto inputBatched = BatchInput(input, leading);
    for (auto i{0U}; i < inputBatched.size();) {
        int64_t remainder{0};
        for (auto j{i}; j < inputBatched.size(); ++j) { // Calculate next digit, dividing inputBatched
            const auto accumulator = (remainder << 8) | inputBatched[j];
            inputBatched[j] = accumulator / base;
            remainder = accumulator % base;
        }
        result += pszBase58[remainder];
        while (i < inputBatched.size() && inputBatched[i] == 0)
            ++i; // Skip new leading zeros
    }
    std::reverse(result.begin() + leading, result.end());
    return result;
}

bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret_len)
{
    if (!ContainsNoNUL(str)) {
        return false;
    }
    return DecodeBase58(str.c_str(), vchRet, max_ret_len);
}

std::string EncodeBase58Check(Span<const unsigned char> input)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(input.begin(), input.end());
    uint256 hash = Hash(vch);
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

[[nodiscard]] static bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet, int max_ret_len)
{
    if (!DecodeBase58(psz, vchRet, max_ret_len > std::numeric_limits<int>::max() - 4 ? std::numeric_limits<int>::max() : max_ret_len + 4) ||
        (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, ensure it matches the included 4-byte checksum
    uint256 hash = Hash(Span{vchRet}.first(vchRet.size() - 4));
    if (memcmp(&hash, &vchRet[vchRet.size() - 4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret)
{
    if (!ContainsNoNUL(str)) {
        return false;
    }
    return DecodeBase58Check(str.c_str(), vchRet, max_ret);
}
