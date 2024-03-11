// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RANDOM_H
#define BITCOIN_RANDOM_H

#include <crypto/chacha20.h>
#include <crypto/common.h>
#include <span.h>
#include <uint256.h>
#include <util/check.h>

#include <bit>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <limits>
#include <vector>

/**
 * Overall design of the RNG and entropy sources.
 *
 * We maintain a single global 256-bit RNG state for all high-quality randomness.
 * The following (classes of) functions interact with that state by mixing in new
 * entropy, and optionally extracting random output from it:
 *
 * - The GetRand*() class of functions, as well as construction of FastRandomContext objects,
 *   perform 'fast' seeding, consisting of mixing in:
 *   - A stack pointer (indirectly committing to calling thread and call stack)
 *   - A high-precision timestamp (rdtsc when available, c++ high_resolution_clock otherwise)
 *   - 64 bits from the hardware RNG (rdrand) when available.
 *   These entropy sources are very fast, and only designed to protect against situations
 *   where a VM state restore/copy results in multiple systems with the same randomness.
 *   FastRandomContext on the other hand does not protect against this once created, but
 *   is even faster (and acceptable to use inside tight loops).
 *
 * - The GetStrongRand*() class of function perform 'slow' seeding, including everything
 *   that fast seeding includes, but additionally:
 *   - OS entropy (/dev/urandom, getrandom(), ...). The application will terminate if
 *     this entropy source fails.
 *   - Another high-precision timestamp (indirectly committing to a benchmark of all the
 *     previous sources).
 *   These entropy sources are slower, but designed to make sure the RNG state contains
 *   fresh data that is unpredictable to attackers.
 *
 * - RandAddPeriodic() seeds everything that fast seeding includes, but additionally:
 *   - A high-precision timestamp
 *   - Dynamic environment data (performance monitoring, ...)
 *   - Strengthen the entropy for 10 ms using repeated SHA512.
 *   This is run once every minute.
 *
 * On first use of the RNG (regardless of what function is called first), all entropy
 * sources used in the 'slow' seeder are included, but also:
 * - 256 bits from the hardware RNG (rdseed or rdrand) when available.
 * - Dynamic environment data (performance monitoring, ...)
 * - Static environment data
 * - Strengthen the entropy for 100 ms using repeated SHA512.
 *
 * When mixing in new entropy, H = SHA512(entropy || old_rng_state) is computed, and
 * (up to) the first 32 bytes of H are produced as output, while the last 32 bytes
 * become the new RNG state.
*/

/**
 * Generate random data via the internal PRNG.
 *
 * These functions are designed to be fast (sub microsecond), but do not necessarily
 * meaningfully add entropy to the PRNG state.
 *
 * Thread-safe.
 */
void GetRandBytes(Span<unsigned char> bytes) noexcept;

/**
 * Return a timestamp in the future sampled from an exponential distribution
 * (https://en.wikipedia.org/wiki/Exponential_distribution). This distribution
 * is memoryless and should be used for repeated network events (e.g. sending a
 * certain type of message) to minimize leaking information to observers.
 *
 * The probability of an event occurring before time x is 1 - e^-(x/a) where a
 * is the average interval between events.
 * */
std::chrono::microseconds GetExponentialRand(std::chrono::microseconds now, std::chrono::seconds average_interval);

uint256 GetRandHash() noexcept;

/**
 * Gather entropy from various sources, feed it into the internal PRNG, and
 * generate random data using it.
 *
 * This function will cause failure whenever the OS RNG fails.
 *
 * Thread-safe.
 */
void GetStrongRandBytes(Span<unsigned char> bytes) noexcept;

/**
 * Gather entropy from various expensive sources, and feed them to the PRNG state.
 *
 * Thread-safe.
 */
void RandAddPeriodic() noexcept;

/**
 * Gathers entropy from the low bits of the time at which events occur. Should
 * be called with a uint32_t describing the event at the time an event occurs.
 *
 * Thread-safe.
 */
void RandAddEvent(const uint32_t event_info) noexcept;

// Forward declaration of RandomMixin, used in RandomNumberGenerator concept.
template<typename T>
class RandomMixin;

/** A concept for RandomMixin-based random number generators. */
template<typename T>
concept RandomNumberGenerator = requires(T& rng, Span<std::byte> s) {
    // A random number generator must provide rand64().
    { rng.rand64() } noexcept -> std::same_as<uint64_t>;
    // A random number generator must derive from RandomMixin, which adds other rand* functions.
    requires std::derived_from<std::remove_reference_t<T>, RandomMixin<std::remove_reference_t<T>>>;
};

/** A concept for C++ std::chrono durations. */
template<typename T>
concept StdChronoDuration = requires {
    []<class Rep, class Period>(std::type_identity<std::chrono::duration<Rep, Period>>){}(
        std::type_identity<T>());
};

/** Mixin class that provides helper randomness functions.
 *
 * Intended to be used through CRTP: https://en.cppreference.com/w/cpp/language/crtp.
 * An RNG class FunkyRNG would derive publicly from RandomMixin<FunkyRNG>. This permits
 * RandomMixin from accessing the derived class's rand64() function, while also allowing
 * the derived class to provide more.
 *
 * The derived class must satisfy the RandomNumberGenerator concept.
 */
template<typename T>
class RandomMixin
{
private:
    uint64_t bitbuf{0};
    int bitbuf_size{0};

    /** Access the underlying generator.
     *
     * This also enforces the RandomNumberGenerator concept. We cannot declare that in the template
     * (no template<RandomNumberGenerator T>) because the type isn't fully instantiated yet there.
     */
    RandomNumberGenerator auto& Impl() { return static_cast<T&>(*this); }

public:
    RandomMixin() noexcept = default;

    // Do not permit copying an RNG.
    RandomMixin(const RandomMixin&) = delete;
    RandomMixin& operator=(const RandomMixin&) = delete;

    RandomMixin(RandomMixin&& other) noexcept : bitbuf(other.bitbuf), bitbuf_size(other.bitbuf_size)
    {
        other.bitbuf = 0;
        other.bitbuf_size = 0;
    }

    RandomMixin& operator=(RandomMixin&& other) noexcept
    {
        bitbuf = other.bitbuf;
        bitbuf_size = other.bitbuf_size;
        other.bitbuf = 0;
        other.bitbuf_size = 0;
        return *this;
    }

    /** Generate a random (bits)-bit integer. */
    uint64_t randbits(int bits) noexcept
    {
        // Requests for the full 64 bits are passed through.
        if (bits == 64) return Impl().rand64();
        uint64_t ret;
        if (bits <= bitbuf_size) {
            // If there is enough entropy left in bitbuf, return its bottom bits bits.
            ret = bitbuf;
            bitbuf >>= bits;
            bitbuf_size -= bits;
        } else {
            // If not, return all of bitbuf, supplemented with the (bits - bitbuf_size) bottom
            // bits of a newly generated 64-bit number on top. The remainder of that generated
            // number becomes the new bitbuf.
            uint64_t gen = Impl().rand64();
            ret = (gen << bitbuf_size) | bitbuf;
            bitbuf = gen >> (bits - bitbuf_size);
            bitbuf_size = 64 + bitbuf_size - bits;
        }
        // Return the bottom bits bits of ret.
        return ret & ((uint64_t{1} << bits) - 1);
    }

    /** Same as above, but with compile-time fixed bits count. */
    template<int Bits>
    uint64_t randbits() noexcept
    {
        static_assert(Bits >= 0 && Bits <= 64);
        if constexpr (Bits == 0) {
            return 0;
        } else if constexpr (Bits == 64) {
            return Impl().rand64();
        } else if constexpr (Bits == 1) {
            uint64_t ret;
            if (bitbuf_size == 0) {
                bitbuf = Impl().rand64();
                bitbuf_size = 64;
            }
            ret = bitbuf & 1;
            bitbuf >>= 1;
            bitbuf_size -= 1;
            return ret;
        } else {
            uint64_t ret;
            if (Bits <= bitbuf_size) {
                ret = bitbuf;
                bitbuf >>= Bits;
                bitbuf_size -= Bits;
            } else {
                uint64_t gen = Impl().rand64();
                ret = (gen << bitbuf_size) | bitbuf;
                bitbuf = gen >> (Bits - bitbuf_size);
                bitbuf_size = 64 + bitbuf_size - Bits;
            }
            constexpr uint64_t MASK = (uint64_t{1} << Bits) - 1;
            return ret & MASK;
        }
    }

    /** Generate a random integer in the range [0..range), with range > 0. */
    template<std::integral I>
    I randrange(I range) noexcept
    {
        static_assert(std::numeric_limits<I>::max() <= std::numeric_limits<uint64_t>::max());
        Assume(range > 0);
        uint64_t maxval = range - 1U;
        int bits = std::bit_width(maxval);
        while (true) {
            uint64_t ret = Impl().randbits(bits);
            if (ret <= maxval) return ret;
        }
    }

    /** Fill a Span with random bytes. */
    void fillrand(Span<std::byte> span) noexcept
    {
        while (span.size() >= 8) {
            uint64_t gen = Impl().rand64();
            WriteLE64(UCharCast(span.data()), gen);
            span = span.subspan(8);
        }
        if (span.size() >= 4) {
            uint32_t gen = Impl().rand32();
            WriteLE32(UCharCast(span.data()), gen);
            span = span.subspan(4);
        }
        while (span.size()) {
            span[0] = std::byte(Impl().template randbits<8>());
            span = span.subspan(1);
        }
    }

    /** Generate a random integer in its entire (non-negative) range. */
    template<std::integral I>
    I rand() noexcept
    {
        static_assert(std::numeric_limits<I>::max() <= std::numeric_limits<uint64_t>::max());
        static constexpr auto BITS = std::bit_width(uint64_t(std::numeric_limits<I>::max()));
        static_assert(std::numeric_limits<I>::max() == std::numeric_limits<uint64_t>::max() >> (64 - BITS));
        return I(Impl().template randbits<BITS>());
    }

    /** Generate random bytes. */
    template <BasicByte B = unsigned char>
    std::vector<B> randbytes(size_t len)
    {
        std::vector<B> ret(len);
        Impl().fillrand(MakeWritableByteSpan(ret));
        return ret;
    }

    /** Generate a random 32-bit integer. */
    uint32_t rand32() noexcept { return Impl().template randbits<32>(); }

    /** generate a random uint256. */
    uint256 rand256() noexcept
    {
        uint256 ret;
        Impl().fillrand(MakeWritableByteSpan(ret));
        return ret;
    }

    /** Generate a random boolean. */
    bool randbool() noexcept { return Impl().template randbits<1>(); }

    /** Return the time point advanced by a uniform random duration. */
    template <typename Tp>
    Tp rand_uniform_delay(const Tp& time, typename Tp::duration range)
    {
        return time + Impl().template rand_uniform_duration<Tp>(range);
    }

    /** Generate a uniform random duration in the range from 0 (inclusive) to range (exclusive). */
    template <typename Chrono> requires StdChronoDuration<typename Chrono::duration>
    typename Chrono::duration rand_uniform_duration(typename Chrono::duration range) noexcept
    {
        using Dur = typename Chrono::duration;
        return range.count() > 0 ? /* interval [0..range) */ Dur{Impl().randrange(range.count())} :
               range.count() < 0 ? /* interval (range..0] */ -Dur{Impl().randrange(-range.count())} :
                                   /* interval [0..0] */ Dur{0};
    };

    /** Generate a uniform random duration in the range [0..max). Precondition: max.count() > 0 */
    template <StdChronoDuration Dur>
    Dur randrange(typename std::common_type_t<Dur> range) noexcept
    // Having the compiler infer the template argument from the function argument
    // is dangerous, because the desired return value generally has a different
    // type than the function argument. So std::common_type is used to force the
    // call site to specify the type of the return value.
    {
        return Dur{Impl().randrange(range.count())};
    }

    // Compatibility with the UniformRandomBitGenerator concept
    typedef uint64_t result_type;
    static constexpr uint64_t min() { return 0; }
    static constexpr uint64_t max() { return std::numeric_limits<uint64_t>::max(); }
    inline uint64_t operator()() noexcept { return Impl().rand64(); }
};

/**
 * Fast randomness source. This is seeded once with secure random data, but
 * is completely deterministic and does not gather more entropy after that.
 *
 * This class is not thread-safe.
 */
class FastRandomContext : public RandomMixin<FastRandomContext>
{
private:
    bool requires_seed;
    ChaCha20 rng;

    void RandomSeed();

public:
    /** Construct a FastRandomContext with GetRandHash()-based entropy (or zero key if fDeterministic). */
    explicit FastRandomContext(bool fDeterministic = false) noexcept;

    /** Initialize with explicit seed (only for testing) */
    explicit FastRandomContext(const uint256& seed) noexcept;

    // Do not permit copying a FastRandomContext (move it, or create a new one to get reseeded).
    FastRandomContext(const FastRandomContext&) = delete;
    FastRandomContext(FastRandomContext&&) = delete;
    FastRandomContext& operator=(const FastRandomContext&) = delete;

    /** Move a FastRandomContext. If the original one is used again, it will be reseeded. */
    FastRandomContext& operator=(FastRandomContext&& from) noexcept;

    /** Generate a random 64-bit integer. */
    uint64_t rand64() noexcept
    {
        if (requires_seed) RandomSeed();
        std::array<std::byte, 8> buf;
        rng.Keystream(buf);
        return ReadLE64(UCharCast(buf.data()));
    }

    /** Fill a byte Span with random bytes. This overrides the RandomMixin version. */
    void fillrand(Span<std::byte> output) noexcept;
};

/** xoroshiro128++ PRNG. Extremely fast, not appropriate for cryptographic purposes.
 *
 * Memory footprint is very small, period is 2^128 - 1.
 * This class is not thread-safe.
 *
 * Reference implementation available at https://prng.di.unimi.it/xoroshiro128plusplus.c
 * See https://prng.di.unimi.it/
 */
class InsecureRandomContext : public RandomMixin<InsecureRandomContext>
{
    uint64_t m_s0;
    uint64_t m_s1;

    [[nodiscard]] constexpr static uint64_t SplitMix64(uint64_t& seedval) noexcept
    {
        uint64_t z = (seedval += 0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

public:
    constexpr explicit InsecureRandomContext(uint64_t seedval) noexcept
        : m_s0(SplitMix64(seedval)), m_s1(SplitMix64(seedval)) {}

    // no copy - that is dangerous, we don't want accidentally copy the RNG and then have two streams
    // with exactly the same results. If you need a copy, call copy().
    InsecureRandomContext(const InsecureRandomContext&) = delete;
    InsecureRandomContext& operator=(const InsecureRandomContext&) = delete;

    // allow moves
    InsecureRandomContext(InsecureRandomContext&&) = default;
    InsecureRandomContext& operator=(InsecureRandomContext&&) = default;

    constexpr uint64_t rand64() noexcept
    {
        uint64_t s0 = m_s0, s1 = m_s1;
        const uint64_t result = std::rotl(s0 + s1, 17) + s0;
        s1 ^= s0;
        m_s0 = std::rotl(s0, 49) ^ s1 ^ (s1 << 21);
        m_s1 = std::rotl(s1, 28);
        return result;
    }
};

/** More efficient than using std::shuffle on a FastRandomContext.
 *
 * This is more efficient as std::shuffle will consume entropy in groups of
 * 64 bits at the time and throw away most.
 *
 * This also works around a bug in libstdc++ std::shuffle that may cause
 * type::operator=(type&&) to be invoked on itself, which the library's
 * debug mode detects and panics on. This is a known issue, see
 * https://stackoverflow.com/questions/22915325/avoiding-self-assignment-in-stdshuffle
 */
template <typename I, RandomNumberGenerator R>
void Shuffle(I first, I last, R&& rng)
{
    while (first != last) {
        size_t j = rng.randrange(last - first);
        if (j) {
            using std::swap;
            swap(*first, *(first + j));
        }
        ++first;
    }
}

/** Generate a uniform random integer of type T in the range [0..nMax)
 *  Precondition: nMax > 0, T is an integral type, no larger than uint64_t
 */
template<typename T>
T GetRand(T nMax) noexcept {
    return T(FastRandomContext().randrange(nMax));
}

/** Generate a uniform random integer of type T in its entire non-negative range. */
template<typename T>
T GetRand() noexcept {
    return T(FastRandomContext().rand<T>());
}

/* Number of random bytes returned by GetOSRand.
 * When changing this constant make sure to change all call sites, and make
 * sure that the underlying OS APIs for all platforms support the number.
 * (many cap out at 256 bytes).
 */
static const int NUM_OS_RANDOM_BYTES = 32;

/** Get 32 bytes of system entropy. Do not use this in application code: use
 * GetStrongRandBytes instead.
 */
void GetOSRand(unsigned char* ent32);

/** Check that OS randomness is available and returning the requested number
 * of bytes.
 */
bool Random_SanityCheck();

/**
 * Initialize global RNG state and log any CPU features that are used.
 *
 * Calling this function is optional. RNG state will be initialized when first
 * needed if it is not called.
 */
void RandomInit();

#endif // BITCOIN_RANDOM_H
