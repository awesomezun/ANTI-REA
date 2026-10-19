#include <cstdint>
#include <generated_config.h>

#if defined(_MSC_VER)
#define ANTI_REA_NOINLINE __declspec(noinline)
#else
#define ANTI_REA_NOINLINE __attribute__((noinline))
#endif

// Synthetic score transformation for a protection-scope experiment. This is
// neither cryptography, authentication, licensing, nor an access-control check.
// Each semantic stage has private build constants; protecting the central loop
// alone intentionally leaves relevant context in the surrounding native code.
extern "C" ANTI_REA_NOINLINE std::uint64_t
antirea_prepare(std::uint32_t x, std::uint32_t y) noexcept {
    std::uint64_t value = (std::uint64_t{x} + ANTI_REA_K0)
                        ^ (std::uint64_t{y} << 17);
    value += (std::uint64_t{y} ^ ANTI_REA_K1) * 257;
    return value ^ (value >> 19);
}

extern "C" ANTI_REA_NOINLINE std::uint64_t
antirea_mix(std::uint64_t state, std::uint32_t x, std::uint32_t y) noexcept {
    for (std::uint32_t round = 0; round < 5; ++round) {
        state ^= state >> 13;
        state *= (std::uint64_t{ANTI_REA_K2} | 1);
        if ((state ^ x ^ round) & 1) {
            state += (std::uint64_t{y} << 11) + round;
        } else {
            state ^= (std::uint64_t{x} << 7) + 0x045D9F3Bu;
        }
        state += std::uint64_t{round + 1} * 0x9E3779B97F4A7C15ULL;
    }
    return state;
}

extern "C" ANTI_REA_NOINLINE std::uint64_t
antirea_adjust(std::uint64_t mixed, std::uint32_t x, std::uint32_t y) noexcept {
    const std::uint64_t offset = (std::uint64_t{x} + y)
                               * (std::uint64_t{ANTI_REA_K3} | 1);
    return (mixed ^ (mixed >> 23)) + offset;
}

extern "C" ANTI_REA_NOINLINE std::uint64_t
antirea_score(std::uint32_t x, std::uint32_t y) noexcept {
    const std::uint64_t prepared = antirea_prepare(x, y);
    const std::uint64_t mixed = antirea_mix(prepared, x, y);
    return antirea_adjust(mixed, x, y);
}

// Public presentation boundary: a transparent forwarding adapter, with no
// private constants, decisions, or transformations. It is deliberately outside
// the protection selection in both core-only and expanded modes.
extern "C" ANTI_REA_NOINLINE std::uint64_t
antirea_present_score(std::uint32_t x, std::uint32_t y) noexcept {
    return antirea_score(x, y);
}
