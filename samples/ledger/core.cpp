#include <cstdint>
#include <generated_config.h>

// Synthetic scoring arithmetic, not cryptography or access control. Keep this
// translation unit separate so the protection tool only processes this core.
extern "C" std::uint64_t antirea_score(std::uint32_t x,
                                     std::uint32_t y) noexcept {
    std::uint64_t a = (std::uint64_t{x} ^ ANTI_REA_K0)
                    + (std::uint64_t{y} << 17);
    std::uint64_t b = (std::uint64_t{y} ^ ANTI_REA_K1)
                    + (std::uint64_t{x} << 9);

    for (std::uint32_t round = 0; round < 5; ++round) {
        a ^= a >> 13;
        a *= (std::uint64_t{ANTI_REA_K2} | 1);
        b += a ^ (std::uint64_t{ANTI_REA_K3}
                  + std::uint64_t{round} * 0x045D9F3Bu);
        if ((a ^ b) & 1) {
            a += (b << 7) ^ (b >> 11);
        } else {
            a ^= (b << 11) + (b >> 5);
        }
        b ^= b << 9;
        b += b >> 5;
        a ^= std::uint64_t{round + 1} * 0x9E3779B97F4A7C15ULL;
    }
    return (a ^ (b >> 3))
         + ((std::uint64_t{x} + y) * (std::uint64_t{ANTI_REA_K0} | 1));
}
