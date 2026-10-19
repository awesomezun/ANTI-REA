#include <cstdint>
#include <iostream>
#include <limits>

extern "C" std::uint64_t antirea_present_score(std::uint32_t,
                                             std::uint32_t) noexcept;

// Reviewed public CLI adapter, compiled separately and outside the core.cpp
// scope analysis. Standard-library I/O is not claimed to have been analyzed.
int main() {
    std::uint64_t x;
    std::uint64_t y;
    while (std::cin >> x) {
        if (!(std::cin >> y)
            || x > std::numeric_limits<std::uint32_t>::max()
            || y > std::numeric_limits<std::uint32_t>::max()) {
            std::cerr << "Expected pairs of unsigned 32-bit decimal integers.\n";
            return 2;
        }
        std::cout << antirea_present_score(static_cast<std::uint32_t>(x),
                                           static_cast<std::uint32_t>(y)) << '\n';
    }
    return std::cin.eof() ? 0 : 2;
}
