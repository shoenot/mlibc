#pragma once
#include <stdint.h>

struct PacketFlags {
    uint16_t bits;
    constexpr PacketFlags(uint16_t val) : bits(val) {}

    static const uint16_t IS_BUFFER = 1 << 0;
    static const uint16_t IS_STREAM = 1 << 1;
    static const uint16_t HAS_NEXT  = 1 << 2;
    static const uint16_t HAS_COUNT = 1 << 3;

    constexpr PacketFlags operator|(const PacketFlags& other) const { return PacketFlags(bits | other.bits); }
    constexpr PacketFlags operator&(const PacketFlags& other) const { return PacketFlags(bits & other.bits); }
    constexpr bool operator==(const PacketFlags& other) const { return bits == other.bits; }
};

struct Signal {
    uint32_t bits;
    constexpr Signal(uint32_t val) : bits(val) {}

    static const uint32_t READABLE  = 1 << 0;
    static const uint32_t WRITABLE  = 1 << 1;
    static const uint32_t ERROR     = 1 << 2;

    constexpr Signal operator|(const Signal& other) const { return Signal(bits | other.bits); }
    constexpr Signal operator&(const Signal& other) const { return Signal(bits & other.bits); }
};

struct AccessRights {
    uint32_t bits;
    constexpr AccessRights(uint32_t val) : bits(val) {}

    static const uint32_t READ    = 1 << 0;
    static const uint32_t WRITE   = 1 << 1;
    static const uint32_t EXECUTE = 1 << 2;

    constexpr AccessRights operator|(const AccessRights& other) const { return AccessRights(bits | other.bits); }
};
