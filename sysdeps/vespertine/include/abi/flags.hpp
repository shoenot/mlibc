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
    Signal() = default;
    constexpr Signal(uint32_t val) : bits(val) {}

    static const uint32_t READABLE    = 1 << 0;
    static const uint32_t WRITABLE    = 1 << 1;
    static const uint32_t PEER_CLOSED = 1 << 2;
    static const uint32_t TERMINATED  = 1 << 3;

    constexpr Signal operator|(const Signal& other) const { return Signal(bits | other.bits); }
    constexpr Signal operator&(const Signal& other) const { return Signal(bits & other.bits); }
};

struct AccessRights {
    uint8_t bits;
    AccessRights() = default;
    constexpr AccessRights(uint8_t val) : bits(val) {}

    static const uint8_t READ     = 1 << 0;
    static const uint8_t WRITE    = 1 << 1;
    static const uint8_t EXECUTE  = 1 << 2;
    static const uint8_t CREATE   = 1 << 3;
    static const uint8_t MUTATE   = 1 << 4;
    static const uint8_t TRAVERSE = 1 << 5;
    static const uint8_t LIST     = 1 << 6;
    static const uint8_t REMOVE   = 1 << 7;

    constexpr AccessRights operator|(const AccessRights& other) const { return AccessRights(bits | other.bits); }
    constexpr AccessRights operator&(const AccessRights& other) const { return AccessRights(bits & other.bits); }
};

static_assert(sizeof(AccessRights) == 1);
