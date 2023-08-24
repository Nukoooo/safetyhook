#include <iterator>

#include <Windows.h>


#if __has_include(<bddisasm/bddisasm.h>)
#include <bddisasm/bddisasm.h>
#elif __has_include(<bddisasm.h>)
#include <bddisasm.h>
#else
#error "bddisasm not found"
#endif

#include <safetyhook/allocator.hpp>
#include <safetyhook/thread_freezer.hpp>
#include <safetyhook/utility.hpp>

#include <safetyhook/inline_hook.hpp>

namespace safetyhook {
class UnprotectMemory {
public:
    UnprotectMemory(uint8_t* address, size_t size)
        : m_address{address},
          m_size{size} {
        VirtualProtect(m_address, m_size, PAGE_EXECUTE_READWRITE, &m_protect);
    }

    ~UnprotectMemory() {
        VirtualProtect(m_address, m_size, m_protect, &m_protect);
    }

private:
    uint8_t* m_address{};
    size_t m_size{};
    DWORD m_protect{};
};

#pragma pack(push, 1)
struct JmpE9 {
    uint8_t opcode{0xE9};
    uint32_t offset{0};
};

#if defined(_M_X64)
struct JmpFF {
    uint8_t opcode0{0xFF};
    uint8_t opcode1{0x25};
    uint32_t offset{0};
};

struct TrampolineEpilogueE9 {
    JmpE9 jmp_to_original{};
    JmpFF jmp_to_destination{};
    uint64_t destination_address{};
};

struct TrampolineEpilogueFF {
    JmpFF jmp_to_original{};
    uint64_t original_address{};
};
#elif defined(_M_IX86)
struct TrampolineEpilogueE9 {
    JmpE9 jmp_to_original{};
    JmpE9 jmp_to_destination{};
};
#endif
#pragma pack(pop)

#ifdef _M_X64
static auto make_jmp_ff(uint8_t* src, uint8_t* dst, uint8_t* data) {
    JmpFF jmp{};

    jmp.offset = static_cast<uint32_t>(data - src - sizeof(jmp));
    store(data, dst);

    return jmp;
}

static void emit_jmp_ff(uint8_t* src, uint8_t* dst, uint8_t* data, size_t size = sizeof(JmpFF)) {
    if (size < sizeof(JmpFF)) {
        return;
    }

    UnprotectMemory unprotect{src, size};

    if (size > sizeof(JmpFF)) {
        std::fill_n(src, size, static_cast<uint8_t>(0x90));
    }

    store(src, make_jmp_ff(src, dst, data));
}
#endif

constexpr auto make_jmp_e9(uint8_t* src, uint8_t* dst) {
    JmpE9 jmp{};

    jmp.offset = static_cast<uint32_t>(dst - src - sizeof(jmp));

    return jmp;
}

static void emit_jmp_e9(uint8_t* src, uint8_t* dst, size_t size = sizeof(JmpE9)) {
    if (size < sizeof(JmpE9)) {
        return;
    }

    UnprotectMemory unprotect{src, size};

    if (size > sizeof(JmpE9)) {
        std::fill_n(src, size, static_cast<uint8_t>(0x90));
    }

    store(src, make_jmp_e9(src, dst));
}

static bool decode(INSTRUX* ix, uint8_t* ip) {
#ifdef _M_X64
    constexpr uint8_t defcode = ND_CODE_64;
    constexpr uint8_t defdata = ND_DATA_64;
#else
    constexpr uint8_t defcode = ND_CODE_32;
    constexpr uint8_t defdata = ND_DATA_32;
#endif

    return ND_SUCCESS(NdDecode(ix, ip, defcode, defdata));
}

std::expected<InlineHook, InlineHook::Error> InlineHook::create(void* target, void* destination) {
    return create(Allocator::global(), target, destination);
}

std::expected<InlineHook, InlineHook::Error> InlineHook::create(
    const std::shared_ptr<Allocator>& allocator, void* target, void* destination) {
    InlineHook hook{};

    if (const auto setup_result =
            hook.setup(allocator, reinterpret_cast<uint8_t*>(target), reinterpret_cast<uint8_t*>(destination));
        !setup_result) {
        return std::unexpected{setup_result.error()};
    }

    return hook;
}

InlineHook::InlineHook(InlineHook&& other) noexcept {
    *this = std::move(other);
}

InlineHook& InlineHook::operator=(InlineHook&& other) noexcept {
    if (this != &other) {
        destroy();

        std::scoped_lock lock{m_mutex, other.m_mutex};

        m_target = other.m_target;
        m_destination = other.m_destination;
        m_trampoline = std::move(other.m_trampoline);
        m_trampoline_size = other.m_trampoline_size;
        m_original_bytes = std::move(other.m_original_bytes);

        other.m_target = nullptr;
        other.m_destination = nullptr;
        other.m_trampoline_size = 0;
    }

    return *this;
}

InlineHook::~InlineHook() {
    destroy();
}

void InlineHook::reset() {
    *this = {};
}

std::expected<void, InlineHook::Error> InlineHook::setup(
    const std::shared_ptr<Allocator>& allocator, uint8_t* target, uint8_t* destination) {
    m_target = target;
    m_destination = destination;

    if (auto e9_result = e9_hook(allocator); !e9_result) {
#ifdef _M_X64
        if (auto ff_result = ff_hook(allocator); !ff_result) {
            return ff_result;
        }
#else
        return e9_result;
#endif
    }

    return {};
}

std::expected<void, InlineHook::Error> InlineHook::e9_hook(const std::shared_ptr<Allocator>& allocator) {
    m_original_bytes.clear();
    m_trampoline_size = sizeof(TrampolineEpilogueE9);

    std::vector<uint8_t*> desired_addresses{m_target};
    INSTRUX ix{};

    for (auto ip = m_target; ip < m_target + sizeof(JmpE9); ip += ix.Length) {
        if (!decode(&ix, ip)) {
            return std::unexpected{Error::failed_to_decode_instruction(ip)};
        }

        m_trampoline_size += ix.Length;
        m_original_bytes.insert(m_original_bytes.end(), ip, ip + ix.Length);

        const auto is_relative = (ix.Operands[0].Type == ND_OP_OFFS) || (ix.Operands[1].Type == ND_OP_OFFS);

        if (is_relative) {
            if (ix.IsRipRelative && ix.HasRelOffs && ix.RelOffsLength == 4) {
                const auto target_address =
                    ip + ix.Length + static_cast<int32_t>(ix.RelativeOffset);
                desired_addresses.emplace_back(target_address);
            } else if (ix.HasDisp && ix.DispLength == 4) {
                auto target_address = ip + ix.Length + static_cast<int32_t>(ix.Displacement);
                desired_addresses.emplace_back(target_address);
            } else if (ix.Category == ND_CAT_COND_BR) {
                const auto target_address =
                    ip + ix.Length + static_cast<int32_t>(ix.Operands[0].Info.RelativeOffset.Rel);
                desired_addresses.emplace_back(target_address);
                m_trampoline_size += 4; // near conditional branches are 4 bytes larger.
            } else if (ix.Category == ND_CAT_UNCOND_BR) {
                const auto target_address =
                    ip + ix.Length + static_cast<int32_t>(ix.Operands[0].Info.RelativeOffset.Rel);
                desired_addresses.emplace_back(target_address);
                m_trampoline_size += 3; // near unconditional branches are 3 bytes larger.
            } else {
                return std::unexpected{Error::unsupported_instruction_in_trampoline(ip)};
            }
        }
    }

    auto trampoline_allocation = allocator->allocate_near(desired_addresses, m_trampoline_size);

    if (!trampoline_allocation) {
        return std::unexpected{Error::bad_allocation(trampoline_allocation.error())};
    }

    m_trampoline = std::move(*trampoline_allocation);

    for (auto ip = m_target, tramp_ip = m_trampoline.data(); ip < m_target + m_original_bytes.size(); ip += ix.Length) {
        if (!decode(&ix, ip)) {
            m_trampoline.free();
            return std::unexpected{Error::failed_to_decode_instruction(ip)};
        }

        const auto is_relative = (ix.Operands[0].Type == ND_OP_OFFS) || (ix.Operands[1].Type == ND_OP_OFFS);

        if (is_relative && ix.IsRipRelative && ix.HasDisp && ix.DispLength == 4) {
            const auto target_address = ip + ix.Length + ix.Displacement;
            const auto new_disp = target_address - (tramp_ip + ix.Length);
            store(tramp_ip + ix.DispOffset, static_cast<int32_t>(new_disp));
            tramp_ip += ix.Length;
        } else if (is_relative && ix.HasRelOffs && ix.RelOffsLength == 4) {
            std::copy_n(ip, ix.Length, tramp_ip);
            const auto target_address = ip + ix.Length + ix.RelativeOffset;
            const auto new_disp = target_address - (tramp_ip + ix.Length);
            store(tramp_ip + ix.RelOffsOffset, static_cast<int32_t>(new_disp));
            tramp_ip += ix.Length;
        } else if (ix.Category == ND_CAT_COND_BR && ix.Operands[0].Size != 32) {
            const auto target_address = ip + ix.Length + ix.Operands[0].Info.RelativeOffset.Rel;
            auto new_disp = target_address - (tramp_ip + 6);

            if (target_address < m_target + m_original_bytes.size()) {
                new_disp = static_cast<ptrdiff_t>(ix.Operands[0].Info.RelativeOffset.Rel);
            }

            *tramp_ip = 0x0F;
            *(tramp_ip + 1) = 0x10 + ix.OpCodeBytes[0];
            store(tramp_ip + 2, static_cast<int32_t>(new_disp));
            tramp_ip += 6;
        } else if (ix.Category == ND_CAT_UNCOND_BR && ix.Operands[0].Size != 32) {
            const auto target_address = ip + ix.Length + ix.Operands[0].Info.RelativeOffset.Rel;
            auto new_disp = target_address - (tramp_ip + 5);

            if (target_address < m_target + m_original_bytes.size()) {
                new_disp = static_cast<ptrdiff_t>(ix.Operands[0].Info.RelativeOffset.Rel);
            }

            *tramp_ip = 0xE9;
            store(tramp_ip + 1, static_cast<int32_t>(new_disp));
            tramp_ip += 5;
        } else {
            std::copy_n(ip, ix.Length, tramp_ip);
            tramp_ip += ix.Length;
        }
    }

    auto trampoline_epilogue = reinterpret_cast<TrampolineEpilogueE9*>(
        m_trampoline.address() + m_trampoline_size - sizeof(TrampolineEpilogueE9));

    // jmp from trampoline to original.
    auto src = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_original);
    auto dst = m_target + m_original_bytes.size();
    emit_jmp_e9(src, dst);

    // jmp from trampoline to destination.
    src = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_destination);
    dst = m_destination;

#ifdef _M_X64
    auto data = reinterpret_cast<uint8_t*>(&trampoline_epilogue->destination_address);
    emit_jmp_ff(src, dst, data);
#else
    emit_jmp_e9(src, dst);
#endif

    // jmp from original to trampoline.
    execute_while_frozen(
        [this, &trampoline_epilogue] {
            const auto src = m_target;
            const auto dst = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_destination);
            emit_jmp_e9(src, dst, m_original_bytes.size());
        },
        [this](uint32_t, HANDLE, CONTEXT& ctx) {
            for (size_t i = 0; i < m_original_bytes.size(); ++i) {
                fix_ip(ctx, m_target + i, m_trampoline.data() + i);
            }
        });

    return {};
}

#ifdef _M_X64
std::expected<void, InlineHook::Error> InlineHook::ff_hook(const std::shared_ptr<Allocator>& allocator) {
    m_original_bytes.clear();
    m_trampoline_size = sizeof(TrampolineEpilogueFF);
    INSTRUX ix{};

    for (auto ip = m_target; ip < m_target + sizeof(JmpFF) + sizeof(uintptr_t); ip += ix.Length) {
        if (!decode(&ix, ip)) {
            return std::unexpected{Error::failed_to_decode_instruction(ip)};
        }

        // We can't support any instruction that is IP relative here because
        // ff_hook should only be called if e9_hook failed indicating that
        // we're likely outside the +- 2GB range.
        if (ix.IsRipRelative || ix.HasRelOffs) {
            return std::unexpected{Error::ip_relative_instruction_out_of_range(ip)};
        }

        m_original_bytes.insert(m_original_bytes.end(), ip, ip + ix.Length);
        m_trampoline_size += ix.Length;
    }

    auto trampoline_allocation = allocator->allocate(m_trampoline_size);

    if (!trampoline_allocation) {
        return std::unexpected{Error::bad_allocation(trampoline_allocation.error())};
    }

    m_trampoline = std::move(*trampoline_allocation);

    std::copy(m_original_bytes.begin(), m_original_bytes.end(), m_trampoline.data());

    const auto trampoline_epilogue =
        reinterpret_cast<TrampolineEpilogueFF*>(m_trampoline.data() + m_trampoline_size - sizeof(TrampolineEpilogueFF));

    // jmp from trampoline to original.
    auto src = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_original);
    auto dst = m_target + m_original_bytes.size();
    auto data = reinterpret_cast<uint8_t*>(&trampoline_epilogue->original_address);
    emit_jmp_ff(src, dst, data);

    // jmp from original to trampoline.
    execute_while_frozen(
        [this] {
            const auto src = m_target;
            const auto dst = m_destination;
            const auto data = src + sizeof(JmpFF);
            emit_jmp_ff(src, dst, data, m_original_bytes.size());
        },
        [this](uint32_t, HANDLE, CONTEXT& ctx) {
            for (size_t i = 0; i < m_original_bytes.size(); ++i) {
                fix_ip(ctx, m_target + i, m_trampoline.data() + i);
            }
        });

    return {};
}
#endif

void InlineHook::destroy() {
    std::scoped_lock lock{m_mutex};

    if (!m_trampoline) {
        return;
    }

    execute_while_frozen(
        [this] {
            UnprotectMemory unprotect{m_target, m_original_bytes.size()};
            std::copy(m_original_bytes.begin(), m_original_bytes.end(), m_target);
        },
        [this](uint32_t, HANDLE, CONTEXT& ctx) {
            for (size_t i = 0; i < m_original_bytes.size(); ++i) {
                fix_ip(ctx, m_trampoline.data() + i, m_target + i);
            }
        });

    m_trampoline.free();
}
} // namespace safetyhook
