#include <algorithm>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

#if __has_include("Zydis/Zydis.h")
#include "Zydis/Zydis.h"
#elif __has_include("Zydis.h")
#include "Zydis.h"
#else
#error "Zydis not found"
#endif

#include "safetyhook/allocator.hpp"
#include "safetyhook/common.hpp"
#include "safetyhook/os.hpp"
#include "safetyhook/utility.hpp"

#include "safetyhook/inline_hook.hpp"

namespace safetyhook {

#pragma pack(push, 1)
struct JmpE9 {
    uint8_t opcode{0xE9};
    uint32_t offset{0};
};

#if SAFETYHOOK_ARCH_X86_64
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
#elif SAFETYHOOK_ARCH_X86_32
struct TrampolineEpilogueE9 {
    JmpE9 jmp_to_original{};
    JmpE9 jmp_to_destination{};
};
#endif
#pragma pack(pop)

#if SAFETYHOOK_ARCH_X86_64
static auto make_jmp_ff(uint8_t* src, uint8_t* dst, uint8_t* data) {
    JmpFF jmp{};

    jmp.offset = static_cast<uint32_t>(data - src - sizeof(jmp));
    store(data, dst);

    return jmp;
}

[[nodiscard]] static std::expected<void, InlineHook::Error> emit_jmp_ff(
    uint8_t* src, uint8_t* dst, uint8_t* data, size_t size = sizeof(JmpFF)) {
    if (size < sizeof(JmpFF)) {
        return std::unexpected{InlineHook::Error::not_enough_space(dst)};
    }

    if (size > sizeof(JmpFF)) {
        std::fill_n(src, size, static_cast<uint8_t>(0x90));
    }

    store(src, make_jmp_ff(src, dst, data));

    return {};
}
#endif

constexpr auto make_jmp_e9(uint8_t* src, uint8_t* dst) {
    JmpE9 jmp{};

    jmp.offset = static_cast<uint32_t>(dst - src - sizeof(jmp));

    return jmp;
}

[[nodiscard]] static std::expected<void, InlineHook::Error> emit_jmp_e9(
    uint8_t* src, uint8_t* dst, size_t size = sizeof(JmpE9)) {
    if (size < sizeof(JmpE9)) {
        return std::unexpected{InlineHook::Error::not_enough_space(dst)};
    }

    if (size > sizeof(JmpE9)) {
        std::fill_n(src, size, static_cast<uint8_t>(0x90));
    }

    store(src, make_jmp_e9(src, dst));

    return {};
}

// A jump whose destination can be changed in place.
#if SAFETYHOOK_ARCH_X86_64
constexpr size_t redirect_size = sizeof(JmpFF) + sizeof(uint64_t);

static void write_redirect(uint8_t* src, uint8_t* dst) {
    store(src, make_jmp_ff(src, dst, src + sizeof(JmpFF)));
}
#elif SAFETYHOOK_ARCH_X86_32
constexpr size_t redirect_size = sizeof(JmpE9);

static void write_redirect(uint8_t* src, uint8_t* dst) {
    store(src, make_jmp_e9(src, dst));
}
#endif

// E9 trampolines end with one: the patch jumps to it, and it jumps to the destination.
static_assert(sizeof(TrampolineEpilogueE9) == sizeof(JmpE9) + redirect_size);

static void redirect(uint8_t* src, uint8_t* dst) {
    trap_threads(src, src, redirect_size, [src, dst] { write_redirect(src, dst); });
}

// All hooks on a target share one patch and one relocation of the code it displaced. The patch leads to the topmost
// enabled hook, and each hook stacked on top of the first gets a trampoline that is just a redirect to the next enabled
// hook below it (or the relocated code). Enabling, disabling or removing a hook re-points redirects, patching the
// target when its first hook is enabled and restoring it when its last one is disabled.
namespace {
struct StackedHook {
    uint8_t* trampoline{}; // What the hook's original() calls.
    uint8_t* destination{};
    uint8_t* next{}; // Where the trampoline leads, if it's a redirect.
    bool enabled{};
};

// The instructions a patch at a target displaces, copied into a trampoline that runs them and jumps back.
struct Relocation {
    Allocation trampoline{};
    uint8_t* entry{}; // The redirect the patch goes through: the end of the trampoline for E9, the patch itself for FF.
    std::vector<uint8_t> original_bytes{};
};

struct Site {
    std::shared_ptr<Allocator> allocator{};
    uint8_t* trampoline{}; // The relocated code, at the bottom of every chain.
    uint8_t* entry{};
    std::vector<uint8_t> original_bytes{};
    Allocation owned_trampoline{};    // Holds the relocated code once no hook's trampoline is it.
    uint8_t* patched_to{};            // Null while the target is unpatched.
    std::vector<StackedHook> hooks{}; // Bottom to top.
};

// Leaked intentionally so they outlive the destructors of any static/global hooks (avoids teardown-order UB).
std::mutex& site_mutex() {
    static auto* mutex = new std::mutex{};
    return *mutex;
}

std::map<uint8_t*, Site>& sites() {
    static auto* registry = new std::map<uint8_t*, Site>{};
    return *registry;
}
} // namespace

static std::expected<Relocation, InlineHook::Error> relocate(
    const std::shared_ptr<Allocator>& allocator, uint8_t* target);

// Points the patch at `destination`, applying it if needed, or restores the original bytes if `destination` is null.
static void aim_patch(uint8_t* target, Site& site, uint8_t* destination) {
    if (destination == site.patched_to) {
        return;
    }

    const auto size = site.original_bytes.size();

    if (destination == nullptr) {
        trap_threads(site.trampoline, target, size,
            [&site, target] { std::copy(site.original_bytes.begin(), site.original_bytes.end(), target); });
    } else if (site.patched_to != nullptr) {
        redirect(site.entry, destination);
    } else if (site.entry != target) {
        // E9: the patch jumps to the redirect at the end of the trampoline.
        write_redirect(site.entry, destination);
        trap_threads(target, site.trampoline, size, [&site, target, size] {
            std::fill_n(target, size, static_cast<uint8_t>(0x90));
            store(target, make_jmp_e9(target, site.entry));
        });
    } else {
        // FF: the patch is the redirect.
        trap_threads(target, site.trampoline, size, [target, size, destination] {
            std::fill_n(target, size, static_cast<uint8_t>(0x90));
            write_redirect(target, destination);
        });
    }

    site.patched_to = destination;
}

// Points each stacked trampoline at the next enabled hook below it and the patch at the topmost one. Fails, changing
// nothing, if the target's code has to be relocated again and can't be.
static std::expected<void, InlineHook::Error> relink(uint8_t* target, Site& site) {
    Allocation replaced_trampoline{}; // Freed once nothing leads to it.

    // While no hook is enabled the target holds its own code, which may have changed since it was relocated. If the
    // first hook's trampoline held the old relocation, it becomes a redirect like the others.
    if (site.patched_to == nullptr && !std::equal(site.original_bytes.begin(), site.original_bytes.end(), target)) {
        auto relocation = relocate(site.allocator, target);

        if (!relocation) {
            return std::unexpected{relocation.error()};
        }

        site.trampoline = relocation->trampoline.data();
        site.entry = relocation->entry;
        site.original_bytes = std::move(relocation->original_bytes);
        replaced_trampoline = std::exchange(site.owned_trampoline, std::move(relocation->trampoline));
    }

    auto* next = site.trampoline;

    for (auto& hook : site.hooks) {
        if (hook.trampoline != site.trampoline && hook.next != next) {
            redirect(hook.trampoline, next);
            hook.next = next;
        }

        if (hook.enabled) {
            next = hook.destination;
        }
    }

    aim_patch(target, site, next != site.trampoline ? next : nullptr);

    return {};
}

static std::expected<void, InlineHook::Error> set_enabled(uint8_t* target, uint8_t* trampoline, bool enabled) {
    std::scoped_lock lock{site_mutex()};

    const auto site = sites().find(target);

    if (site == sites().end()) {
        return {};
    }

    auto& hooks = site->second.hooks;
    const auto stacked = std::find_if(
        hooks.begin(), hooks.end(), [trampoline](const auto& hook) { return hook.trampoline == trampoline; });

    stacked->enabled = enabled;

    auto result = relink(target, site->second);

    if (!result) {
        stacked->enabled = !enabled;
    }

    return result;
}

static bool decode(ZydisDecodedInstruction* ix, uint8_t* ip) {
    ZydisDecoder decoder{};
    ZyanStatus status;

#if SAFETYHOOK_ARCH_X86_64
    status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#elif SAFETYHOOK_ARCH_X86_32
    status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#endif

    if (!ZYAN_SUCCESS(status)) {
        return false;
    }

    return ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr, ip, 15, ix));
}

#if SAFETYHOOK_ARCH_X86_32
static std::optional<uint8_t> x86_get_pc_thunk_register(uint8_t* ip, const ZydisDecodedInstruction& ix) {
    if (ix.mnemonic != ZYDIS_MNEMONIC_CALL || ix.raw.imm[0].size != 32) {
        return std::nullopt;
    }

    const auto* thunk_ip = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
    ZydisDecodedInstruction mov_ix{};
    ZydisDecodedInstruction ret_ix{};

    if (!decode(&mov_ix, const_cast<uint8_t*>(thunk_ip)) ||
        !decode(&ret_ix, const_cast<uint8_t*>(thunk_ip + mov_ix.length))) {
        return std::nullopt;
    }

    // GNU i386 PIC thunks have this body: mov r32, [esp]; ret.
    if (mov_ix.mnemonic != ZYDIS_MNEMONIC_MOV || mov_ix.length != 3 || ret_ix.mnemonic != ZYDIS_MNEMONIC_RET ||
        ret_ix.length != 1 || thunk_ip[0] != 0x8B || thunk_ip[2] != 0x24 || thunk_ip[mov_ix.length] != 0xC3) {
        return std::nullopt;
    }

    const auto modrm = thunk_ip[1];

    if ((modrm & 0xC7) != 0x04) {
        return std::nullopt;
    }

    return (modrm >> 3) & 0x07;
}

static void emit_mov_r32_imm32(uint8_t* ip, uint8_t reg, uint8_t* value) {
    *ip = static_cast<uint8_t>(0xB8 + reg);
    store(ip + 1, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(value)));
}
#endif

std::expected<InlineHook, InlineHook::Error> InlineHook::create(void* target, void* destination, Flags flags) {
    return create(Allocator::global(), target, destination, flags);
}

std::expected<InlineHook, InlineHook::Error> InlineHook::create(
    const std::shared_ptr<Allocator>& allocator, void* target, void* destination, Flags flags) {
    InlineHook hook{};

    if (const auto setup_result =
            hook.setup(allocator, reinterpret_cast<uint8_t*>(target), reinterpret_cast<uint8_t*>(destination));
        !setup_result) {
        return std::unexpected{setup_result.error()};
    }

    if (!(flags & StartDisabled)) {
        if (auto enable_result = hook.enable(); !enable_result) {
            return std::unexpected{enable_result.error()};
        }
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
        m_original_bytes = std::move(other.m_original_bytes);
        m_enabled = other.m_enabled;

        other.m_target = nullptr;
        other.m_destination = nullptr;
        other.m_enabled = false;
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

    std::scoped_lock lock{site_mutex()};
    auto [it, created] = sites().try_emplace(m_target);
    auto& site = it->second;

    if (created) {
        // The first hook on a target relocates the code its patch displaces and uses that as its trampoline.
        auto relocation = relocate(allocator, m_target);

        if (!relocation) {
            sites().erase(it);
            return std::unexpected{relocation.error()};
        }

        m_trampoline = std::move(relocation->trampoline);
        site.allocator = allocator;
        site.trampoline = m_trampoline.data();
        site.entry = relocation->entry;
        site.original_bytes = std::move(relocation->original_bytes);
    } else {
        // Hooks stacked on top get a trampoline that redirects to whatever is enabled below them.
        auto trampoline_allocation = allocator->allocate(redirect_size);

        if (!trampoline_allocation) {
            return std::unexpected{Error::bad_allocation(trampoline_allocation.error())};
        }

        m_trampoline = std::move(*trampoline_allocation);
    }

    site.hooks.push_back({m_trampoline.data(), m_destination, nullptr, false});

    if (auto result = relink(m_target, site); !result) {
        return result;
    }

    m_original_bytes = site.original_bytes;

    return {};
}

static std::expected<Relocation, InlineHook::Error> relocate_e9(
    const std::shared_ptr<Allocator>& allocator, uint8_t* target) {
    Relocation relocation{};
    auto& original_bytes = relocation.original_bytes;
    auto trampoline_size = sizeof(TrampolineEpilogueE9);

    std::vector<uint8_t*> desired_addresses{target};
    ZydisDecodedInstruction ix{};

    for (auto ip = target; ip < target + sizeof(JmpE9); ip += ix.length) {
        if (!decode(&ix, ip)) {
            return std::unexpected{InlineHook::Error::failed_to_decode_instruction(ip)};
        }

        trampoline_size += ix.length;
        original_bytes.insert(original_bytes.end(), ip, ip + ix.length);

        const auto is_relative = (ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;

        if (is_relative) {
            if (ix.raw.disp.size == 32) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.disp.value);
                desired_addresses.emplace_back(target_address);
            } else if (ix.raw.imm[0].size == 32) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
                desired_addresses.emplace_back(target_address);
            } else if (ix.meta.category == ZYDIS_CATEGORY_COND_BR && ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
                desired_addresses.emplace_back(target_address);
                trampoline_size += 4; // near conditional branches are 4 bytes larger.
            } else if (ix.meta.category == ZYDIS_CATEGORY_UNCOND_BR && ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
                desired_addresses.emplace_back(target_address);
                trampoline_size += 3; // near unconditional branches are 3 bytes larger.
            } else {
                return std::unexpected{InlineHook::Error::unsupported_instruction_in_trampoline(ip)};
            }
        }
    }

    auto trampoline_allocation = allocator->allocate_near(desired_addresses, trampoline_size);

    if (!trampoline_allocation) {
        return std::unexpected{InlineHook::Error::bad_allocation(trampoline_allocation.error())};
    }

    relocation.trampoline = std::move(*trampoline_allocation);
    auto* trampoline = relocation.trampoline.data();

    for (auto ip = target, tramp_ip = trampoline; ip < target + original_bytes.size(); ip += ix.length) {
        if (!decode(&ix, ip)) {
            return std::unexpected{InlineHook::Error::failed_to_decode_instruction(ip)};
        }

        const auto is_relative = (ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;

#if SAFETYHOOK_ARCH_X86_32
        if (auto thunk_reg = x86_get_pc_thunk_register(ip, ix); thunk_reg) {
            emit_mov_r32_imm32(tramp_ip, *thunk_reg, ip + ix.length);
            tramp_ip += ix.length;
            continue;
        }
#endif

        if (is_relative && ix.raw.disp.size == 32) {
            std::copy_n(ip, ix.length, tramp_ip);
            const auto target_address = ip + ix.length + ix.raw.disp.value;
            const auto new_disp = target_address - (tramp_ip + ix.length);
            store(tramp_ip + ix.raw.disp.offset, static_cast<int32_t>(new_disp));
            tramp_ip += ix.length;
        } else if (is_relative && ix.raw.imm[0].size == 32) {
            std::copy_n(ip, ix.length, tramp_ip);
            const auto target_address = ip + ix.length + ix.raw.imm[0].value.s;
            const auto new_disp = target_address - (tramp_ip + ix.length);
            store(tramp_ip + ix.raw.imm[0].offset, static_cast<int32_t>(new_disp));
            tramp_ip += ix.length;
        } else if (ix.meta.category == ZYDIS_CATEGORY_COND_BR && ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT) {
            const auto target_address = ip + ix.length + ix.raw.imm[0].value.s;
            auto new_disp = target_address - (tramp_ip + 6);

            // Handle the case where the target is now in the trampoline.
            if (target_address >= target && target_address < target + original_bytes.size()) {
                new_disp = static_cast<ptrdiff_t>(ix.raw.imm[0].value.s);
            }

            *tramp_ip = 0x0F;
            *(tramp_ip + 1) = 0x10 + ix.opcode;
            store(tramp_ip + 2, static_cast<int32_t>(new_disp));
            tramp_ip += 6;
        } else if (ix.meta.category == ZYDIS_CATEGORY_UNCOND_BR && ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT) {
            const auto target_address = ip + ix.length + ix.raw.imm[0].value.s;
            auto new_disp = target_address - (tramp_ip + 5);

            // Handle the case where the target is now in the trampoline.
            if (target_address >= target && target_address < target + original_bytes.size()) {
                new_disp = static_cast<ptrdiff_t>(ix.raw.imm[0].value.s);
            }

            *tramp_ip = 0xE9;
            store(tramp_ip + 1, static_cast<int32_t>(new_disp));
            tramp_ip += 5;
        } else {
            std::copy_n(ip, ix.length, tramp_ip);
            tramp_ip += ix.length;
        }
    }

    auto trampoline_epilogue =
        reinterpret_cast<TrampolineEpilogueE9*>(trampoline + trampoline_size - sizeof(TrampolineEpilogueE9));

    // jmp from trampoline to original.
    auto src = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_original);
    auto dst = target + original_bytes.size();

    if (auto result = emit_jmp_e9(src, dst); !result) {
        return std::unexpected{result.error()};
    }

    // The patch leads through the redirect at the end of the trampoline to the destination.
    relocation.entry = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_destination);

    return relocation;
}

#if SAFETYHOOK_ARCH_X86_64
static std::expected<Relocation, InlineHook::Error> relocate_ff(
    const std::shared_ptr<Allocator>& allocator, uint8_t* target) {
    Relocation relocation{};
    auto& original_bytes = relocation.original_bytes;
    auto trampoline_size = sizeof(TrampolineEpilogueFF);
    ZydisDecodedInstruction ix{};

    for (auto ip = target; ip < target + sizeof(JmpFF) + sizeof(uintptr_t); ip += ix.length) {
        if (!decode(&ix, ip)) {
            return std::unexpected{InlineHook::Error::failed_to_decode_instruction(ip)};
        }

        // We can't support any instruction that is IP relative here because
        // relocate_ff should only be called if relocate_e9 failed indicating that
        // we're likely outside the +- 2GB range.
        if (ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
            return std::unexpected{InlineHook::Error::ip_relative_instruction_out_of_range(ip)};
        }

        original_bytes.insert(original_bytes.end(), ip, ip + ix.length);
        trampoline_size += ix.length;
    }

    auto trampoline_allocation = allocator->allocate(trampoline_size);

    if (!trampoline_allocation) {
        return std::unexpected{InlineHook::Error::bad_allocation(trampoline_allocation.error())};
    }

    relocation.trampoline = std::move(*trampoline_allocation);
    auto* trampoline = relocation.trampoline.data();

    std::copy(original_bytes.begin(), original_bytes.end(), trampoline);

    const auto trampoline_epilogue =
        reinterpret_cast<TrampolineEpilogueFF*>(trampoline + trampoline_size - sizeof(TrampolineEpilogueFF));

    // jmp from trampoline to original.
    auto src = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_original);
    auto dst = target + original_bytes.size();
    auto data = reinterpret_cast<uint8_t*>(&trampoline_epilogue->original_address);

    if (auto result = emit_jmp_ff(src, dst, data); !result) {
        return std::unexpected{result.error()};
    }

    // The patch holds the jump to the destination itself.
    relocation.entry = target;

    return relocation;
}
#endif

// Relocates the instructions a patch at `target` displaces into a trampoline that runs them and jumps back.
static std::expected<Relocation, InlineHook::Error> relocate(
    const std::shared_ptr<Allocator>& allocator, uint8_t* target) {
#if SAFETYHOOK_ARCH_X86_64
    if (auto relocation = relocate_e9(allocator, target)) {
        return relocation;
    }

    return relocate_ff(allocator, target);
#elif SAFETYHOOK_ARCH_X86_32
    return relocate_e9(allocator, target);
#endif
}

std::expected<void, InlineHook::Error> InlineHook::enable() {
    std::scoped_lock lock{m_mutex};

    if (m_enabled) {
        return {};
    }

    if (auto result = set_enabled(m_target, m_trampoline.data(), true); !result) {
        return result;
    }

    m_enabled = true;

    return {};
}

std::expected<void, InlineHook::Error> InlineHook::disable() {
    std::scoped_lock lock{m_mutex};

    if (!m_enabled) {
        return {};
    }

    if (auto result = set_enabled(m_target, m_trampoline.data(), false); !result) {
        return result;
    }

    m_enabled = false;

    return {};
}

void InlineHook::destroy() {
    [[maybe_unused]] auto disable_result = disable();

    std::scoped_lock lock{m_mutex};

    if (!m_trampoline) {
        return;
    }

    std::scoped_lock sites_lock{site_mutex()};

    if (auto site = sites().find(m_target); site != sites().end()) {
        auto& hooks = site->second.hooks;

        std::erase_if(hooks, [this](const auto& hook) { return hook.trampoline == m_trampoline.data(); });

        if (hooks.empty()) {
            sites().erase(site);
        } else if (m_trampoline.data() == site->second.trampoline) {
            // The hooks stacked above still run the original code through it.
            site->second.owned_trampoline = std::move(m_trampoline);
        }
    }

    m_trampoline.free();
}
} // namespace safetyhook
