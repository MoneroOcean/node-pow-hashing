#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>
#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <unistd.h>
#include <vector>
#include <mutex>

#if defined(__ARM_ARCH)
  #define my_malloc(a, b) malloc(a)
#else
  #define my_malloc(a, b) _mm_malloc(a, b)
#endif

//#if (defined(__AES__) && (__AES__ == 1)) || defined(__APPLE__) || defined(__ARM_ARCH)
//#else
//#define _mm_aeskeygenassist_si128(a, b) a
//#define _mm_aesenc_si128(a, b) a
//#endif

#include "crypto/common/VirtualMemory.h"
#include "backend/cpu/Cpu.h"
#include "backend/cpu/interfaces/ICpuInfo.h"
#include "crypto/cn/CnCtx.h"
#include "crypto/cn/CnHash.h"
#include "crypto/randomx/configuration.h"
#include "crypto/randomx/randomx.h"
#include "crypto/astrobwt/AstroBWT.h"
#include "crypto/kawpow/KPHash.h"
#include "crypto/kawpow/KPCache.h"
#include "3rdparty/libethash/ethash.h"
#include "crypto/ghostrider/ghostrider.h"
#include "crypto/ghostrider/sph_keccak.h"

extern "C" {
#include "crypto/randomx/panthera/KangarooTwelve.h"
#include "crypto/randomx/blake2/blake2.h"
#if defined(__x86_64__) || defined(_M_X64)
#include "crypto/randomx/blake2/avx2/blake2b.h"
#endif
#include "c29/portable_endian.h" // for htole32/64
#include "c29/int-util.h"
}

#include "c29.h"

void (*rx_blake2b_compress)(blake2b_state* S, const uint8_t * block) = rx_blake2b_compress_integer;
int (*rx_blake2b)(void* out, size_t outlen, const void* in, size_t inlen) = rx_blake2b_default;

#undef NAN_METHOD
#define NAN_METHOD(name) void name(const v8::FunctionCallbackInfo<v8::Value>& info)

namespace {

struct KawpowCacheEntry {
    std::unique_ptr<xmrig::KPCache> cache;
    uint64_t last_used = 0;
};

using KawpowCacheTime = std::chrono::steady_clock::time_point;

struct KawpowCacheLookupStats {
    bool created = false;
    int64_t evicted_epoch = -1;
    size_t trimmed_entries = 0;
    size_t cache_capacity = 1;
    size_t recent_epochs = 0;
    size_t total_cache_size = 0;
    size_t total_cache_memory_size = 0;
};

struct KawpowEpochAccess {
    uint32_t epoch = 0;
    KawpowCacheTime last_seen;
};

constexpr size_t KAWPOW_MIN_CACHE_ENTRIES = 1;
constexpr size_t KAWPOW_MAX_CACHE_ENTRIES = 10;
constexpr auto KAWPOW_CACHE_GROW_WINDOW = std::chrono::hours(1);
std::vector<KawpowCacheEntry> kawpow_caches;
std::vector<KawpowEpochAccess> kawpow_cache_epoch_accesses;
uint64_t kawpow_cache_clock = 0;

inline v8::Local<v8::String> NewString(v8::Isolate* isolate, const char* value) {
    return v8::String::NewFromUtf8(isolate, value).ToLocalChecked();
}

inline void SetExport(v8::Isolate* isolate, v8::Local<v8::Object> target,
                      const char* name, v8::FunctionCallback callback) {
    target->Set(
        isolate->GetCurrentContext(),
        NewString(isolate, name),
        v8::Function::New(isolate->GetCurrentContext(), callback).ToLocalChecked()
    ).Check();
}

inline void SetArrayValue(v8::Isolate* isolate, v8::Local<v8::Array> target,
                          uint32_t index, v8::Local<v8::Value> value) {
    target->Set(isolate->GetCurrentContext(), index, value).Check();
}

void PruneKawpowCacheEpochAccesses(KawpowCacheTime now) {
    kawpow_cache_epoch_accesses.erase(
        std::remove_if(
            kawpow_cache_epoch_accesses.begin(),
            kawpow_cache_epoch_accesses.end(),
            [now](const KawpowEpochAccess& access) {
                return now - access.last_seen > KAWPOW_CACHE_GROW_WINDOW;
            }
        ),
        kawpow_cache_epoch_accesses.end()
    );
}

void RecordKawpowCacheEpochAccess(uint32_t epoch, KawpowCacheTime now) {
    for (KawpowEpochAccess& access : kawpow_cache_epoch_accesses) {
        if (access.epoch == epoch) {
            access.last_seen = now;
            return;
        }
    }

    kawpow_cache_epoch_accesses.push_back({ epoch, now });
}

size_t KawpowCacheCapacity() {
    size_t capacity = kawpow_cache_epoch_accesses.size();
    if (capacity < KAWPOW_MIN_CACHE_ENTRIES) capacity = KAWPOW_MIN_CACHE_ENTRIES;
    if (capacity > KAWPOW_MAX_CACHE_ENTRIES) capacity = KAWPOW_MAX_CACHE_ENTRIES;
    return capacity;
}

void UpdateKawpowCacheStats(KawpowCacheLookupStats& stats) {
    stats.cache_capacity = KawpowCacheCapacity();
    stats.recent_epochs = kawpow_cache_epoch_accesses.size();
    stats.total_cache_size = 0;
    stats.total_cache_memory_size = 0;

    for (const KawpowCacheEntry& item : kawpow_caches) {
        if (!item.cache) continue;
        stats.total_cache_size += item.cache->size();
        stats.total_cache_memory_size += item.cache->memorySize();
    }
}

void TrimKawpowCaches(size_t capacity, const xmrig::KPCache* keep, KawpowCacheLookupStats& stats) {
    while (kawpow_caches.size() > capacity) {
        size_t victim = kawpow_caches.size();
        for (size_t i = 0; i < kawpow_caches.size(); ++i) {
            if (kawpow_caches[i].cache.get() == keep) continue;
            if (victim == kawpow_caches.size() || kawpow_caches[i].last_used < kawpow_caches[victim].last_used) {
                victim = i;
            }
        }

        if (victim == kawpow_caches.size()) return;
        if (stats.evicted_epoch == -1 && kawpow_caches[victim].cache) {
            stats.evicted_epoch = static_cast<int64_t>(kawpow_caches[victim].cache->epoch());
        }
        kawpow_caches.erase(kawpow_caches.begin() + victim);
        ++stats.trimmed_entries;
    }
}

xmrig::KPCache* GetKawpowCache(uint32_t epoch, KawpowCacheLookupStats& stats) {
    stats = {};
    const auto now = std::chrono::steady_clock::now();
    PruneKawpowCacheEpochAccesses(now);
    ++kawpow_cache_clock;

    if (xmrig::KPCache::cache_size(epoch) == 0) return nullptr;
    RecordKawpowCacheEpochAccess(epoch, now);

    for (KawpowCacheEntry& entry : kawpow_caches) {
        if (entry.cache && entry.cache->epoch() == epoch) {
            entry.last_used = kawpow_cache_clock;
            xmrig::KPCache* cache = entry.cache.get();
            TrimKawpowCaches(KawpowCacheCapacity(), cache, stats);
            UpdateKawpowCacheStats(stats);
            return cache;
        }
    }

    const size_t capacity = KawpowCacheCapacity();
    KawpowCacheEntry* entry = nullptr;
    if (kawpow_caches.size() < capacity) {
        kawpow_caches.push_back({});
        entry = &kawpow_caches.back();
    }
    else {
        entry = &kawpow_caches.front();
        for (KawpowCacheEntry& item : kawpow_caches) {
            if (item.last_used < entry->last_used) entry = &item;
        }
        stats.evicted_epoch = entry->cache ? static_cast<int64_t>(entry->cache->epoch()) : -1;
    }

    entry->cache = std::make_unique<xmrig::KPCache>();
    entry->last_used = kawpow_cache_clock;
    stats.created = true;
    if (!entry->cache->init(epoch)) return nullptr;

    xmrig::KPCache* cache = entry->cache.get();
    TrimKawpowCaches(capacity, cache, stats);
    UpdateKawpowCacheStats(stats);
    return cache;
}

}  // namespace

#if (defined(__AES__) && (__AES__ == 1)) || (defined(__ARM_FEATURE_CRYPTO) && (__ARM_FEATURE_CRYPTO == 1))
  #define SOFT_AES 0
  #if defined(CPU_INTEL)
    #warning Using IvyBridge assembler implementation
    #define ASM_TYPE xmrig::Assembly::INTEL
  #elif defined(CPU_AMD)
    #warning Using Ryzen assembler implementation
    #define ASM_TYPE xmrig::Assembly::RYZEN
  #elif defined(CPU_AMD_OLD)
    #warning Using Bulldozer assembler implementation
    #define ASM_TYPE xmrig::Assembly::BULLDOZER
  #elif !defined(__ARM_ARCH)
    #error Unknown ASM implementation!
  #endif
#else
  #warning Using software AES
  #define SOFT_AES 1
#endif

#define FN(algo)  xmrig::CnHash::fn(xmrig::Algorithm::algo, SOFT_AES ? xmrig::CnHash::AV_SINGLE_SOFT : xmrig::CnHash::AV_SINGLE, xmrig::Assembly::NONE)
#if defined(ASM_TYPE)
  #define FNA(algo) xmrig::CnHash::fn(xmrig::Algorithm::algo, SOFT_AES ? xmrig::CnHash::AV_SINGLE_SOFT : xmrig::CnHash::AV_SINGLE, ASM_TYPE)
#else
  #define FNA(algo) xmrig::CnHash::fn(xmrig::Algorithm::algo, SOFT_AES ? xmrig::CnHash::AV_SINGLE_SOFT : xmrig::CnHash::AV_SINGLE, xmrig::Assembly::NONE)
#endif


const size_t max_mem_size = 20 * 1024 * 1024;
constexpr size_t ghostrider_min_input_size = 36;
xmrig::VirtualMemory mem(max_mem_size, true, false, 0, 4096);
static struct cryptonight_ctx* ctx = nullptr;

const int MAXRX = 4;
int rx2id(xmrig::Algorithm::Id algo) {
  switch (algo) {
      case xmrig::Algorithm::RX_0:     return 0;
      case xmrig::Algorithm::RX_V2:    return 1;
      case xmrig::Algorithm::RX_ARQ:   return 2;
      //case xmrig::Algorithm::RX_WOW:   return 2;
      //case xmrig::Algorithm::RX_GRAFT: return 3;
      //case xmrig::Algorithm::RX_SFX:   return 4;
      //case xmrig::Algorithm::RX_KEVA:  return 5;
      case xmrig::Algorithm::RX_XLA:   return MAXRX-1;
      default: return 0;
  }
}

static randomx_vm*    rx_vm[MAXRX]            = {nullptr};
static bool           rx_vm_jit[MAXRX]        = {false};
static uint32_t       rx_vm_algo[MAXRX]       = {0};

const int rx_seed_cache_size = MAXRX+2;
static randomx_cache* rx_cache[rx_seed_cache_size]         = {nullptr};
static uint8_t*       rx_cache_mem[rx_seed_cache_size]     = {nullptr};
static uint8_t        rx_seed_hash[rx_seed_cache_size][32] = {0};
static uint32_t       rx_seed_algo[rx_seed_cache_size]     = {0};
static int            rx_active_cache_size                 = rx_seed_cache_size;

static std::mutex randomx_mutex;
static std::mutex ethash_mutex;
static std::mutex etchash_mutex;

struct InitCtx {
    InitCtx() {
        xmrig::CnCtx::create(&ctx, static_cast<uint8_t*>(my_malloc(max_mem_size, 4096)), max_mem_size, 1);
        for (int i = 0; i != rx_seed_cache_size; ++ i) memset(rx_seed_hash[i], 0xCC, sizeof(rx_seed_hash[0]));
    }
} s;

void init_rx(const uint8_t* seed_hash_data, xmrig::Algorithm::Id algo) {
    std::lock_guard<std::mutex> lock(randomx_mutex);
    const int rxid = rx2id(algo);
    assert(rxid < MAXRX);

    randomx_set_scratchpad_prefetch_mode(0);
    randomx_set_huge_pages_jit(true);
    //randomx_set_optimized_dataset_init(0);

    switch (algo) {
        case xmrig::Algorithm::RX_0:
            randomx_apply_config(RandomX_MoneroConfig);
            break;
        case xmrig::Algorithm::RX_V2:
            randomx_apply_config(RandomX_MoneroConfigV2);
            break;
        case xmrig::Algorithm::RX_WOW:
            randomx_apply_config(RandomX_WowneroConfig);
            break;
        case xmrig::Algorithm::RX_ARQ:
            randomx_apply_config(RandomX_ArqmaConfig);
            break;
        case xmrig::Algorithm::RX_XEQ:
            randomx_apply_config(RandomX_EquilibriaConfig);
            break;
        case xmrig::Algorithm::RX_GRAFT:
            randomx_apply_config(RandomX_GraftConfig);
            break;
        case xmrig::Algorithm::RX_KEVA:
            randomx_apply_config(RandomX_KevaConfig);
            break;
        case xmrig::Algorithm::RX_XLA:
            randomx_apply_config(RandomX_ScalaConfig);
            break;
        default:
            throw std::domain_error("Unknown RandomX algo");
    }

    int found_rxid = -1;
    for (int i = 0; i != rx_active_cache_size; ++ i)
      if (rx_seed_algo[i] == static_cast<uint32_t>(algo) &&
          memcmp(rx_seed_hash[i], seed_hash_data, sizeof(rx_seed_hash[0])) == 0) {
        found_rxid = i;
        break;
      }

    if (found_rxid == -1) {
        static int new_rxid = 0;
        if (rx_cache_mem[new_rxid] == nullptr) {
            rx_cache_mem[new_rxid] = static_cast<uint8_t*>(my_malloc(RANDOMX_CACHE_MAX_SIZE, 4096));
        }
        if (rx_cache[new_rxid] != nullptr) {
            randomx_release_cache(rx_cache[new_rxid]);
        }
        rx_cache[new_rxid] = randomx_create_cache(RANDOMX_FLAG_JIT, rx_cache_mem[new_rxid]);
        if (rx_cache[new_rxid] == nullptr) {
            rx_cache[new_rxid] = randomx_create_cache(RANDOMX_FLAG_DEFAULT, rx_cache_mem[new_rxid]);
        }
        if (rx_cache[new_rxid] == nullptr) {
            throw std::runtime_error("Unable to create RandomX cache");
        }
        rx_seed_algo[new_rxid] = static_cast<uint32_t>(algo);
        memcpy(rx_seed_hash[new_rxid], seed_hash_data, sizeof(rx_seed_hash[0]));
        randomx_init_cache(rx_cache[new_rxid], rx_seed_hash[new_rxid], sizeof(rx_seed_hash[0]));
        found_rxid = new_rxid;
        ++ new_rxid;
        if (new_rxid >= rx_active_cache_size) new_rxid = 0;
    }

    const bool use_vm_jit = false;
    if (rx_vm[rxid] != nullptr &&
        (rx_vm_algo[rxid] != static_cast<uint32_t>(algo) || rx_vm_jit[rxid] != use_vm_jit)) {
        randomx_destroy_vm(rx_vm[rxid]);
        rx_vm[rxid] = nullptr;
    }

    if (rx_vm[rxid] == nullptr) {
        int flags = 0;
#if !SOFT_AES
        flags |= RANDOMX_FLAG_HARD_AES;
#endif
        if (use_vm_jit) flags |= RANDOMX_FLAG_JIT;
        rx_vm[rxid] = randomx_create_vm(static_cast<randomx_flags>(flags), rx_cache[found_rxid], nullptr, mem.scratchpad(), 0);
        if (rx_vm[rxid] == nullptr && use_vm_jit) {
            flags &= ~RANDOMX_FLAG_JIT;
            rx_vm[rxid] = randomx_create_vm(static_cast<randomx_flags>(flags), rx_cache[found_rxid], nullptr, mem.scratchpad(), 0);
            rx_vm_jit[rxid] = false;
        } else {
            rx_vm_jit[rxid] = use_vm_jit;
        }
        if (rx_vm[rxid] == nullptr) {
            throw std::runtime_error("Unable to create RandomX VM");
        }
        rx_vm_algo[rxid] = static_cast<uint32_t>(algo);
    } else {
        randomx_vm_set_cache(rx_vm[rxid], rx_cache[found_rxid]);
    }
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
    free(data);
}

using namespace v8;
using namespace Nan;
namespace Buffer = node::Buffer;

NAN_METHOD(randomx) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    Local<Object> seed_hash = info[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(seed_hash)) return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");
    if (Buffer::Length(seed_hash) != sizeof(rx_seed_hash[0])) return THROW_ERROR_EXCEPTION("Argument 2 size should be 32 bytes.");

    int algo = 0;
    if (info.Length() >= 3) {
        if (info[2]->IsString()) {
            Nan::Utf8String algo_name(info[2]);
            if (strcmp(*algo_name, "rx/2") == 0) algo = -2;
            else return THROW_ERROR_EXCEPTION("Unsupported RandomX algo name");
        } else if (info[2]->IsNumber()) {
            algo = Nan::To<int>(info[2]).FromMaybe(0);
        } else return THROW_ERROR_EXCEPTION("Argument 3 should be a number or supported string");
    }

    xmrig::Algorithm xalgo;
    switch (algo) {
        case 0:  xalgo = xmrig::Algorithm::RX_0; break;
        case -2: xalgo = xmrig::Algorithm::RX_V2; break;
        case 2:  xalgo = xmrig::Algorithm::RX_ARQ; break;
        case 1:
        case 3:  xalgo = xmrig::Algorithm::RX_XLA; break;
        case 17: xalgo = xmrig::Algorithm::RX_WOW; break;
        //case 18: xalgo = xmrig::Algorithm::RX_LOKI; break;
        case 19: xalgo = xmrig::Algorithm::RX_KEVA; break;
        case 20: xalgo = xmrig::Algorithm::RX_GRAFT; break;
        case 22: xalgo = xmrig::Algorithm::RX_XEQ; break;
        default: xalgo = xmrig::Algorithm::RX_0;
    }

    try {
        init_rx(reinterpret_cast<const uint8_t*>(Buffer::Data(seed_hash)), xalgo);
    } catch (const std::domain_error &e) {
        return THROW_ERROR_EXCEPTION(e.what());
    } catch (const std::exception &e) {
        return THROW_ERROR_EXCEPTION(e.what());
    }

    char output[32];
    {
        std::lock_guard<std::mutex> lock(randomx_mutex);
        randomx_calculate_hash(rx_vm[rx2id(xalgo)], reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), xalgo);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(setRandomxCacheSize) {
    if (info.Length() < 1 || !info[0]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 1 should be a number");
    const int size = Nan::To<int>(info[0]).FromMaybe(rx_seed_cache_size);
    if (size < 1 || size > rx_seed_cache_size) return THROW_ERROR_EXCEPTION("RandomX cache size is out of bounds");
    rx_active_cache_size = size;
}

void ghostrider(const unsigned char* data, size_t size, unsigned char* output, cryptonight_ctx** ctx, uint64_t) {
    xmrig::ghostrider::hash(data, size, output, ctx, nullptr);
}

static xmrig::cn_hash_fun get_cn_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(CN_0);
    case 1:  return FN(CN_1);
    case 4:  return FN(CN_FAST);
    case 6:  return FN(CN_XAO);
    case 7:  return FN(CN_RTO);
    case 8:  return FNA(CN_2);
    case 9:  return FNA(CN_HALF);
    case 11: return FN(CN_GPU);
    case 13: return FNA(CN_R);
    case 14: return FNA(CN_RWZ);
    case 15: return FNA(CN_ZLS);
    case 16: return FNA(CN_DOUBLE);
    case 17: return FNA(CN_CCX);
    case 18: return ghostrider;
    default: return FN(CN_R);
  }
}

static xmrig::cn_hash_fun get_cn_lite_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(CN_LITE_0);
    case 1:  return FN(CN_LITE_1);
    default: return FN(CN_LITE_1);
  }
}

static xmrig::cn_hash_fun get_cn_heavy_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(CN_HEAVY_0);
    case 1:  return FN(CN_HEAVY_XHV);
    case 2:  return FN(CN_HEAVY_TUBE);
    default: return FN(CN_HEAVY_0);
  }
}

static xmrig::cn_hash_fun get_cn_pico_fn(const int algo) {
  switch (algo) {
    case 0:  return FNA(CN_PICO_0);
    default: return FNA(CN_PICO_0);
  }
}
static xmrig::cn_hash_fun get_argon2_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(AR2_CHUKWA);
    case 1:  return FN(AR2_WRKZ);
    case 2:  return FN(AR2_CHUKWA_V2);
    default: return FN(AR2_CHUKWA);
  }
}

static xmrig::cn_hash_fun get_astrobwt_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(ASTROBWT_DERO);
    case 1:  return FN(ASTROBWT_DERO_2);
    default: return FN(ASTROBWT_DERO);
  }
}

NAN_METHOD(cryptonight) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;
    bool height_set = false;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<uint32_t>(info[2]).FromMaybe(0);
        height_set = true;
    }

    if ((algo == 12 || algo == 13) && !height_set) return THROW_ERROR_EXCEPTION("CryptonightR requires block template height as Argument 3");
    if (algo == 19) return THROW_ERROR_EXCEPTION("Unsupported CryptoNight algorithm");
    if (algo == 18 && Buffer::Length(target) < ghostrider_min_input_size) {
        return THROW_ERROR_EXCEPTION("GhostRider requires input length of at least 36 bytes");
    }

    const xmrig::cn_hash_fun fn = get_cn_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_light) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_cn_lite_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_heavy) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }


    const xmrig::cn_hash_fun fn = get_cn_heavy_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_pico) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_cn_pico_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(argon2) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_argon2_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(astrobwt) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_astrobwt_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(k12) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    char output[32];
    KangarooTwelve((const unsigned char *)Buffer::Data(target), Buffer::Length(target), (unsigned char *)output, 32, 0, 0);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

static void setsipkeys(const char *keybuf,siphash_keys *keys) {
	keys->k0 = htole64(((uint64_t *)keybuf)[0]);
	keys->k1 = htole64(((uint64_t *)keybuf)[1]);
	keys->k2 = htole64(((uint64_t *)keybuf)[2]);
	keys->k3 = htole64(((uint64_t *)keybuf)[3]);
}

static void c29_setheader(const char *header, const uint32_t headerlen, siphash_keys *keys) {
	char hdrkey[32];
	rx_blake2b((void *)hdrkey, sizeof(hdrkey), (const void *)header, headerlen);
	setsipkeys(hdrkey,keys);
}

NAN_METHOD(c29) {
        if (info.Length() != 2) return THROW_ERROR_EXCEPTION("You must provide 2 arguments: header, ring");

        char * input = Buffer::Data(info[0]);
        uint32_t input_len = Buffer::Length(info[0]);

        siphash_keys keys;
        c29_setheader(input,input_len,&keys);

        Local<Array> ring = Local<Array>::Cast(info[1]);

        uint32_t edges[PROOFSIZE];
        for (uint32_t n = 0; n < PROOFSIZE; n++)
                edges[n]=ring->Get(Nan::GetCurrentContext(), n).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

        int retval = c29_verify(edges,&keys);

        info.GetReturnValue().Set(Nan::New<Number>(retval));
}

NAN_METHOD(c29s) {
	if (info.Length() != 2) return THROW_ERROR_EXCEPTION("You must provide 2 arguments: header, ring");

	char * input = Buffer::Data(info[0]);
	uint32_t input_len = Buffer::Length(info[0]);

	siphash_keys keys;
	c29_setheader(input,input_len,&keys);

	Local<Array> ring = Local<Array>::Cast(info[1]);

	uint32_t edges[PROOFSIZEs];
	for (uint32_t n = 0; n < PROOFSIZEs; n++)
		edges[n]=ring->Get(Nan::GetCurrentContext(), n).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

	int retval = c29s_verify(edges,&keys);

	info.GetReturnValue().Set(Nan::New<Number>(retval));
}

NAN_METHOD(c29v) {
	if (info.Length() != 2) return THROW_ERROR_EXCEPTION("You must provide 2 arguments: header, ring");

	char * input = Buffer::Data(info[0]);
	uint32_t input_len = Buffer::Length(info[0]);

	siphash_keys keys;
	c29_setheader(input,input_len,&keys);

	Local<Array> ring = Local<Array>::Cast(info[1]);

	uint32_t edges[PROOFSIZEv];
	for (uint32_t n = 0; n < PROOFSIZEv; n++)
		edges[n]=ring->Get(Nan::GetCurrentContext(), n).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

	int retval = c29v_verify(edges,&keys);

	info.GetReturnValue().Set(Nan::New<Number>(retval));
}

NAN_METHOD(c29i) {
	if (info.Length() != 2) return THROW_ERROR_EXCEPTION("You must provide 2 arguments: header, ring");

	char * input = Buffer::Data(info[0]);
	uint32_t input_len = Buffer::Length(info[0]);

	siphash_keys keys;
	c29_setheader(input,input_len,&keys);

	Local<Array> ring = Local<Array>::Cast(info[1]);

	uint32_t edges[PROOFSIZEi];
	for (uint32_t n = 0; n < PROOFSIZEi; n++)
		edges[n]=ring->Get(Nan::GetCurrentContext(), n).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

	int retval = c29i_verify(edges,&keys);

	info.GetReturnValue().Set(Nan::New<Number>(retval));
}

NAN_METHOD(c29b) {
	if (info.Length() != 2) return THROW_ERROR_EXCEPTION("You must provide 2 arguments: header, ring");

	char * input = Buffer::Data(info[0]);
	uint32_t input_len = Buffer::Length(info[0]);

	siphash_keys keys;
	c29_setheader(input,input_len,&keys);

	Local<Array> ring = Local<Array>::Cast(info[1]);

	uint32_t edges[PROOFSIZEb];
	for (uint32_t n = 0; n < PROOFSIZEb; n++)
		edges[n]=ring->Get(Nan::GetCurrentContext(), n).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

	int retval = c29b_verify(edges,&keys);

	info.GetReturnValue().Set(Nan::New<Number>(retval));
}

NAN_METHOD(c29_cycle_hash) {
        if (info.Length() != 1) return THROW_ERROR_EXCEPTION("You must provide 1 argument: packed edge buffer");

	v8::Isolate *isolate = v8::Isolate::GetCurrent();
        Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
        if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

        char * input = Buffer::Data(info[0]);
        uint32_t input_len = Buffer::Length(info[0]);

	if (!input_len) return THROW_ERROR_EXCEPTION("Argument 1 should be a non empty buffer object.");

        unsigned char cyclehash[32];
        rx_blake2b((void *)cyclehash, sizeof(cyclehash), (uint8_t *)input, input_len);

        unsigned char rev_cyclehash[32];
        for(int i = 0; i < 32; i++)
                rev_cyclehash[i] = cyclehash[31-i];

        v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)rev_cyclehash, 32).ToLocalChecked();
        info.GetReturnValue().Set(returnValue);
}


NAN_METHOD(c29_packed_edges) {
        if (info.Length() != 1) return THROW_ERROR_EXCEPTION("You must provide 1 argument:ring");

        Local<Array> ring = Local<Array>::Cast(info[0]);

        uint8_t hashdata[PROOFSIZE*EDGEBITS/8+1];
        memset(hashdata, 0, PROOFSIZE*EDGEBITS/8+1);

        int bytepos = 0;
        int bitpos = 0;
        for(int i = 0; i < PROOFSIZE; i++){

                uint32_t node = ring->Get(Nan::GetCurrentContext(), i).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

                for(int j = 0; j < EDGEBITS; j++) {

                        if((node >> j) & 1U)
                                hashdata[bytepos] |= 1UL << bitpos;

                        bitpos++;
                        if(bitpos==8) {
                                bitpos=0;bytepos++;
                        }
                }
        }

        v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)hashdata, sizeof(hashdata)).ToLocalChecked();
        info.GetReturnValue().Set(returnValue);
}


NAN_METHOD(c29s_packed_edges) {
	if (info.Length() != 1) return THROW_ERROR_EXCEPTION("You must provide 1 argument:ring");

	Local<Array> ring = Local<Array>::Cast(info[0]);

	uint8_t hashdata[PROOFSIZEs*EDGEBITS/8];
	memset(hashdata, 0, PROOFSIZEs*EDGEBITS/8);

	int bytepos = 0;
	int bitpos = 0;
	for(int i = 0; i < PROOFSIZEs; i++){

		uint32_t node = ring->Get(Nan::GetCurrentContext(), i).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

		for(int j = 0; j < EDGEBITS; j++) {

			if((node >> j) & 1U)
				hashdata[bytepos] |= 1UL << bitpos;

			bitpos++;
			if(bitpos==8) {
				bitpos=0;bytepos++;
			}
		}
	}

        v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)hashdata, sizeof(hashdata)).ToLocalChecked();
        info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(c29v_packed_edges) {
        if (info.Length() != 1) return THROW_ERROR_EXCEPTION("You must provide 1 argument:ring");

        Local<Array> ring = Local<Array>::Cast(info[0]);

        uint8_t hashdata[PROOFSIZEv*EDGEBITS/8];
        memset(hashdata, 0, PROOFSIZEv*EDGEBITS/8);

        int bytepos = 0;
        int bitpos = 0;
        for(int i = 0; i < PROOFSIZEv; i++){

                uint32_t node = ring->Get(Nan::GetCurrentContext(), i).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

                for(int j = 0; j < EDGEBITS; j++) {

                        if((node >> j) & 1U)
                                hashdata[bytepos] |= 1UL << bitpos;

                        bitpos++;
                        if(bitpos==8) {
                                bitpos=0;bytepos++;
                        }
                }
        }

        v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)hashdata, sizeof(hashdata)).ToLocalChecked();
        info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(c29b_packed_edges) {
	if (info.Length() != 1) return THROW_ERROR_EXCEPTION("You must provide 1 argument:ring");

	Local<Array> ring = Local<Array>::Cast(info[0]);

	uint8_t hashdata[PROOFSIZEb*EDGEBITS/8];
	memset(hashdata, 0, PROOFSIZEb*EDGEBITS/8);

	int bytepos = 0;
	int bitpos = 0;
	for(int i = 0; i < PROOFSIZEb; i++){

		uint32_t node = ring->Get(Nan::GetCurrentContext(), i).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

		for(int j = 0; j < EDGEBITS; j++) {

			if((node >> j) & 1U)
				hashdata[bytepos] |= 1UL << bitpos;

			bitpos++;
			if(bitpos==8) {
				bitpos=0;bytepos++;
			}
		}
	}

        v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)hashdata, sizeof(hashdata)).ToLocalChecked();
        info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(c29i_packed_edges) {
	if (info.Length() != 1) return THROW_ERROR_EXCEPTION("You must provide 1 argument:ring");

	Local<Array> ring = Local<Array>::Cast(info[0]);

	uint8_t hashdata[PROOFSIZEi*EDGEBITS/8];
	memset(hashdata, 0, PROOFSIZEi*EDGEBITS/8);

	int bytepos = 0;
	int bitpos = 0;
	for(int i = 0; i < PROOFSIZEi; i++){

		uint32_t node = ring->Get(Nan::GetCurrentContext(), i).ToLocalChecked()->Uint32Value(Nan::GetCurrentContext()).FromJust();

		for(int j = 0; j < EDGEBITS; j++) {

			if((node >> j) & 1U)
				hashdata[bytepos] |= 1UL << bitpos;

			bitpos++;
			if(bitpos==8) {
				bitpos=0;bytepos++;
			}
		}
	}

        v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)hashdata, sizeof(hashdata)).ToLocalChecked();
        info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(kawpow) {
	if (info.Length() != 3) return THROW_ERROR_EXCEPTION("You must provide 3 argument buffers: header hash (32 bytes), nonce (8 bytes), mixhash (32 bytes)");

	v8::Isolate *isolate = v8::Isolate::GetCurrent();

	Local<Object> header_hash_buff = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
	if (!Buffer::HasInstance(header_hash_buff)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");
	if (Buffer::Length(header_hash_buff) != 32) return THROW_ERROR_EXCEPTION("Argument 1 should be a 32 bytes long buffer object.");

	Local<Object> nonce_buff = info[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
	if (!Buffer::HasInstance(nonce_buff)) return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");
	if (Buffer::Length(nonce_buff) != 8) return THROW_ERROR_EXCEPTION("Argument 2 should be a 8 bytes long buffer object.");

	Local<Object> mix_hash_buff = info[2]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
	if (!Buffer::HasInstance(mix_hash_buff)) return THROW_ERROR_EXCEPTION("Argument 3 should be a buffer object.");
	if (Buffer::Length(mix_hash_buff) != 32) return THROW_ERROR_EXCEPTION("Argument 3 should be a 8 bytes long buffer object.");

	uint32_t header_hash[8];
	memcpy(header_hash, reinterpret_cast<const uint8_t*>(Buffer::Data(header_hash_buff)), sizeof(header_hash));
        const uint64_t nonce = __builtin_bswap64(*(reinterpret_cast<const uint64_t*>(Buffer::Data(nonce_buff))));
        uint32_t mix_hash[8];
	memcpy(mix_hash, reinterpret_cast<const uint8_t*>(Buffer::Data(mix_hash_buff)), sizeof(mix_hash));

        uint32_t output[8];
	xmrig::KPHash::verify(header_hash, nonce, mix_hash, output);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(kawpow_light) {
	if (info.Length() != 3) return THROW_ERROR_EXCEPTION("You must provide 3 arguments: header hash (32 bytes), nonce (8 bytes), height (integer)");

	v8::Isolate *isolate = v8::Isolate::GetCurrent();

	Local<Object> header_hash_buff = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
	if (!Buffer::HasInstance(header_hash_buff)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");
	if (Buffer::Length(header_hash_buff) != 32) return THROW_ERROR_EXCEPTION("Argument 1 should be a 32 bytes long buffer object.");

	Local<Object> nonce_buff = info[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
	if (!Buffer::HasInstance(nonce_buff)) return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");
	if (Buffer::Length(nonce_buff) != 8) return THROW_ERROR_EXCEPTION("Argument 2 should be a 8 bytes long buffer object.");

	if (!info[2]->IsUint32()) return THROW_ERROR_EXCEPTION("Argument 3 should be an unsigned 32-bit integer");
	const uint32_t height = Nan::To<uint32_t>(info[2]).FromMaybe(0);
	const uint32_t epoch = height / 7500;

	uint8_t header_hash[32];
	memcpy(header_hash, reinterpret_cast<const uint8_t*>(Buffer::Data(header_hash_buff)), sizeof(header_hash));
	const uint64_t nonce = __builtin_bswap64(*(reinterpret_cast<const uint64_t*>(Buffer::Data(nonce_buff))));

	uint32_t output[8];
	uint32_t mix_hash[8];

	{
		std::lock_guard<std::mutex> lock(xmrig::KPCache::s_cacheMutex);
		KawpowCacheLookupStats cache_stats;
		const auto start_time = std::chrono::steady_clock::now();
		xmrig::KPCache* cache = GetKawpowCache(epoch, cache_stats);
		if (!cache) {
			return THROW_ERROR_EXCEPTION("Unable to initialize KawPoW light cache for height");
		}
		if (cache_stats.created) {
			const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - start_time
			).count();
			std::cout << "KawPoW light cache rebuild"
				<< ": pid=" << getpid()
				<< " height=" << height
				<< " epoch=" << epoch
				<< " evicted_epoch=" << cache_stats.evicted_epoch
				<< " cache_entries=" << kawpow_caches.size()
				<< " cache_capacity=" << cache_stats.cache_capacity
				<< " max_cache_entries=" << KAWPOW_MAX_CACHE_ENTRIES
				<< " recent_epochs=" << cache_stats.recent_epochs
				<< " trimmed_entries=" << cache_stats.trimmed_entries
				<< " cache_size=" << cache->size()
				<< " dag_cache_size=" << cache->dagCacheSize()
				<< " cache_memory_size=" << cache->memorySize()
				<< " total_cache_size=" << cache_stats.total_cache_size
				<< " total_cache_memory_size=" << cache_stats.total_cache_memory_size
				<< " elapsed_ms=" << elapsed_ms
				<< std::endl;
		}
		xmrig::KPHash::calculate(*cache, height, header_hash, nonce, output, mix_hash);
	}

	v8::Local<v8::Array> returnValue = v8::Array::New(isolate, 2);
	SetArrayValue(isolate, returnValue, 0, Nan::CopyBuffer((char*)output, 32).ToLocalChecked());
	SetArrayValue(isolate, returnValue, 1, Nan::CopyBuffer((char*)mix_hash, 32).ToLocalChecked());
	info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(ethash) {
	if (info.Length() != 3) return THROW_ERROR_EXCEPTION("You must provide 3 arguments: header hash (32 bytes), nonce (8 bytes), height (integer)");

	v8::Isolate *isolate = v8::Isolate::GetCurrent();

	Local<Object> header_hash_buff = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
	if (!Buffer::HasInstance(header_hash_buff)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");
	if (Buffer::Length(header_hash_buff) != 32) return THROW_ERROR_EXCEPTION("Argument 1 should be a 32 bytes long buffer object.");

	Local<Object> nonce_buff = info[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
	if (!Buffer::HasInstance(nonce_buff)) return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");
	if (Buffer::Length(nonce_buff) != 8) return THROW_ERROR_EXCEPTION("Argument 2 should be a 8 bytes long buffer object.");

        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        const int height = Nan::To<int>(info[2]).FromMaybe(0);

	ethash_h256_t header_hash;
	memcpy(&header_hash, reinterpret_cast<const uint8_t*>(Buffer::Data(header_hash_buff)), sizeof(header_hash));
        const uint64_t nonce = __builtin_bswap64(*(reinterpret_cast<const uint64_t*>(Buffer::Data(nonce_buff))));

        ethash_return_value_t res;
        {
            std::lock_guard<std::mutex> lock(ethash_mutex);
            static int prev_epoch = 0;
            static ethash_light_t cache = nullptr;
            const int epoch = height / ETHASH_EPOCH_LENGTH;
            if (prev_epoch != epoch) {
                if (cache) ethash_light_delete(cache);
                cache = ethash_light_new(height, epoch, epoch);
                prev_epoch = epoch;
            }
            res = ethash_light_compute(cache, header_hash, nonce);
        }

        v8::Local<v8::Array> returnValue = v8::Array::New(isolate, 2);
        SetArrayValue(isolate, returnValue, 0, Nan::CopyBuffer((char*)&res.result.b[0], 32).ToLocalChecked());
        SetArrayValue(isolate, returnValue, 1, Nan::CopyBuffer((char*)&res.mix_hash.b[0], 32).ToLocalChecked());
	info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(etchash) {
	if (info.Length() != 3) return THROW_ERROR_EXCEPTION("You must provide 3 arguments: header hash (32 bytes), nonce (8 bytes), height (integer)");

	v8::Isolate *isolate = v8::Isolate::GetCurrent();

	Local<Object> header_hash_buff = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
	if (!Buffer::HasInstance(header_hash_buff)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");
	if (Buffer::Length(header_hash_buff) != 32) return THROW_ERROR_EXCEPTION("Argument 1 should be a 32 bytes long buffer object.");

	Local<Object> nonce_buff = info[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
	if (!Buffer::HasInstance(nonce_buff)) return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");
	if (Buffer::Length(nonce_buff) != 8) return THROW_ERROR_EXCEPTION("Argument 2 should be a 8 bytes long buffer object.");

        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        const int height = Nan::To<int>(info[2]).FromMaybe(0);

	ethash_h256_t header_hash;
	memcpy(&header_hash, reinterpret_cast<const uint8_t*>(Buffer::Data(header_hash_buff)), sizeof(header_hash));
        const uint64_t nonce = __builtin_bswap64(*(reinterpret_cast<const uint64_t*>(Buffer::Data(nonce_buff))));

        ethash_return_value_t res;
        {
            std::lock_guard<std::mutex> lock(etchash_mutex);
            static int prev_epoch_seed = 0;
            static ethash_light_t cache = nullptr;
            const int epoch_length = height >= ETCHASH_EPOCH_HEIGHT ? ETCHASH_EPOCH_LENGTH : ETHASH_EPOCH_LENGTH;
            const int epoch       = height / epoch_length;
            const int epoch_seed  = (epoch * epoch_length + 1) / ETHASH_EPOCH_LENGTH;
            if (prev_epoch_seed != epoch_seed) {
                if (cache) ethash_light_delete(cache);
                cache = ethash_light_new(height, epoch_seed, epoch);
                prev_epoch_seed = epoch_seed;
            }
            res = ethash_light_compute(cache, header_hash, nonce);
        }

        v8::Local<v8::Array> returnValue = v8::Array::New(isolate, 2);
        SetArrayValue(isolate, returnValue, 0, Nan::CopyBuffer((char*)&res.result.b[0], 32).ToLocalChecked());
        SetArrayValue(isolate, returnValue, 1, Nan::CopyBuffer((char*)&res.mix_hash.b[0], 32).ToLocalChecked());
	info.GetReturnValue().Set(returnValue);
}


void init(v8::Local<v8::Object> exports, v8::Local<v8::Value>,
          v8::Local<v8::Context> context, void*) {
    v8::Isolate* isolate = context->GetIsolate();
#if defined(__x86_64__) || defined(_M_X64)
    const xmrig::ICpuInfo& cpuInfo = *xmrig::Cpu::info();
    if (cpuInfo.has(xmrig::ICpuInfo::FLAG_SSE41)) {
        rx_blake2b_compress = rx_blake2b_compress_sse41;
    }
    if (cpuInfo.hasAVX2()) {
        rx_blake2b = blake2b_avx2;
    }
#endif
    SetExport(isolate, exports, "cryptonight", cryptonight);
    SetExport(isolate, exports, "cryptonight_light", cryptonight_light);
    SetExport(isolate, exports, "cryptonight_heavy", cryptonight_heavy);
    SetExport(isolate, exports, "cryptonight_pico", cryptonight_pico);
    SetExport(isolate, exports, "randomx", randomx);
    SetExport(isolate, exports, "setRandomxCacheSize", setRandomxCacheSize);
    SetExport(isolate, exports, "argon2", argon2);
    SetExport(isolate, exports, "astrobwt", astrobwt);
    SetExport(isolate, exports, "k12", k12);
    SetExport(isolate, exports, "c29", c29);
    SetExport(isolate, exports, "c29s", c29s);
    SetExport(isolate, exports, "c29v", c29v);
    SetExport(isolate, exports, "c29b", c29b);
    SetExport(isolate, exports, "c29i", c29i);
    SetExport(isolate, exports, "c29_cycle_hash", c29_cycle_hash);
    SetExport(isolate, exports, "c29_packed_edges", c29_packed_edges);
    SetExport(isolate, exports, "c29s_packed_edges", c29s_packed_edges);
    SetExport(isolate, exports, "c29v_packed_edges", c29v_packed_edges);
    SetExport(isolate, exports, "c29b_packed_edges", c29b_packed_edges);
    SetExport(isolate, exports, "c29i_packed_edges", c29i_packed_edges);
    SetExport(isolate, exports, "kawpow", kawpow);
    SetExport(isolate, exports, "kawpow_light", kawpow_light);
    SetExport(isolate, exports, "ethash", ethash);
    SetExport(isolate, exports, "etchash", etchash);
}

NODE_MODULE_CONTEXT_AWARE(cryptonight, init)
