#include <cstdint>
#include <functional>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef LOG_INFO
#    define LOG_INFO(fmt, ...)
#endif
#ifndef LOG_WARN
#    define LOG_WARN(fmt, ...)
#endif
#ifndef LOG_ERROR
#    define LOG_ERROR(fmt, ...)
#endif

#ifndef WITCH_NOINLINE
#    if defined(_MSC_VER)
#        define WITCH_NOINLINE __declspec(noinline)
#    elif defined(__GNUC__) || defined(__clang__)
#        define WITCH_NOINLINE __attribute__((noinline))
#    else
#        define WITCH_NOINLINE
#    endif
#endif
#ifndef WITCH_INLINE
#    if defined(_MSC_VER)
#        define WITCH_INLINE __forceinline
#    elif defined(__GNUC__) || defined(__clang__)
#        define WITCH_INLINE __attribute__((always_inline))
#    else
#        define WITCH_INLINE
#    endif
#endif
namespace witch_cult {
    template <typename CharT> inline constexpr CharT ToLower(CharT c) noexcept {
        if (c >= CharT('A') && c <= CharT('Z')) {
            return c + (CharT('a') - CharT('A'));
        }
        return c;
    }
    template <typename CharT> inline constexpr std::uint32_t Fnv1aHash(const CharT *src, const size_t length) {
        std::uint32_t hash = 2166136261u;
        for (size_t i = 0; i < length; i++) {
            hash ^= static_cast<std::uint32_t>(src[i]);
            hash *= 16777619u;
        }
        return hash;
    }
    template <typename CharT> inline constexpr std::uint32_t Fnv1aHashByLower(const CharT *src, const size_t length) {
        std::uint32_t hash = 2166136261u;
        for (size_t i = 0; i < length; i++) {
            hash ^= static_cast<std::uint32_t>(ToLower(src[i]));
            hash *= 16777619u;
        }
        return hash;
    }

    template <typename CharT> inline constexpr std::size_t strlen(const CharT *s) {
        const CharT *p = s;
        while (*p)
            ++p;
        return static_cast<std::size_t>(p - s);
    }

    enum pe_magic_t { dos_header = 0x5a4d, nt_headers = 0x4550, opt_header = 0x020b };
    struct dos_header_t {
        std::int16_t m_magic;
        std::int16_t m_cblp;
        std::int16_t m_cp;
        std::int16_t m_crlc;
        std::int16_t m_cparhdr;
        std::int16_t m_minalloc;
        std::int16_t m_maxalloc;
        std::int16_t m_ss;
        std::int16_t m_sp;
        std::int16_t m_csum;
        std::int16_t m_ip;
        std::int16_t m_cs;
        std::int16_t m_lfarlc;
        std::int16_t m_ovno;
        std::int16_t m_res0[0x4];
        std::int16_t m_oemid;
        std::int16_t m_oeminfo;
        std::int16_t m_res1[0xa];
        std::int32_t m_lfanew;

        [[nodiscard]] constexpr bool is_valid() { return m_magic == pe_magic_t::dos_header; }
    };
    struct data_directory_t {
        std::int32_t m_virtual_address;
        std::int32_t m_size;

        template <class type_t, typename addr_t> [[nodiscard]] type_t as_rva(addr_t rva) {
            return reinterpret_cast<type_t>(rva + m_virtual_address);
        }
    };
    struct nt_headers_t {
        std::int32_t m_signature;
        std::int16_t m_machine;
        std::int16_t m_number_of_sections;
        std::int32_t m_time_date_stamp;
        std::int32_t m_pointer_to_symbol_table;
        std::int32_t m_number_of_symbols;
        std::int16_t m_size_of_optional_header;
        std::int16_t m_characteristics;

        std::int16_t m_magic;
        std::int8_t m_major_linker_version;
        std::int8_t m_minor_linker_version;
        std::int32_t m_size_of_code;
        std::int32_t m_size_of_initialized_data;
        std::int32_t m_size_of_uninitialized_data;
        std::int32_t m_address_of_entry_point;
        std::int32_t m_base_of_code;
        std::uint64_t m_image_base;
        std::int32_t m_section_alignment;
        std::int32_t m_file_alignment;
        std::int16_t m_major_operating_system_version;
        std::int16_t m_minor_operating_system_version;
        std::int16_t m_major_image_version;
        std::int16_t m_minor_image_version;
        std::int16_t m_major_subsystem_version;
        std::int16_t m_minor_subsystem_version;
        std::int32_t m_win32_version_value;
        std::int32_t m_size_of_image;
        std::int32_t m_size_of_headers;
        std::int32_t m_check_sum;
        std::int16_t m_subsystem;
        std::int16_t m_dll_characteristics;
        std::uint64_t m_size_of_stack_reserve;
        std::uint64_t m_size_of_stack_commit;
        std::uint64_t m_size_of_heap_reserve;
        std::uint64_t m_size_of_heap_commit;
        std::int32_t m_loader_flags;
        std::int32_t m_number_of_rva_and_sizes;

        data_directory_t m_export_table;
        data_directory_t m_import_table;
        data_directory_t m_resource_table;
        data_directory_t m_exception_table;
        data_directory_t m_certificate_table;
        data_directory_t m_base_relocation_table;
        data_directory_t m_debug;
        data_directory_t m_architecture;
        data_directory_t m_global_ptr;
        data_directory_t m_tls_table;
        data_directory_t m_load_config_table;
        data_directory_t m_bound_import;
        data_directory_t m_iat;
        data_directory_t m_delay_import_descriptor;
        data_directory_t m_clr_runtime_header;
        data_directory_t m_reserved;

        [[nodiscard]] constexpr bool is_valid() {
            return m_signature == pe_magic_t::nt_headers && m_magic == pe_magic_t::opt_header;
        }
    };
    struct export_directory_t {
        std::int32_t m_characteristics;
        std::int32_t m_time_date_stamp;
        std::int16_t m_major_version;
        std::int16_t m_minor_version;
        std::int32_t m_name;
        std::int32_t m_base;
        std::int32_t m_number_of_functions;
        std::int32_t m_number_of_names;
        std::int32_t m_address_of_functions;
        std::int32_t m_address_of_names;
        std::int32_t m_address_of_names_ordinals;
    };

    struct section_header_t {
        char m_name[0x8];
        union {
            std::int32_t m_physical_address;
            std::int32_t m_virtual_size;
        };
        std::int32_t m_virtual_address;
        std::int32_t m_size_of_raw_data;
        std::int32_t m_pointer_to_raw_data;
        std::int32_t m_pointer_to_relocations;
        std::int32_t m_pointer_to_line_numbers;
        std::int16_t m_number_of_relocations;
        std::int16_t m_number_of_line_numbers;
        std::int32_t m_characteristics;
    };

    struct list_entry_t {
        list_entry_t *m_flink;
        list_entry_t *m_blink;
    };

    typedef struct _LSA_UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;
    typedef struct _LDR_MODULE {
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID BaseAddress;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        SHORT LoadCount;
        SHORT TlsIndex;
        LIST_ENTRY HashTableEntry;
        ULONG TimeDateStamp;
    } LDR_MODULE;
    struct peb_ldr_data_t {
        std::uint32_t m_length;
        bool m_initialized;
        void *m_ss_handle;
        LIST_ENTRY m_module_list_load_order;
        LIST_ENTRY m_module_list_memory_order;
        LIST_ENTRY m_module_list_in_it_order;
    };

    struct rtl_critical_section_t {
        void *m_debug_info;
        std::int32_t m_lock_count;
        std::int32_t m_recursion_count;
        void *m_owning_thread;
        void *m_lock_semaphore;
        std::uint32_t m_spin_count;
    };

    struct unicode_string_t {
        std::uint16_t m_length;
        std::uint16_t m_maximum_length;
        wchar_t *m_buffer;
    };
    struct peb_t {
        std::uint8_t m_inherited_address_space;
        std::uint8_t m_read_image_file_exec_options;
        std::uint8_t m_being_debugged;
        std::uint8_t m_bit_field;

        void *m_mutant;
        void *m_image_base_address;
        peb_ldr_data_t *m_ldr;
        void *m_process_parameters;
        void *m_subsystem_data;
        void *m_process_heap;
        rtl_critical_section_t *m_fast_peb_lock;
        void *m_atl_thunk_slist_ptr;
        void *m_ifeo_key;

        struct {
            std::uint32_t m_process_in_job : 1;
            std::uint32_t m_process_initializing : 1;
            std::uint32_t m_reserved_bits0 : 30;
        } m_cross_process_flags;

        union {
            void *m_kernel_callback_table;
            void *m_user_shared_info_ptr;
        };

        std::uint32_t m_system_reserved[1];
        std::uint32_t m_spare_ulong;
        void *m_free_list;
        std::uint32_t m_tls_expansion_counter;
        void *m_tls_bitmap;
        std::uint32_t m_tls_bitmap_bits[2];
        void *m_read_only_shared_memory_base;
        void *m_hotpatch_information;
        void **m_read_only_static_server_data;
        void *m_ansi_code_page_data;
        void *m_oem_code_page_data;
        void *m_unicode_case_table_data;
        std::uint32_t m_number_of_processors;
        std::uint32_t m_nt_global_flag;
        std::int64_t m_critical_section_timeout;
        std::uint32_t m_heap_segment_reserve;
        std::uint32_t m_heap_segment_commit;
        std::uint32_t m_heap_decomit_total_free_threshold;
        std::uint32_t m_heap_decomit_free_block_threshold;
        std::uint32_t m_number_of_heaps;
        std::uint32_t m_maximum_number_of_heaps;
        void **m_process_heaps;
        void *m_gdi_shared_handle_table;
        void *m_process_starter_helper;
        std::uint32_t m_gdi_dc_attribute_list;
        rtl_critical_section_t *m_loader_lock;
        std::uint32_t m_os_major_version;
        std::uint32_t m_os_minor_version;
        std::uint16_t m_os_build_number;
        std::uint16_t m_os_csd_version;
        std::uint32_t m_os_platform_id;
        std::uint32_t m_image_subsystem;
        std::uint32_t m_image_subsystem_major_version;
        std::uint32_t m_image_subsystem_minor_version;
        std::uint32_t m_image_process_affinity_mask;
        std::uint32_t m_gdi_handle_buffer[34];
        void *m_post_process_init_routine;
        void *m_tls_expansion_bitmap;
        std::uint32_t m_tls_expansion_bitmap_bits[32];
        std::uint32_t m_session_id;
        std::uint64_t m_app_compat_flags;
        std::uint64_t m_app_compat_flags_user;
        void *m_p_shim_data;
        void *m_app_compat_info;
        unicode_string_t m_csd_version;
        void *m_activation_context_data;
        void *m_process_assembly_storage_map;
        void *m_system_default_activation_context_data;
        void *m_system_assembly_storage_map;
        std::uint32_t m_minimum_stack_commit;
        void *m_fls_callback;
        list_entry_t m_fls_list_head;
        void *m_fls_bitmap;
        std::uint32_t m_fls_bitmap_bits[4];
        std::uint32_t m_fls_high_index;
        void *m_wer_registration_data;
        void *m_wer_ship_assert_ptr;
    };

    WITCH_INLINE peb_t *peb() {
#if defined(_WIN64)
        return reinterpret_cast<peb_t *>(__readgsqword(0x60));
#elif defined(_WIN32)
        return reinterpret_cast<peb_t *>(__readfsdword(0x30));
#endif
    }

    inline WITCH_INLINE uint8_t *FindExportFromModule(std::uint8_t *address, const std::uint32_t hash) {
        if (!address) {
            LOG_ERROR("Module base address is null\n");
            return nullptr;
        }
        auto dos_header{reinterpret_cast<dos_header_t *>(address)};
        auto nt_headers{reinterpret_cast<nt_headers_t *>(address + dos_header->m_lfanew)};
        if (!dos_header->is_valid() || !nt_headers->is_valid())
            return {};

        // 获取导出表目录范围，用于检查转发器
        auto &export_dir_entry = nt_headers->m_export_table;
        std::size_t exp_base = export_dir_entry.m_virtual_address;
        std::size_t exp_end = exp_base + export_dir_entry.m_size;

        auto exp_dir{nt_headers->m_export_table.as_rva<export_directory_t *>(address)};

        if (!nt_headers->m_export_table.m_virtual_address || !nt_headers->m_export_table.m_size)
            return {};
        if (!exp_dir->m_address_of_functions || !exp_dir->m_address_of_names || !exp_dir->m_address_of_names_ordinals)
            return {};
        auto name{reinterpret_cast<std::int32_t *>(address + exp_dir->m_address_of_names)};
        auto func{reinterpret_cast<std::int32_t *>(address + exp_dir->m_address_of_functions)};
        auto ords{reinterpret_cast<std::int16_t *>(address + exp_dir->m_address_of_names_ordinals)};

        for (std::int32_t i{}; i < exp_dir->m_number_of_names; i++) {
            auto cur_name{address + name[i]};
            std::size_t func_rva = func[ords[i]];
            // 检查是否为转发函数 (Forwarder)
            if (func_rva >= exp_base && func_rva < exp_end) {
                LOG_WARN("Forwarded exports are not supported: %s\n", cur_name);
                continue;
            }
            auto cur_func{address + func[ords[i]]};

            if (!cur_name || !cur_func)
                continue;
            if (Fnv1aHash(reinterpret_cast<char *>(cur_name), strlen(reinterpret_cast<char *>(cur_name))) == hash)
                return cur_func;
        }
        return {};
    }

    inline WITCH_INLINE HMODULE FindModule(std::uint32_t hash) {
        auto peb_ptr = peb();
        PLIST_ENTRY head = &peb_ptr->m_ldr->m_module_list_memory_order;
        PLIST_ENTRY next = head->Flink;

        while (head != next) {
            if (auto module = CONTAINING_RECORD(next, LDR_MODULE, InMemoryOrderModuleList);
                module->BaseDllName.Buffer != nullptr) {
                auto length = module->BaseDllName.Length / sizeof(char16_t);
                auto result = Fnv1aHashByLower(reinterpret_cast<char16_t *>(module->BaseDllName.Buffer), length);

                if (hash == result) {
                    return reinterpret_cast<HMODULE>(module->BaseAddress);
                }
            }
            next = next->Flink;
        }
        return nullptr;
    }

    template <std::uint32_t Hash> struct ImportModule {
        using Type = HMODULE;
        WITCH_INLINE auto resolve() -> Type { return reinterpret_cast<Type>(FindModule(Hash)); }
        WITCH_INLINE auto cached() -> Type {

#ifdef _MSC_VER
            auto result =
                InterlockedCompareExchangePointer(reinterpret_cast<void *volatile *>(&cached_value), nullptr, nullptr);
#else
            auto result = __atomic_load_n(&cached_mod, __ATOMIC_ACQUIRE);
#endif
            if (result)
                return reinterpret_cast<Type>(result);
            result = resolve();
#ifdef _MSC_VER
            auto prev =
                InterlockedCompareExchangePointer(reinterpret_cast<void *volatile *>(&cached_value), result, nullptr);
            return prev ? reinterpret_cast<Type>(prev) : reinterpret_cast<Type>(result);
#else
            Type expected{};
            if (__atomic_compare_exchange_n(&cached_mod, &expected, result, false, __ATOMIC_RELEASE,
                                            __ATOMIC_RELAXED)) {
                return result;
            } else {
                return expected;
            }
#endif
        }

        inline static alignas(8) void *cached_value{};
    };

    template <typename Fn, std::uint32_t ModHash, std::uint32_t Hash> struct ImportFn {
        using Type = Fn *;

        WITCH_INLINE auto resolve() -> Type {
            auto result =
                FindExportFromModule(reinterpret_cast<std::uint8_t *>(ImportModule<ModHash>{}.resolve()), Hash);
            return reinterpret_cast<Type>(result);
        }
        WITCH_INLINE auto cached() -> Type {
#ifdef _MSC_VER
            auto result =
                InterlockedCompareExchangePointer(reinterpret_cast<void *volatile *>(&cached_value), nullptr, nullptr);
#else
            auto result = __atomic_load_n(&cached_value, __ATOMIC_ACQUIRE);
#endif
            if (result)
                return reinterpret_cast<Type>(result);
            result = resolve();
#ifdef _MSC_VER
            auto prev =
                InterlockedCompareExchangePointer(reinterpret_cast<void *volatile *>(&cached_value), result, nullptr);
            return prev ? reinterpret_cast<Type>(prev) : reinterpret_cast<Type>(result);
#else
            Type expected{};
            if (__atomic_compare_exchange_n(&cached_value, &expected, result, false, __ATOMIC_RELEASE,
                                            __ATOMIC_RELAXED)) {
                return result;
            } else {
                return expected;
            }
#endif
        }
        template <typename... Args> WITCH_INLINE auto operator()(Args... args) -> std::invoke_result_t<Fn, Args...> {
            using ResultType = std::invoke_result_t<Fn, Args...>;

            auto fn = cached();
            if (!fn) {
                LOG_ERROR("Failed to resolve function import\n");
                if constexpr (std::is_void_v<ResultType>) {
                    return;
                } else {
                    return ResultType{};
                }
            }
            if constexpr (std::is_void_v<ResultType>) {
                fn(std::forward<Args>(args)...);
                return;
            } else {
                return fn(std::forward<Args>(args)...);
            }
        }
        inline static alignas(8) void *cached_value{};
    };
    template <typename T> struct as_t {
        using type = T;
    };

    template <typename T> inline constexpr as_t<T> as{};
    template <std::uint32_t ModHash, std::uint32_t Hash> struct ImportInvoke {
        using Type = void *;
        WITCH_INLINE auto resolve() -> Type {
            auto result =
                FindExportFromModule(reinterpret_cast<std::uint8_t *>(ImportModule<ModHash>{}.resolve()), Hash);
            return reinterpret_cast<Type>(result);
        }
        WITCH_INLINE auto cached() -> Type {
#ifdef _MSC_VER
            auto result =
                InterlockedCompareExchangePointer(reinterpret_cast<void *volatile *>(&cached_value), nullptr, nullptr);
#else
            auto result = __atomic_load_n(&cached_value, __ATOMIC_ACQUIRE);
#endif
            if (result)
                return reinterpret_cast<Type>(result);
            result = resolve();
#ifdef _MSC_VER
            auto prev =
                InterlockedCompareExchangePointer(reinterpret_cast<void *volatile *>(&cached_value), result, nullptr);
            return prev ? reinterpret_cast<Type>(prev) : reinterpret_cast<Type>(result);
#else
            Type expected{};
            if (__atomic_compare_exchange_n(&cached_value, &expected, result, false, __ATOMIC_RELEASE,
                                            __ATOMIC_RELAXED)) {
                return result;
            } else {
                return expected;
            }
#endif
        }
        template <typename T, typename... Args> WITCH_INLINE auto operator()(as_t<T>, Args... args) -> T {
            using ResultType = T;
            auto fn = reinterpret_cast<ResultType (*)(Args...)>(cached());
            if (!fn) {
                LOG_ERROR("Failed to resolve function import\n");
                if constexpr (std::is_void_v<ResultType>) {
                    return;
                } else {
                    return ResultType{};
                }
            }
            if constexpr (std::is_void_v<ResultType>) {
                fn(std::forward<Args>(args)...);
                return;
            } else {
                return fn(std::forward<Args>(args)...);
            }
        }
        inline static alignas(8) void *cached_value{};
    };
} // namespace witch_cult
#define ModHash(x) witch_cult::Fnv1aHashByLower(L## #x, sizeof(L## #x) / sizeof(wchar_t) - 1)
#define FnHash(x) witch_cult::Fnv1aHash(#x, sizeof(#x) - 1)
#define LazyImportMod(x) witch_cult::ImportModule<ModHash(x)>()
#define LazyFn(mod, fn) witch_cult::ImportFn<decltype(fn), ModHash(mod), FnHash(fn)>()
#define LazyInvoke(mod, fn) witch_cult::ImportInvoke<ModHash(mod), FnHash(fn)>()
