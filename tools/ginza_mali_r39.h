#ifndef GINZA_MALI_R39_H
#define GINZA_MALI_R39_H

#include <stdint.h>
#include <sys/ioctl.h>

#define GINZA_MALI_DEVICE "/dev/mali0"
#define GINZA_KBASE_API_MAJOR 11U
#define GINZA_KBASE_API_MINOR 35U
#define GINZA_MALI_PAGE_SHIFT 12U
#define GINZA_MALI_PAGE_SIZE (1UL << GINZA_MALI_PAGE_SHIFT)

#define KBASE_IOCTL_TYPE 0x80

struct kbase_ioctl_version_check {
  uint16_t major;
  uint16_t minor;
};

#define KBASE_IOCTL_VERSION_CHECK                                              \
  _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check)

struct kbase_ioctl_set_flags {
  uint32_t create_flags;
};

#define KBASE_IOCTL_SET_FLAGS                                                  \
  _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)

struct kbase_ioctl_job_submit {
  uint64_t addr;
  uint32_t nr_atoms;
  uint32_t stride;
};

#define KBASE_IOCTL_JOB_SUBMIT                                                 \
  _IOW(KBASE_IOCTL_TYPE, 2, struct kbase_ioctl_job_submit)

union kbase_ioctl_mem_alloc {
  struct {
    uint64_t va_pages;
    uint64_t commit_pages;
    uint64_t extension;
    uint64_t flags;
  } in;
  struct {
    uint64_t flags;
    uint64_t gpu_va;
  } out;
};

#define KBASE_IOCTL_MEM_ALLOC                                                  \
  _IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)

union kbase_ioctl_mem_query {
  struct {
    uint64_t gpu_addr;
    uint64_t query;
  } in;
  struct {
    uint64_t value;
  } out;
};

#define KBASE_IOCTL_MEM_QUERY                                                  \
  _IOWR(KBASE_IOCTL_TYPE, 6, union kbase_ioctl_mem_query)

struct kbase_ioctl_mem_free {
  uint64_t gpu_addr;
};

#define KBASE_IOCTL_MEM_FREE                                                   \
  _IOW(KBASE_IOCTL_TYPE, 7, struct kbase_ioctl_mem_free)

struct kbase_ioctl_mem_jit_init {
  uint64_t va_pages;
  uint8_t max_allocations;
  uint8_t trim_level;
  uint8_t group_id;
  uint8_t padding[5];
  uint64_t phys_pages;
};

#define KBASE_IOCTL_MEM_JIT_INIT                                               \
  _IOW(KBASE_IOCTL_TYPE, 14, struct kbase_ioctl_mem_jit_init)

struct kbase_ioctl_mem_commit {
  uint64_t gpu_addr;
  uint64_t pages;
};

#define KBASE_IOCTL_MEM_COMMIT                                                 \
  _IOW(KBASE_IOCTL_TYPE, 20, struct kbase_ioctl_mem_commit)

union kbase_ioctl_mem_alias {
  struct {
    uint64_t flags;
    uint64_t stride;
    uint64_t nents;
    uint64_t aliasing_info;
  } in;
  struct {
    uint64_t flags;
    uint64_t gpu_va;
    uint64_t va_pages;
  } out;
};

#define KBASE_IOCTL_MEM_ALIAS                                                  \
  _IOWR(KBASE_IOCTL_TYPE, 21, union kbase_ioctl_mem_alias)

struct kbase_ioctl_mem_flags_change {
  uint64_t gpu_va;
  uint64_t flags;
  uint64_t mask;
};

#define KBASE_IOCTL_MEM_FLAGS_CHANGE                                           \
  _IOW(KBASE_IOCTL_TYPE, 23, struct kbase_ioctl_mem_flags_change)

struct base_mem_handle {
  struct {
    uint64_t handle;
  } basep;
};

struct base_mem_aliasing_info {
  struct base_mem_handle handle;
  uint64_t offset;
  uint64_t length;
};

struct base_jd_atom_v2 {
  uint64_t jc;
  uint64_t udata[2];
  uint64_t extres_list;
  uint16_t nr_extres;
  uint8_t jit_id[2];
  uint8_t pre_dep[4];
  uint8_t atom_number;
  uint8_t prio;
  uint8_t device_nr;
  uint8_t jobslot;
  uint32_t core_req;
  uint8_t renderpass_id;
  uint8_t padding[7];
};

struct base_jd_event_v2 {
  uint32_t event_code;
  uint8_t atom_number;
  uint8_t padding[3];
  uint64_t udata[2];
};

struct base_jit_alloc_info {
  uint64_t gpu_alloc_addr;
  uint64_t va_pages;
  uint64_t commit_pages;
  uint64_t extension;
  uint8_t id;
  uint8_t bin_id;
  uint8_t max_allocations;
  uint8_t flags;
  uint8_t padding[2];
  uint16_t usage_id;
  uint64_t heap_info_gpu_addr;
};

#define BASE_MEM_PROT_CPU_RD (1ULL << 0)
#define BASE_MEM_PROT_CPU_WR (1ULL << 1)
#define BASE_MEM_PROT_GPU_RD (1ULL << 2)
#define BASE_MEM_PROT_GPU_WR (1ULL << 3)
#define BASE_MEM_PROT_GPU_EX (1ULL << 4)
#define BASE_MEM_SAME_VA (1ULL << 13)
#define BASE_MEM_DONT_NEED (1ULL << 17)
#define BASE_MEM_GROUP_ID(group) ((uint64_t)(group) << 22)

#define BASE_MEM_MMU_DUMP_HANDLE (1UL << GINZA_MALI_PAGE_SHIFT)
#define BASE_MEM_MAP_TRACKING_HANDLE (3UL << GINZA_MALI_PAGE_SHIFT)

#define KBASE_MEM_QUERY_COMMIT_SIZE 1ULL
#define KBASE_MEM_QUERY_VA_SIZE 2ULL
#define KBASE_MEM_QUERY_FLAGS 3ULL

#define BASE_JD_REQ_SOFT_JOB (1U << 9)
#define BASE_JD_REQ_CS (1U << 1)
#define BASE_JD_REQ_SOFT_JIT_ALLOC (BASE_JD_REQ_SOFT_JOB | 0x9U)
#define BASE_JD_REQ_SOFT_JIT_FREE (BASE_JD_REQ_SOFT_JOB | 0xaU)

_Static_assert(sizeof(struct kbase_ioctl_job_submit) == 16, "job submit ABI");
_Static_assert(sizeof(union kbase_ioctl_mem_alloc) == 32, "mem alloc ABI");
_Static_assert(sizeof(union kbase_ioctl_mem_query) == 16, "mem query ABI");
_Static_assert(sizeof(struct kbase_ioctl_mem_jit_init) == 24, "JIT init ABI");
_Static_assert(sizeof(struct kbase_ioctl_mem_commit) == 16, "mem commit ABI");
_Static_assert(sizeof(union kbase_ioctl_mem_alias) == 32, "mem alias ABI");
_Static_assert(sizeof(struct kbase_ioctl_mem_flags_change) == 24,
               "mem flags ABI");
_Static_assert(sizeof(struct base_mem_aliasing_info) == 24, "alias info ABI");
_Static_assert(sizeof(struct base_jd_atom_v2) == 56, "atom ABI");
_Static_assert(sizeof(struct base_jd_event_v2) == 24, "event ABI");
_Static_assert(sizeof(struct base_jit_alloc_info) == 48, "JIT allocation ABI");

#endif
