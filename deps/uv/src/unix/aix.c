/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"
#include "internal.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <utmp.h>

#include <sys/protosw.h>
#include <libperfstat.h>
#include <sys/proc.h>
#include <sys/procfs.h>

#define reqevents events
#define rtnevents revents
#include <sys/poll.h>
#undef reqevents
#undef rtnevents
#undef events
#undef revents

#include <sys/pollset.h>

int uv__platform_loop_init(uv_loop_t* loop, int default_loop) {
  loop->fs_fd = -1;

  loop->backend_fd = pollset_create(256);

  if (loop->backend_fd == -1)
    return -1;

  uv__cloexec(loop->backend_fd, 1);

  return 0;
}


void uv__platform_loop_delete(uv_loop_t* loop) {
  if (loop->fs_fd == -1) {
    close(loop->fs_fd);
    loop->fs_fd = -1;
  }

  if (loop->backend_fd != -1) {
    close(loop->backend_fd);
    loop->backend_fd = -1;
  }
}


void uv__io_poll(uv_loop_t* loop, int timeout) {
  struct pollfd events[1024];
  struct pollfd* pe;
  struct poll_ctl pc;
  ngx_queue_t* q;
  uv__io_t* w;
  uint64_t base;
  uint64_t diff;
  int nevents;
  int count;
  int nfds;
  int i;

  if (loop->nfds == 0) {
    assert(ngx_queue_empty(&loop->watcher_queue));
    return;
  }

  while (!ngx_queue_empty(&loop->watcher_queue)) {
    q = ngx_queue_head(&loop->watcher_queue);
    ngx_queue_remove(q);
    ngx_queue_init(q);

    w = ngx_queue_data(q, uv__io_t, watcher_queue);
    assert(w->pevents != 0);
    assert(w->fd >= 0);
    assert(w->fd < (int) loop->nwatchers);

    if (w->events == 0)
      pc.cmd = PS_ADD;
    else
      pc.cmd = PS_MOD;
    pc.events = w->pevents;
    pc.fd = w->fd;

    /* XXX Future optimization: do PS_MOD lazily if we stop watching
     * events, skip the syscall and squelch the events after epoll_wait().
     */
    if (pollset_ctl(loop->backend_fd, &pc, 1)) {
      if (errno != EINVAL)
        abort();

      assert(pc.cmd == PS_ADD);

      /* We've reactivated a file descriptor that's been watched before. */
      pc.cmd = PS_MOD;
      if (pollset_ctl(loop->backend_fd, &pc, 1))
        abort();
    }

    w->events = w->pevents;
  }

  assert(timeout >= -1);
  base = loop->time;
  count = 48; /* Benchmarks suggest this gives the best throughput. */

  for (;;) {
    nfds = pollset_poll(loop->backend_fd,
                        events,
                        ARRAY_SIZE(events),
                        timeout);

    /* Update loop->time unconditionally. It's tempting to skip the update when
     * timeout == 0 (i.e. non-blocking poll) but there is no guarantee that the
     * operating system didn't reschedule our process while in the syscall.
     */
    SAVE_ERRNO(uv__update_time(loop));

    if (nfds == 0) {
      assert(timeout != -1);
      return;
    }

    if (nfds == -1) {
      if (errno != EINTR)
        abort();

      if (timeout == -1)
        continue;

      if (timeout == 0)
        return;

      /* Interrupted by a signal. Update timeout and poll again. */
      goto update_timeout;
    }

    nevents = 0;

    for (i = 0; i < nfds; i++) {
      pe = events + i;
      pc.cmd = PS_DELETE;
      pc.fd = pe->fd;

      assert(pc.fd >= 0);
      assert((unsigned) pc.fd < loop->nwatchers);

      w = loop->watchers[pc.fd];

      if (w == NULL) {
        /* File descriptor that we've stopped watching, disarm it.
         *
         * Ignore all errors because we may be racing with another thread
         * when the file descriptor is closed.
         */
        pollset_ctl(loop->backend_fd, &pc, 1);
        continue;
      }

      w->cb(loop, w, pe->revents);
      nevents++;
    }

    if (nevents != 0) {
      if (nfds == ARRAY_SIZE(events) && --count != 0) {
        /* Poll for more events but don't block this time. */
        timeout = 0;
        continue;
      }
      return;
    }

    if (timeout == 0)
      return;

    if (timeout == -1)
      continue;

update_timeout:
    assert(timeout > 0);

    diff = loop->time - base;
    if (diff >= (uint64_t) timeout)
      return;

    timeout -= diff;
  }
}


uint64_t uv__hrtime(void) {
  uint64_t G = 1000000000;
  timebasestruct_t t;
  read_wall_time(&t, TIMEBASE_SZ);
  time_base_to_time(&t, TIMEBASE_SZ);
  return (uint64_t) t.tb_high * G + t.tb_low;
}


/*
 * We could use a static buffer for the path manipulations that we need outside
 * of the function, but this function could be called by multiple consumers and
 * we don't want to potentially create a race condition in the use of snprintf.
 */
int uv_exepath(char* buffer, size_t* size) {
  ssize_t res;
  char pp[64], cwdl[PATH_MAX];
  struct psinfo ps;
  int fd;

  if (buffer == NULL)
    return (-1);

  if (size == NULL)
    return (-1);

  (void) snprintf(pp, sizeof(pp), "/proc/%lu/cwd", (unsigned long) getpid());

  res = readlink(pp, cwdl, sizeof(cwdl) - 1);
  if (res < 0)
    return res;

  cwdl[res] = '\0';

  (void) snprintf(pp, sizeof(pp), "/proc/%lu/psinfo", (unsigned long) getpid());
  fd = open(pp, O_RDONLY);
  if (fd < 0)
    return fd;

  res = read(fd, &ps, sizeof(ps));
  close(fd);
  if (res < 0)
    return res;

  (void) snprintf(buffer, *size, "%s%s", cwdl, ps.pr_fname);
  *size = strlen(buffer);
  return 0;
}


uint64_t uv_get_free_memory(void) {
  perfstat_memory_total_t mem_total;
  int result = perfstat_memory_total(NULL, &mem_total, sizeof(mem_total), 1);
  if (result == -1) {
    return 0;
  }
  return mem_total.real_free * 4096;
}


uint64_t uv_get_total_memory(void) {
  perfstat_memory_total_t mem_total;
  int result = perfstat_memory_total(NULL, &mem_total, sizeof(mem_total), 1);
  if (result == -1) {
    return 0;
  }
  return mem_total.real_total * 4096;
}


void uv_loadavg(double avg[3]) {
  perfstat_cpu_total_t ps_total;
  int result = perfstat_cpu_total(NULL, &ps_total, sizeof(ps_total), 1);
  if (result == -1) {
    avg[0] = 0.; avg[1] = 0.; avg[2] = 0.;
    return;
  }
  avg[0] = ps_total.loadavg[0] / (double)(1 << SBITS);
  avg[1] = ps_total.loadavg[1] / (double)(1 << SBITS);
  avg[2] = ps_total.loadavg[2] / (double)(1 << SBITS);
}


int uv_fs_event_init(uv_loop_t* loop,
                     uv_fs_event_t* handle,
                     const char* filename,
                     uv_fs_event_cb cb,
                     int flags) {
  uv__set_sys_error(loop, ENOSYS);
  return -1;
}


void uv__fs_event_close(uv_fs_event_t* handle) {
  UNREACHABLE();
}


char** uv_setup_args(int argc, char** argv) {
  return argv;
}


uv_err_t uv_set_process_title(const char* title) {
  return uv_ok_;
}


uv_err_t uv_get_process_title(char* buffer, size_t size) {
  if (size > 0) {
    buffer[0] = '\0';
  }
  return uv_ok_;
}


uv_err_t uv_resident_set_memory(size_t* rss) {
  char pp[64];
  psinfo_t psinfo;
  uv_err_t err;
  int fd;

  (void) snprintf(pp, sizeof(pp), "/proc/%lu/psinfo", (unsigned long) getpid());

  fd = open(pp, O_RDONLY);
  if (fd == -1)
    return uv__new_sys_error(errno);

  err = uv_ok_;

  if (read(fd, &psinfo, sizeof(psinfo)) == sizeof(psinfo))
    *rss = (size_t)psinfo.pr_rssize * 1024;
  else
    err = uv__new_sys_error(EINVAL);

  close(fd);

  return err;
}


uv_err_t uv_uptime(double* uptime) {
  struct utmp *utmp_buf;
  size_t entries = 0;
  time_t boot_time;

  utmpname(UTMP_FILE);

  setutent();

  while ((utmp_buf = getutent()) != NULL) {
    if (utmp_buf->ut_user[0] && utmp_buf->ut_type == USER_PROCESS)
      ++entries;
    if (utmp_buf->ut_type == BOOT_TIME)
      boot_time = utmp_buf->ut_time;
  }

  endutent();

  if (boot_time == 0)
    return uv__new_artificial_error(UV_ENOSYS);

  *uptime = time(NULL) - boot_time;
  return uv_ok_;
}


uv_err_t uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {
  uv_cpu_info_t* cpu_info;
  perfstat_cpu_total_t ps_total;
  perfstat_cpu_t* ps_cpus;
  perfstat_id_t cpu_id;
  int result, ncpus, idx = 0;

  result = perfstat_cpu_total(NULL, &ps_total, sizeof(ps_total), 1);
  if (result == -1) {
    return uv__new_artificial_error(UV_ENOSYS);
  }

  ncpus = result = perfstat_cpu(NULL, NULL, sizeof(perfstat_cpu_t), 0);
  if (result == -1) {
    return uv__new_artificial_error(UV_ENOSYS);
  }

  ps_cpus = (perfstat_cpu_t*) malloc(ncpus * sizeof(perfstat_cpu_t));
  if (!ps_cpus) {
    return uv__new_artificial_error(UV_ENOMEM);
  }

  strcpy(cpu_id.name, FIRST_CPU);
  result = perfstat_cpu(&cpu_id, ps_cpus, sizeof(perfstat_cpu_t), ncpus);
  if (result == -1) {
    free(ps_cpus);
    return uv__new_artificial_error(UV_ENOSYS);
  }

  *cpu_infos = (uv_cpu_info_t*) malloc(ncpus * sizeof(uv_cpu_info_t));
  if (!*cpu_infos) {
    free(ps_cpus);
    return uv__new_artificial_error(UV_ENOMEM);
  }

  *count = ncpus;

  cpu_info = *cpu_infos;
  while (idx < ncpus) {
    cpu_info->speed = (int)(ps_total.processorHZ / 1000000);
    cpu_info->model = strdup(ps_total.description);
    cpu_info->cpu_times.user = ps_cpus[idx].user;
    cpu_info->cpu_times.sys = ps_cpus[idx].sys;
    cpu_info->cpu_times.idle = ps_cpus[idx].idle;
    cpu_info->cpu_times.irq = ps_cpus[idx].wait;
    cpu_info->cpu_times.nice = 0;
    cpu_info++;
    idx++;
  }

  free(ps_cpus);
  return uv_ok_;
}


void uv_free_cpu_info(uv_cpu_info_t* cpu_infos, int count) {
  int i;

  for (i = 0; i < count; ++i) {
    free(cpu_infos[i].model);
  }

  free(cpu_infos);
}


uv_err_t uv_interface_addresses(uv_interface_address_t** addresses,
  int* count) {
  uv_interface_address_t* address;
  int sockfd, size = 1;
  struct ifconf ifc;
  struct ifreq *ifr, *p, flg;

  *count = 0;

  if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))) {
    return uv__new_artificial_error(UV_ENOSYS);
  }

  if (ioctl(sockfd, SIOCGSIZIFCONF, &size) == -1) {
    close(sockfd);
    return uv__new_artificial_error(UV_ENOSYS);
  }

  ifc.ifc_req = (struct ifreq*)malloc(size);
  ifc.ifc_len = size;
  if (ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) {
    close(sockfd);
    return uv__new_artificial_error(UV_ENOSYS);
  }

#define ADDR_SIZE(p) MAX((p).sa_len, sizeof(p))

  /* Count all up and running ipv4/ipv6 addresses */
  ifr = ifc.ifc_req;
  while ((char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len) {
    p = ifr;
    ifr = (struct ifreq*)
      ((char*)ifr + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

    if (!(p->ifr_addr.sa_family == AF_INET6 ||
          p->ifr_addr.sa_family == AF_INET))
      continue;

    memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1) {
      close(sockfd);
      return uv__new_artificial_error(UV_ENOSYS);
    }

    if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
      continue;

    (*count)++;
  }

  /* Alloc the return interface structs */
  *addresses = (uv_interface_address_t*)
    malloc(*count * sizeof(uv_interface_address_t));
  if (!(*addresses)) {
    close(sockfd);
    return uv__new_artificial_error(UV_ENOMEM);
  }
  address = *addresses;

  ifr = ifc.ifc_req;
  while ((char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len) {
    p = ifr;
    ifr = (struct ifreq*)
      ((char*)ifr + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

    if (!(p->ifr_addr.sa_family == AF_INET6 ||
          p->ifr_addr.sa_family == AF_INET))
      continue;

    memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1) {
      close(sockfd);
      return uv__new_artificial_error(UV_ENOSYS);
    }

    if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
      continue;

    /* All conditions above must match count loop */

    address->name = strdup(p->ifr_name);

    if (p->ifr_addr.sa_family == AF_INET6) {
      address->address.address6 = *((struct sockaddr_in6 *)&p->ifr_addr);
    } else {
      address->address.address4 = *((struct sockaddr_in *)&p->ifr_addr);
    }

    address->is_internal = flg.ifr_flags & IFF_LOOPBACK ? 1 : 0;

    address++;
  }

#undef ADDR_SIZE

  close(sockfd);
  return uv_ok_;
}


void uv_free_interface_addresses(uv_interface_address_t* addresses,
  int count) {
  int i;

  for (i = 0; i < count; ++i) {
    free(addresses[i].name);
  }

  free(addresses);
}
