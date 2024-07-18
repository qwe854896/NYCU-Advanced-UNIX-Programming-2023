#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <netdb.h>
#include <regex>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Begin Executable Part */

#define LOGGER_BUF_SIZE 128

namespace {
void _print_usage() {
  write(STDERR_FILENO,
        "Usage: ./logger config.txt [-o file] [-p sopath] command [arg1 arg2 "
        "...]\n",
        74);
}
} // namespace

int main(int argc, char *argv[]) {
  if (argc < 3) {
    _print_usage();
    return 1;
  }

  std::string config_fn = argv[1];
  std::string log_fn = "";
  std::string so_path = "./logger.so";

  int opt_idx;
  for (opt_idx = 2; opt_idx + 1 < argc; ++opt_idx) {
    if (argv[opt_idx] == std::string("-o")) {
      log_fn = argv[++opt_idx];
    } else if (argv[opt_idx] == std::string("-p")) {
      so_path = argv[++opt_idx];
    } else {
      break;
    }
  }

  int cmd_argc = argc - opt_idx;

  if (cmd_argc < 1) {
    _print_usage();
    return 1;
  }

  /* Print the output to `file` if specified, else print it to `stderr` */
  if (log_fn.empty()) {
    // dup2(STDERR_FILENO, STDOUT_FILENO);
  } else {
    int fd = open(log_fn.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
      return 1;
    }
    dup2(fd, STDERR_FILENO);
    dup2(fd, STDOUT_FILENO);
  }

  char so_path_env[LOGGER_BUF_SIZE], config_path_env[LOGGER_BUF_SIZE];
  sprintf(so_path_env, "LD_PRELOAD=%s", so_path.c_str());
  sprintf(config_path_env, "LOGGER_CONFIG=%s", config_fn.c_str());

  char **const cmd_argv = argv + opt_idx;
  char *const cmd_envp[] = {so_path_env, config_path_env, nullptr};

  execvpe(cmd_argv[0], cmd_argv, cmd_envp);
}

/* End Executable Part */

using file_open_t = FILE *(*)(const char *, const char *);
using file_read_t = size_t (*)(void *, size_t, size_t, FILE *);
using file_write_t = size_t (*)(const void *, size_t, size_t, FILE *);
using connect_t = int (*)(int, const struct sockaddr *, socklen_t);
using getaddrinfo_t = int (*)(const char *, const char *,
                              const struct addrinfo *, struct addrinfo **);
using system_t = int (*)(const char *);

namespace {
void *_get_real_func(const char *func_name) {
  static void *handle = nullptr;
  if (!handle) {
    if (!(handle = dlopen("libc.so.6", RTLD_LAZY))) {
      return nullptr;
    }
  }
  return dlsym(handle, func_name);
}

void _write_log(const char *fmt, ...) {
  char buf[LOGGER_BUF_SIZE];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, LOGGER_BUF_SIZE, fmt, args);
  va_end(args);
  write(STDERR_FILENO, buf, strlen(buf));
  fflush(stderr);
}

bool _match(const std::string &str, const std::string &pattern) {
  auto wildcard_pattern = regex_replace(
      regex_replace(pattern, std::regex("\\*"), ".*"), std::regex("\\?"), ".");
  std::regex re("^" + wildcard_pattern + "$");
  return std::regex_match(str, re);
}

bool _match_content(const std::string &str, const std::string &pattern) {
  std::regex re(pattern);
  return std::regex_search(str, re);
}

bool _is_blacklisted(const std::string &str, const std::string &type) {
  static const char *config_fn = getenv("LOGGER_CONFIG");
  static file_open_t real_fopen = nullptr;

  if (!real_fopen) {
    real_fopen = (file_open_t)_get_real_func("fopen");
  }

  FILE *config_fp = real_fopen(config_fn, "r");

  char begin_token[LOGGER_BUF_SIZE], end_token[LOGGER_BUF_SIZE];
  sprintf(begin_token, "BEGIN %s", type.c_str());
  sprintf(end_token, "END %s", type.c_str());

  static char buf[LOGGER_BUF_SIZE];
  for (bool found = false; fgets(buf, LOGGER_BUF_SIZE, config_fp);) {
    // Trim ' ' and '\n' from the end
    for (int i = strlen(buf) - 1; i >= 0 && (buf[i] == ' ' || buf[i] == '\n');
         --i) {
      buf[i] = '\0';
    }

    if (_match(buf, begin_token)) {
      found = true;
      continue;
    }
    if (_match(buf, end_token)) {
      break;
    }
    if (found && type == "read-blacklist" && _match_content(str, buf)) {
      return true;
    }
    if (found && type != "read-blacklist" && _match(str, buf)) {
      return true;
    }
  }

  return false;
}

char *_get_filename_from_fp(FILE *fp) {
  int fd = fileno(fp);
  static char fd_path[LOGGER_BUF_SIZE];
  sprintf(fd_path, "/proc/self/fd/%d", fd);
  ssize_t r = readlink(fd_path, fd_path, LOGGER_BUF_SIZE);
  fd_path[r] = '\0';
  return fd_path;
}

void _write_log_to_file(const void *ptr, const char *filename, size_t size,
                        const char *type) {
  static file_open_t real_fopen = nullptr;
  static file_write_t real_fwrite = nullptr;

  if (!real_fopen) {
    real_fopen = (file_open_t)_get_real_func("fopen");
  }
  if (!real_fwrite) {
    real_fwrite = (file_write_t)_get_real_func("fwrite");
  }

  std::string base_filename = filename;
  base_filename = base_filename.substr(base_filename.find_last_of("/\\") + 1);

  // remove extension name
  base_filename = base_filename.substr(0, base_filename.find_last_of("."));

  std::string log_fn = std::to_string(getpid()) + "-" + base_filename + "-" +
                       std::string(type) + ".log";

  FILE *log_fp = real_fopen(log_fn.c_str(), "a");
  size_t ret = real_fwrite(ptr, 1, size, log_fp);
}

std::string _realpath(const char *filename) {
  // if the file is not a symbolic link, return the original path
  struct stat st;
  lstat(filename, &st);
  if (!S_ISLNK(st.st_mode)) {
    return filename;
  }

  std::string ret = filename;
  std::string suffix = "";

  while (realpath(ret.c_str(), nullptr) == nullptr) {
    size_t pos = ret.find_last_of("/\\");
    if (pos == std::string::npos) {
      break;
    }
    suffix = ret.substr(pos) + suffix;
    ret = ret.substr(0, pos);
  }

  return realpath(ret.c_str(), nullptr) + suffix;
}

} // namespace

FILE *fopen(const char *filename, const char *mode) {
  static file_open_t real_fopen = nullptr;
  if (!real_fopen) {
    real_fopen = (file_open_t)_get_real_func("fopen");
  }

  if (_is_blacklisted(_realpath(filename), "open-blacklist")) {
    _write_log("[logger] fopen(\"%s\", \"%s\") = 0x0\n", filename, mode);
    errno = EACCES;
    return NULL;
  }

  // int c = getchar();

  FILE *ret = real_fopen(filename, mode);

  _write_log("[logger] fopen(\"%s\", \"%s\") = %p\n", filename, mode, ret);

  return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  static file_read_t real_fread = nullptr;
  if (!real_fread) {
    real_fread = (file_read_t)_get_real_func("fread");
  }

  static char buf[LOGGER_BUF_SIZE];

  size_t ret = real_fread(buf, size, nmemb, stream);

  if (_is_blacklisted(buf, "read-blacklist")) {
    _write_log("[logger] fread(%p, %zu, %zu, %p) = 0\n", ptr, size, nmemb,
               stream);
    errno = EACCES;
    return 0;
  }

  strcpy((char *)ptr, buf);

  _write_log_to_file(ptr, _get_filename_from_fp(stream), ret, "read");

  _write_log("[logger] fread(%p, %zu, %zu, %p) = %zu\n", ptr, size, nmemb,
             stream, ret);

  return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
  static file_write_t real_fwrite = nullptr;
  if (!real_fwrite) {
    real_fwrite = (file_write_t)_get_real_func("fwrite");
  }

  std::string format_ptr = std::string((const char *)ptr);
  format_ptr = std::regex_replace(format_ptr, std::regex("\n"), "\\n");

  if (_is_blacklisted(_get_filename_from_fp(stream), "write-blacklist")) {
    _write_log("[logger] fwrite(\"%s\", %zu, %zu, %p) = 0\n",
               format_ptr.c_str(), size, nmemb, stream);
    errno = EACCES;
    return 0;
  }

  size_t ret = real_fwrite(ptr, size, nmemb, stream);

  _write_log_to_file(ptr, _get_filename_from_fp(stream), ret, "write");

  _write_log("[logger] fwrite(\"%s\", %zu, %zu, %p) = %zu\n",
             format_ptr.c_str(), size, nmemb, stream, ret);

  return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  static connect_t real_connect = nullptr;
  if (!real_connect) {
    real_connect = (connect_t)_get_real_func("connect");
  }

  char ipv4_name[INET_ADDRSTRLEN];
  char port_name[6];
  getnameinfo(addr, addrlen, ipv4_name, INET_ADDRSTRLEN, port_name, 6,
              NI_NUMERICHOST | NI_NUMERICSERV);

  if (_is_blacklisted(std::string(ipv4_name), "connect-blacklist")) {
    _write_log("[logger] connect(%d, %p, %d) = -1\n", sockfd, addr, addrlen);
    errno = ECONNREFUSED;
    return -1;
  }

  int ret = real_connect(sockfd, addr, addrlen);

  _write_log("[logger] connect(%d, %p, %d) = %d\n", sockfd, addr, addrlen, ret);

  return ret;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
  static getaddrinfo_t real_getaddrinfo = nullptr;
  if (!real_getaddrinfo) {
    real_getaddrinfo = (getaddrinfo_t)_get_real_func("getaddrinfo");
  }

  if (_is_blacklisted(std::string(node), "getaddrinfo-blacklist")) {
    _write_log("[logger] getaddrinfo(\"%s\", %s, %p, %p) = -1\n", node, service,
               hints, res);
    return EAI_NONAME;
  }

  int ret = real_getaddrinfo(node, service, hints, res);

  _write_log("[logger] getaddrinfo(\"%s\", %s, %p, %p) = %d\n", node, service,
             hints, res, ret);

  return ret;
}

int system(const char *command) {
  static system_t real_system = nullptr;
  if (!real_system) {
    real_system = (system_t)_get_real_func("system");
  }

  static const char *config_fn = getenv("LOGGER_CONFIG");
  static const char *preload_so = getenv("LD_PRELOAD");

  std::string cmd = "LD_PRELOAD=" + std::string(preload_so) + " " +
                    "LOGGER_CONFIG=" + std::string(config_fn) + " " +
                    std::string(command);
  // "ls -al | grep logger";

  int ret = real_system(cmd.c_str());

  _write_log("[logger] system(\"%s\") = %d\n", command, ret);

  return ret;
}
