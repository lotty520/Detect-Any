#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/system_properties.h>

#include <string>
#include <vector>

// 任务 2.4：属性访问层（双路径）。
// API 26+：__system_property_read_callback（无 92 字节截断），经 dlsym 运行时解析；
// API 24/25：__system_property_read 旧签名（PROP_VALUE_MAX=92 截断，上层感知）。
//
// 实测教训（API 35 模拟器，2026-11）：
// 1. 旧 __system_property_read 遇到超长属性名（>=PROP_NAME_MAX）会 SIGSEGV —— 枚举也必须双路径；
// 2. bionic 回调原型是 callback(void* cookie, const char* name, const char* value, uint32_t serial)
//    —— cookie 在第一位（与直觉相反），参数序错位会把 serial 当指针用。

namespace {

constexpr size_t kValueBuf = 256;

// bionic 原型（sys/system_properties.h, API 26+）：
//   void __system_property_read_callback(const prop_info* pi,
//       void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
//       void* cookie);
typedef void (*prop_cb_t)(void *cookie, const char *name, const char *value, uint32_t serial);
typedef void (*read_cb_fn)(const prop_info *pi, prop_cb_t callback, void *cookie);

read_cb_fn resolve_read_callback() {
    static read_cb_fn cached = reinterpret_cast<read_cb_fn>(-1);
    if (cached == reinterpret_cast<read_cb_fn>(-1)) {
        // dlsym 在属性读取路径上的使用是安全的：这里不做完整性验证，
        // 且 RTLD_DEFAULT 对该符号在 24/25 上返回 nullptr（API 26 引入）
        cached = reinterpret_cast<read_cb_fn>(dlsym(RTLD_DEFAULT, "__system_property_read_callback"));
    }
    return cached;
}

struct ReadResult {
    char value[kValueBuf];
    size_t len = 0;
    bool truncated = false;
};

void read_via_callback(void *cookie, const char *name, const char *value, uint32_t /*serial*/) {
    auto *out = static_cast<ReadResult *>(cookie);
    out->len = strnlen(value, kValueBuf);
    out->truncated = out->len >= kValueBuf - 1;
    const size_t copy = out->len < kValueBuf - 1 ? out->len : kValueBuf - 1;
    memcpy(out->value, value, copy);
    out->value[copy] = '\0';
}

ReadResult read_prop(const prop_info *pi) {
    ReadResult r;
    if (read_cb_fn cb = resolve_read_callback(); cb != nullptr) {
        cb(pi, read_via_callback, &r);
        return r;
    }
    // API 24/25 旧路径：92 字节缓冲
    char value[PROP_VALUE_MAX];
    __system_property_read(pi, nullptr, value);
    const size_t len = strnlen(value, PROP_VALUE_MAX);
    r.len = len;
    r.truncated = len >= PROP_VALUE_MAX - 1;
    const size_t copy = len < kValueBuf - 1 ? len : kValueBuf - 1;
    memcpy(r.value, value, copy);
    r.value[copy] = '\0';
    return r;
}

void list_via_callback(void *cookie, const char *name, const char *value, uint32_t /*serial*/) {
    auto *out = static_cast<std::vector<std::string> *>(cookie);
    out->emplace_back(std::string(name) + "=" + std::string(value));
}

void trampoline(const prop_info *pi, void *cookie) {
    auto *out = static_cast<std::vector<std::string> *>(cookie);
    if (read_cb_fn cb = resolve_read_callback(); cb != nullptr) {
        cb(pi, list_via_callback, out);
        return;
    }
    char name[PROP_NAME_MAX];
    char value[PROP_VALUE_MAX];
    __system_property_read(pi, name, value);
    out->emplace_back(std::string(name) + "=" + std::string(value));
}

}  // namespace

// 全量枚举为 "key=value" 列表（旧路径值可能被 92 字节截断——上层必须处理）。
int da_prop_list(std::vector<std::string> *out) {
    out->clear();
    return __system_property_foreach(trampoline, out);
}

// 单键读取：返回 0 成功 / -ENOENT 键不存在；truncated 指示值长度顶满缓冲（疑似截断）。
int da_prop_get(const char *key, char *buf, size_t buf_size, int *truncated) {
    const prop_info *pi = __system_property_find(key);
    if (pi == nullptr) return -ENOENT;
    const ReadResult r = read_prop(pi);
    *truncated = r.truncated ? 1 : 0;
    const size_t copy = r.len < buf_size - 1 ? r.len : buf_size - 1;
    memcpy(buf, r.value, copy);
    buf[copy] = '\0';
    return 0;
}
