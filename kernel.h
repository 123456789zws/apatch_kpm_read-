
#ifndef _KERNEL_H_
#define _KERNEL_H_
#include <cstdint>
#include <unistd.h>
#include <string>
#include <iostream>
#include <sys/syscall.h>

#define MAJOR 0
#define MINOR 11
#define PATCH 1

#define SUPERCALL_HELLO_ECHO "hello1158"

// #define __NR_supercall __NR3264_truncate // 45
#define __NR_supercall 45

#define SUPERCALL_HELLO 0x1000
#define SUPERCALL_KLOG 0x1004

#define SUPERCALL_KERNELPATCH_VER 0x1008
#define SUPERCALL_KERNEL_VER 0x1009


#define SUPERCALL_KPM_LOAD 0x1020
#define SUPERCALL_KPM_UNLOAD 0x1021
#define SUPERCALL_KPM_CONTROL 0x1022

#define SUPERCALL_KPM_NUMS 0x1030
#define SUPERCALL_KPM_LIST 0x1031
#define SUPERCALL_KPM_INFO 0x1032


#define SUPERCALL_HELLO_MAGIC 0x11581158


static inline long hash_key(const char *key)
{
    long hash = 1000000007;
    for (int i = 0; key[i]; i++) {
        hash = hash * 31 + key[i];
    }
    return hash;
}
// be 0a04
static inline long hash_key_cmd(const char *key, long cmd)
{
    long hash = hash_key(key);
    return (hash & 0xFFFF0000) | cmd;
}

// ge 0a05
static inline long ver_and_cmd( long cmd)
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return ((long)version_code << 32) | (0x1158 << 16) | (cmd & 0xFFFF);
}

static inline long compact_cmd(const char *key, long cmd)
{
    long ver = syscall(__NR_supercall, key, ver_and_cmd( SUPERCALL_KERNELPATCH_VER));
    if (ver >= 0xa05) return ver_and_cmd( cmd);
    return hash_key_cmd(key, cmd);
}


static inline long sc_hello(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, compact_cmd(key, SUPERCALL_HELLO));
    return ret;
}

static inline bool sc_ready(const char *key)
{
    return sc_hello(key) == SUPERCALL_HELLO_MAGIC;
}

class kernel
{
private:
    struct kpm_read
    {
        uint64_t key;
        int pid;
        int size;
        uint64_t addr;
        void *buffer;

    };

    struct kpm_mod
    {
        uint64_t key;
        int pid;
        char *name;
        uintptr_t base;

    };
    uint64_t key_vertify;
    uint64_t cmd_read;
    uint64_t cmd_write;
    uint64_t cmd_mod;
    struct kpm_read kread;
    struct kpm_mod kmod;

public:
    
    int cmd_ctl(std::string SuperCallKey){
        if(SuperCallKey.empty()) return -1;
        std::string key_cmd = "get_key";
        char  buf[256] = {0};
        long ret = syscall(__NR_supercall, SuperCallKey.c_str() , compact_cmd(SuperCallKey.c_str(), SUPERCALL_KPM_CONTROL), "kpm_kread", key_cmd.c_str(), buf, 256);
        if(ret<0) return -1;
        std::string str_buf = std::string(buf);
        //std::cout<<"str_buf: "<<str_buf<<std::endl;
        int pos = str_buf.find("-");
        if(pos == std::string::npos) return -1;
        key_vertify = std::stoull(str_buf.substr(0,pos),nullptr,16);
        cmd_read = std::stoull(str_buf.substr(pos+1),nullptr,16);
        init(cmd_read,key_vertify);
        return 0;
    }

    kernel(){};

    void init(uint64_t cmd,uint64_t key){
        cmd_read = cmd;//十六进制
        cmd_write = cmd + 1;
        cmd_mod = cmd + 2;
        kread.key = key;//十六进制
        kmod.key = key;
    };

    void set_pid(int pid){
        kread.pid = pid;
        kmod.pid = pid;
    }

    template<typename T>
    T read(uint64_t addr){
        T data;
        kread.addr = addr & 0xffffffffffff;
        kread.size = sizeof(T);
        kread.buffer = &data;
        int ret = ioctl(-1,cmd_read,&kread);
        //syscall(entry,-1, cmd_read, &kread);
        // ioctl(-1,cmd_read,&kread);
        if(ret<0){
            //std::cout<<"read error maybe pa false"<<std::endl;
            return 0;
        }
        return data;
    }

    void read(uint64_t addr, void *buffer, int size){
        kread.addr = addr & 0xffffffffffff;
        kread.size = size;
        kread.buffer = buffer;
        int ret = ioctl(-1,cmd_read,&kread);
        //sycall(entry,-1, cmd_read,&kread);
        //ioctl(-1,cmd_read,&kread);
        // if(ret<0){
        //     //std::cout<<"read error"<<std::endl;
        // }
    }

    void write(uint64_t addr,  void *buffer, int size){
        kread.addr = addr & 0xffffffffffff;
        kread.size = size;
        kread.buffer = buffer;
        int ret = ioctl(-1,cmd_write,&kread);
        //syscall(entry,-1, cmd_write,&kread);
        //ioctl(-1,cmd_write,&kread);
        // if(ret<0){
        //     //std::cout<<"write error"<<std::endl;
        // }
    }

    template<typename T>
    bool write(uint64_t addr, T data){
        kread.addr = addr  & 0xffffffffffff;
        kread.size = sizeof(T);
        kread.buffer = &data;
        int ret = ioctl(-1,cmd_write,&kread);
        // syscall(entry,-1, cmd_write,&kread);
        //ioctl(-1,cmd_write,&kread);
        if(ret<0){
           // std::cout<<"write error"<<std::endl;
            return false;
        }
        return ret==0;
    }

    uint64_t get_mod_base(std::string name){
        kmod.name = const_cast<char*>(name.c_str());
        int ret = ioctl(-1,cmd_mod,&kmod);
        //syacall(entry,-1, cmd_mod,&kmod);
        //ioctl(-1,cmd_mod,&kmod);
        if(ret<0){
            std::cout<<"get_mod_base error" << std::hex << kmod.base <<
                     ", pid:"<< std::dec << kmod.pid <<std::endl;
            return 0;
        }
        return kmod.base;
    }


};

extern kernel* driver;

typedef unsigned short UTF16;
typedef char UTF8;
typedef char PACKAGENAME;	// 包名
//pid_t pid;	// 进程ID

// 读取字符信息
inline void getUTF8(UTF8 * buf, unsigned long namepy)
{
	UTF16 buf16[16] = { 0 };
	driver->read(namepy, buf16, 28);
	UTF16 *pTempUTF16 = buf16;
	UTF8 *pTempUTF8 = buf;
	UTF8 *pUTF8End = pTempUTF8 + 32;
	while (pTempUTF16 < pTempUTF16 + 28)
	{
		if (*pTempUTF16 <= 0x007F && pTempUTF8 + 1 < pUTF8End)
		{
			*pTempUTF8++ = (UTF8) * pTempUTF16;
		}
		else if (*pTempUTF16 >= 0x0080 && *pTempUTF16 <= 0x07FF && pTempUTF8 + 2 < pUTF8End)
		{
			*pTempUTF8++ = (*pTempUTF16 >> 6) | 0xC0;
			*pTempUTF8++ = (*pTempUTF16 & 0x3F) | 0x80;
		}
		else if (*pTempUTF16 >= 0x0800 && *pTempUTF16 <= 0xFFFF && pTempUTF8 + 3 < pUTF8End)
		{
			*pTempUTF8++ = (*pTempUTF16 >> 12) | 0xE0;
			*pTempUTF8++ = ((*pTempUTF16 >> 6) & 0x3F) | 0x80;
			*pTempUTF8++ = (*pTempUTF16 & 0x3F) | 0x80;
		}
		else
		{
			break;
		}
		pTempUTF16++;
	}
}



inline int getPID(char* PackageName)
{
    pid_t pid;	// 进程ID
	FILE* fp;
    char cmd[0x100] = "pidof ";
    strcat(cmd, PackageName);
    fp = popen(cmd,"r");
    fscanf(fp,"%d", &pid);
    pclose(fp);
	
    return pid;
}


inline uint64_t ReadValue(uint64_t addr)
{
    addr = addr & 0xfffffffffff;
	uint64_t he=0;
	driver->read(addr, &he, 8);
	
	return he & 0xfffffffffff;
}

inline int ReadDword(uint64_t addr)
{
    addr=addr& 0xfffffffffff;
	int he=0;
	driver->read(addr, &he, 4);
	return he;
}

inline float ReadFloat(long addr)
{
    addr=addr& 0xfffffffffff;
	float he=0;
	driver->read(addr, &he, 4);
	return he;
}

inline int WriteDword(long int addr, int value)
{
    addr=addr& 0xfffffffffff;
	driver->write(addr, &value, 4);
	return 0;
}

inline int WriteFloat(long int addr, float value)
{
	driver->write(addr, &value, 4);
	return 0;
}


#endif /* _KERNEL_H_ */

/*
#include "kernel.h"

kernel* driver = new kernel();

int main(int argc, char *argv[]) {


//内核初始化
std::cout << "输入你的apatch修补时的key" << std::endl;
std::string apatch_key = "" ;
std::cin >> apatch_key;

std::cout << "apatch_key:" << apatch_key << std::endl;

bool is_patch = sc_ready(apatch_key.c_str());
if(is_patch){
    std::cout<<"patch success"<<std::endl;
}else{
    std::cout<<"错误的ap环境"<<std::endl;
    return -1;
}

int driver_ctl = driver->cmd_ctl(apatch_key);
if(driver_ctl == 0){
    std::cout<<"环境初始化成功"<<std::endl;
}else{
    std::cout<<"环境初始化失败"<<std::endl;
    return -1;
}
}
*/