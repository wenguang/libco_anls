/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/un.h>

#include <dlfcn.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <errno.h>
#include <time.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>

#include <resolv.h>
#include <netdb.h>

#include <time.h>
#include "co_routine.h"
#include "co_routine_inner.h"
#include "co_routine_specific.h"

typedef long long ll64_t;

/* 套接字hook信息结构 - 存储hook函数中跟套接字相关的信息
 *
 * 为什么需要该结构呢? - 举例说明, 套接字的O_NONBLOCK属性决定了hook后的read函数是直接调用系统的read函数,
 * 还是先向内核注册事件(向内核注册事件时又需要读超时时间), 然后切换协程并等待事件发生时切换回该协程, 最后调用
 * 系统的read函数. 如果不把这些信息(是否O_NONBLOCK, 读写超时时间等)传递到被hook函数中, 我们就无法实现hook
 * 函数的逻辑. 这就是需要该结构的原因！
 *
 * 说句题外话, 其实我觉得该结构是非必需的, O_NONBLOCK属性可通过未hook的fcntl函数获得, 超时时间采用全局设置也未尝不可.
 * */
struct rpchook_t
{
    int user_flag;                                  // 套接字的阻塞/非阻塞属性
    struct sockaddr_in dest; //maybe sockaddr_un;   // 套接字目的主机地址
    int domain; //AF_LOCAL , AF_INET                // 套接字类型
    
    struct timeval read_timeout;                    // 套接字读超时时间
    struct timeval write_timeout;                   // 该套接写超时时间
};

/* 获取线程id */
static inline pid_t GetPid()
{
    char **p = (char**)pthread_self();
    return p ? *(pid_t*)(p + 18) : getpid();
}

/* 套接字hook信息数组 - 存储(该线程内)所有协程中的套接字hook信息, 便于套接字hook信息在被hook的系统调用之间传递,
 * 部分被hook函数用这些信息来控制函数逻辑(详见下面被hook的系统调用).
 *
 * 理解这个数组是重点, 一部分被hook的系统调用初始化这些数组中的元素, 另一部分被hook的系统调用获取数组元素来控制函数逻辑.
 * */
static rpchook_t *g_rpchook_socket_fd[ 102400 ] = { 0 };

/* 对每个被hook的系统调用声明一种函数指针类型 */
typedef int (*socket_pfn_t)(int domain, int type, int protocol);
typedef int (*connect_pfn_t)(int socket, const struct sockaddr *address, socklen_t address_len);
typedef int (*close_pfn_t)(int fd);

typedef ssize_t (*read_pfn_t)(int fildes, void *buf, size_t nbyte);
typedef ssize_t (*write_pfn_t)(int fildes, const void *buf, size_t nbyte);

typedef ssize_t (*sendto_pfn_t)(int socket, const void *message, size_t length,
	                 int flags, const struct sockaddr *dest_addr,
					               socklen_t dest_len);

typedef ssize_t (*recvfrom_pfn_t)(int socket, void *buffer, size_t length,
	                 int flags, struct sockaddr *address,
					               socklen_t *address_len);

typedef size_t (*send_pfn_t)(int socket, const void *buffer, size_t length, int flags);
typedef ssize_t (*recv_pfn_t)(int socket, void *buffer, size_t length, int flags);

typedef int (*poll_pfn_t)(struct pollfd fds[], nfds_t nfds, int timeout);
typedef int (*setsockopt_pfn_t)(int socket, int level, int option_name,
			                 const void *option_value, socklen_t option_len);

typedef int (*fcntl_pfn_t)(int fildes, int cmd, ...);
typedef struct tm *(*localtime_r_pfn_t)( const time_t *timep, struct tm *result );

typedef void *(*pthread_getspecific_pfn_t)(pthread_key_t key);
typedef int (*pthread_setspecific_pfn_t)(pthread_key_t key, const void *value);

typedef int (*setenv_pfn_t)(const char *name, const char *value, int overwrite);
typedef int (*unsetenv_pfn_t)(const char *name);
typedef char *(*getenv_pfn_t)(const char *name);
typedef hostent* (*gethostbyname_pfn_t)(const char *name);
typedef res_state (*__res_state_pfn_t)();
typedef int (*__poll_pfn_t)(struct pollfd fds[], nfds_t nfds, int timeout);

/* 将动态库中被hook的系统调用的地址(即函数指针)绑定到以g_sys_##name##__func命名的函数指针
 *
 * 为什么要这么做呢? - 这样做的目的是在链接阶段让系统调用在动态库中找不到对应的实现, 而来链接到我们代码中的同名函数(即被hook的函数)
 * */
static socket_pfn_t g_sys_socket_func 	= (socket_pfn_t)dlsym(RTLD_NEXT,"socket");
static connect_pfn_t g_sys_connect_func = (connect_pfn_t)dlsym(RTLD_NEXT,"connect");
static close_pfn_t g_sys_close_func 	= (close_pfn_t)dlsym(RTLD_NEXT,"close");

static read_pfn_t g_sys_read_func 		= (read_pfn_t)dlsym(RTLD_NEXT,"read");
static write_pfn_t g_sys_write_func 	= (write_pfn_t)dlsym(RTLD_NEXT,"write");

static sendto_pfn_t g_sys_sendto_func 	= (sendto_pfn_t)dlsym(RTLD_NEXT,"sendto");
static recvfrom_pfn_t g_sys_recvfrom_func = (recvfrom_pfn_t)dlsym(RTLD_NEXT,"recvfrom");

static send_pfn_t g_sys_send_func 		= (send_pfn_t)dlsym(RTLD_NEXT,"send");
static recv_pfn_t g_sys_recv_func 		= (recv_pfn_t)dlsym(RTLD_NEXT,"recv");

static poll_pfn_t g_sys_poll_func 		= (poll_pfn_t)dlsym(RTLD_NEXT,"poll");

static setsockopt_pfn_t g_sys_setsockopt_func 
										= (setsockopt_pfn_t)dlsym(RTLD_NEXT,"setsockopt");
static fcntl_pfn_t g_sys_fcntl_func 	= (fcntl_pfn_t)dlsym(RTLD_NEXT,"fcntl");

static setenv_pfn_t g_sys_setenv_func   = (setenv_pfn_t)dlsym(RTLD_NEXT,"setenv");
static unsetenv_pfn_t g_sys_unsetenv_func = (unsetenv_pfn_t)dlsym(RTLD_NEXT,"unsetenv");
static getenv_pfn_t g_sys_getenv_func   =  (getenv_pfn_t)dlsym(RTLD_NEXT,"getenv");
static __res_state_pfn_t g_sys___res_state_func  = (__res_state_pfn_t)dlsym(RTLD_NEXT,"__res_state");

static gethostbyname_pfn_t g_sys_gethostbyname_func = (gethostbyname_pfn_t)dlsym(RTLD_NEXT, "gethostbyname");

static __poll_pfn_t g_sys___poll_func = (__poll_pfn_t)dlsym(RTLD_NEXT, "__poll");


/*
static pthread_getspecific_pfn_t g_sys_pthread_getspecific_func 
			= (pthread_getspecific_pfn_t)dlsym(RTLD_NEXT,"pthread_getspecific");

static pthread_setspecific_pfn_t g_sys_pthread_setspecific_func 
			= (pthread_setspecific_pfn_t)dlsym(RTLD_NEXT,"pthread_setspecific");

static pthread_rwlock_rdlock_pfn_t g_sys_pthread_rwlock_rdlock_func  
			= (pthread_rwlock_rdlock_pfn_t)dlsym(RTLD_NEXT,"pthread_rwlock_rdlock");

static pthread_rwlock_wrlock_pfn_t g_sys_pthread_rwlock_wrlock_func  
			= (pthread_rwlock_wrlock_pfn_t)dlsym(RTLD_NEXT,"pthread_rwlock_wrlock");

static pthread_rwlock_unlock_pfn_t g_sys_pthread_rwlock_unlock_func  
			= (pthread_rwlock_unlock_pfn_t)dlsym(RTLD_NEXT,"pthread_rwlock_unlock");
*/


/* 未使用该函数 */
static inline unsigned long long get_tick_count()
{
	uint32_t lo, hi;
	__asm__ __volatile__ (
			"rdtscp" : "=a"(lo), "=d"(hi)
			);
	return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

/* 未使用该结构 */
struct rpchook_connagent_head_t
{
    unsigned char    bVersion;
    struct in_addr   iIP;
    unsigned short   hPort;
    unsigned int     iBodyLen;
    unsigned int     iOssAttrID;
    unsigned char    bIsRespNotExist;
	unsigned char    sReserved[6];
}__attribute__((packed));

/* hook系统调用 - 将动态库中名为name的系统调用地址(即函数指针)绑定到以g_sys_##name##__func命名的函数指针 */
#define HOOK_SYS_FUNC(name) if( !g_sys_##name##_func ) { g_sys_##name##_func = (name##_pfn_t)dlsym(RTLD_NEXT,#name); }

/*
 * diff_ms - 计算以毫秒为单位的时间差
 * @param begin - (input) 开始时间
 * @param end - (input) 结束时间
 * @return 毫秒为单位的时间差
 * */
static inline ll64_t diff_ms(struct timeval &begin,struct timeval &end)
{
	ll64_t u = (end.tv_sec - begin.tv_sec) ;
	u *= 1000 * 10;
	u += ( end.tv_usec - begin.tv_usec ) / (  100 );
	return u;
}

/*
 * get_by_fd - 在套接字hook信息数组(g_rpchook_socket_fd)中获取套接字fd对应的rpchook_t类型变量的指针
 * @param fd - (input) 套接字文件描述符
 * @return 成功返回rpchook_t类型变量的指针, 失败返回NULL
 * */
static inline rpchook_t * get_by_fd( int fd )
{
	if( fd > -1 && fd < (int)sizeof(g_rpchook_socket_fd) / (int)sizeof(g_rpchook_socket_fd[0]) )
	{
		return g_rpchook_socket_fd[ fd ];
	}
	return NULL;
}

/*
 * alloc_by_fd - 为套接字fd分配对应的rpchook_t类型类型的存储空间, 并将存储空间的地址加入到套接字hook信息数组(g_rpchook_socket_fd)中
 * @param fd - (input) 套接字文件描述符
 * @return 成功返回rpchook_t类型变量的指针, 失败返回NULL
 * */
static inline rpchook_t * alloc_by_fd( int fd )
{
	if( fd > -1 && fd < (int)sizeof(g_rpchook_socket_fd) / (int)sizeof(g_rpchook_socket_fd[0]) )
	{
		rpchook_t *lp = (rpchook_t*)calloc( 1,sizeof(rpchook_t) );
		lp->read_timeout.tv_sec = 1;
		lp->write_timeout.tv_sec = 1;
		g_rpchook_socket_fd[ fd ] = lp;
		return lp;
	}
	return NULL;
}

/*
 * free_by_fd - 在套接字hook信息数组(g_rpchook_socket_fd)中释放套接字fd对应rpchook_t类型变量的存储空间
 * @param fd - (input) 套接字文件描述符
 * @return
 * */
static inline void free_by_fd( int fd )
{
	if( fd > -1 && fd < (int)sizeof(g_rpchook_socket_fd) / (int)sizeof(g_rpchook_socket_fd[0]) )
	{
		rpchook_t *lp = g_rpchook_socket_fd[ fd ];
		if( lp )
		{
			g_rpchook_socket_fd[ fd ] = NULL;
			free(lp);	
		}
	}
	return;

}

/* socket - 被hook后的socket函数, 主要是为套接字fd分配对应的rpchook_t类型的内存空间, 并往g_rpchook_socket_fd中添加该内存空间的地址(指针指向的变量未全部初始化) */
int socket(int domain, int type, int protocol)
{
    // 重命名动态库中的socket系统调用
	HOOK_SYS_FUNC( socket );

    // 协程禁止hook系统调用, 则直接调用socket系统调用返回socket文件描述符fd
	if( !co_is_enable_sys_hook() )
	{
		return g_sys_socket_func( domain,type,protocol );
	}
    
    // 协程使用了hook, 则直接调用socket系统调用获取socket文件描述符fd
	int fd = g_sys_socket_func(domain,type,protocol);
	if( fd < 0 )
	{
		return fd;
	}

    // 为fd分配rpchook_t类型的内存空间, 其中存储套接字hook信息, 并将其加入套接字hook信息数组g_rpchook_socket_fd中
	rpchook_t *lp = alloc_by_fd( fd );
	lp->domain = domain;
	
    // 设置套接字fd属性
	fcntl( fd, F_SETFL, g_sys_fcntl_func(fd, F_GETFL,0 ) );

	return fd;
}

/* co_accpet - accpet系统调用的封装而已 */
int co_accept( int fd, struct sockaddr *addr, socklen_t *len )
{
	int cli = accept( fd,addr,len );
	if( cli < 0 )
	{
		return cli;
	}
	alloc_by_fd( cli );
	return cli;
}

/* connect - 被hook后的connect函数, 主要是初始化(g_rpchook_socket_fd中)套接字fd对应的rpchook_t类型变量的dest成员 */
int connect(int fd, const struct sockaddr *address, socklen_t address_len)
{
	HOOK_SYS_FUNC( connect );

	if( !co_is_enable_sys_hook() )
	{
		return g_sys_connect_func(fd,address,address_len);
	}

	//1.sys call
	int ret = g_sys_connect_func( fd,address,address_len );

	rpchook_t *lp = get_by_fd( fd );
	if( !lp ) return ret;

	if( sizeof(lp->dest) >= address_len )
	{
		 memcpy( &(lp->dest),address,(int)address_len );
	}
	if( O_NONBLOCK & lp->user_flag ) 
	{
		return ret;
	}
	
	if (!(ret < 0 && errno == EINPROGRESS))
	{
		return ret;
	}

	//2.wait
	int pollret = 0;
	struct pollfd pf = { 0 };

	for(int i=0;i<3;i++) //25s * 3 = 75s
	{
		memset( &pf,0,sizeof(pf) );
		pf.fd = fd;
		pf.events = ( POLLOUT | POLLERR | POLLHUP );

		pollret = poll( &pf,1,25000 );

		if( 1 == pollret  )
		{
			break;
		}
	}
	if( pf.revents & POLLOUT ) //connect succ
	{
		errno = 0;
		return 0;
	}

	//3.set errno
	int err = 0;
	socklen_t errlen = sizeof(err);
	getsockopt( fd,SOL_SOCKET,SO_ERROR,&err,&errlen);
	if( err ) 
	{
		errno = err;
	}
	else
	{
		errno = ETIMEDOUT;
	} 
	return ret;
}

/* close - 被hook后的close函数, 主要是释放(g_rpchook_socket_fd中)套接字fd对应的rpchook_t类型存储空间 */
int close(int fd)
{
	HOOK_SYS_FUNC( close );
	
    // 协程禁止hook系统调用, 则直接调用系统调用
	if( !co_is_enable_sys_hook() )
	{
		return g_sys_close_func( fd );
	}
    // 协程hook系统调用, 则释放(g_rpchook_socket_fd中)套接字fd对应的rpchook_t类型的存储空间
	free_by_fd( fd );
	int ret = g_sys_close_func(fd);

	return ret;
}

/* read - 被hook后的read函数, 主要是向内核注册套接字fd上的事件 */
ssize_t read( int fd, void *buf, size_t nbyte )
{
	HOOK_SYS_FUNC( read );
	
    // 协程禁止hook系统调用, 则直接调用系统调用
	if( !co_is_enable_sys_hook() )
	{
		return g_sys_read_func( fd,buf,nbyte );
	}
    // 协程hook系统调用, 根据套接字是否为非阻塞选择不同的处理方式
	rpchook_t *lp = get_by_fd( fd );

	if( !lp || ( O_NONBLOCK & lp->user_flag ) ) 
	{
		ssize_t ret = g_sys_read_func( fd,buf,nbyte );
		return ret;
	}
    
    // 阻塞, 向内核注册套接字fd的事件
    // poll如果未hook,则直接调用poll系统调用;
    // poll如果被hook,则调用co_poll向内核注册, co_poll中会切换协程, 协程被恢复时将会从co_poll中的挂起点继续运行
	int timeout = ( lp->read_timeout.tv_sec * 1000 ) 
				+ ( lp->read_timeout.tv_usec / 1000 );

	struct pollfd pf = { 0 };
	pf.fd = fd;
	pf.events = ( POLLIN | POLLERR | POLLHUP );

	int pollret = poll( &pf,1,timeout );

	ssize_t readret = g_sys_read_func( fd,(char*)buf ,nbyte );

	if( readret < 0 )
	{
		co_log_err("CO_ERR: read fd %d ret %ld errno %d poll ret %d timeout %d",
					fd,readret,errno,pollret,timeout);
	}

	return readret;
	
}

/* write - 被hook后的write函数, 主要是向内核注册套接字fd上的事件 */
ssize_t write( int fd, const void *buf, size_t nbyte )
{
	HOOK_SYS_FUNC( write );
    
	// 协程禁止hook系统调用, 则直接调用系统调用
	if( !co_is_enable_sys_hook() )
	{
		return g_sys_write_func( fd,buf,nbyte );
	}
    // 协程hook系统调用, 根据套接字是否为非阻塞选择不同的处理方式
	rpchook_t *lp = get_by_fd( fd );

    // 非阻塞, 直接调用系统调用
	if( !lp || ( O_NONBLOCK & lp->user_flag ) )
	{
		ssize_t ret = g_sys_write_func( fd,buf,nbyte );
		return ret;
	}
    
    // 阻塞, 向内核注册套接字fd的事件
    // poll如果未hook,则直接调用poll系统调用;
    // poll如果被hook,则调用co_poll向内核注册, co_poll中会切换协程, 协程被恢复时将会从co_poll中的挂起点继续运行
	size_t wrotelen = 0;
	int timeout = ( lp->write_timeout.tv_sec * 1000 ) 
				+ ( lp->write_timeout.tv_usec / 1000 );

	ssize_t writeret = g_sys_write_func( fd,(const char*)buf + wrotelen,nbyte - wrotelen );

	if (writeret == 0)
	{
		return writeret;
	}

	if( writeret > 0 )
	{
		wrotelen += writeret;	
	}
	while( wrotelen < nbyte )
	{
        // buf中的数据未全部写到fd上, 则向内核注册套接字fd的事件
		struct pollfd pf = { 0 };
		pf.fd = fd;
		pf.events = ( POLLOUT | POLLERR | POLLHUP );
		poll( &pf,1,timeout );

		writeret = g_sys_write_func( fd,(const char*)buf + wrotelen,nbyte - wrotelen );
		
		if( writeret <= 0 )
		{
			break;
		}
		wrotelen += writeret ;
	}
	if (writeret <= 0 && wrotelen == 0)
	{
		return writeret;
	}
	return wrotelen;
}

/* sendto - 被hook后的sendto函数, 主要是向内核注册套接字fd上的事件 */
ssize_t sendto(int socket, const void *message, size_t length,
	                 int flags, const struct sockaddr *dest_addr,
					               socklen_t dest_len)
{
	/*
		1.no enable sys call ? sys
		2.( !lp || lp is non block ) ? sys
		3.try
		4.wait
		5.try
	*/
	HOOK_SYS_FUNC( sendto );
	if( !co_is_enable_sys_hook() )
	{
		return g_sys_sendto_func( socket,message,length,flags,dest_addr,dest_len );
	}

	rpchook_t *lp = get_by_fd( socket );
	if( !lp || ( O_NONBLOCK & lp->user_flag ) )
	{
		return g_sys_sendto_func( socket,message,length,flags,dest_addr,dest_len );
	}

	ssize_t ret = g_sys_sendto_func( socket,message,length,flags,dest_addr,dest_len );
	if( ret < 0 && EAGAIN == errno )
	{
		int timeout = ( lp->write_timeout.tv_sec * 1000 ) 
					+ ( lp->write_timeout.tv_usec / 1000 );


		struct pollfd pf = { 0 };
		pf.fd = socket;
		pf.events = ( POLLOUT | POLLERR | POLLHUP );
		poll( &pf,1,timeout );

		ret = g_sys_sendto_func( socket,message,length,flags,dest_addr,dest_len );

	}
	return ret;
}

/* recvfrom - 被hook后的recvfrom函数, 主要是向内核注册套接字fd上的事件 */
ssize_t recvfrom(int socket, void *buffer, size_t length,
	                 int flags, struct sockaddr *address,
					               socklen_t *address_len)
{
	HOOK_SYS_FUNC( recvfrom );
	if( !co_is_enable_sys_hook() )
	{
		return g_sys_recvfrom_func( socket,buffer,length,flags,address,address_len );
	}

	rpchook_t *lp = get_by_fd( socket );
	if( !lp || ( O_NONBLOCK & lp->user_flag ) )
	{
		return g_sys_recvfrom_func( socket,buffer,length,flags,address,address_len );
	}

	int timeout = ( lp->read_timeout.tv_sec * 1000 ) 
				+ ( lp->read_timeout.tv_usec / 1000 );


	struct pollfd pf = { 0 };
	pf.fd = socket;
	pf.events = ( POLLIN | POLLERR | POLLHUP );
	poll( &pf,1,timeout );

	ssize_t ret = g_sys_recvfrom_func( socket,buffer,length,flags,address,address_len );
	return ret;
}

/* send - 被hook后的send函数, 主要是向内核注册套接字fd上的事件 */
ssize_t send(int socket, const void *buffer, size_t length, int flags)
{
	HOOK_SYS_FUNC( send );
	
	if( !co_is_enable_sys_hook() )
	{
		return g_sys_send_func( socket,buffer,length,flags );
	}
	rpchook_t *lp = get_by_fd( socket );

	if( !lp || ( O_NONBLOCK & lp->user_flag ) )
	{
		return g_sys_send_func( socket,buffer,length,flags );
	}
	size_t wrotelen = 0;
	int timeout = ( lp->write_timeout.tv_sec * 1000 ) 
				+ ( lp->write_timeout.tv_usec / 1000 );

	ssize_t writeret = g_sys_send_func( socket,buffer,length,flags );
	if (writeret == 0)
	{
		return writeret;
	}

	if( writeret > 0 )
	{
		wrotelen += writeret;	
	}
	while( wrotelen < length )
	{

		struct pollfd pf = { 0 };
		pf.fd = socket;
		pf.events = ( POLLOUT | POLLERR | POLLHUP );
		poll( &pf,1,timeout );

		writeret = g_sys_send_func( socket,(const char*)buffer + wrotelen,length - wrotelen,flags );
		
		if( writeret <= 0 )
		{
			break;
		}
		wrotelen += writeret ;
	}
	if (writeret <= 0 && wrotelen == 0)
	{
		return writeret;
	}
	return wrotelen;
}

/* recv - 被hook后的recv函数, 主要是向内核注册套接字fd上的事件 */
ssize_t recv( int socket, void *buffer, size_t length, int flags )
{
	HOOK_SYS_FUNC( recv );
	
	if( !co_is_enable_sys_hook() )
	{
		return g_sys_recv_func( socket,buffer,length,flags );
	}
	rpchook_t *lp = get_by_fd( socket );

	if( !lp || ( O_NONBLOCK & lp->user_flag ) ) 
	{
		return g_sys_recv_func( socket,buffer,length,flags );
	}
	int timeout = ( lp->read_timeout.tv_sec * 1000 ) 
				+ ( lp->read_timeout.tv_usec / 1000 );

	struct pollfd pf = { 0 };
	pf.fd = socket;
	pf.events = ( POLLIN | POLLERR | POLLHUP );

	int pollret = poll( &pf,1,timeout );

	ssize_t readret = g_sys_recv_func( socket,buffer,length,flags );

	if( readret < 0 )
	{
		co_log_err("CO_ERR: read fd %d ret %ld errno %d poll ret %d timeout %d",
					socket,readret,errno,pollret,timeout);
	}

	return readret;
	
}

extern int co_poll_inner( stCoEpoll_t *ctx,struct pollfd fds[], nfds_t nfds, int timeout, poll_pfn_t pollfunc);

int poll(struct pollfd fds[], nfds_t nfds, int timeout)
{

	HOOK_SYS_FUNC( poll );

	if( !co_is_enable_sys_hook() )
	{
		return g_sys_poll_func( fds,nfds,timeout );
	}

	return co_poll_inner( co_get_epoll_ct(),fds,nfds,timeout, g_sys_poll_func);

}

/* setsockopt - 被hook后的setsockopt函数, 主要是初始化(g_rpchook_socket_fd中)套接字fd对应的rpchook_t类型变量的read_timeout和write_timeout成员 */
int setsockopt(int fd, int level, int option_name,
			                 const void *option_value, socklen_t option_len)
{
	HOOK_SYS_FUNC( setsockopt );

	if( !co_is_enable_sys_hook() )
	{
		return g_sys_setsockopt_func( fd,level,option_name,option_value,option_len );
	}
	rpchook_t *lp = get_by_fd( fd );

	if( lp && SOL_SOCKET == level )
	{
		struct timeval *val = (struct timeval*)option_value;
		if( SO_RCVTIMEO == option_name  ) 
		{
			memcpy( &lp->read_timeout,val,sizeof(*val) );
		}
		else if( SO_SNDTIMEO == option_name )
		{
			memcpy( &lp->write_timeout,val,sizeof(*val) );
		}
	}
	return g_sys_setsockopt_func( fd,level,option_name,option_value,option_len );
}

/* fcntl - 被hook后的fcntl函数, 主要是初始化(g_rpchook_socket_fd中)套接字fd对应的rpchook_t类型变量的user_flag成员 */
int fcntl(int fildes, int cmd, ...)
{
	HOOK_SYS_FUNC( fcntl );

	if( fildes < 0 )
	{
		return __LINE__;
	}

	va_list arg_list;
	va_start( arg_list,cmd );

	int ret = -1;
	rpchook_t *lp = get_by_fd( fildes );
	switch( cmd )
	{
		case F_DUPFD:
		{
			int param = va_arg(arg_list,int);
			ret = g_sys_fcntl_func( fildes,cmd,param );
			break;
		}
		case F_GETFD:
		{
			ret = g_sys_fcntl_func( fildes,cmd );
			break;
		}
		case F_SETFD:
		{
			int param = va_arg(arg_list,int);
			ret = g_sys_fcntl_func( fildes,cmd,param );
			break;
		}
		case F_GETFL:
		{
			ret = g_sys_fcntl_func( fildes,cmd );
			break;
		}
		case F_SETFL:
		{
			int param = va_arg(arg_list,int);
			int flag = param;
			if( co_is_enable_sys_hook() && lp )
			{
				flag |= O_NONBLOCK;
			}
			ret = g_sys_fcntl_func( fildes,cmd,flag );
			if( 0 == ret && lp )
			{
				lp->user_flag = param;
			}
			break;
		}
		case F_GETOWN:
		{
			ret = g_sys_fcntl_func( fildes,cmd );
			break;
		}
		case F_SETOWN:
		{
			int param = va_arg(arg_list,int);
			ret = g_sys_fcntl_func( fildes,cmd,param );
			break;
		}
		case F_GETLK:
		{
			struct flock *param = va_arg(arg_list,struct flock *);
			ret = g_sys_fcntl_func( fildes,cmd,param );
			break;
		}
		case F_SETLK:
		{
			struct flock *param = va_arg(arg_list,struct flock *);
			ret = g_sys_fcntl_func( fildes,cmd,param );
			break;
		}
		case F_SETLKW:
		{
			struct flock *param = va_arg(arg_list,struct flock *);
			ret = g_sys_fcntl_func( fildes,cmd,param );
			break;
		}
	}

	va_end( arg_list );

	return ret;
}

struct stCoSysEnv_t
{
	char *name;	
	char *value;
};
struct stCoSysEnvArr_t
{
	stCoSysEnv_t *data;
	size_t cnt;
};
static stCoSysEnvArr_t *dup_co_sysenv_arr( stCoSysEnvArr_t * arr )
{
	stCoSysEnvArr_t *lp = (stCoSysEnvArr_t*)calloc( sizeof(stCoSysEnvArr_t),1 );	
	if( arr->cnt )
	{
		lp->data = (stCoSysEnv_t*)calloc( sizeof(stCoSysEnv_t) * arr->cnt,1 );
		lp->cnt = arr->cnt;
		memcpy( lp->data,arr->data,sizeof( stCoSysEnv_t ) * arr->cnt );
	}
	return lp;
}

static int co_sysenv_comp(const void *a, const void *b)
{
	return strcmp(((stCoSysEnv_t*)a)->name, ((stCoSysEnv_t*)b)->name); 
}
static stCoSysEnvArr_t g_co_sysenv = { 0 };


  
void co_set_env_list( const char *name[],size_t cnt)
{
	if( g_co_sysenv.data )
	{
		return ;
	}
	g_co_sysenv.data = (stCoSysEnv_t*)calloc( 1,sizeof(stCoSysEnv_t) * cnt  );

	for(size_t i=0;i<cnt;i++)
	{
		if( name[i] && name[i][0] )
		{
			g_co_sysenv.data[ g_co_sysenv.cnt++ ].name = strdup( name[i] );
		}
	}
	if( g_co_sysenv.cnt > 1 )
	{
		qsort( g_co_sysenv.data,g_co_sysenv.cnt,sizeof(stCoSysEnv_t),co_sysenv_comp );
		stCoSysEnv_t *lp = g_co_sysenv.data;
		stCoSysEnv_t *lq = g_co_sysenv.data + 1;
		for(size_t i=1;i<g_co_sysenv.cnt;i++)
		{
			if( strcmp( lp->name,lq->name ) )
			{
				++lp;
				if( lq != lp  )
				{
					*lp = *lq;
				}
			}
			++lq;
		}
		g_co_sysenv.cnt = lp - g_co_sysenv.data + 1;
	}

}

int setenv(const char *n, const char *value, int overwrite)
{
	HOOK_SYS_FUNC( setenv )
	if( co_is_enable_sys_hook() && g_co_sysenv.data )
	{
		stCoRoutine_t *self = co_self();
		if( self )
		{
			if( !self->pvEnv )
			{
				self->pvEnv = dup_co_sysenv_arr( &g_co_sysenv );
			}
			stCoSysEnvArr_t *arr = (stCoSysEnvArr_t*)(self->pvEnv);

			stCoSysEnv_t name = { (char*)n,0 };

			stCoSysEnv_t *e = (stCoSysEnv_t*)bsearch( &name,arr->data,arr->cnt,sizeof(name),co_sysenv_comp );

			if( e )
			{
				if( overwrite || !e->value  )
				{
					if( e->value ) free( e->value );
					e->value = ( value ? strdup( value ) : 0 );
				}
				return 0;
			}
		}

	}
	return g_sys_setenv_func( n,value,overwrite );
}
int unsetenv(const char *n)
{
	HOOK_SYS_FUNC( unsetenv )
	if( co_is_enable_sys_hook() && g_co_sysenv.data )
	{
		stCoRoutine_t *self = co_self();
		if( self )
		{
			if( !self->pvEnv )
			{
				self->pvEnv = dup_co_sysenv_arr( &g_co_sysenv );
			}
			stCoSysEnvArr_t *arr = (stCoSysEnvArr_t*)(self->pvEnv);

			stCoSysEnv_t name = { (char*)n,0 };

			stCoSysEnv_t *e = (stCoSysEnv_t*)bsearch( &name,arr->data,arr->cnt,sizeof(name),co_sysenv_comp );

			if( e )
			{
				if( e->value )
				{
					free( e->value );
					e->value = 0;
				}
				return 0;
			}
		}

	}
	return g_sys_unsetenv_func( n );
}
char *getenv( const char *n )
{
	HOOK_SYS_FUNC( getenv )
	if( co_is_enable_sys_hook() && g_co_sysenv.data )
	{
		stCoRoutine_t *self = co_self();

		stCoSysEnv_t name = { (char*)n,0 };

		if( !self->pvEnv )
		{
			self->pvEnv = dup_co_sysenv_arr( &g_co_sysenv );
		}
		stCoSysEnvArr_t *arr = (stCoSysEnvArr_t*)(self->pvEnv);

		stCoSysEnv_t *e = (stCoSysEnv_t*)bsearch( &name,arr->data,arr->cnt,sizeof(name),co_sysenv_comp );

		if( e )
		{
			return e->value;
		}

	}
	return g_sys_getenv_func( n );

}
struct hostent* co_gethostbyname(const char *name);

struct hostent *gethostbyname(const char *name)
{
	HOOK_SYS_FUNC( gethostbyname );

#ifdef __APPLE__
	return g_sys_gethostbyname_func( name );
#else
	if (!co_is_enable_sys_hook())
	{
		return g_sys_gethostbyname_func(name);
	}
	return co_gethostbyname(name);
#endif

}


struct res_state_wrap
{
	struct __res_state state;
};
CO_ROUTINE_SPECIFIC(res_state_wrap, __co_state_wrap);

extern "C"
{
	res_state __res_state() 
	{
		HOOK_SYS_FUNC(__res_state);

		if (!co_is_enable_sys_hook()) 
		{
			return g_sys___res_state_func();
		}

		return &(__co_state_wrap->state);
	}
	int __poll(struct pollfd fds[], nfds_t nfds, int timeout)
	{
		return poll(fds, nfds, timeout);
	}
}

struct hostbuf_wrap 
{
	struct hostent host;
	char* buffer;
	size_t iBufferSize;
	int host_errno;
};

CO_ROUTINE_SPECIFIC(hostbuf_wrap, __co_hostbuf_wrap);

#ifndef __APPLE__
struct hostent *co_gethostbyname(const char *name)
{
	if (!name)
	{
		return NULL;
	}

	if (__co_hostbuf_wrap->buffer && __co_hostbuf_wrap->iBufferSize > 1024)
	{
		free(__co_hostbuf_wrap->buffer);
		__co_hostbuf_wrap->buffer = NULL;
	}
	if (!__co_hostbuf_wrap->buffer)
	{
		__co_hostbuf_wrap->buffer = (char*)malloc(1024);
		__co_hostbuf_wrap->iBufferSize = 1024;
	}

	struct hostent *host = &__co_hostbuf_wrap->host;
	struct hostent *result = NULL;
	int *h_errnop = &(__co_hostbuf_wrap->host_errno);

	int ret = -1;
	while (ret = gethostbyname_r(name, host, __co_hostbuf_wrap->buffer, 
				__co_hostbuf_wrap->iBufferSize, &result, h_errnop) == ERANGE && 
				*h_errnop == NETDB_INTERNAL )
	{
		free(__co_hostbuf_wrap->buffer);
		__co_hostbuf_wrap->iBufferSize = __co_hostbuf_wrap->iBufferSize * 2;
		__co_hostbuf_wrap->buffer = (char*)malloc(__co_hostbuf_wrap->iBufferSize);
	}

	if (ret == 0 && (host == result)) 
	{
		return host;
	}
	return NULL;
}
#endif

/* co_enable_hook_sys - 设置当前线程中正在运行的协程中使用hook系统调用*/
void co_enable_hook_sys() //这函数必须写在这里,否则本文件会被忽略!!!
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( co )
	{
		co->cEnableSysHook = 1;
	}
}

