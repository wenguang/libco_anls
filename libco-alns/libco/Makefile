#
# Tencent is pleased to support the open source community by making Libco available.
# 
# Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, 
# software distributed under the License is distributed on an "AS IS" BASIS, 
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
# See the License for the specific language governing permissions and 
# limitations under the License.
#


COMM_MAKE = 1
COMM_ECHO = 1
version=0.5
v=debug
## 引入co.mk文件
include co.mk

########## 编译选项 ##########
#### 编译参数参考：http://www.cnblogs.com/zhangsir6/articles/2956798.html
#### GCC中文手册：https://github.com/wenguang/startup/blob/master/GCC%20%E4%B8%AD%E6%96%87%E6%89%8B%E5%86%8C.pdf 
CFLAGS += -g -fno-strict-aliasing -O2 -Wall -export-dynamic \
	-Wall -pipe  -D_GNU_SOURCE -D_REENTRANT -fPIC -Wno-deprecated -m64

#### 链接阶段的参数，在./lib目录下搜索colib pthread dl 且链接库
LINKS += -g -L./lib -lcolib -lpthread -ldl 

####
COLIB_OBJS=co_epoll.o co_routine.o co_hook_sys_call.o coctx_swap.o coctx.o
#co_swapcontext.o

PROGS = colib example_poll example_echosvr example_echocli example_thread  example_cond example_specific example_copystack example_closure

all:$(PROGS)

colib:libcolib.a libcolib.so

libcolib.a: $(COLIB_OBJS)
	$(ARSTATICLIB) 
libcolib.so: $(COLIB_OBJS)
	$(BUILDSHARELIB)


### BUILDEXE 变量定义在co.mk文件中 BUILDEXE = $(CPP) $(BFLAGS) -o $@ $^ $(LINKS)
example_echosvr:example_echosvr.o
	$(BUILDEXE) 
example_echocli:example_echocli.o
	$(BUILDEXE) 
example_thread:example_thread.o
	$(BUILDEXE) 
example_poll:example_poll.o
	$(BUILDEXE) 
example_exit:example_exit.o
	$(BUILDEXE) 
example_cond:example_cond.o
	$(BUILDEXE)
example_specific:example_specific.o
	$(BUILDEXE)
example_copystack:example_copystack.o
	$(BUILDEXE)
example_setenv:example_setenv.o
	$(BUILDEXE)
example_closure:example_closure.o
	$(BUILDEXE)

dist: clean libco-$(version).src.tar.gz

libco-$(version).src.tar.gz:
	@find . -type f | grep -v CVS | grep -v .svn | sed s:^./:libco-$(version)/: > MANIFEST
	@(cd ..; ln -s libco_pub libco-$(version))
	(cd ..; tar cvf - `cat libco_pub/MANIFEST` | gzip > libco_pub/libco-$(version).src.tar.gz)
	@(cd ..; rm libco-$(version))

clean:
	$(CLEAN) *.o $(PROGS)
	rm -fr MANIFEST lib solib libco-$(version).src.tar.gz libco-$(version)

