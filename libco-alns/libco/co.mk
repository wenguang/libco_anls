#
# Tencent is pleased to support the open source community by making Libco available.
#
# Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, 
# software distributed under the License is distributed on an "AS IS" BASIS, 
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
# See the License for the specific language governing permissions and 
# limitations under the License.
#

### 参考 Make 命令教程：http://www.ruanyifeng.com/blog/2015/02/make.html


##### Makefile Rules ##########
MAIL_ROOT=.
SRCROOT=.

## 定义编译器 g++ gcc 分别是GNU的c & c++编译器，ar 创建静态库.a文件
CPP = g++
CC  = gcc
AR = ar -rc
RANLIB = ranlib

CPPSHARE = $(CPP) -fPIC -shared -O2 -pipe -L$(SRCROOT)/solib/ -o 
CSHARE = $(CC) -fPIC -shared -O2 -pipe -L$(SRCROOT)/solib/ -o 

## 判断 如果$v等于release
ifeq ($v,release)
CFLAGS= -O2 $(INCLS) -fPIC  -DLINUX -pipe -Wno-deprecated -c
else
CFLAGS= -g $(INCLS) -fPIC -DLINUX -pipe -c -fno-inline
endif

## 判断 如果$v不等于release
ifneq ($v,release)
BFLAGS= -g
endif

STATICLIBPATH=$(SRCROOT)/lib
DYNAMICLIBPATH=$(SRCROOT)/solib

INCLS += -I$(SRCROOT)

## default links
ifeq ($(LINKS_DYNAMIC), 1)
LINKS += -L$(DYNAMICLIBPATH) -L$(STATICLIBPATH)
else
LINKS += -L$(STATICLIBPATH)
endif

### 函数格式
## $(function arguments)
#   或者
## ${function arguments}

## wildcard函数：扩展通配符，把所有相关后缀文件全部展开
## 因为在变量的定义和函数引用时，通配符将失效，就需要使用函数“wildcard”
## 参考：http://blog.csdn.net/liangkaiming/article/details/6267357
## $(wildcard *.cpp)：指代当前目录下所有cpp文件
CPPSRCS  = $(wildcard *.cpp)
CSRCS  = $(wildcard *.c)

## patsubst函数：替换通配符，参考：http://blog.csdn.net/liangkaiming/article/details/6267357
## $(patsubst %.cpp,%.o,$(CPPSRCS))：把变量$(CPPSRCS)中的后缀.cpp替换为.o
## 以下是定义C/C++的.o文件
CPPOBJS  = $(patsubst %.cpp,%.o,$(CPPSRCS))
COBJS  = $(patsubst %.c,%.o,$(CSRCS))

SRCS = $(CPPSRCS) $(CSRCS)
OBJS = $(CPPOBJS) $(COBJS)

## 定义编译指令及参数
CPPCOMPI=$(CPP) $(CFLAGS) -Wno-deprecated
CCCOMPI=$(CC) $(CFLAGS)


## 自动变量 $@：指代当前目标，$^：指代所有前置条件
BUILDEXE = $(CPP) $(BFLAGS) -o $@ $^ $(LINKS)
CLEAN = rm -f *.o 

## 自动变量 $<：指代第一个前置条件
## 以下是定义完整编译命令
CPPCOMPILE = $(CPPCOMPI) $< $(FLAGS) $(INCLS) $(MTOOL_INCL) -o $@
CCCOMPILE = $(CCCOMPI) $< $(FLAGS) $(INCLS) $(MTOOL_INCL) -o $@

ARSTATICLIB = $(AR) $@.tmp $^ $(AR_FLAGS); \
			  if [ $$? -ne 0 ]; then exit 1; fi; \
			  test -d $(STATICLIBPATH) || mkdir -p $(STATICLIBPATH); \
			  mv -f $@.tmp $(STATICLIBPATH)/$@;

BUILDSHARELIB = $(CPPSHARE) $@.tmp $^ $(BS_FLAGS); \
				if [ $$? -ne 0 ]; then exit 1; fi; \
				test -d $(DYNAMICLIBPATH) || mkdir -p $(DYNAMICLIBPATH); \
				mv -f $@.tmp $(DYNAMICLIBPATH)/$@;

## 执行规则
.cpp.o:
	$(CPPCOMPILE)
.c.o:
	$(CCCOMPILE)
