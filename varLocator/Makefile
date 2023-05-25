

CXX = g++
LD = g++

SRCS = $(wildcard *.cpp)

OBJS = $(patsubst %cpp, %o, $(SRCS))

CXXFLAGS = -O2 -g -ldwarf -fsanitize=leak

# 可执行文件的名字
TARGET = varLocator

.PHONY:all clean

all: $(TARGET)

# 第一行依赖关系：冒号后面为依赖的文件，相当于Hello: main.o a.o b.o
# 第二行规则：$@表示目标文件，$^表示所有依赖文件，$<表示第一个依赖文件
$(TARGET): $(OBJS)
	$(LD) -o $@ $^ -ldwarf

# 上一句目标文件依赖一大堆.o文件，这句表示所有.o都由相应名字的.c文件自动生成
%.o:%.cpp
	$(CXX) -c $^ $(CXXFLAGS) -I./thirdparty/nlohmann

# make clean删除所有.o和目标文件
clean:
	rm -f $(OBJS) $(TARGET)
