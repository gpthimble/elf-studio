// mul_demo.c

// 1. 定义全局变量：链接时会被全局指针（gp）相对寻址优化，从而触发松弛化
int global_factor = 35;

int test_calc(int val) {
    // 2. 软件乘法：rv32i 下编译器会调用 __mulsi3
    int res = val * global_factor;

    // 3. 内部条件跳转（局部跳转）：用于观察松弛化带来的整体地址平移
    if (res > 500) {
        res += 100;
    } else {
        res -= 100;
    }

    return res;
}
