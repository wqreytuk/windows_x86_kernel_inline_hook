# 示例

hook ntopenfile

```
-hba 0029a411 -hea 0029a41b -rba '' -mn nt -pn x86kh -comment "break before calling iofcalldriver at IopParseDevice"
```

hook handler的calling convention为fastcall，如下图所示

![image](https://github.com/user-attachments/assets/43a11884-6e0f-46fe-bf22-6606ee1ee9fa)

在rba选项中，我们可以最多传送两个寄存器进去，通过ecx和edx传输给hook handler，原始的ebp和esp值为固定的a3和a4，如果还需要其他的寄存器，我后面再更新

如果我们hook的是一个函数的开始部分，比如说nt!NtCreateUserProcess，该函数有11个参数，那么我们获取每一个参数的方式就是

```c
b4 esp=a4;
b4 p1 = d(esp+1*4);
b4 p2 = d(esp+2*4);
...
```

也就是说获取第几个参数，就是用参数的inex*4+esp取值即可


# 2025-04-29更新  扩大handler调用前的保留栈空间   解决随机BSOD问题

![image](https://github.com/user-attachments/assets/d7bd3f62-2f0a-4063-99b7-0be76f4d56f8)
