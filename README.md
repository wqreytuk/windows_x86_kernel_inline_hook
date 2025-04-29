# 示例

hook ntopenfile

```
-hba 0029a411 -hea 0029a41b -rba '' -mn nt -pn x86kh -comment "break before calling iofcalldriver at IopParseDevice"
```

x86不同于x64，除了thiscall用了ecx传递第一个参数，其余的调用方式都是通过esp传递参数的，所以基本上用不上-rba选项

如下图所示，eax就是hook位置的esp原始值，在hookhandler中，需要使用a1来访问被hook的函数的参数

![image](https://github.com/user-attachments/assets/90025098-df00-4c73-a0d2-390cf96eebfb)

`[esp+4]`就是第一个参数，+8是第二个参数，依次类推


# 2025-04-29更新  扩大handler调用前的保留栈空间   解决随机BSOD问题

![image](https://github.com/user-attachments/assets/d7bd3f62-2f0a-4063-99b7-0be76f4d56f8)
