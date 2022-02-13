# 护卫盾破解补丁

作者:荒陌 [学习讨论群聊](https://jq.qq.com/?_wv=1027&k=tyB55yFf)

此项目内只默认写了对一款GTA5菜单(XiPro)的破解

## 优点:
1. 修复了VMP壳的内存保护
2. 不会受到hwd.dll的更新或者其他程序的更新而挂钩失败

---
## 包含库:
- MinHook(函数挂钩)
- Cryptopp(数据加密解密,暂未应用到项目中)
---

## 原理:
1. 修改内存保护(VirtualProtect AGE_EXECUTE_READWRITE)
2. 修补因加VMP壳导致的无法挂钩函数(因为VMP壳挂钩了NtProtectVirtualMemory函数,复原为4C 8B D1 B8 50即可)
3. 挂钩hwd.dll的导出函数
4. 伪造正常登录时的返回值和伪造各种buffer的数据操作
5. 享受
---

