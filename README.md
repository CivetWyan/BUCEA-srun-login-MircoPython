# BUCEA-srun-login-MircoPython
北京建筑大学深澜校园网MircoPython登录脚本
基于https://github.com/coffeehat/BIT-srun-login-script 适配

原作者fork自（目前404了）：https://coding.net/u/huxiaofan1223/p/jxnu_srun/git

通过修改登陆地址和ip地址读取方法，适配了北京建筑大学2021年3月的校园网登录页面。

另有支持多平台（包括openwrt）的golang版本，请见：https://github.com/Mmx233/BitSrunLoginGo （适用于北京理工大学，尚未适配北京建筑大学）

如果校园网有变动，欢迎及时反馈。如果你有好的解决方案，也欢迎提个pr。非常感谢~~ o(*￣▽￣*)ブ

本版本来自：https://github.com/SudoShutdownNow/BUCEA-srun-login-script

实现单片机可用的版本目前测试在RP2040、ESP32-S2-C3的mircopython上可正常运行，其他单片机未做测试，大家可以积极帮忙测试下能否在其他单片机上运行。

# 概述

北京建筑大学深澜校园网登录mircopython脚本，可用于任何支持mircopython的设备使用来登录。

有关原理，详细文档见：[深澜校园网登录的分析与python实现-北京理工大学版](https://zhuanlan.zhihu.com/p/122556315)



# 文件说明

|文件|说明|
|:-:|:-:|
LoginManager.py 代码及库封装位置
main.py 运行示例

