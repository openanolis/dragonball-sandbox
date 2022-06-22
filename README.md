本开发分支为阿里巴巴编程之夏 轻量虚拟机任务 的临时分支。

## 任务目标
【必选】将dragonball-sandbox组件和rust-vmm组件组合，搭建出一个简易的轻量虚拟机。
【可选】参与到Kata3.0 Dragonball VMM侧的开源建设工作
## 任务拆解
### [必选] 简易轻量虚拟机任务
基于上游社区的guest kernel和rootfs（任务开始后由导师提供），以及dragonball-sandbox、rust-vmm组件，搭建出一个简易的轻量虚拟机。
任务开始后，将在dragonball-sandbox内新建开源之夏相关分支，导师会给到代码大致框架，并且会按阶段分配任务，每个阶段都需将写的代码和文档上传到相应开发分支，最终可启动一个虚拟机并可以运行基础命令即算任务成功。
需要实现的主要模块：
● CPU虚拟化（会涉及的依赖库： dbs-boot， dbs-arch）,
  ○ 基于KVM完成虚拟机对CPU虚拟化的基础支持。
● 内存虚拟化（会涉及的依赖库：vm-memory, dbs-address-space)
  ○ 包含一个address space manager来做地址空间管理
●  API Server（需要自建）
  ○ 支持通过API的方式传入vm config(例如，cpu个数、内存大小等信息) 来做系统启动、关闭等操作
● Block Device Manager (会涉及的依赖库： dbs_virtio_devices)
  ○ 用于支持rootfs加载
● guest kernel加载模块（会涉及的依赖库： linux loader）
● console manager（会涉及的依赖库：dbs_legacy_devices)
  ○ 用于进行命令行互动
● epoll event manager（会涉及的依赖库：dbs_utils::epoll_manager）
  ○ 用于处理epoll事件，用于处理API请求以及关闭虚拟机等操作

### [可选] Kata社区开源建设工作
Dragonball也正在积极向Kata社区开源的过程中，可以有两个角度参与到社区实际的建设：
1. Dragonball相关patch会有来自社区reviewer的修改建议，如若是不紧急的可以参与一起改进。
2. Dragonball会有许多来自社区的issue，可以选择力所能及的issue加入到社区的工作。