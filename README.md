 # sparkbomb

 **这是一款python多线程爆破程序**

### 目的
 写这个程序的主要目的在于burpsuite爆破的两个缺点
 1. 虽然它支持四种方式爆破，但是它没法混合爆破。也就是不能将多个参数分不同的爆破方式来爆破
 2. 在现在许多cms中，会对你的ip进行封锁，但是我们可以通过`client-ip`或者`x-forworded-for`来进行绕过，因此我们可能会需要爆破的时候生成随机x-forworded-for来绕过它的机制

## 环境
* python3.* (python2搞不好也能运行)
* python的各种库

## 输入
像burpsuite一样输入一个http请求文本即可，然后以{cluster[]}来指定笛卡尔积爆破的参数，以{pitchfork}来指定鱼叉参数

## 特点
* 采用socket而不是request库，这样得到最原始的返回响应，但是对于重定向就比较无助
* 
