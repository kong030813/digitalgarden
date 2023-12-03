---
{"dg-publish":true,"permalink":"/hack/开发&代审/代审/JAVA/经典反序列化漏洞解析/shiro反序列化漏洞分析/"}
---

### **环境配置**
idea+tomcat9+jdk1.8+shiro示例代码
下载：https://github.com/apache/shiro/releases
示例代码位置
![](https://s2.loli.net/2023/12/02/KQ1fSBulomzVOr9.png)
在idea打开并添加版本（不然会报500错误）
![](https://s2.loli.net/2023/12/02/JOtpoUTV15GvabX.png)
启动服务成功搭建好环境
![](https://s2.loli.net/2023/12/02/vOg5MPW8FtEQi4n.png)
### **shiro**
#### 介绍:
Apache Shiro 是Java 的一个安全框架。Shiro 可以非常容易的开发出足够好的应用，其不仅可以用在JavaSE 环境，也可以用在JavaEE 环境。Shiro 可以帮助我们完成：认证、授权、加密、会话管理、与Web 集成、缓存等。
简单地说就是一个身份权限验证组件
#### 特征：
cookie中带有rememberme=字段
![Pasted image 20231202232920.png](/img/user/note/%E9%99%84%E4%BB%B6/Pasted%20image%2020231202232920.png)
### **shiro反序列化漏洞分析**
#### 漏洞原理：
<font color="#ff0000">客户端：恶意序列化payload-->AES加密-->BASE64编码-->通过cookie中的rememberme字段传入</font>
<font color="#ff0000">服务端：接受到cookie中的rememberme字段数据-->BASE64解码-->AES解密-->反序列化恶意payload</font>
在整个过程中比较关键的条件就是AES加密需要知道服务端硬编码的密钥key，我们可以通过爆破等方式来获取key从而
#### 寻找漏洞点代码位置
这里以反序列化代码审计搜索readObject()方法入手
![](https://s2.loli.net/2023/12/03/plSJ3at8OwGXV7n.png)
找到了DefaultSerializer.java文件中的deserialize方法（注解如下）：

```java
public T deserialize(byte[] serialized) throws SerializationException {
    // 检查传入的字节数组是否为null
    if (serialized == null) {
        String msg = "参数不能为null。";
        throw new IllegalArgumentException(msg);
    }
    
    // 创建一个ByteArrayInputStream，将字节数组包装成输入流
    ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
    
    // 创建一个BufferedInputStream，提高读取性能
    BufferedInputStream bis = new BufferedInputStream(bais);
    
    try {
        // 创建一个ObjectInputStream，用于从输入流中读取对象
        ObjectInputStream ois = new ClassResolvingObjectInputStream(bis);
        
        // 使用ObjectInputStream读取对象，并进行类型转换（泛型T）
        @SuppressWarnings({"unchecked"})
        T deserialized = (T) ois.readObject();
        
        // 关闭ObjectInputStream
        ois.close();
        
        // 返回反序列化后的对象
        return deserialized;
    } catch (Exception e) {
        // 捕获异常，如果发生异常则抛出SerializationException
        String msg = "无法反序列化参数字节数组。";
        throw new SerializationException(msg, e);
    }
}
```
跟踪到AbstractRememberMeManager.java中的convertBytesToPrincipals方法调用了deserialize
![](https://s2.loli.net/2023/12/03/Uqjb92tdToLAwcS.png)
代码注解
```java
protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
    // 检查是否配置了 CipherService（加密服务）
    if (getCipherService() != null) {
        // 如果配置了加密服务，则对字节数组进行解密
        bytes = decrypt(bytes);
    }

    // 调用 deserialize 方法将字节数组反序列化为 PrincipalCollection 对象
    return deserialize(bytes);
}
```
#### 跟踪漏洞点传入的参数是否为用户可控
继续跟进看看bytes是否可控
同文件下的getRememberedPrincipals方法定义了bytes然后调用convertBytesToPrincipals方法给bytes解密
![](https://s2.loli.net/2023/12/03/fnAgMpDwCHtbO8Y.png)
DefaultSecurityManager.java文件中的getRememberedIdentity方法调用了getRememberedPrincipals
![](https://s2.loli.net/2023/12/03/OXJinuaxNfCWe7z.png)
继续跟进 同文件下的resolvePrincipals方法调用了getRememberedIdentity
![](https://s2.loli.net/2023/12/03/jKl7FqJteyZa3dp.png)
同文件下的createSubject方法调用了resolvePrincipals
![](https://s2.loli.net/2023/12/03/jVMwJs7rGoue5QB.png)
同文件下的login方法调用了createSubject
![](https://s2.loli.net/2023/12/03/gZr6ompdAl8HPF5.png)
传入了token, info, subject
继续跟进login方法
并没有搜索到哪里调用了login方法传参了
![](https://s2.loli.net/2023/12/03/6DxLPCmyhQF3Ifk.png)
由方法名可推测，登录处肯定是会调用该方法，采用断点动态调试功能跟踪
![](https://s2.loli.net/2023/12/03/P3FhXVntRr5ZT8A.png)
输入测试用的账号密码点击登录
![](https://s2.loli.net/2023/12/03/EOBvnMCj92D1Pwf.png)
成功断下来了，可以看到token是我们输入的账号密码等等参数值
![](https://s2.loli.net/2023/12/03/jPIH9oyZFmO7V5R.png)
接下来逆着往回走看看token和subject是从哪里传入的
![](https://s2.loli.net/2023/12/03/CgFefsBVXbovQTD.png)
继续步出
从动态调试可以看到是AuthenticatingFilter类中的executelogin方法调用了login
![](https://s2.loli.net/2023/12/03/SJsKIDPzfMqXA6U.png)
之前为什么没搜到呢，查看该文件路径，发现和之前搜索路径有出入
![](https://s2.loli.net/2023/12/03/zyJY7faGiOlK1NZ.png)
![](https://s2.loli.net/2023/12/03/lMDXKPhRSkFcA6d.png)
我们采用动态调试的方法找到了该文件，阅读该方法代码
可以看到token是从createToken方法中得到的，继续跟踪createToken方法
![](https://s2.loli.net/2023/12/03/H6lQYcz4KWAuhdy.png)
到这里我们终于跟踪到了反序列化对象在哪里传入，并且是参数可以由我们控制的，可以构造恶意的序列化payload传入即可造成反序列化漏洞
#### 总结图
![](https://s2.loli.net/2023/12/03/lgoDrZUpi16uR3P.png)

### 构造恶意的序列化payload
#### 构造前提
在我们跟踪传入的参数的时候发现，该参数经过了很多方法的处理，其中包括比较敏感的decrypt（解密）等方法，那我们构造payload时必然要用加密函数处理才能将正确的序列化payload传入deserialize方法。
#### 寻找加密函数
我们在跟踪漏洞点的时候可以看到decrypt方法上面就有一个encrypt方法
![](https://s2.loli.net/2023/12/03/6OY7WTBnQ4VdfaP.png)

最简单的判断加密方式的方法：
在此下断点，动态调试，看看在加密的时候都传入了什么参数进而来判断加密方式
![](https://s2.loli.net/2023/12/03/XkEJGOZntBQ9m3L.png)
由名称（密码服务）和稍微了解过密码学的应该可以一眼丁真看出是AES加密的cbc模式。
根据密码学知识
我们对payload进行aes加密然后让服务端正常解密的话，需要知道AES的密钥(key)这个是硬编码在代码中的，我们在动态调试的参数中也能看到
![](https://s2.loli.net/2023/12/03/UZC3bdnXGmS4TrV.png)
但是这个key是以字节数组的形式，我们写个脚本转换为真正的key：kPH+bIxk5D2deZiIxcaaaA==
![](https://s2.loli.net/2023/12/03/VGhKm2CZMrBqifw.png)
当然我们也可以跟踪代码在代码中找到硬编码的key
![](https://s2.loli.net/2023/12/03/nDrFbBqI3thTvN8.png)
这样我们就解决了加密
#### base64解码方法
跟踪的过程中还有一个敏感方法处理了参数
![](https://s2.loli.net/2023/12/03/nx8XwLpBdE6uGZW.png)
跟进这个方法可以看到是对cookie中的rememberme值做了base64解码
![](https://s2.loli.net/2023/12/03/G6S8f4eCB9wcs2r.png)
那我们构造payload就要进行base64编码
#### 整个流程
那么整个流程就很清晰了
<font color="#ff0000">客户端：恶意序列化payload-->AES加密-->BASE64编码-->通过cookie中的rememberme字段传入</font>
<font color="#ff0000">服务端：接受到cookie中的rememberme字段数据-->BASE64解码-->AES解密-->反序列化恶意payload</font>
