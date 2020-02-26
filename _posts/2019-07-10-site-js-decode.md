---
layout:     post
title:      "某站点登录算法解析"
subtitle:   "某站点登录算法解析"
date:       2019-07-10 12:00:00
author:     "T-bag"
header-img: "img/post-bg-unix-linux.jpg"
header-mask: 0.3
catalog:    true
tags:
    - 前端
    - JS解密
---

### 前言

之前看过一些登录协议的分析，但都没有找到容易上手的站点，实地操作下。这里把最近分析的一个站点的登录协议分析过程记录一下。

## 目标

后台登录界面如下。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F0fa6d889-ef84-4e45-84bc-fd53b256f66e%2FUntitled.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F0fa6d889-ef84-4e45-84bc-fd53b256f66e%2FUntitled.png)

选择密码登录，随便填入账号密码，使用burp进行抓包，简单分析，站点应该在前端对用户名和密码进行了加密，然后请求后端进行判断。该登录算法也就是我们此次要分析的目标了。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F6d772a78-0775-4f1a-84af-c4b77ae99966%2FUntitled.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F6d772a78-0775-4f1a-84af-c4b77ae99966%2FUntitled.png)

错误的话则返回用户名或密码错误。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F78ec0ee1-0af2-4ef5-aa86-9b0d7eb5993a%2FUntitled.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F78ec0ee1-0af2-4ef5-aa86-9b0d7eb5993a%2FUntitled.png)

## 登录分析

在控制台上查看Network，过滤出XHR请求，很容易定位到前面burp抓包到的登录点，并且可以确认这是前端发出的XHR请求，记录下URL `https://platform-user-center.inboyu.com/account/login?r=6983562843299285`。有用

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F669d0b00-bb5e-4555-a812-4daaa38475ae%2FUntitled.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F669d0b00-bb5e-4555-a812-4daaa38475ae%2FUntitled.png)

### 定位算法

下XHR断点，填前面的获取到的登录api的HOST `platform-user-center.inboyu.com`

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F9564fd24-755e-44fd-9015-d58274ad465e%2FUntitled.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F9564fd24-755e-44fd-9015-d58274ad465e%2FUntitled.png)

断到登录发送请求的地方了。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F5c72b4ea-3c31-426c-a1dd-f81fa02e4ed3%2FUntitled.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F5c72b4ea-3c31-426c-a1dd-f81fa02e4ed3%2FUntitled.png)

从前面的调用栈中寻找登录点，可以定位到登陆的POST请求，这里JS代码进行了简单的混淆。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa0bd6332-8ed5-4ba1-a3ac-14a0e96575a2%2FUntitled.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa0bd6332-8ed5-4ba1-a3ac-14a0e96575a2%2FUntitled.png)

所以选择这里下断点，重新登录，成功断到这里，确认这里就是我们要找的登录点了。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F4bd67074-750e-4c71-aab3-8ac3678f7fa3%2F859EE7B6-1F9F-453E-8BF4-6A9E6BCFFEB3.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F4bd67074-750e-4c71-aab3-8ac3678f7fa3%2F859EE7B6-1F9F-453E-8BF4-6A9E6BCFFEB3.png)

而加密方法应该就是`f["a"].encrypt()`了，翻下JS代码找到定义f对象的地方，如下。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F5093f400-02b6-4d30-a3de-cd8a482f3df3%2F95AE6FDA-245E-473B-9CFC-2BBAE0D64314.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F5093f400-02b6-4d30-a3de-cd8a482f3df3%2F95AE6FDA-245E-473B-9CFC-2BBAE0D64314.png)

这里定义了f对象为`n("141a")`，这里直接全局搜索141a进行定位，搜索如下，141a为一个fuction对象。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fd53eb634-f8ba-448f-b4d8-60748d8fdd80%2F2C0AA9FF-F700-47B3-8CD2-021F735D3844.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fd53eb634-f8ba-448f-b4d8-60748d8fdd80%2F2C0AA9FF-F700-47B3-8CD2-021F735D3844.png)

翻到函数的下面，可以看到141a函数对象定义的a对象，对象里又定义了encrypt的函数对象，前面的`f[“a”].encript()`应该可以确定就是调用了此处的加密函数。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F70151a5f-50ca-47c7-a80c-35c9b7650183%2F86A31C93-B592-4A10-9973-90788BDA33FC.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F70151a5f-50ca-47c7-a80c-35c9b7650183%2F86A31C93-B592-4A10-9973-90788BDA33FC.png)

### 算法分析

前面定位的ecrypt函数对象调用了k函数进行加密，k函数就是此次登录的核心算法了。k的第一参数为需加密字符串，第二个参数为，第三个参数为固定密钥值，这里为20180710，记下有用。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb8caff28-4a19-4b7e-aeb1-07bb5499bbe2%2FDA7670D6-2AD1-4C7C-B0D3-C00EA9BEEAD7.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb8caff28-4a19-4b7e-aeb1-07bb5499bbe2%2FDA7670D6-2AD1-4C7C-B0D3-C00EA9BEEAD7.png)

右侧导航的Closure，可以看到闭包141a的相关属性，这里记下后面用到的函数名。

    base64_decode: /ƒ v (e)/
    base64_encode: /ƒ b (e)/
    encrypt1: /ƒ k (e,t,n)/
    hex_md5: /ƒ _ (e)/

对K(encrypt1)函数进行分析，分析写在注释里了。

    var r = {}
        , i = 0
        , a = 8;
    
    //省略代码
    
    function _(e) {
        return g(o(h(e), e.length * a))
    }
    function k(e, t, n) {//参数值e为为原字符串，即要加密的字符串，t参数为E或D,用来判断进行加密或者解密,n参数为密钥
        
      	//调用_(hex_md5)函数对密钥字符进行了一次加密，生成32位hex_md5值
      //函数名判断这应该是一个MD5加密函数，较为繁杂，这里就不深入进去了
        n = _(n);
        var r = n.length;//秘钥长度
        
        //判断t值，从下面的r.encrypt和r.decrypt判断这里只有E和D两种值，即加密和解密
        //t值为D的话则调用v函数,v函数为base64_decode解码函数
        //t值为E的话则调用_函数对密钥值和原字符串的拼接进行加密,并提取前8位，然后再次拼接原字符串
        e = "D" == t ? v(e) : _(e + n).substr(0, 8) + e;
      
        //将密钥Unicode之后填充满256长度的数组。生成a密钥数组，和o数组(加密数组)
        for (var i = e.length, a = [], o = [], c = "", s = 0; s <= 255; s++)
            a[s] = n.charCodeAt(s % r),
                o[s] = s;
        
        //根据密钥数组对o数组进行打乱
        for (var u = s = 0; s < 256; s++) {
            u = (u + o[s] + a[s]) % 256;
            var l = o[s];
            o[s] = o[u],
                o[u] = l
        }
        
        for (var d = u = s = 0; s < i; s++)
            //再次打乱
            d = (d + 1) % 256,
                u = (u + o[d]) % 256,
                l = o[d],
                o[d] = o[u],
                o[u] = l,
                
                //密钥字符串各个字符与o数组进行异或加解密，生成加密后字符串
                c += String.fromCharCode(e.charCodeAt(s) ^ o[(o[d] + o[u]) % 256]);
      
        //判断t值
        //t值为D(解密)，则返回解密后字符串c
        //t值为E(加密)，则调用b(base64_encode)函数，对c进行base_64加密
        return "D" == t ? c.substr(0, 8) == _(c.substr(8) + n).substr(0, 8) ? c.substr(8) : "" : b(c).replace(/=/g, "")
    }
    r.encrypt = function(e, t) {
        return k(e, "E", t)
    }
    
    r.encrypt = function(e, t) {
                return k(e, "E", t)
            },
    r.decrypt = function(e, t) {
        return k(e, "D", t)
    },
    r.hex_md5 = function(e) {
        return _(e) // md5加密函数
    },
    r.str_md5 = function(e) {
        return m(o(h(e), e.length * a))
    }

大致加密流程：

1. 密钥md5 = hex_md5(密钥值)
2. 新的原字符串 = hex_md5(原字符串 +密钥md5 ).substr(0, 8) + 原字符串
3. 密钥md5值Unicode之后填充满256位数组，生成密钥数组，和加密数组
4. 算法打乱加密数组之后，与新的原字符串进行异或加密。生成加密字符串
5. 对加密字符串进行base_64_encode编码，输出结果。

后面发现这个加密算法改编自discuz的authcode加密算法，[authcode算法](https://github.com/Discuz-X/DiscuzX/blob/35db41f75b102708033f3bd501eace6dbe11b7e2/api/db/dbbak.php#L854)。
[image:E3053BC6-4DC3-415A-9ED5-CBD5432BBCFC-308-0002DDA1D78C3297/CD0A9A12-5BB9-4D1E-9EB3-BBE37D147FAD.png]

## CODE

解密code时候挺好写的直接把，141a函数对象整个copy下来就可以了。

    var r = {}
        , i = 0
        , a = 8;
    function o(e, t) {
        e[t >> 5] |= 128 << t % 32,
            e[14 + (t + 64 >>> 9 << 4)] = t;
        for (var n = 1732584193, r = -271733879, i = -1732584194, a = 271733878, o = 0; o < e.length; o += 16) {
            var c = n
                , p = r
                , h = i
                , m = a;
            n = s(n, r, i, a, e[o + 0], 7, -680876936),
                a = s(a, n, r, i, e[o + 1], 12, -389564586),
                i = s(i, a, n, r, e[o + 2], 17, 606105819),
                r = s(r, i, a, n, e[o + 3], 22, -1044525330),
                n = s(n, r, i, a, e[o + 4], 7, -176418897),
                a = s(a, n, r, i, e[o + 5], 12, 1200080426),
                i = s(i, a, n, r, e[o + 6], 17, -1473231341),
                r = s(r, i, a, n, e[o + 7], 22, -45705983),
                n = s(n, r, i, a, e[o + 8], 7, 1770035416),
                a = s(a, n, r, i, e[o + 9], 12, -1958414417),
                i = s(i, a, n, r, e[o + 10], 17, -42063),
                r = s(r, i, a, n, e[o + 11], 22, -1990404162),
                n = s(n, r, i, a, e[o + 12], 7, 1804603682),
                a = s(a, n, r, i, e[o + 13], 12, -40341101),
                i = s(i, a, n, r, e[o + 14], 17, -1502002290),
                r = s(r, i, a, n, e[o + 15], 22, 1236535329),
                n = u(n, r, i, a, e[o + 1], 5, -165796510),
                a = u(a, n, r, i, e[o + 6], 9, -1069501632),
                i = u(i, a, n, r, e[o + 11], 14, 643717713),
                r = u(r, i, a, n, e[o + 0], 20, -373897302),
                n = u(n, r, i, a, e[o + 5], 5, -701558691),
                a = u(a, n, r, i, e[o + 10], 9, 38016083),
                i = u(i, a, n, r, e[o + 15], 14, -660478335),
                r = u(r, i, a, n, e[o + 4], 20, -405537848),
                n = u(n, r, i, a, e[o + 9], 5, 568446438),
                a = u(a, n, r, i, e[o + 14], 9, -1019803690),
                i = u(i, a, n, r, e[o + 3], 14, -187363961),
                r = u(r, i, a, n, e[o + 8], 20, 1163531501),
                n = u(n, r, i, a, e[o + 13], 5, -1444681467),
                a = u(a, n, r, i, e[o + 2], 9, -51403784),
                i = u(i, a, n, r, e[o + 7], 14, 1735328473),
                r = u(r, i, a, n, e[o + 12], 20, -1926607734),
                n = l(n, r, i, a, e[o + 5], 4, -378558),
                a = l(a, n, r, i, e[o + 8], 11, -2022574463),
                i = l(i, a, n, r, e[o + 11], 16, 1839030562),
                r = l(r, i, a, n, e[o + 14], 23, -35309556),
                n = l(n, r, i, a, e[o + 1], 4, -1530992060),
                a = l(a, n, r, i, e[o + 4], 11, 1272893353),
                i = l(i, a, n, r, e[o + 7], 16, -155497632),
                r = l(r, i, a, n, e[o + 10], 23, -1094730640),
                n = l(n, r, i, a, e[o + 13], 4, 681279174),
                a = l(a, n, r, i, e[o + 0], 11, -358537222),
                i = l(i, a, n, r, e[o + 3], 16, -722521979),
                r = l(r, i, a, n, e[o + 6], 23, 76029189),
                n = l(n, r, i, a, e[o + 9], 4, -640364487),
                a = l(a, n, r, i, e[o + 12], 11, -421815835),
                i = l(i, a, n, r, e[o + 15], 16, 530742520),
                r = l(r, i, a, n, e[o + 2], 23, -995338651),
                n = d(n, r, i, a, e[o + 0], 6, -198630844),
                a = d(a, n, r, i, e[o + 7], 10, 1126891415),
                i = d(i, a, n, r, e[o + 14], 15, -1416354905),
                r = d(r, i, a, n, e[o + 5], 21, -57434055),
                n = d(n, r, i, a, e[o + 12], 6, 1700485571),
                a = d(a, n, r, i, e[o + 3], 10, -1894986606),
                i = d(i, a, n, r, e[o + 10], 15, -1051523),
                r = d(r, i, a, n, e[o + 1], 21, -2054922799),
                n = d(n, r, i, a, e[o + 8], 6, 1873313359),
                a = d(a, n, r, i, e[o + 15], 10, -30611744),
                i = d(i, a, n, r, e[o + 6], 15, -1560198380),
                r = d(r, i, a, n, e[o + 13], 21, 1309151649),
                n = d(n, r, i, a, e[o + 4], 6, -145523070),
                a = d(a, n, r, i, e[o + 11], 10, -1120210379),
                i = d(i, a, n, r, e[o + 2], 15, 718787259),
                r = d(r, i, a, n, e[o + 9], 21, -343485551),
                n = f(n, c),
                r = f(r, p),
                i = f(i, h),
                a = f(a, m)
        }
        return Array(n, r, i, a)
    }
    function c(e, t, n, r, i, a) {
        return f(p(f(f(t, e), f(r, a)), i), n)
    }
    function s(e, t, n, r, i, a, o) {
        return c(t & n | ~t & r, e, t, i, a, o)
    }
    function u(e, t, n, r, i, a, o) {
        return c(t & r | n & ~r, e, t, i, a, o)
    }
    function l(e, t, n, r, i, a, o) {
        return c(t ^ n ^ r, e, t, i, a, o)
    }
    function d(e, t, n, r, i, a, o) {
        return c(n ^ (t | ~r), e, t, i, a, o)
    }
    function f(e, t) {
        var n = (65535 & e) + (65535 & t)
            , r = (e >> 16) + (t >> 16) + (n >> 16);
        return r << 16 | 65535 & n
    }
    function p(e, t) {
        return e << t | e >>> 32 - t
    }
    function h(e) {
        for (var t = Array(), n = (1 << a) - 1, r = 0; r < e.length * a; r += a)
            t[r >> 5] |= (e.charCodeAt(r / a) & n) << r % 32;
        return t
    }
    function m(e) {
        for (var t = "", n = (1 << a) - 1, r = 0; r < 32 * e.length; r += a)
            t += String.fromCharCode(e[r >> 5] >>> r % 32 & n);
        return t
    }
    function g(e) {
        for (var t = i ? "0123456789ABCDEF" : "0123456789abcdef", n = "", r = 0; r < 4 * e.length; r++)
            n += t.charAt(e[r >> 2] >> r % 4 * 8 + 4 & 15) + t.charAt(e[r >> 2] >> r % 4 * 8 & 15);
        return n
    }
    function v(e) {
        var t, n, r, i, a = new Array(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1), o = 0, c = e.length, s = "";
        while (o < c) {
            do {
                t = a[255 & e.charCodeAt(o++)]
            } while (o < c && -1 == t);if (-1 == t)
                break;
            do {
                n = a[255 & e.charCodeAt(o++)]
            } while (o < c && -1 == n);if (-1 == n)
                break;
            s += String.fromCharCode(t << 2 | (48 & n) >> 4);
            do {
                if (r = 255 & e.charCodeAt(o++),
                61 == r)
                    return s;
                r = a[r]
            } while (o < c && -1 == r);if (-1 == r)
                break;
            s += String.fromCharCode((15 & n) << 4 | (60 & r) >> 2);
            do {
                if (i = 255 & e.charCodeAt(o++),
                61 == i)
                    return s;
                i = a[i]
            } while (o < c && -1 == i);if (-1 == i)
                break;
            s += String.fromCharCode((3 & r) << 6 | i)
        }
        return s
    }
    function b(e) {
        var t, n, r, i = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", a = 0, o = e.length, c = "";
        while (a < o) {
            if (t = 255 & e.charCodeAt(a++),
            a == o) {
                c += i.charAt(t >> 2),
                    c += i.charAt((3 & t) << 4),
                    c += "==";
                break
            }
            if (n = e.charCodeAt(a++),
            a == o) {
                c += i.charAt(t >> 2),
                    c += i.charAt((3 & t) << 4 | (240 & n) >> 4),
                    c += i.charAt((15 & n) << 2),
                    c += "=";
                break
            }
            r = e.charCodeAt(a++),
                c += i.charAt(t >> 2),
                c += i.charAt((3 & t) << 4 | (240 & n) >> 4),
                c += i.charAt((15 & n) << 2 | (192 & r) >> 6),
                c += i.charAt(63 & r)
        }
        return c
    }
    function _(e) {
        return g(o(h(e), e.length * a))
    }
    function k(e, t, n) {
        n = _(n);
        var r = n.length;
        e = "D" == t ? v(e) : _(e + n).substr(0, 8) + e;
        for (var i = e.length, a = [], o = [], c = "", s = 0; s <= 255; s++)
            a[s] = n.charCodeAt(s % r),
                o[s] = s;
        for (var u = s = 0; s < 256; s++) {
            u = (u + o[s] + a[s]) % 256;
            var l = o[s];
            o[s] = o[u],
                o[u] = l
        }
        for (var d = u = s = 0; s < i; s++)
            d = (d + 1) % 256,
                u = (u + o[d]) % 256,
                l = o[d],
                o[d] = o[u],
                o[u] = l,
                c += String.fromCharCode(e.charCodeAt(s) ^ o[(o[d] + o[u]) % 256]);
        return "D" == t ? c.substr(0, 8) == _(c.substr(8) + n).substr(0, 8) ? c.substr(8) : "" : b(c).replace(/=/g, "")
    }
    r.encrypt = function(e, t) {
        return k(e, "E", t)
    }
        ,
        r.decrypt = function(e, t) {
            return k(e, "D", t)
        }
        ,
        r.hex_md5 = function(e) {
            return _(e)
        }
        ,
        r.str_md5 = function(e) {
            return m(o(h(e), e.length * a))
    };
    
    
    console.log(r.encrypt("admin","20180710")); //这里修改字符串参数

运行

    console.log(r.encrypt("admin","20180710")); //改为自己要加密的字符串
    node boyu_encrypt.js //运行

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F87476c6b-9ca2-4733-a71b-ef82cfcdece6%2F53077DBC-2707-4F73-AA00-0461A91D29F0.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F87476c6b-9ca2-4733-a71b-ef82cfcdece6%2F53077DBC-2707-4F73-AA00-0461A91D29F0.png)

## 总结

u1s1, Chrome Devtools还是牛逼 !!