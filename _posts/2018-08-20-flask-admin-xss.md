---
layout:     post
title:      "Flask-admin 某处Reflected XSS引发的思考"
subtitle:   "Flask-admin 某处Reflected XSS引发的思考"
date:       2018-08-20 12:00:00
author:     "T-bag"
header-img: "img/post-bg-unix-linux.jpg"
header-mask: 0.3
catalog:    true
tags:
    - web安全
    - 漏洞分析
    - flask
---

## 前言

Flask-Admin是一个功能齐全、简单易用的Flask扩展，让你可以为Flask应用程序增加管理界面。
介绍完毕，首先去官方GitHub上看了下，翻了翻issue。发现了了一个蛮有趣的xss，非常少见url解析错误导致xss的案例，于是就动手分析一下。顺便学习一下flask-admin
[refs #1503 fix reflected xss by lbhsot · Pull Request #1699 · flask-admin/flask-admin · GitHub](https://github.com/flask-admin/flask-admin/pull/1699)

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F01494566-f248-49a4-9de4-b845ff71a290/9F0CD3DA-1377-4E34-B606-297A3889D0C6.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F01494566-f248-49a4-9de4-b845ff71a290/9F0CD3DA-1377-4E34-B606-297A3889D0C6.png)

## 环境搭建

首先这个是对于issure#1503的反射xss的绕过，issure地址为 [Reflected XSS · Issue #1503 · flask-admin/flask-admin · GitHub](https://github.com/flask-admin/flask-admin/issues/1503)
后面开发人员在[Merge pull request #1505 from pawl/issue_1503 · flask-admin/flask-admin@960f5e0 · GitHub](https://github.com/flask-admin/flask-admin/commit/960f5e0a0185a7c04a8f98678a845ad57d472285) 中对其进行了修复。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F5547459e-1caa-4974-8430-a1afa8b85284/B2143783-8129-4CA8-9DD6-C9101CB399E3.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F5547459e-1caa-4974-8430-a1afa8b85284/B2143783-8129-4CA8-9DD6-C9101CB399E3.png)

搭建：

    git clone <https://github.com/flask-admin/flask-admin>
    git checkout 960f5e0a0185a7c04a8f98678a845ad57d472285  #这里切换到issue#1503修复完成的分支
    cd examples/sqla/
    python3 app.py  #运行官方的demo代码

## 漏洞复现

payload：
`http://127.0.0.1:5000/admin/user/edit/?url=javascript%0a:alert(1)&id=1`
这里直接用issue#1699中提供的的绕过Payload，此时URL中的url参数正常情况下将会别作为返回的url赋值给前端的List导航和Cancel按钮的href属性。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Ff8b1d112-bab2-4356-8a0d-3826dc13f560/D4BE0D66-ACE0-4F12-9386-331CCCACC466.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Ff8b1d112-bab2-4356-8a0d-3826dc13f560/D4BE0D66-ACE0-4F12-9386-331CCCACC466.png)

这是一个需要交互的XSS，点击Cancel按钮或者List导航即可触发触发。这时候源码是这样的。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb6515737-2011-4152-b40b-c04c5b4c2d26/55B4E492-5912-4403-9315-A18E1818ADCF.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb6515737-2011-4152-b40b-c04c5b4c2d26/55B4E492-5912-4403-9315-A18E1818ADCF.png)

## 漏洞分析

观察一下payload URL， `/admin`为基础路由，`/user`为用户通过add_view定义的路由，重点的 `/edit`为flask-admin提供的exit操作路由。分析就从这里开始，搜索`/edit`，进入到`flask-admin/base.py`中查看`/edit` 路由。

    @expose('/edit/', methods=('GET', 'POST'))
        def edit_view(self):
            return_url = get_redirect_target() or self.get_url('.index_view')
            if not self.can_edit:
                return redirect(return_url)
    
            id = get_mdict_item_or_list(request.args, 'id')
            if id is None:
                return redirect(return_url)
    
            model = self.get_one(id)
            ...省略...
            return self.render(template,
                               model=model,
                               form=form,
                               form_opts=form_opts,
                               return_url=return_url)

其对应的temlpate为`flask_admin/templates/bootstrap2/admin/model/edit.html`，下面的模板代码对应的就是页面上的List导航的按钮，可以看到这里通过Jinja2获取了return_url。

    <li>
        <a href="{{ return_url }}">{{ _gettext('List') }}</a>
    </li>

return_url将会由get_redirect_target()获取，查看get_redirect_target()的代码，这里获取了request的URL参数，并且通过is_safe_url进行判断，判断字符串是否安全。

    def get_redirect_target(param_name='url'):
        target = request.values.get(param_name)
    
        if target and is_safe_url(target):
            return target

进入到is_safe_url中观察，开发对其修复针对的正是该函数。

    VALID_SCHEMES = ['http', 'https']
    def is_safe_url(target):
        # prevent urls starting with "javascript:"
        target = target.strip()
        target_info = urlparse(target)
        target_scheme = target_info.scheme
        if target_scheme and target_scheme not in VALID_SCHEMES:
            return False
    
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        return ref_url.netloc == test_url.netloc

结合issure#1503 中提供的Payload `https://10.0.0.1/admin/user/edit/?url=%20javascript%3aalert(document.domain)&id=8`，和官方对其进行的修复，就可以看出开发人员仅仅针对这单一payload进行了修复。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F8c2c6326-20f7-4458-8336-f9ca42ed2aa7/009577E8-10B9-4395-8F7F-BD6E2A0AB377.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F8c2c6326-20f7-4458-8336-f9ca42ed2aa7/009577E8-10B9-4395-8F7F-BD6E2A0AB377.png)

开发人员的第一层防护，首先`target = target.strip()` ，通过strip过滤了空字符，而strip函数过滤仅仅针对于字符串前后两端的空白字符。可以过滤`%20javascript:alert(1)`，但对于 `javascript%0a:alert(1)`这种是无法进行过滤的。
然后是第二层防护对URL进行urlparse，然后判断scheme是否存在并且在白名单`VALID_SCHEMES = ['http', 'https']`中。
联想到之前看的一篇[CVE-2017-7233分析](https://paper.seebug.org/274/)，而其中针对于Django URL跳转的bypass正是通过`urllib.parse.url.parse`的解析错误问题。
这里写个demo测试一下

    url1 = unquote("javascript%0a:alert(1)")
    print(urlparse(url1))
    url2 = unquote("javascript:alert(1)")
    print(urlparse(url2))

结果

    ParseResult(scheme='', netloc='', path='javascript\\n:alert(1)', params='', query='', fragment='')
    ParseResult(scheme='javascript', netloc='', path='alert(1)', params='', query='', fragment='')

可以看到在存在`%0a`的字符下urlparse对URL的解析出现了错误，这里scheme为空。对于形成原因，后面会具体分析一下。

所以这里通过`javascript%0a:alert(1)`即可绕过这第二层防护，因为这时候的scheme为空，将会跳到下一个步骤，

接着就是第三层防护了，通过判断host的netloc和ref_url的netloc是否相同，其实在绕过上一步之后这里就形同虚设了。因为在类似urljoin(base,target)时候，当target的netloc为空的情况下，其netloc就会被设定为base的netloc，所以这里的防护完全没用。

    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return ref_url.netloc == test_url.netloc

当判断url参数安全之后，get_redirect_target将会返回url参数的值，这里的返回结果为`javascript\\n:alert(1)`，结果将会返回给edit路由函edit_view中的return_url，还有需要注意的是，这里必须有id参数，否则将会直接跳转。

    id = get_mdict_item_or_list(request.args, 'id')
    if id is None:
        return redirect(return_url)

最后return_url通过render函数传递给了前端template。

    return self.render(template,
                               model=model,
                               form=form,
                               form_opts=form_opts,
                               return_url=return_url)

前端结果就是这样子了，点击跳转，触发弹窗。

    <li>
       <a href="javascript
    :alert(1)">List</a>
    </li>

## 关于urlparse的思考

漏洞已经分析完了，成因是主要是因为urllib的urlparse函数的解析错误造成is_safe_url的绕过。从而导致xss，感觉这是一个非常有趣的案例。
对于urlparse解析错误的原因还是不明白，于是决定深入urllib.parse的源码分析一下。
这里写个demo进行分析

    url = unquote("javascript%0a:alert(1)")
    return_url = urljoin("<http://baidu.com/>", url)
    print(urlparse(return_url))

结果

    ParseResult(scheme='http', netloc='baidu.com', path='/javascript\\n:alert(1)', params='', query='', fragment='')

而在`url = unquote("javascript:alert(1)")`的情况下，结果的协议为正常的javascript

    ParseResult(scheme='javascript', netloc='', path='alert(1)', params='', query='', fragment='')

着手分析，首先程序进入到urllib.parse.urljoin函数中，这里省略了大部分内容，留下一些我们用到的。urljoin的原理通过urlparse对参数base和url进行了分割，最后结果将结果通过urlunparse生成为URL返回

    def urljoin(base, url, allow_fragments=True):
        """Join a base URL and a possibly relative URL to form an absolute
        interpretation of the latter."""
        if not base:
            return url
        if not url:
            return base
    
        base, url, _coerce_result = _coerce_args(base, url)
        bscheme, bnetloc, bpath, bparams, bquery, bfragment = \\
                urlparse(base, '', allow_fragments)
        scheme, netloc, path, params, query, fragment = \\
                urlparse(url, bscheme, allow_fragments)
    
        if scheme != bscheme or scheme not in uses_relative:
            return _coerce_result(url)
        if scheme in uses_netloc:
            if netloc:
                return _coerce_result(urlunparse((scheme, netloc, path,
                                                  params, query, fragment)))
            netloc = bnetloc
    
        ...省略..
    
        return _coerce_result(urlunparse((scheme, netloc, '/'.join(
            resolved_path) or '/', params, query, fragment)))

我们查看一下调用的两次urlparse函数，

    bscheme, bnetloc, bpath, bparams, bquery, bfragment = \\
                urlparse(base, '', allow_fragments)
    scheme, netloc, path, params, query, fragment = \\
                urlparse(url, bscheme, allow_fragments)

第一次urlparse为对base参数`http://baidu.com/`的正常解析。这里直接给返回结果如下。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F0d9a255c-7e2e-48b4-ad50-1a775aec75f5/EBB39169-1B54-48A2-82E5-2D328484FF09.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F0d9a255c-7e2e-48b4-ad50-1a775aec75f5/EBB39169-1B54-48A2-82E5-2D328484FF09.png)

接着第二次对于url 参数`'javascript\\n:alert(1)'`的解析，这里就是我们需要着重分析的地方了。执行了`urlparse(url, bscheme, allow_fragments)`函数，这里看到第二个参数url的scheme最开始被设置为了bscheme，也就是http。

我们跟进到urlparse函数中进行分析通过`urlsplit(url, scheme, allow_fragments)`函数对URL进行了分割。

    def urlparse(url, scheme='', allow_fragments=True):
        url, scheme, _coerce_result = _coerce_args(url, scheme)
        splitresult = urlsplit(url, scheme, allow_fragments)
        scheme, netloc, url, query, fragment = splitresult
        if scheme in uses_params and ';' in url:
            url, params = _splitparams(url)
        else:
            params = ''
        result = ParseResult(scheme, netloc, url, params, query, fragment)
        return _coerce_result(result)

跟进到urlsplit函数中，可以看到首先通过`I = url.find(':')`返回`:`d的位置，然后在接下将会对字符进行一系列判断，这里省略大部分。

    def urlsplit(url, scheme='', allow_fragments=True):
        url, scheme, _coerce_result = _coerce_args(url, scheme)
        allow_fragments = bool(allow_fragments)
        ...
        netloc = query = fragment = ''
        i = url.find(':')
        if i > 0:
            if url[:i] == 'http': # optimize the common case
                scheme = url[:i].lower()
                url = url[i+1:]
                if url[:2] == '//':
                    ...
                return _coerce_result(v)
            for c in url[:i]:
                if c not in scheme_chars:
                    break
            else:
                rest = url[i+1:]
                if not rest or any(c not in '0123456789' for c in rest):
                    scheme, url = url[:i].lower(), rest
        ...
        v = SplitResult(scheme, netloc, url, query, fragment)
        _parse_cache[key] = v
        return _coerce_result(v)

截取后的第一层判断，用于判断协议是否为http，因为我们输入的为`javascript%0a:alert(1)`，所以这里直接跳过。将会继续执行下面的语句，判断`：`前面的字符是否在URL白名单内，在一番轮训之后检测到`\\n`这个字符不在白名单内，就会break，这里划重点。

    for c in url[:i]:
                if c not in scheme_chars:
                    break

scheme_chars

    scheme_chars = ('abcdefghijklmnopqrstuvwxyz'
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                    '0123456789'
                    '+-.')

因为这里有个有趣的点，因为这里break之后，将不会执行下面的else语句，这里的else语句`scheme, url = url[:i].lower(), rest`，用于设置适用于将`:`前面的字符串设置为协议的。而这里中途被break，并不会执行。

正常思路下，在if判断为False的情况下，将会直接执行else语句的，然而并不是，这里用个demo验证下。

    if 1:
        a = 1
        if a >1:
            print()
            print(">1")
        for i in [1,2,3]:
            if i == 1:
                print("==1")
                break
        else:
            print("<1")

上面的demo输出结果为`==1`，也就说明if 下的for循环语句出现break的话，将会跳出判断，不执行下面的else语句。

回到urlsplit函数中，因为跳过了用于设定协议的else语句，所以此时schem依旧为空。接下来将会在对url进行一系列判断和处理，最后返回结果

    if url[:2] == '//':
        netloc, url = _splitnetloc(url, 2)
        if (('[' in netloc and ']' not in netloc) or
                (']' in netloc and '[' not in netloc)):
            raise ValueError("Invalid IPv6 URL")
    if allow_fragments and '#' in url:
        url, fragment = url.split('#', 1)
    if '?' in url:
        url, query = url.split('?', 1)
    v = SplitResult(scheme, netloc, url, query, fragment)
    _parse_cache[key] = v
    return _coerce_result(v)

最后返回的schem,等结果如下。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F09c37aec-e251-417c-aa21-c725a8bfd8be/0EA8C921-EC65-407A-8D28-B98CE960E9D7.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F09c37aec-e251-417c-aa21-c725a8bfd8be/0EA8C921-EC65-407A-8D28-B98CE960E9D7.png)

结果将会返回给回到urlparse中，urlparse在以元组的形式返回给urljoin。urljoin接下来将会检查scheme，我们的schem在开始就被设置为了http，然后会判断netloc是否为空，我们的netloc未设置所以为空，所以会被设置为bnetloc，即`baidu.com`。

    if scheme in uses_netloc:
        if netloc:
            return _coerce_result(urlunparse((scheme, netloc, path,
                                              params, query, fragment)))
        netloc = bnetloc

接下来，将会通过urlunparse对scheme和netloc等参数进行拼接，urlunparse在调用urlunsplit函数进行处理

    return _coerce_result(urlunparse((scheme, netloc, '/'.join(
            resolved_path) or '/', params, query, fragment)))

urlspilit函数

    def urlunsplit(components):
        scheme, netloc, url, query, fragment, _coerce_result = (
                                              _coerce_args(*components))
        if netloc or (scheme and scheme in uses_netloc and url[:2] != '//'):
            if url and url[:1] != '/': url = '/' + url
            url = '//' + (netloc or '') + url
        if scheme:
            url = scheme + ':' + url
        if query:
            url = url + '?' + query
        if fragment:
            url = url + '#' + fragment
        return _coerce_result(url)

最后urljoin生成的字符串也就为

    <http://baidu.com/javascript>
    :alert(1)

其urlparse对象如下，可以看到scheme和netloc都为正常的base url的scheme和netloc。可以知道urlparse问题出在urlsplit中的for循环判断字符是否在URL白名单的地方，在检测到`\\n`，`\\r`等不在白名单中的字符的情况下，将会break，导致后续的else未执行，协议未设置，也就为base url的协议，netloc也为base_url的netloc。如果正常输入`javascript:alert(1)`的话，其所有字符都在白名单内，不会break，最后的协议也就为正常的JavaScript了

    ParseResult(scheme='http', netloc='baidu.com', path='/javascript\\n:alert(1)', params='', query='', fragment='')

最后用一个Python脚本验证一下可用的Payload字符

    tmp = '''<a href='javascript[a]:alert(1)'>payload [b]</a>\\r\\n'''
    
    content = ""
    for x in xrange(255):
    	item = tmp.replace("[a]", chr(x))
    	item = item.replace("[b]", hex(x))
    	content += item
    
    
    with file ("out.html", "wb") as f:
    	f.write(content)

测试结果，可用的payload字符有%0a(\n)换行符，%0d(\r)回车符，%09（\t）制表符

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fdcfbb8f4-1786-4f3a-a830-a1eba71a25e0/F63F0F47-A2BE-4B1C-A553-6B954CFED086.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fdcfbb8f4-1786-4f3a-a830-a1eba71a25e0/F63F0F47-A2BE-4B1C-A553-6B954CFED086.png)

最后关于其它语言其它类库的URL解析差异问题，可以参考orange的[SSRF](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)演讲

## 总结

回过头来，我们其实可以知道漏洞形成的整体原因了，urlparse解析问题是因为其中的urlsplit函数中的for循环判断字符是否在URL白名单的地方，在检测到`\\n`，`\\r`，`\\t`等不在白名单中的字符的情况下，将会break，导致后续的else未执行，没有设置协议，而此时的协议又是为最开始bscheme的协议。netloc也为base的netloc。而在flask-admin中is_safe_url，仅仅判断了scheme和netloc这两个属性。导致`javascript%0a:alert(1)`被判断为安全的URL。在服务端中被解析为`javascript\\n:alert(1)`，并赋值给前端，还需要注意到的一个点是urlparse和我们测试的所用的谷歌浏览器对于[RFC 3986]文档的实现是存在差异的，根据[RFC 3986](https://tools.ietf.org/html/rfc3986#section-3.1) 中对于scheme的描述，协议仅支持`scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`，字母，数字，加号减号，点号等字符，从我们之前的分析中可知python中的urlparse库遵守了该规定，所以可以说urlparse的解析并不能算错误，因为它确实正确遵守RFC3986中对于URL的规定，协议中仅支持上述字符，而有些浏览器并没有严格遵守这个规定，支持换行和回车等操作符，因为这点也导致了在浏览器处理的时候`javascript\\n:alert(1)`中被认定为合法的URL，导致Payload可执行。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fab852257-0ad9-42d5-96dc-6bca6255d108/9.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fab852257-0ad9-42d5-96dc-6bca6255d108/9.png)

## 参考

[Django的两个url跳转漏洞分析:CVE-2017-7233&7234](https://paper.seebug.org/274/)[A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)[RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax](https://tools.ietf.org/html/rfc3986#section-3.1)