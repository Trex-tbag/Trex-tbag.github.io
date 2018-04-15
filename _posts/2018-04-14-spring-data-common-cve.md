---
layout:     post
title:      "Spring Data Commons组件远程代码执行漏洞(CVE-2018-1273) 分析过程"
subtitle:   "漏洞分析过程记录"
date:       2018-04-14 12:00:00
author:     "T-bag"
header-img: "img/post-bg-unix-linux.jpg"
header-mask: 0.3
catalog:    true
tags:
    - 漏洞分析
    - SpringMvc
    - Web安全
---

### 前言

Spring Data是Spring框架中提供底层数据访问的项目 模块，Spring Data Commons是一个共用的基础模块。此模 块对特殊属性处理时会使用SpEl表达式，导致攻击者可以通 过构造特殊的URL请求，造成服务端远程代码执行。

### 漏洞原理

[补丁地址](https://github.com/spring-projects/spring-data-commons/commit/ae1dd2741ce06d44a0966ecbd6f47beabde2b653)

简单分析一下漏洞补丁，通过下面标注的地方，可以发现这是一段SpEl表达式解析。所以猜测可能是SpEl表达式注入导致的远程代码执行

![Jcve1](/img/in-post/cve_2018_1273/图片 1.png)

通过两个简单例子了解一下SpEL注入

**SpEl的hello world程序:**

从下面的代码可以看出该例子通过实例化SpelExpressionParser类创建对象作为Spel的解析器，该解析器可用于解析字符串等，成功解析了hello world字符串并然后输出

```java
public class speltest {
    public static void main(String[] args) {
        ExpressionParser parser=new SpelExpressionParser();  //创建了一个Spel的解析器 
        Expression exp=parser.parseExpression("'hello world！'"); //解析表达式hello world 
        System.out.println(exp.getValue().toString()); //输出字符串
    }
}
```



然后是一个**命令执行**的例子。

需要注意的是这里通过new StandardEvaluationContext();创建了一个EvaluationContext 对象，相当于一个容器。接下来解析SpEl表达式（SpEL表达式是#{}格式的）。在解析表达式的过程中利用反射将会获取到Runtime类达，通过执行其exec函数运行命令从而达到命令执行的效果。最终执行是在setValue()或者getValue()函数执行之后。

```java
public class speltest {

    public static void main(String[] args) {
        
        EvaluationContext ctx = new StandardEvaluationContext(); //创建一个容器
        String[] students=new String[]{"a","b","c","d"};
        //students.getClass().forName("java.lang.Runtime").getName()
        ctx.setVariable("students", students);
        //在格式化表达式的过程中利用反射将会获取到Runtime类达通过exec函数运行命令
        String student = parser.parseExpression("#students.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"/Applications/Calculator.app/Contents/MacOS/Calculator\")").getValue(ctx,String.class);
        System.out.println(student);
        
    }
}
```

运行该例子将会打开计算器

![Jcve1](/img/in-post/cve_2018_1273/图片 2.png)



简单说明SpEl注入原理，接下来进行分析

### 调试环境搭建

**IDE**: intellj Idea

**Demo**:下载[spring-data-examples](https://github.com/spring-projects/spring-data-examples)

在idea中直接运行 **web/example**：

![Jcve1](/img/in-post/cve_2018_1273/图片 3.png)

### 分析过程

可以直接使用SpEL表达式注入的Payload进行测试

**Poc:**

```java
username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("/Applications/Calculator.app/Contents/MacOS/Calculator")]=tbag&password=tbag&repeatedPassword=tabg
```

可以看到成功执行，说明POC可用

![Jcve1](/img/in-post/cve_2018_1273/图片 4.png)

接下来进行断点调试，因为payload是在post数据中的，看一下代码，决定在`@RequestMapping(method = RequestMethod.POST)`注解的方法中尝试下断点，该注解用于接受post请求传递过来的数据

```java
@RequestMapping(method = RequestMethod.POST)

         public Objectregister(UserForm userForm, BindingResult binding, Model model)

```

在开头下好断点之后，然后在浏览器中请求数据。Debug调试。方法刚开始命令就执行了。难道poc在通过这里之前就已经执行了吗。所以这个点一开始就被我排除了，这也是较为坑爹的地方。后面会讲到

![Jcve1](/img/in-post/cve_2018_1273/图片 5.png)

换个断点试试。看到了一个`@ModelAttribute`注解，该注解下面标明的方法，会在所有Controler方法执行之前率先执行。所以决定把断点下在这里

```java
java @ModelAttribute("users")//在ModelAttrribute会先去其它执行方法先执行
     publicPage<User> users(@PageableDefault(size = 5) Pageable pageable) {
              returnuserManagement.findAll(pageable);
     }
```



下好断点之后，debug运行。这时候断点停住了，并且poc没有运行。难道poc是在这里面执行的？然后开始了坑爹的单步调试。经过很多很多次的单步调试后。没啥动静。越发觉得不对劲。于是分析了一下该处的代码跟HTML的代码

![Jcve1](/img/in-post/cve_2018_1273/图片 6.png)

分析了一下，这里应该是通过`@ModelAttribute`注解声明了users对象。作为**`Page<User>`**类型的数据集，前端可以通过users对象访问到数据，并对其进行展示。然道poc是在取出的时候被执行的?

于是直接运行，并把post数据去掉。什么事都没发生。

![Jcve1](/img/in-post/cve_2018_1273/图片 7.png)

加载post数据，poc还是执行了。说明并不是在数据展示的时候执行的。而是通过数据获取的。然而可以获得数据的就只有第一次下断点的地方。那里一开始就被排除掉了

思路断掉了，只能换一种调试方式了。从漏洞修复代码中可以看出来。漏洞位置是`MapDataBinder.class` 下的`setPropertyValue`方法。所以在这里下断点

![Jcve1](/img/in-post/cve_2018_1273/图片 8.png)

debug调试。在浏览器中请求数据。可以看到在断点处停下来了，username的数据已经传递出来了，并且poc还没没开始执行

![Jcve1](/img/in-post/cve_2018_1273/图片 9.png)

接下来我们在`expression.setValue(context,value);`中下个断点。setValue。poc的最终执行就是通过这里的。经过这里之后poc刚好执行，然后`setPropertyValue`继续对接下来的数据进行处理。从这里可以确定就是SpEl产生的表达式注入

![Jcve1](/img/in-post/cve_2018_1273/图片 10.png)



漏洞点已经确认了，就是`setPropertyValue`。现在需要知道的是数据是如何被引用到这里来的。可以通过idea自带的Drop Frame调试，或者直接看右边方框的函数引用列表

![Jcve1](/img/in-post/cve_2018_1273/图片 11.png)

接下来分析一下引用流程

在`ModelAttributeMethodProcessor.class`中执行了下面这段函数

```java
try {
    attribute = this.createAttribute(name, parameter, binderFactory, webRequest);
}
```

看一下它的参数，name为userForm，而binderFactory为`ServletRequestDataBinder`。ServletRequestDataBinder的作用是把Servlet请求过来的数据封装为一个对象。记录一下

![Jcve1](/img/in-post/cve_2018_1273/图片 12.png)

继续看下去，在`ProxyingHandlerMethodArgumentResolver.class`中

```java
protected Object createAttribute(String attributeName, MethodParameter parameter, WebDataBinderFactory binderFactory, NativeWebRequest request) throws Exception {
        MapDataBinder binder = new MapDataBinder(parameter.getParameterType(), (ConversionService)this.conversionService.getObject());
        binder.bind(new MutablePropertyValues(request.getParameterMap()));
        return this.proxyFactory.createProjection(parameter.getParameterType(), binder.getTarget());
}
```



看到实例化了`MapDataBinder`，调用了`bind`方法。并将`request.getParameterMap()`作为参数。`request.getParameterMap()`可以获得前端传递过来的key-value的**map类型**的值，也就是说请求数据就是这里传递进去的

![Jcve1](/img/in-post/cve_2018_1273/图片 13.png)

然后是`DataBinder.class`的`applyPropertyValues`函数。该函数是用于对字段值进行设置

![Jcve1](/img/in-post/cve_2018_1273/图片 14.png)

最后就是`MapDataBinder.class`的`setPropertyValue`函数了，该函数应该是将获得的请求数据与userForm对象进行了绑定，因为在绑定过程中。SpEl解析了命令执行代码，所以出现了漏洞

![Jcve1](/img/in-post/cve_2018_1273/图片 15.png)

在这里`setValue`执行反射导致命令执行

![Jcve1](/img/in-post/cve_2018_1273/图片 16.png)

其实看这个过程，大体可以看出这是一个`@ModelAttribute`注解将请求转换为指定对象的过程。但是为什么userFrom没有设置**@ModelAttribute** 注解也会被作为对象呢。

![Jcve1](/img/in-post/cve_2018_1273/图片 17.png)

看了一些文章，发现写`UserForm2 userForm `和

```java
@ModelAttribute UserForm2 userForm //添不添加注解效果是一样的
```

两种写法的效果是一样的。以下代码可用于测试

**UserControler.java：**

```java
@RequestMapping(method = RequestMethod.POST,value = "/helloWorld")
	public String helloWorld(@ModelAttribute UserForm2 userForm,Model model) {
		System.out.println(1);
		return "ssss";
	}
```

**form表单接口:**

这里需要注意的是需要做相关的参数设置`String getUsername1();StringgetPassword1();` 

否则无法获得参数。表单接口的编写我也不太懂

```java
interface UserForm2{
		String getUsername1();
		String getPassword1();
	}
```

**helloworld.html:**

```html
<form action="/users/helloWorld" name="loginfrom" accept-charset="utf-8" method="post" >
    <label class="label-tips" for="u">账号:</label>
    <input type="text" id="u" name="username1" class="inputstyle"/>
    <div>
        <label class="lable-tips" for="password1">密码:</label>
        <input type="password" id="password1" name="password1" class="inputstyle" />
    </div>
    <input type="submit" name="登录"/>
    <a href="register.html" class="zcxy" target="_blank">注册</a>
</form>
```

测试是可行的:

![Jcve1](/img/in-post/cve_2018_1273/图片 18.png)

### 总结

也就是说漏洞的触发环境是在使用了类似于`@ModelAttribute UserForm2 userForm`或者`UserForm2 userFor`这种form表单接口获取前端数据。然后在对数据进行对象绑定的时候使用SpEl解析导致了表达式注入。从而造成了命令执行。还有其它获取数据的方法可以都去试试看会不会触发。暂时测试@RequestParam应该没有该问题

### 修复方案



- 2.0.x users should upgrade to 2.0.6


- 1.13.x users should upgrade to 1.13.11


- Older versions should upgrade to a supported branch

### 参考链接

1. [https://mp.weixin.qq.com/s?__biz=MzU0NzYzMzU0Mw==&mid=2247483666&idx=1&sn=91e3b2aab354c55e0677895c02fb068c&from=1084195010&wm=20005_0002&weiboauthoruid=5458358938](https://mp.weixin.qq.com/s?__biz=MzU0NzYzMzU0Mw==&mid=2247483666&idx=1&sn=91e3b2aab354c55e0677895c02fb068c&from=1084195010&wm=20005_0002&weiboauthoruid=5458358938)
2. [https://github.com/spring-projects/spring-data-commons/commit/ae1dd2741ce06d44a0966ecbd6f47beabde2b653](https://github.com/spring-projects/spring-data-commons/commit/ae1dd2741ce06d44a0966ecbd6f47beabde2b653)
3. [http://www.moonsec.com/post-701.html](http://www.moonsec.com/post-701.html)
4. [https://www.cnblogs.com/best/p/5748105.html](https://www.cnblogs.com/best/p/5748105.html)
5. [https://zhuanlan.zhihu.com/p/28667845](https://zhuanlan.zhihu.com/p/28667845)
6. [https://blog.csdn.net/li_xiao_ming/article/details/8349115](https://blog.csdn.net/li_xiao_ming/article/details/8349115)





