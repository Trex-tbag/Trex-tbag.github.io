---
layout:     post
title:      "Django CVE-2019-14234 SQL Injection分析"
subtitle:   "Django CVE-2019-14234 SQL Injection分析"
date:       2019-09-10 12:00:00
author:     "T-bag"
header-img: "img/post-bg-unix-linux.jpg"
header-mask: 0.3
catalog:    true
tags:
    - web安全
    - django
    - 漏洞分析
    - python安全
---

## 前言

近期，Django进行了安全更新，这里对其CVE-2019-14234的SQL注入漏洞进行分析。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa33d7e4d-c15f-4334-bf0b-5f0ae0abda33/4B8B9E8D-DA68-4AE7-B51F-8786C2FA17A3.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa33d7e4d-c15f-4334-bf0b-5f0ae0abda33/4B8B9E8D-DA68-4AE7-B51F-8786C2FA17A3.png)

## 环境搭建

配置相关数据库信息

    DATABASES = {
        'default':{
            'ENGINE':'django.db.backends.postgresql_psycopg2',
            'NAME':'test',#数据库名字
            'USER':'test',#登录用户名
            'PASSWORD':'password',
            'HOST':'127.0.0.1',
            'PORT':'5432',
        },
        'TEST': {
               'NAME': 'my_test', # 用于测试
        }
    }

Django APP中添加model

    from django.db import models
    from django.contrib.postgres.fields import JSONField
    
    class User(models.Model):
        name = models.CharField(max_length=100)
        info = JSONField()

然后生成迁移脚本，并生成对应数据表了

    python3 manage.py makemigrations
    python3 manage.py migrate

## 漏洞复现

直接进入Django shell中进行操作

    python3 manage.py shell
    Python 3.6.5 (default, Apr 16 2018, 17:17:10)
    [GCC 4.2.1 Compatible Apple LLVM 9.0.0 (clang-900.0.39.2)] on darwin
    Type "help", "copyright", "credits" or "license" for more information.
    (InteractiveConsole)
    >>> from cve_2019_14234.models import User
    >>> user = User(name="test", info={'name':'xiaoxiao','age':21})
    >>> user.save()
    >>> info = User.objects.filter(**{"info__name'":"xiaoxiao"})
    >>> info[0].name

可以看到输出了报错语句，说明存在注入。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F37b41b99-6251-4c90-b330-fb893ca0381e%2FE87FD959-6F91-4489-8889-A7827A2C0DB4.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F37b41b99-6251-4c90-b330-fb893ca0381e%2FE87FD959-6F91-4489-8889-A7827A2C0DB4.png)

## 单元测试

[Django单元测试基础知识 - 简书](https://www.jianshu.com/p/34267dd79ad6)

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa6737152-d762-4d21-8cef-bcea0ab98a31%2F7DD5AD67-B7C5-4946-A1DE-6B40E292CAB7.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa6737152-d762-4d21-8cef-bcea0ab98a31%2F7DD5AD67-B7C5-4946-A1DE-6B40E292CAB7.png)

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F805da70a-e83a-4bd5-9b3d-2d1f18b6a744%2FBFDC7560-97D6-4382-8180-446A3D8590CF.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F805da70a-e83a-4bd5-9b3d-2d1f18b6a744%2FBFDC7560-97D6-4382-8180-446A3D8590CF.png)

## 漏洞分析

观察payload，猜测应该是在拼接where语句的时候没有做处理，导致注入产生。所以这里在`db.model.sql.compiler.execute_sql`编译执行SQL语句函数中下断点，这里将会调用`as_sql()`函数，用于生成SQL语句。

    try:
        sql, params = self.as_sql()
        if not sql:
            raise EmptyResultSet
    except EmptyResultSet:
        ...

as_sql里将会处理self.where参数，这里的self.where为whereNode对象，将会调用compile函数对其编译生成SQL语句。
`where, w_params = self.compile(self.where) if self.where is not None else ("", [])`

whereNode对象如下。该对象包含查找表达式子对象，存放在children列中。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb051fed1-7b78-4365-a26f-eed848fe121a%2F4C29C19C-9C5A-4EDE-9678-C63216BD5AAA.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb051fed1-7b78-4365-a26f-eed848fe121a%2F4C29C19C-9C5A-4EDE-9678-C63216BD5AAA.png)

说到查找表达式的话，我们需要了解Django`Lookup API`。该API主要用于构建WHERE数据库查询子句。其有个组件即Query Expression (查找表达式)。
而Django的的Lookup类 和Transform类，便遵循于这种查找表达式。
例如我们此时测试的payload `filter(**{"info__name'":"xiaoxiao"})` 将其转换为LookUp表达式之后就变成了，`filter(info__name'__exact = "xiaoxiao"})`。

官方文档给出的Lookup类支持的查找表达式格式为:`<lhs>__<lookup_name>=<rhs>`
对应对应我们的payload看下：

    lhs => info__name' 想要查找的内容
    rhs => "xiaoxiao" 与要查找的内容进行对比
    lookup_name => exact 对比方法，精确查找即等于

`filter(info__name'__exact = "xiaoxiao"})`，排除报错的话，该表达式的就相当于匹配info表中name属性值为xiaoxiao的数据。

对whereNode进行处理的函数，会遍历whereNode的children表中的表达式对象对象，这里的子对象为JSONExact，也就是我们的payload表达式对象。`contrib.postrges.fields.jsonb`中对其进行了注册为lookup对象。

    JSONField.register_lookup(lookups.JSONExact)

下面是LookUp类的as_sql函数

    def as_sql(self, compiler, connection):
        lhs_sql, params = self.process_lhs(compiler, connection)
        rhs_sql, rhs_params = self.process_rhs(compiler, connection)
        params.extend(rhs_params)
        rhs_sql = self.get_rhs_op(connection, rhs_sql)
        return '%s %s' % (lhs_sql, rhs_sql), params

其返回格式如下。

    (lhs_sql) = %s

上面的lhs_sql即lhs生成的SQL语句，而`lhs => info_name'` 为对应的表达式对象为`KeyTransform()` KeyTransform()为`contrib.postrges.fields.jsonb`重写的Transform对象。其as_sql函数如下，这里语句生成直接采用字符串连接的方式，导致最后生成的payload，单引号溢出，最终报错。

    def as_sql(self, compiler, connection):
        key_transforms = [self.key_name]
        previous = self.lhs
        while isinstance(previous, KeyTransform):
            key_transforms.insert(0, previous.key_name)
            previous = previous.lhs
        lhs, params = compiler.compile(previous)
        if len(key_transforms) > 1:
            return "(%s %s %%s)" % (lhs, self.nested_operator), [key_transforms] + params
        try:
            int(self.key_name)
        except ValueError:
            lookup = "'%s'" % self.key_name
        else:
            lookup = "%s" % self.key_name
        return "(%s %s %s)" % (lhs, self.operator, lookup), params

生成的lhs_sql如下。可以看到这里单引号已经溢出了

    ("cve_2019_14234_user"."info" -> 'name'')

而最终生成的payload 如下。

    SELECT "cve_2019_14234_user"."id", "cve_2019_14234_user"."name", "cve_2019_14234_user"."info" FROM "cve_2019_14234_user" WHERE ("cve_2019_14234_user"."info" -> 'name'') = "xiaoxiao" LIMIT 1

## 修复

官方补丁的修复方式是把lookup与后面的param进行拼接，和参数一起进行参数化查询，防止注入。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F33096831-f9eb-48df-9294-b461ee4e85b5%2F30FF5436-83A1-499B-9E7A-ABC07A503226.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F33096831-f9eb-48df-9294-b461ee4e85b5%2F30FF5436-83A1-499B-9E7A-ABC07A503226.png)

## 总结

pass

## 参考

[https://www.leavesongs.com/PENETRATION/django-jsonfield-cve-2019-14234.html](https://www.leavesongs.com/PENETRATION/django-jsonfield-cve-2019-14234.html)