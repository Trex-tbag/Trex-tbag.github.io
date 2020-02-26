---
layout:     post
title:      "JQuery-File-Upload CVE-2018-9206 任意文件上传漏洞分析"
subtitle:   "JQuery-File-Upload CVE-2018-9206 任意文件上传漏洞分析"
date:       2018-07-19 12:00:00
author:     "T-bag"
header-img: "img/post-bg-unix-linux.jpg"
header-mask: 0.3
catalog:    true
tags:
    - web安全
    - 漏洞分析
    - JQuery-File-Upload
---

## 前言

jQuery-File-Upload是GitHub上非常受欢迎的jQuery项目，star数不下100个，在近期的版本中进行了两次安全修复，对CVE-2018-9206 任意文件上传漏洞及其绕过进行了修复

## 漏洞原理

在jQuery-File-Upload v9.22.1的之前的版本中，是默认允许上传任意类型的文件，而使用.htaccess对 `jQuery-File-Upload/server/php/files`这个上传目录下的文件限制执行，只允许存在GIF，JPEG，PNG后缀文件。但是自Apache版本2.3.9起，默认情况下禁用.htaccess支持，所以在失去了.hatches文件配置的防护之后，导致可以执行`jQuery-File-Upload/server/php/files`下的任意类型文件。
而在v9.22.1版本中 blueimp对其进行一次修复，限制了上传文件类型GIF，JPEG，PNG，但是可以上传`example.php.jpg`的文件绕过验证，在v9.24.1对此进行了修复。

## 漏洞复现

### 版本 < v9.22.1复现

### 环境搭建

在Apache2.3.9以上的版本中AllowOverride，默认设置为node，及不允许.htaccess覆写

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F99a75e9b-246e-4a8b-a9b8-7d456c4129a8/E6D0DA14-0BD1-4901-ADDF-2F0A6D132416.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F99a75e9b-246e-4a8b-a9b8-7d456c4129a8/E6D0DA14-0BD1-4901-ADDF-2F0A6D132416.png)

如下面的httpd.conf中的配置， AllowOverride 设置为None

    <Directory "/Applications/XAMPP/xamppfiles/htdocs">
        Options Indexes FollowSymLinks ExecCGI Includes
        AllowOverride None
        Require all granted
    </Directory>

安装

    Apache/2.4.34 (Unix)
    
    git clone <https://github.com/blueimp/jQuery-File-Upload>
    git checkout e6f059023afdae3efe9ce66970745254caa80256 #回退到v9.22修复之前的版本，这里会退到v9.21.0

### 复现过程

访问 `http://127.0.0.1/jQuery-File-Upload/index.html`
复现过程较为简单，点击Add File 添加文件，然后点击Start 上传shell文件就可以了

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Ffdcf0e5c-4ab9-45af-871e-8907c5238f71/DF800A1E-0727-4DBD-B149-6A9502B50B7B.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Ffdcf0e5c-4ab9-45af-871e-8907c5238f71/DF800A1E-0727-4DBD-B149-6A9502B50B7B.png)

上传成功
[image:531AAB0B-7C07-4262-AF86-25ED6724B9F8-8220-00003F5EC60908B3/73369CA2-A4A9-4160-81C7-DD3351C68B03.png]

访问`http://127.0.0.1/jQuery-File-Upload/server/php/files/uploadtest.php`

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F65516d43-d2d9-47b1-983d-de44ef5dec65/73369CA2-A4A9-4160-81C7-DD3351C68B03.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F65516d43-d2d9-47b1-983d-de44ef5dec65/73369CA2-A4A9-4160-81C7-DD3351C68B03.png)

### v9.22.1 - v9.24.1复现

    git checkout 3e828564324cf5aea2b0d0c7f3a7a17996cb9a9a #版本会退到v9.24.0

Apacle的httpd.conf需要手动配置允许php解析。重启Apacle

    AddHandler php5-script .php
    LoadModule php5_module modules/libphp5.so

上传文件内容为`<?php phpinfo()?>`的`example.php.jpg`图片文件，

上传成功。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fd043916b-e051-43ab-b31e-99397625f98d/73369CA2-A4A9-4160-81C7-DD3351C68B03.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fd043916b-e051-43ab-b31e-99397625f98d/73369CA2-A4A9-4160-81C7-DD3351C68B03.png)

访问`http://127.0.0.1/jQuery-File-Upload/server/php/files/example.php.jpg`，可以看到代码执行了。

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F4c9b9b03-9b4a-494c-8d2f-cba8b2b9ce39/02C33BF3-7768-4DB3-935F-BB2363C8B709.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F4c9b9b03-9b4a-494c-8d2f-cba8b2b9ce39/02C33BF3-7768-4DB3-935F-BB2363C8B709.png)

## 简单分析

### < v9.22.1

v9.22.1的之前的版本中，默认允许上传任意类型的文件。直接看下面的上传处理函数片段，可以处理过程中调用了validate函数进行文件名验证。

    protected function handle_file_upload($uploaded_file, $name, $size, $type, $error,
                $index = null, $content_range = null) {
            $file = new \\stdClass();
            ... 
            $file->type = $type;
            //调用 validate 函数文件名验证
            if ($this->validate($uploaded_file, $file, $error, $index)) {
                ...
                if ($uploaded_file && is_uploaded_file($uploaded_file)) {
                    // multipart/formdata uploads (POST method uploads)
                    if ($append_file) {
                        file_put_contents(
                            $file_path,
                            fopen($uploaded_file, 'r'),
                            FILE_APPEND
                        );
                    } else {
                        move_uploaded_file($uploaded_file, $file_path);  //保存文件
                    }
                } 
                ...
            return $file;
        }

在validate中判断了允许的文件类型，不允许的话返会错误。

    if (!preg_match($this->options['accept_file_types'], $file->name)) {
                $file->error = $this->get_error_message('accept_file_types');
                return false;
            }

这里通过accept_file_types进行匹配，但在options的默认配置中，允许任意文件类型，所以导致可以上传任意文件

    'accept_file_types' => '/.+$/i',

而将上传文件的执行权限交给了.htaccess判断，默认只能解析gif jpg jpeg png格式的文件。

    SetHandler default-handler
    ForceType application/octet-stream
    Header set Content-Disposition attachment
    <FilesMatch "(?i)\\.(gif|jpe?g|png)$">
    	ForceType none
    	Header unset Content-Disposition
    </FilesMatch>
    Header set X-Content-Type-Options nosniff

而在Apache2.3.9版本之后，默认不能.htaccess，导致这一层防护失效，上传的shell文件也就可以解析了。

在v9.22.1中，对其进行了一次修复，对上传格式进行了限制。不允许的格式将会返回错误

    'accept_file_types' => '/\\.(gif|jpe?g|png)$/i' //只允许上传gif,jpg,jpeg,png后缀的文件

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fda946cfc-5c01-49a5-bb8b-e2832711963a/76685F01-6B1B-4EBE-836F-C7251B09C8F6.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fda946cfc-5c01-49a5-bb8b-e2832711963a/76685F01-6B1B-4EBE-836F-C7251B09C8F6.png)

### v9.22.1 - v9.24.0

在v9.22.1中修复的正则可以通过`example.php.jpg`格式进行绕过，但httpd.conf中需要进行设置才能解析为PHP

    AddHandler php5-script .php

在v9.24.1中对该绕过进行了修复，按照`.`号分割之后，在用`_`进行组合，确保文件格式为`example_php.jpg`的图片格式

![https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb6e79d17-e270-4572-9232-6151d0f39850/1D22030F-3DFA-4AC2-8E05-1ABE3C21CD69.png](https://www.notion.so/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb6e79d17-e270-4572-9232-6151d0f39850/1D22030F-3DFA-4AC2-8E05-1ABE3C21CD69.png)

## 修复方案

1. 升级到最新版本的jQuery-File-Upload
2. 使用官方提供的[示例配置](https://github.com/blueimp/jQuery-File-Upload/blob/master/SECURITY.md#apache-config)

## 参考

1. [https://github.com/blueimp/jQuery-File-Upload/blob/master/VULNERABILITIES.md#remote-code-execution-vulnerability-in-the-php-component](https://github.com/blueimp/jQuery-File-Upload/blob/master/VULNERABILITIES.md#remote-code-execution-vulnerability-in-the-php-component)
2. [https://github.com/lcashdol/Exploits/tree/master/CVE-2018-9206](https://github.com/lcashdol/Exploits/tree/master/CVE-2018-9206)