# Keycloak (Quarkus 25.x.x) Phone Provider

此项目原作者并不是我，项目源地址：https://github.com/cooperlyt/keycloak-phone-provider

我们团队是在：https://github.com/cooperlyt/keycloak-phone-provider/tree/10.0.2

也就是使用Keycloak的11.0.3版本作为基线开发的版本基础上为了做定制化需求做了二开，加入了人机验证geetest，国际区号选择功能并使其兼容了Keycloak 25版本。

本插件运行环境要求：
+ Keycloak 25.x.x
+ Java 21

## 项目前端
前端项目地址：https://gitee.com/Dracowyn/keycloak-phone-provider-frontend

## 主要功能
~~+ 支持多种短信服务商~~(这个没做，其它服务商可以参考keycloak-sms-provider-dummy的代码去实现)
+ 支持国际区号选择
+ 支持人机验证(极验)
+ 支持短信验证码重置密码
+ 支持短信验证码认证
+ 支持自动创建用户
+ 支持手机号注册
+ 支持只允许用手机号登录
+ 支持注册时添加用户属性与redirect_uri参数
+ 支持归属地黑名单检测
+ 支持自定义短信模板
+ 支持自定义短信签名

## 客户端

此为原作者的安卓手机客户端项目 [KeycloakClient](https://github.com/cooper-lyt/KeycloakClient) 

## 使用方法

### 安装教程

#### 1. 添加模块
```bash
# 编译后将target/providers目录中的文件拷贝到Keycloak根目录下的providers即可
# 注意：除了target/providers/keycloak-captcha-provider-recaptcha.jar（因为这个没做适配）
cp target/providers/*.jar $KEYCLOAK_HOME/providers/
```

#### 2. 配置keycloak.conf
在keycloak根目录下conf/keycloak.conf添加以下信息：

```properties
# 短信发送服务商
spi-phone-provider-config-sender-service=Aliyun
# 验证码有效期（秒）
spi-phone-provider-config-token-expires=300
# 默认区号
spi-phone-provider-config-default-areacode=86
# 区号配置信息
spi-phone-provider-config-areacode-config=${kc.home.dir:}/conf/areacode.json
# 锁定区号
spi-phone-provider-config-area-locked=false
```

#### 3. 设置短信模板ID、短信签名、accessKeyID、accessSecret
```properties
# 短信验证码模板
spi-message-sender-service-aliyun-DEFAULT_TEMPLATE=你的短信模板ID
# 短信签名
spi-message-sender-service-aliyun-DEFAULT_SIGNNAME=你的短信签名
# 阿里云ID与Key
spi-message-sender-service-aliyun-access-key-id=你的AccessKeyId
spi-message-sender-service-aliyun-access-secret=你的AccessKeySecret
```

#### 4. 设置极验ID和key
```properties
# 极验ID和key
spi-captcha-service-geetest-id=你的极验ID
spi-captcha-service-geetest-key=你的极验Key
```

#### 5. 设置号码归属地黑名单检测（可选）
```properties
# 是否开启号码归属地黑名单检测
spi-phone-provider-config-location-verify=true
# 号码归属地检测APPCODE
# 用的是阿里云的手机号码归属地查询服务
# 购买地址：https://market.aliyun.com/products/57126001/cmapi022206.html
spi-phone-provider-config-location-appcode=你的APPCODE
# 号码归属地黑名单（中文务必使用unicode编码）英文逗号分隔
spi-phone-provider-config-location-black-list=\u865a\u62df
```

### 配置认证流程

#### 手机短信OTP认证

1. 在管理控制台进入 **Authentication(身份验证)** 页面
2. 复制 **Browser** 流程并重命名为 **Browser with Phone**
3. 在菜单中添加执行器，选择 `OTP Over SMS` 作为新的执行器
4. 将此流程副本绑定为默认的浏览器流程
5. 在 **Required Actions(必需的操作)** 标签页开启 `Update Phone Number` 和 `Configure OTP over SMS` 操作

#### 仅使用手机号登录或通过端点获取访问令牌

在 **Authentication > Flows** 下：
+ 复制 'Direct Grant' 流程为 'Direct grant with phone' 流程
+ 在 'Provide Phone Number' 行点击 'Actions > Add execution'
+ 在 'Provide Verification Code' 行点击 'Actions > Add execution'  
+ 删除或禁用其他项目
+ 将 'Provide Phone Number' 和 'Provide Verification Code' 都设置为 'REQUIRED'

在 **Clients > $YOUR_CLIENT > Authentication Flow Overrides** 或 **Authentication > Bindings** 下：
将 Direct Grant Flow 设置为 'Direct grant with phone'

#### 任何手机号码认证（如果用户不存在则通过手机号创建用户）

在 **Authentication > Flows** 下：
+ 复制 'Direct Grant' 流程为 'Direct grant everybody with phone' 流程
+ 在 'Authentication Everybody By Phone' 行点击 'Actions > Add execution'
+ 删除或禁用其他项目
+ 将 'Authentication Everybody By Phone' 设置为 'REQUIRED'

在 **Clients > $YOUR_CLIENT > Authentication Flow Overrides** 或 **Authentication > Bindings** 下：
将 Direct Grant Flow 设置为 'Direct grant everybody with phone'

#### 重置凭据
待编写

#### 手机号注册支持

在 **Authentication > Flows** 下：
+ 从注册创建流程：
  复制 'Registration' 流程为 'Registration fast by phone' 流程

+ （可选）将手机号用作新用户的用户名：
  删除或禁用 'Registration User Creation'
  在 'Registration Fast By Phone Registration Form > Actions > Add execution' 中添加 'Registration Phone As Username Creation'
  将此项移动到第一位

+ 将手机号添加到配置文件：
  在 'Registration Fast By Phone Registration Form > Actions > Add execution' 中添加 'Phone Validation'

+ （可选）隐藏除手机号外的所有其他字段：
  在 'Registration Fast By Phone Registration Form > Actions > Add execution' 添加 'Registration Least'

+ （可选）读取查询参数并添加到用户属性：
  在 'Registration Fast By Phone Registration Form > Actions > Add execution' 中添加 'Query Parameter Reader'
  在 'Registration Fast By Phone Registration Form > Actions > configure' 中配置接受的参数名

+ （可选）隐藏密码字段：
  删除或禁用 'Password Validation'

将所有添加的项目设置为必需(Required)。

在 **Authentication > Bindings** 下：
将 Registration Flow 设置为 'Registration fast by phone'

在 **Realm Settings > Themes** 下：
将 Login Theme 设置为 'phone'

## 认证设置

### 浏览器手机认证
![](https://i.imgur.com/5UTcWXN.png)

### 手机号注册
![](https://i.imgur.com/vQT4gSm.png)

### 手机重置凭据
![](https://i.imgur.com/R7cul0l.png)

### 测试注册链接
```
http://<地址>/realms/<域名>/protocol/openid-connect/registrations?client_id=<客户端ID>&response_type=code&scope=openid%20email&redirect_uri=<重定向URI>
```

## API端点说明

您将获得2个额外的端点，这些端点对于从自定义应用程序进行验证非常有用：

+ `GET /realms/{realmName}/sms/verification-code?phoneNumber=+8613800138000` (请求号码验证，无需认证)
+ `POST /realms/{realmName}/sms/verification-code?phoneNumber=+8613800138000&code=123456` (验证过程，用户必须已认证)

您还将获得2个额外的端点，用于从自定义应用程序获取访问令牌：

+ `GET /realms/{realmName}/sms/authentication-code?phoneNumber=+8613800138000` (请求号码验证，无需认证)
+ `POST /realms/{realmName}/protocol/openid-connect/token`
  ```
  Content-Type: application/x-www-form-urlencoded
  grant_type=password&phone_number=$PHONE_NUMBER&code=$VERIFICATION_CODE&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET
  ```

然后使用验证码认证流程和代码来获取访问码。

## 感谢

部分代码基于这两个项目中的现有代码编写：[keycloak-sms-provider](https://github.com/mths0x5f/keycloak-sms-provider) 和 [keycloak-phone-authenticator](https://github.com/FX-HAO/keycloak-phone-authenticator)。如果盲写编写所有这些提供程序，我肯定会遇到很多问题。谢谢！
