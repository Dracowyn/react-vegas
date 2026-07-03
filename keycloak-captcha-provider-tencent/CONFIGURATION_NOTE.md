# 腾讯云验证码配置说明

## 重要说明

### 关于 `captchaType` 参数

**`captchaType` 参数是可选的，通常不需要配置。**

#### 为什么不需要配置？

1. **在线配置**: 验证码类型（滑块、文字点选、图形点选等）是在腾讯云控制台创建验证码应用时配置的
2. **自动识别**: 腾讯云API会根据 `captchaAppId` 自动识别对应的验证码类型
3. **简化配置**: 减少配置项，降低配置错误的可能性

#### 什么时候需要配置？

只有在极少数特殊情况下，需要在API调用时强制指定验证码类型时，才配置此参数。

### 必需配置项

只需配置以下4个参数：

```properties
# Keycloak 25 配置文件 (conf/keycloak.conf)
spi-captcha-service-provider=tencent
spi-captcha-service-tencent-secret-id=YOUR_SECRET_ID
spi-captcha-service-tencent-secret-key=YOUR_SECRET_KEY
spi-captcha-service-tencent-captcha-app-id=YOUR_CAPTCHA_APP_ID
spi-captcha-service-tencent-app-secret-key=YOUR_APP_SECRET_KEY
```

## 配置步骤

### 1. 在腾讯云控制台创建验证码应用

1. 登录[腾讯云验证码控制台](https://console.cloud.tencent.com/captcha)
2. 创建新的验证码应用
3. **选择验证码类型**（滑块/文字点选/图形点选等）← 在这里配置，不在Keycloak中配置
4. 配置应用域名白名单
5. 获取以下信息：
   - `CaptchaAppId`: 验证码应用ID
   - `AppSecretKey`: 验证码应用密钥

### 2. 获取腾讯云API密钥

1. 访问[腾讯云API密钥管理](https://console.cloud.tencent.com/cam/capi)
2. 创建或查看现有密钥
3. 获取：
   - `SecretId`: API密钥ID
   - `SecretKey`: API密钥Key

### 3. 配置Keycloak

将获取的信息配置到Keycloak中（参考上面的必需配置项）。

## 配置示例

### 最小配置（推荐）

```properties
# conf/keycloak.conf
spi-captcha-service-provider=tencent
spi-captcha-service-tencent-secret-id=AKIDxxxxxxxxxxxxx
spi-captcha-service-tencent-secret-key=xxxxxxxxxxxxxxxxxxxxx
spi-captcha-service-tencent-captcha-app-id=2012345678
spi-captcha-service-tencent-app-secret-key=xxxxxxxxxxxxxxxxxxxxx
```

### 完整配置（包含可选项）

```properties
# conf/keycloak.conf
spi-captcha-service-provider=tencent

# 必需配置
spi-captcha-service-tencent-secret-id=AKIDxxxxxxxxxxxxx
spi-captcha-service-tencent-secret-key=xxxxxxxxxxxxxxxxxxxxx
spi-captcha-service-tencent-captcha-app-id=2012345678
spi-captcha-service-tencent-app-secret-key=xxxxxxxxxxxxxxxxxxxxx

# 可选配置（一般不需要）
# spi-captcha-service-tencent-captcha-type=9
# spi-captcha-service-tencent-endpoint=captcha.tencentcloudapi.com
# spi-captcha-service-tencent-fallback-on-error=false
```

## 验证码类型说明

虽然 `captchaType` 通常不需要配置，但了解各类型对应的值仍有帮助：

| 类型值 | 验证码类型 | 说明 |
|-------|----------|------|
| 9 | 滑块验证码 | 用户拖动滑块完成拼图 |
| 其他 | 其他类型 | 参考腾讯云文档 |

**注意**: 这些类型是在腾讯云控制台配置的，API会自动识别。

## 常见问题

### Q1: 为什么之前的文档要求配置 captchaType？

**A**: 这是一个可选参数，添加它是为了提供更多灵活性。但实际使用中，腾讯云会根据CaptchaAppId自动识别验证码类型，所以通常不需要配置。

### Q2: 如果我配置了 captchaType 会怎样？

**A**: 如果配置了，系统会使用配置的值。但如果不配置，腾讯云会自动识别，结果是一样的。

### Q3: 我在腾讯云控制台修改了验证码类型，需要修改Keycloak配置吗？

**A**: **不需要**。只要 `captchaAppId` 不变，验证码会自动使用新的类型，无需修改Keycloak配置。

### Q4: 什么情况下需要明确配置 captchaType？

**A**: 极少数情况：
- 腾讯云API的特殊要求
- 调试和测试特定类型
- 技术支持明确要求时

### Q5: 我的配置里有 captchaType，需要删除吗？

**A**: 不必删除，保留也没有问题。但新的部署建议省略此参数以简化配置。

## 代码实现

### 自动识别逻辑

```java
// 构建请求
DescribeCaptchaResultRequest request = new DescribeCaptchaResultRequest();

// CaptchaType是可选的，腾讯云会根据CaptchaAppId自动识别验证码类型
// 如果需要明确指定类型，可以配置captchaType参数
String captchaTypeStr = config.get("captchaType");
if (captchaTypeStr != null) {
    request.setCaptchaType(Long.parseLong(captchaTypeStr));
}

request.setTicket(ticket);
request.setRandstr(randstr);
request.setUserIp(userIp);
request.setCaptchaAppId(Long.parseLong(captchaAppId));
request.setAppSecretKey(appSecretKey);
```

### 优势

1. **代码更简洁**: 减少不必要的配置处理
2. **配置更简单**: 用户只需关注必需参数
3. **更易维护**: 减少配置错误的可能性
4. **自动适配**: 腾讯云控制台修改后自动生效

## 迁移指南

如果你已经在使用包含 `captchaType` 的配置：

### 现有配置（可以继续使用）

```properties
spi-captcha-service-tencent-captcha-type=9
```

### 简化后的配置（推荐）

```properties
# 不配置 captchaType，让腾讯云自动识别
```

**无需立即修改现有配置**，但新部署建议采用简化配置。

## 参考资源

- [腾讯云验证码控制台](https://console.cloud.tencent.com/captcha)
- [腾讯云验证码文档](https://cloud.tencent.com/document/product/1110/36334)
- [腾讯云API密钥管理](https://console.cloud.tencent.com/cam/capi)

---

**最后更新**: 2026-01-14  
**版本**: 1.2.1+
