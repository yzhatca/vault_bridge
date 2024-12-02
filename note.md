2. 什么是 STS-based Secret Token？
STS-based Secret Token 是一种通过 STS 生成的临时访问令牌，用于授权对敏感资源（如数据库、对象存储、API 等）的访问。

生成和使用流程
请求 STS Token：

应用或用户通过 STS 服务请求临时凭证。
STS 验证请求的身份（例如 IAM 用户或角色）。
生成临时凭证：

STS 生成一个 Token (令牌)，包括：
Access Key: 访问密钥。
Secret Key: 密钥。
Session Token: 会话令牌。
返回的凭证具有有限的有效期（例如 1 小时）。
访问资源：

应用使用生成的凭证（Access Key、Secret Key 和 Session Token）访问目标资源。
凭证失效：

一旦凭证过期，应用必须重新请求新的 STS Token。
示例：AWS STS Token
通过 AWS CLI 或 SDK 请求 STS Token：

bash
Copy code
aws sts assume-role \
    --role-arn "arn:aws:iam::123456789012:role/MyRole" \
    --role-session-name "MySession"
返回结果：

json
Copy code
{
  "Credentials": {
    "AccessKeyId": "ASIAEXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "SessionToken": "FQoGZXIvYXdz...",
    "Expiration": "2024-01-01T12:34:56Z"
  }
}
AccessKeyId 和 SecretAccessKey：临时访问密钥。
SessionToken：标识当前会话的令牌。
Expiration：凭证过期时间。