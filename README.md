# GraduationProject
毕业设计：基于OpenIOC的网络威胁情报收集及管理

系统设计思路:

（1）采用cuckoo（杜鹃沙箱，一个通过将恶意程序放入虚拟机中自动分析来自动出报告的系统，最主流的开源恶意程序分析系统）进行威胁情报采集；

（2）使用python进行编程，调用cuckoo的API，将cuckoo中的威胁情报转换成OpenIOC格式；

（3）使用openioc官方的mandiant IOCe进行威胁情报查看和管理；

（4）使用威胁情报中心MISP进行威胁情报的整合。

![image](https://github.com/NikolaGareth/GraduationProject/blob/master/process.png)

## 前置要求

### 系统要求
- **Python 版本**: Python 3.6 或更高版本
- **操作系统**: Linux、macOS 或 Windows

### 依赖安装

1. **克隆项目**：
```bash
git clone <repository-url>
cd CuckooToOpenIOC
```

2. **安装 Python 依赖**：
```bash
pip install -r requirements.txt
```

或手动安装：
```bash
pip install ioc-writer>=0.3.3
pip install python-dotenv>=0.19.0  # 可选，用于更方便地加载 .env 文件
```

3. **验证安装**：
```bash
python -c "import ioc_writer; print('依赖安装成功')"
```

### Cuckoo Sandbox 要求
- 需要一个运行中的 Cuckoo Sandbox 实例
- Cuckoo API 必须可访问（默认端口 1337）
- 需要有效的 API 认证令牌

## 安全配置说明

### 配置文件

项目包含一个 `config.json` 配置文件，用于管理各种检测规则和列表：

- **suspicious_imports**: 可疑的PE导入函数列表（用于检测恶意行为）
- **good_pe_sections**: 正常的PE节名称列表
- **pe_version_fields**: PE文件版本信息字段列表

您可以根据需要修改 `config.json` 来自定义检测规则。如果配置文件不存在或格式错误，程序会使用内置的默认配置并记录警告日志。

### 环境变量设置（必需）

为了安全起见，本项目使用环境变量来存储敏感配置信息。请按以下步骤配置：

1. 复制配置文件模板：
```bash
cp .env.example .env
```

2. 编辑 `.env` 文件，填入实际值：
```bash
# Cuckoo API 地址（强烈建议使用 HTTPS）
CUCKOO_API_URL=https://192.168.22.176:1337

# Cuckoo API 认证令牌
CUCKOO_API_TOKEN=your_actual_token_here

# IOC 文件输出目录（可选，默认为当前目录）
IOC_OUTPUT_DIR=/path/to/output

# SSL 证书验证（可选，开发环境可设为 true）
# 警告：生产环境不要禁用 SSL 证书验证
CUCKOO_ALLOW_SELF_SIGNED=false
```

3. 加载环境变量：
```bash
# Linux/macOS
export CUCKOO_API_URL='https://192.168.22.176:1337'
export CUCKOO_API_TOKEN='your_token'
export IOC_OUTPUT_DIR='/path/to/output'

# 或使用 python-dotenv（推荐）
# 安装后自动加载 .env 文件无需手动 export
```

### 使用方法

1. 确保 `config.json` 配置文件存在（已提供默认配置）
2. 设置必需的环境变量
3. 运行程序：

```bash
python openioc.py
```

程序会提示输入任务ID，只接受纯数字输入。

### 自定义配置

您可以编辑 `config.json` 文件来自定义检测规则。如果您想要创建本地覆盖配置而不修改原始文件，可以创建 `config.local.json`（此文件不会被提交到Git）：

```json
{
  "suspicious_imports": [
    "OpenProcess",
    "VirtualAllocEx",
    ...
  ],
  "good_pe_sections": [
    ".text",
    ".code",
    ...
  ],
  "pe_version_fields": [
    "FileVersion",
    "ProductName",
    ...
  ]
}
```

**配置优先级**：
1. `config.local.json`（如果存在）- 本地自定义配置，不会提交到版本控制
2. `config.json` - 默认配置，会提交到版本控制
3. 内置默认配置 - 如果上述文件都不存在或格式错误

### 安全改进说明

本版本包含以下安全修复：

✅ **P0 修复（已完成）**：
- 移除硬编码凭证，改用环境变量
- 添加 task_id 输入验证，防止 SSRF 和路径遍历攻击
- 添加 HTTP 协议安全警告，推荐使用 HTTPS
- 添加 SSL 证书验证，支持自签名证书（开发环境）
- 修复硬编码输出路径，改用配置

✅ **P1 修复（已完成）**：
- 改进所有异常处理，移除空的 `except: pass` 块
- 添加完整的 JSON 数据验证，使用 `safe_get()` 和 `safe_iter()` 函数防止 KeyError
- 改进正则表达式：
  - IP 地址验证确保每个段在 0-255 之间
  - Email 地址使用更严格的正则表达式
- 添加完整的日志记录系统：
  - 日志同时输出到控制台和 `openioc.log` 文件
  - 记录所有关键操作和错误信息
  - 便于调试和问题追踪
- 缓存频繁访问的嵌套结构，提高性能

✅ **P2 修复（已完成）**：
- 修复代码中的拼写错误
- 为所有函数添加完整的文档字符串（docstring）和类型提示
- 将硬编码列表提取到 `config.json` 配置文件：
  - 可疑PE导入函数列表
  - 正常PE节名称列表
  - PE版本信息字段列表
- 添加配置文件加载函数，支持降级到默认配置
- 代码结构优化和可维护性提升

✅ **其他改进**：
- 完善的错误处理和用户友好的错误提示
- 输出目录权限验证
- .gitignore 防止敏感配置文件和日志文件泄露
- 类型提示（Type Hints）提高代码可读性和 IDE 支持
- 数据验证和类型检查
- 配置驱动的架构，易于扩展和维护
- 创建 requirements.txt 方便依赖管理

### 安全注意事项

⚠️ **重要**：
- 不要在代码中硬编码认证令牌
- 生产环境必须使用 HTTPS 协议
- 生产环境必须启用 SSL 证书验证（不要设置 `CUCKOO_ALLOW_SELF_SIGNED=true`）
- 定期更换 API Token
- `.env` 文件已添加到 `.gitignore`，确保不会提交到版本控制系统
- 请妥善保管 API Token，不要分享给他人
- 建议在生产环境使用专门的密钥管理服务（如 HashiCorp Vault、AWS Secrets Manager）


