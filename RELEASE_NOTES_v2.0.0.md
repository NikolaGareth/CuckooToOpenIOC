# Release v2.0.0 - 安全加固与代码质量提升

## 🔒 安全加固与代码质量提升

这是一个重大安全更新版本，修复了所有已知的安全漏洞并大幅提升了代码质量。

### 🎯 主要改进

#### 🔒 安全改进
- ✅ 移除硬编码凭证，改用环境变量
- ✅ 添加 SSL/TLS 证书验证
- ✅ 防止 SSRF 和路径遍历攻击
- ✅ 完善的输入验证和数据清洗

#### 🚀 性能优化
- ⚡ 缓存频繁访问的嵌套数据结构
- ⚡ 优化列表迭代性能
- ⚡ 减少重复计算

#### 📝 代码质量
- 📖 完整的类型提示（Type Hints）
- 📖 详细的函数文档字符串
- 🛡️ 改进的异常处理机制
- ✨ 更严格的正则表达式验证

#### 📦 新增功能
- 🔍 新增 21 个恶意软件常用 API 检测规则
- 🔍 新增 9 个可疑 PE 节名称检测
- 📊 完整的日志记录系统
- ⚙️ 配置文件支持（config.json）

#### 📚 文档与配置
- 📄 requirements.txt 依赖管理
- 📄 .env.example 配置模板
- 📘 完善的 README 文档
- 🔐 改进的 .gitignore

### ⚠️ 破坏性变更

- **环境变量**：需要设置 `CUCKOO_API_URL` 和 `CUCKOO_API_TOKEN`
- **Python 版本**：要求 Python 3.6+
- **依赖安装**：需要运行 `pip install -r requirements.txt`

### 📖 迁移指南

#### 1. 安装依赖
```bash
pip install -r requirements.txt
```

#### 2. 配置环境变量
```bash
cp .env.example .env
# 编辑 .env 文件，填入实际的 Cuckoo API 配置
```

示例配置：
```bash
CUCKOO_API_URL=https://192.168.22.176:1337
CUCKOO_API_TOKEN=your_actual_token_here
IOC_OUTPUT_DIR=/path/to/output
CUCKOO_ALLOW_SELF_SIGNED=false
```

#### 3. 运行程序
```bash
# Linux/macOS
export $(cat .env | xargs)
python openioc.py

# 或使用 python-dotenv（推荐）
pip install python-dotenv
python openioc.py
```

详细说明请查看 [README.md](https://github.com/NikolaGareth/CuckooToOpenIOC/blob/master/README.md)

### 📊 统计数据

- **6 个文件变更**
- **748 行新增**
- **95 行删除**
- **净增加 653 行代码**

#### 新增文件
- `.env.example` - 环境变量配置模板（66 行）
- `config.json` - 检测规则配置文件（100 行）
- `requirements.txt` - Python 依赖管理（18 行）

#### 修改文件
- `.gitignore` - 防止敏感信息泄露（+24 行）
- `README.md` - 完善文档（+179 行）
- `openioc.py` - 核心代码重构（+361 行, -95 行）

### 🔧 技术细节

#### 新增检测规则

**恶意软件常用 API（新增 21 个）**：
- `NtQuerySystemInformation`, `RtlAdjustPrivilege`
- `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`
- `Module32First`, `Module32Next`
- `VirtualProtectEx`, `SetThreadContext`, `GetThreadContext`
- `ResumeThread`, `SuspendThread`, `TerminateProcess`
- `CreateProcessAsUser`, `LogonUser`, `ImpersonateLoggedOnUser`
- `NetUserAdd`, `NetLocalGroupAddMembers`
- `CryptAcquireContext`, `CryptEncrypt`, `CryptDecrypt`

**PE 节名称检测**：
- 正常节：13 个（`.text`, `.data`, `.rdata`, 等）
- 可疑节：9 个（`.UPX`, `packed`, `.aspack`, 等）

### 🛡️ 安全注意事项

1. **不要在代码中硬编码凭证**
2. **生产环境必须使用 HTTPS**
3. **生产环境必须启用 SSL 证书验证**
4. **定期更换 API Token**
5. **妥善保管 `.env` 文件**
6. **建议使用专门的密钥管理服务**（如 HashiCorp Vault、AWS Secrets Manager）

### 🙏 致谢

感谢所有代码审查中提供建议的人员。

---

**完整变更日志**：[v1.0...v2.0.0](https://github.com/NikolaGareth/CuckooToOpenIOC/compare/1.0...v2.0.0)

**标签**：`security`, `enhancement`, `breaking-change`, `documentation`
