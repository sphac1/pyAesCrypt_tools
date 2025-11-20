# pyAesCrypt 暴力破解工具

一个高性能的多进程暴力破解工具，用于解密 pyAesCrypt 加密的文件。自动处理虚拟环境设置并支持多种攻击模式。

## 功能特点

- 🚀 **多进程并行处理** - 最大化性能
- 🛡️ **自动虚拟环境设置** - 兼容 Kali 2024+
- 📦 **多种攻击模式** - 字典、暴力和掩码攻击
- ⚡ **快速常见密码测试** - 快速获得结果
- 📊 **实时进度统计** - 带速度监控
- 💾 **可配置临时目录** - 优化 I/O 性能
- 🎨 **彩色编码输出** - 更好的可读性

## 快速开始

```
# 使脚本可执行
chmod +x pyAesCrypt.py

# 使用常见密码快速测试
python3 pyAesCrypt.py -f encrypted_file.aes --quick

# 字典攻击
python3 pyAesCrypt.py -f encrypted_file.aes -w passwords.txt

# 暴力破解数字
python3 pyAesCrypt.py -f encrypted_file.aes -b -c "0123456789" -l "4-8"
```



## 安装

工具在首次运行时自动设置虚拟环境并安装依赖项。无需手动安装！

## 使用方法

### 基本语法

```
python3 pyAesCrypt.py -f <加密文件> [选项] [攻击模式]
```



### 攻击模式

#### 1. 快速常见密码测试

```
python3 pyAesCrypt.py -f encrypted_file.aes --quick
```



#### 2. 字典攻击

```
python3 pyAesCrypt.py -f encrypted_file.aes -w passwords.txt
```



#### 3. 暴力破解攻击

```
# 仅数字，长度4-8
python3 pyAesCrypt.py -f encrypted_file.aes -b -c "0123456789" -l "4-8"

# 字母数字组合
python3 pyAesCrypt.py -f encrypted_file.aes -b -c "abcdefghijklmnopqrstuvwxyz0123456789" -l "3-6"
```



#### 4. 掩码攻击

```
# 2个小写字母 + 2个数字
python3 pyAesCrypt.py -f encrypted_file.aes -m "?l?l?d?d"

# 1个大写字母 + 3个数字 + 1个特殊字符
python3 pyAesCrypt.py -f encrypted_file.aes -m "?u?d?d?d?s"
```



### 掩码语法

- `?l` - 小写字母 (a-z)
- `?u` - 大写字母 (A-Z)
- `?d` - 数字 (0-9)
- `?s` - 特殊字符 (!@#$% 等)
- `?a` - 所有字符 (字母 + 数字 + 特殊字符)

## 命令行选项

### 必需参数

- `-f, --file` - 目标加密文件（必需）

### 输出选项

- `-o, --output` - 解密内容的输出文件（默认：decrypted.bin）
- `--tmp` - 进程文件的临时目录（推荐：/dev/shm 用于 tmpfs）

### 性能选项

- `-p, --processes` - 工作进程数量（默认：CPU 核心数）
- `-v, --verbose` - 启用详细输出

### 攻击模式选项

- `--quick` - 首先快速测试常见密码
- `-w, --wordlist` - 字典攻击的字典文件
- `-b, --brute` - 启用暴力破解模式
- `-m, --mask` - 掩码攻击的模式
- `-c, --charset` - 暴力破解的字符集（默认："0123456789"）
- `-l, --length` - 密码长度范围 "最小-最大"（默认："1-4"）

### 实用工具选项

- `--create-wordlist` - 创建示例字典文件

## 示例

### 基本用法

```
# 使用常见密码快速测试
python3 pyAesCrypt.py -f backup.zip.aes --quick

# 使用自定义字典进行字典攻击
python3 pyAesCrypt.py -f config.aes -w my_passwords.txt -o decrypted_config.txt

# 高性能暴力破解
python3 pyAesCrypt.py -f database.aes -b -c "0123456789" -l "6-8" -p 8 --tmp /dev/shm
```



### 高级场景

```
# 综合攻击策略
# 1. 首先尝试快速常见密码
python3 pyAesCrypt.py -f target.aes --quick

# 2. 如果快速模式失败，尝试字典攻击
python3 pyAesCrypt.py -f target.aes -w /usr/share/wordlists/rockyou.txt

# 3. 最后，使用最优设置进行暴力破解
python3 pyAesCrypt.py -f target.aes -b -c "abcdefghijklmnopqrstuvwxyz0123456789" -l "4-6" -p 12
```



### 性能调优

```
# 在多核系统上获得最大性能
python3 pyAesCrypt.py -f large_file.aes -w big_wordlist.txt -p 16 --tmp /dev/shm

# 一般使用的平衡性能
python3 pyAesCrypt.py -f medium_file.aes -w common_passwords.txt -p 8

# 低资源模式
python3 pyAesCrypt.py -f small_file.aes -b -c "0123456789" -l "1-4" -p 2
```



## 性能提示

1. **尽可能使用 tmpfs 作为临时目录**：

   ```
   --tmp /dev/shm
   ```

   

2. **根据 CPU 调整进程数量**：

   - 4-8 核心：`-p 4`
   - 8-16 核心：`-p 8`
   - 16+ 核心：`-p 12-16`

3. **从快速模式开始** 以快速捕获简单密码

4. **使用适当的字符集** 以减少搜索空间

## 输出示例

```
[*] 快速测试 25 个常见密码...
[+] 找到密码：'backup2024'

=== 攻击完成 ===
总尝试次数：15
总时间：00:00:03
平均速度：5 密码/秒
状态：成功找到密码！
```



## 故障排除

### 常见问题

1. **虚拟环境创建失败**
   - 确保安装了 Python 3.8+
   - 检查当前目录的磁盘空间
   - 如果有权限问题，使用 `sudo` 运行
2. **性能缓慢**
   - 使用 `--tmp /dev/shm` 获得更快的 I/O
   - 增加 `-p` 值以使用更多 CPU 核心
   - 对字典文件使用 SSD 存储
3. **未找到密码**
   - 尝试不同的字符集
   - 增加密码长度范围
   - 使用更大、更全面的字典

### 调试模式

要进行故障排除，请使用详细输出运行：

```
python3 pyAesCrypt.py -f target.aes -w wordlist.txt -v
```



## 法律和道德使用

此工具适用于：

- 安全研究和教育
- 授权的渗透测试
- 个人数据恢复
- 合法的取证调查

**⚠️ 警告**：仅对您拥有或获得明确测试权限的文件使用。未经授权的解密尝试可能违反法律法规。

## 支持

对于问题和疑问：

1. 查看上面的故障排除部分
2. 查看脚本的帮助：`python3 pyAesCrypt.py --help`
3. 确保使用正确的文件格式（由 pyAesCrypt 加密的 .aes 文件）

------

**注意**：首次运行可能需要更长时间，因为它会设置虚拟环境。后续运行会更快。
