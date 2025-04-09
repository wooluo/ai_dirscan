# AI DirScan - 智能目录扫描与漏洞分析工具

🔗 **项目地址**: [https://github.com/Elitewa/ai_dirscan](https://github.com/Elitewa/ai_dirscan)

## 📖 项目简介

AI DirScan 是基于 **MCP协议** 的新一代智能安全扫描工具，创新性地将传统目录爆破工具 dirsearch 与大型语言模型（LLM）相结合，实现：

✨ **核心功能**  
✅ 自动化目录扫描与状态码分析  
✅ 智能结果解析与漏洞关联分析  
✅ 主流大模型兼容支持（需自行配置API）  

🚀 **技术亮点**  
- 采用 **FastMCP** 框架实现高并发处理
- 支持 200/403/500 等状态码智能过滤
- 全流程扫描日志追溯机制

## 🛠️ 快速开始

### 环境要求
- Python 3.10+
- UV 虚拟环境工具
- 支持的大模型API密钥

### 安装步骤
```bash
# 克隆仓库
git clone https://github.com/Elitewa/ai_dirscan.git
cd ai_dirscan

# 创建虚拟环境
uv venv .venv

# 激活环境
（macOS/Linux）
source .venv/bin/activate
（Windows）
.venv\Scripts\activate.bat

# 安装依赖
uv pip install -e .
cd dirsearch
uv pip install -r requirements.txt
uv pip install setuptools
# 对接客户端
    "scan_dir": {
      "command": "uv",
      "args": [
        "--directory",
        "your_path/ai_dirscan/",
        "run",
        "main.py"
      ]
    }