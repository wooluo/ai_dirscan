import json
import subprocess
from datetime import datetime
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# 初始化 MCP 服务
mcp = FastMCP("ai_dirscan")

# 配置存储路径
SCAN_RESULT_DIR = Path("scan_results")
SCAN_RESULT_DIR.mkdir(exist_ok=True)  # 自动创建存储目录[5](@ref)

@mcp.tool()
def scan_dir(url: str) -> str:
    """
    可以用于扫描网站的目录
    执行目录扫描并返回200状态码的路径
    参数：
        url: 目标网站的URL，如 https://xxx.xxx.com
    返回：包含文件路径和有效结果的JSON响应
    """
    # 生成唯一文件名（带时间戳）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = SCAN_RESULT_DIR / f"scan_{timestamp}.json"

    # 构建Dirsearch命令[1,6](@ref)
    base_cmd = [
        "python3", "./dirsearch/dirsearch.py",
        "-u", url,
        "-o", str(output_file),  # 直接输出到文件[5,8](@ref)
        "--format=json",         # JSON格式输出[6](@ref)
        "-q",                    # 安静模式（抑制控制台输出）[2](@ref)
        "--no-color",            # 禁用颜色代码[1](@ref)
        "-i", "200",             # 仅保留200状态码结果[4](@ref)
        "--exclude-status=404,403,500"  # 排除常见错误码[1](@ref)
    ]

    response = {"status": 500, "message": "初始化失败"}
    
    try:
        # 执行扫描命令[8](@ref)
        subprocess.run(
            base_cmd,
            check=True,
            capture_output=True,
            timeout=300,
            text=True
        )

        # 读取并过滤结果
        with open(output_file, "r") as f:
            scan_data = json.load(f)
        
        # 提取200状态码的路径
        valid_paths = [
            entry["url"] for entry in scan_data["results"]
            if entry["status"] == 200
        ]

        response = {
            "status": 200,
            "data": {
                "file_path": str(output_file),
                "valid_paths": valid_paths,
                "total_found": len(valid_paths)
            },
            "message": "扫描完成"
        }

    except subprocess.CalledProcessError as e:
        response = error_response(e, 500, "扫描执行失败", output_file)
    except json.JSONDecodeError:
        response = error_response(None, 502, "结果解析失败", output_file)
    except Exception as e:
        response = error_response(e, 500, "未知系统错误", output_file)
    
    return json.dumps(response, ensure_ascii=False)

def error_response(exception, code, message, filepath):
    """构建错误响应模板"""
    return {
        "status": code,
        "error": {
            "type": exception.__class__.__name__ if exception else "UnknownError",
            "details": str(exception) if exception else ""
        },
        "message": message,
        "failed_path": str(filepath) if filepath else None
    }

if __name__ == "__main__":
    mcp.run(transport='stdio')