import json
import subprocess
from collections import defaultdict
import requests
from datetime import datetime
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# 初始化 MCP 服务
mcp = FastMCP("ai_dirscan",port=8001)

# 配置存储路径
SCAN_RESULT_DIR = Path("scan_results")
SCAN_RESULT_DIR.mkdir(exist_ok=True)

@mcp.tool()
def scan_dir(url: str) -> str:
    """
    执行网站目录扫描，返回结构化扫描结果
    
    Args:
        url (str): 目标网站URL，需包含协议头(如http/https)
        
    Returns:
        str: JSON格式响应，包含：
            - status_200: 200状态的有效路径列表
            - non_200_results: 非200状态的有效结果列表（包含状态码）
            - report_path: 结果文件路径
            - stats: 各类状态码统计
    """
    # 生成结果文件路径
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = SCAN_RESULT_DIR / f"scan_{timestamp}.json"
    
    # 构建扫描命令
    base_cmd = [
        "python3", "./dirsearch/dirsearch.py",
        "-u", url,
        "-o", str(output_file),
        "--format=json",
        "-q",
        "--no-color",
    ]

    response = {"status": 500, "message": "初始化失败"}
    
    try:
        # 执行目录扫描
        subprocess.run(
            base_cmd,
            check=True,
            capture_output=True,
            timeout=300,
            text=True
        )

        # 加载原始扫描结果
        with open(output_file, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
        
        # 初始化数据结构
        status_200 = []
        non_200_results = []
        status_counter = defaultdict(int)
        unique_tracker = set()

        # 结果分类处理
        for entry in scan_data.get("results", []):
            status = entry["status"]
            url_path = entry["url"]
            content_length = entry["content-length"]
            
            # 状态码统计
            status_counter[status] += 1
            
            # 生成唯一标识符防止重复
            entry_key = f"{status}|{content_length}"
            if entry_key in unique_tracker:
                continue
            unique_tracker.add(entry_key)

            # 分类存储结果
            if status == 200:
                status_200.append(url_path)
            elif content_length != 0:
                non_200_results.append({
                    "url": url_path,
                    "status": status,
                    "content_length": content_length
                })

        # 构建统计信息
        stats = {
            "total_200": len(status_200),
            "total_non_200": len(non_200_results),
            "status_distribution": dict(status_counter)
        }

        # 生成最终响应
        response = {
            "status": 200,
            "data": {
                "status_200": status_200,
                "non_200_results": non_200_results,
                "report_path": str(output_file),
                "stats": stats
            },
            "message": "扫描完成，结果已分类"
        }

    except json.JSONDecodeError as e:
        response = {"status": 500, "message": f"结果解析失败: {str(e)}"}
    except subprocess.TimeoutExpired:
        response = {"status": 408, "message": "扫描超时"}
    except Exception as e:
        response = {"status": 500, "message": f"扫描失败: {str(e)}"}
    
    return json.dumps(response, ensure_ascii=False, indent=2)
@mcp.tool()
def get_content(url: str) -> str:
    """
    获取非200响应界面的网页内容
    :param url: 需要检测的网页地址
    :return: 返回页面的完整内容（若目标页面返回非200状态码）
    """
    try:
        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=5
        )
        
        if response.status_code != 200:
            return response.text
        return f"200响应页面，无需进行深度分析"
        
    except requests.exceptions.RequestException as e:
        return f"请求异常：{str(e)}"
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
    mcp.run(transport='sse')