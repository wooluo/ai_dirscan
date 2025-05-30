import json
import subprocess
from collections import defaultdict
import requests
from datetime import datetime
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# 初始化 MCP 服务
mcp = FastMCP("ai_dirscan",port=8000)

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
        "python", "./dirsearch/dirsearch.py",
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
            headers={"User-Agent": "Windows-Azure-Web/1.0 Microsoft-HTTPAPI/2.0"},
            timeout=5
        )
        
        if response.status_code != 200:
            return response.text
        return f"200响应页面，无需进行深度分析"
        
    except requests.exceptions.RequestException as e:
        return f"请求异常：{str(e)}"

@mcp.tool()
def detect_sql_injection(url: str) -> str:
    """
    检测URL是否存在SQL注入漏洞，如存在则自动调用SQLmap
    
    Args:
        url (str): 要检测的URL
        
    Returns:
        str: JSON格式的检测结果
    """
    try:
        # 检测SQL注入漏洞的简单测试
        test_url = f"{url}?id=1'"
        response = requests.get(test_url, timeout=5)
        
        # 检查常见SQL错误特征
        sql_errors = [
            "SQL syntax", "MySQL", "ORA-", 
            "syntax error", "unclosed", "quoted"
        ]
        
        if any(error in response.text for error in sql_errors):
            # 发现潜在SQL注入漏洞，自动调用SQLmap
            sqlmap_result = run_sqlmap(url)
            return json.dumps({
                "status": 200,
                "vulnerable": True,
                "sqlmap_result": json.loads(sqlmap_result)
            }, ensure_ascii=False)
        
        return json.dumps({
            "status": 200,
            "vulnerable": False,
            "message": "未检测到明显的SQL注入漏洞"
        }, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({
            "status": 500,
            "error": str(e)
        }, ensure_ascii=False)
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

@mcp.tool()
def run_sqlmap(target_url: str, options: str = None) -> str:
    """
    自动执行SQLmap扫描
    
    Args:
        target_url (str): 目标URL
        options (str): 可选参数，将直接传递给SQLmap
        
    注意：字典文件路径已更新为dirsearch/db/sql.txt
        options (str): SQLmap命令行选项(可选)
        
    Returns:
        str: JSON格式的扫描结果
    """
    try:
        # 构建基本命令
        base_cmd = ["python", "./sqlmap/sqlmap.py", "-u", target_url, "--batch", "--output-dir=scan_results"]
        
        # 添加可选参数
        if options:
            base_cmd.extend(options.split())
        
        # 执行扫描
        result = subprocess.run(
            base_cmd,
            check=True,
            capture_output=True,
            text=True
        )
        
        # 返回结果
        return json.dumps({
            "status": 200,
            "output": result.stdout,
            "report_path": f"scan_results/sqlmap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        }, ensure_ascii=False)
        
    except subprocess.CalledProcessError as e:
        return json.dumps({
            "status": 500,
            "error": str(e),
            "output": e.stdout
        }, ensure_ascii=False)

if __name__ == "__main__":
    mcp.run(transport='sse')