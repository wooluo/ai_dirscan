import json
import subprocess
import os
import re
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from mcp.server.fastmcp import FastMCP

# 初始化
mcp = FastMCP("ai_dirscan", port=8000)
SCAN_RESULT_DIR = Path("scan_results")
SCAN_RESULT_DIR.mkdir(exist_ok=True)

SCAN_TIMEOUT = 300
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@mcp.tool()
async def scan_dir(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return response_json(400, "无效的URL，请确保URL以http://或https://开头")

    dirsearch_path = find_dirsearch()
    if not dirsearch_path:
        return response_json(
            500, "dirsearch工具未安装，请先安装dirsearch",
            extra={"installation_hint": "参考: https://github.com/maurosoria/dirsearch"}
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = SCAN_RESULT_DIR / f"scan_{timestamp}.json"

    cmd = [
            "python", str(dirsearch_path),
            "-u", url,
            "--output-file", str(output_file),
            "-O", "json",
            "--log", str(SCAN_RESULT_DIR / f"scan_{timestamp}.log"),
            "-q", "--no-color",
            "-t", "50"  # 添加并发线程数参数提升扫描效率
        ]

    try:
        start_time = datetime.now()
        logger.info(f"Start scanning: {url} (timeout={SCAN_TIMEOUT}s)")
        process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_TIMEOUT)
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Scan completed in {duration:.2f}s. Return code: {process.returncode}")

        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd, stdout, stderr)

        if not output_file.exists():
            return response_json(
                500, "扫描结果文件未生成",
                extra={"possible_reasons": [" 目标服务器不可访问", "防火墙限制", "dirsearch配置问题"]}
            )

        scan_data = parse_scan_results(output_file)
        if not scan_data:
            return response_json(500, "无效的扫描结果", extra={"output_file": str(output_file)})

        status_200, non_200, stats = process_scan_results(scan_data)

        return json.dumps({
            "status": 200,
            "message": "扫描完成",
            "data": {
                "status_200": status_200,
                "non_200_results": non_200,
                "report_path": str(output_file),
                "stats": stats
            },
            "scan_details": {
                "target_url": url,
                "scan_time": timestamp,
                "result_count": len(status_200) + len(non_200)
            }
        }, ensure_ascii=False, indent=2)

    except subprocess.CalledProcessError as e:
            # 同时记录stdout和stderr增强调试信息
            return response_json(500, "dirsearch执行失败", extra={
                "error": f"stdout: {e.stdout}\nstderr: {e.stderr}",
                "command": " ".join(cmd)
            })
    except asyncio.TimeoutError:
        return response_json(408, "扫描超时")
    except Exception as e:
        logger.exception("Unexpected error")
        return response_json(500, f"扫描失败: {str(e)}")


def response_json(status, message, extra=None):
    data = {"status": status, "message": message}
    if extra:
        data.update(extra)
    return json.dumps(data, ensure_ascii=False, indent=2)


def find_dirsearch() -> str:
    possible_paths = [
        Path(__file__).parent / "dirsearch/dirsearch.py",
        Path("/usr/local/bin/dirsearch"),
        Path("/opt/dirsearch/dirsearch.py"),
        Path.home() / ".local/bin/dirsearch",
        *Path("/usr/bin").glob("dirsearch*"),
        *Path("/usr/local/bin").glob("dirsearch*")
    ]
    for path in possible_paths:
        if path.exists():  # 统一使用Path对象的exists方法
            logger.info(f"Found dirsearch at: {path}")
            return path
    return None


def find_sqlmap() -> str:
    possible_paths = [
        Path(__file__).parent / "sqlmap/sqlmap.py",
        Path("/usr/local/bin/sqlmap"),
        Path("/opt/sqlmap/sqlmap.py"),
        Path.home() / ".local/bin/sqlmap",
        *Path("/usr/bin").glob("sqlmap*"),
        *Path("/usr/local/bin").glob("sqlmap*")
    ]
    for path in possible_paths:
        if path.exists():
            logger.info(f"Found sqlmap at: {path}")
            return path
    return None


def parse_scan_results(output_file: Path) -> dict:
    try:
        if output_file.suffix == ".json":
            with open(output_file, "r", encoding="utf-8") as f:
                content = f.read()
                if not content.strip():
                    return {}
                return json.loads(content)
        else:
            with open(output_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            results = []
            for line in lines:
                if line.strip().startswith("#") or not line.strip():
                    continue
                match = re.match(r'^\[(\d{3})\]\s+(\d+)\s+(.+)$', line.strip())
                if match:
                    status, length, path = match.groups()
                    results.append({
                        "url": path,
                        "status": int(status),
                        "content-length": int(length)
                    })
            return {"results": results}
    except Exception as e:
        logger.error(f"解析扫描结果失败: {str(e)}", exc_info=True)
        return {}


def process_scan_results(scan_data: dict) -> tuple:
    status_200 = []
    non_200_results = []
    status_counter = defaultdict(int)
    seen = set()

    for entry in scan_data.get("results", []):
        status = entry.get("status")
        url = entry.get("url")
        content_length = entry.get("content-length", 0)

        status_counter[status] += 1
        entry_key = f"{status}|{content_length}|{url}"
        if entry_key in seen:
            continue
        seen.add(entry_key)

        if status == 200:
            status_200.append(url)
        elif content_length:
            non_200_results.append({
                "url": url,
                "status": status,
                "content_length": content_length
            })

    stats = {
        "total_200": len(status_200),
        "total_non_200": len(non_200_results),
        "status_distribution": dict(status_counter)
    }
    return status_200, non_200_results, stats


@mcp.tool()
async def scan_sql(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return response_json(400, "无效的URL，请确保URL以http://或https://开头")

    sqlmap_path = find_sqlmap()
    if not sqlmap_path:
        return response_json(
            500, "sqlmap工具未安装，请先安装sqlmap",
            extra={"installation_hint": "参考: https://github.com/sqlmapproject/sqlmap"}
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = SCAN_RESULT_DIR / f"sqlmap_{timestamp}.json"

    cmd = [
        "python", str(sqlmap_path),
        "-u", url,
        "--batch",
        "--random-agent",  # 随机使用常见浏览器的User-Agent
        "--level=5",  # 最高级别
        "--risk=3",  # 最高风险
        "--threads=1",  # 并发线程数
        "--timeout=30",  # 超时时间
        "--output-dir", str(SCAN_RESULT_DIR),# 目录路径，不要带文件名
        "--results-file", str(SCAN_RESULT_DIR / f"scan_{timestamp}.json"),  # 明确指定JSON输出文件
        "--tamper=space2comment"
    ]

    try:
        start_time = datetime.now()
        logger.info(f"Start SQL injection scan: {url} (timeout={SCAN_TIMEOUT}s)")
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_TIMEOUT)
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"SQL scan completed in {duration:.2f}s. Return code: {process.returncode}")

        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd, stdout, stderr)

        return response_json(200, "SQL注入扫描完成", extra={
            "output_dir": str(SCAN_RESULT_DIR),
            "scan_time": timestamp
        })

    except subprocess.CalledProcessError as e:
        return response_json(500, "sqlmap执行失败", extra={
            "error": f"stdout: {e.stdout}\nstderr: {e.stderr}",
            "command": " ".join(cmd)
        })
    except asyncio.TimeoutError:
        return response_json(408, "SQL注入扫描超时")
    except Exception as e:
        logger.exception("Unexpected error")
        return response_json(500, f"SQL注入扫描失败: {str(e)}")


if __name__ == "__main__":
    logger.info("Starting MCP server...")
    # 使用正确的静态方式启动
    asyncio.run(mcp.run(transport="sse"))