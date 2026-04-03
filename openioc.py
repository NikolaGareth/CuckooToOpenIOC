# -*-coding:utf-8-*-
# cuckoo启动
# cd /usr/local/mongodb/bin
# ./mongod
# cuckoo -d
# cuckoo web runserver 0.0.0.0:1338
# cuckoo api --host 0.0.0.0 --port 1337
import json
import logging
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from ioc_writer import ioc_api

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "suspicious_imports": [],
    "good_pe_sections": [".text", ".code", "CODE", "INIT", "PAGE"],
    "suspicious_pe_sections": [],
    "pe_version_fields": ["LegalCopyright", "InternalName", "FileVersion", "CompanyName"],
}
DEFAULT_REQUEST_TIMEOUT = 30.0
MUTEX_NAME_SEARCH_PATH = "ProcessItem/HandleList/Handle/Name"


def configure_logging() -> None:
    """配置文件和控制台日志输出。"""
    if logger.handlers:
        return

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    file_handler = logging.FileHandler("openioc.log")
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.propagate = False


def load_dotenv_if_available() -> bool:
    """加载项目根目录下的 .env 文件；如果未安装 python-dotenv 则静默跳过。"""
    try:
        from dotenv import load_dotenv
    except ImportError:
        logger.debug("python-dotenv 未安装，跳过 .env 加载")
        return False

    env_path = os.path.join(os.path.dirname(__file__), ".env")
    return load_dotenv(env_path)


def get_request_timeout() -> float:
    """从环境变量读取网络超时时间，异常时回退到默认值。"""
    timeout_value = os.getenv("CUCKOO_API_TIMEOUT", str(DEFAULT_REQUEST_TIMEOUT))

    try:
        timeout = float(timeout_value)
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        return timeout
    except ValueError:
        logger.warning(
            "无效的 CUCKOO_API_TIMEOUT=%s，回退到默认超时 %.1f 秒",
            timeout_value,
            DEFAULT_REQUEST_TIMEOUT,
        )
        return DEFAULT_REQUEST_TIMEOUT


def load_config() -> Dict[str, Any]:
    """加载配置文件并与默认配置合并。"""
    local_config_file = os.path.join(os.path.dirname(__file__), "config.local.json")
    config_file = os.path.join(os.path.dirname(__file__), "config.json")
    merged_config = {key: list(value) for key, value in DEFAULT_CONFIG.items()}

    if os.path.exists(local_config_file):
        config_file = local_config_file
        logger.info("使用本地配置文件: %s", local_config_file)

    try:
        with open(config_file, "r", encoding="utf-8") as config_handle:
            loaded_config = json.load(config_handle)
    except FileNotFoundError:
        logger.warning("配置文件 %s 不存在，使用默认配置", config_file)
        return merged_config
    except json.JSONDecodeError as exc:
        logger.error("配置文件JSON格式错误: %s，使用默认配置", exc)
        return merged_config

    if not isinstance(loaded_config, dict):
        logger.error("配置文件 %s 不是 JSON 对象，使用默认配置", config_file)
        return merged_config

    for key, default_value in DEFAULT_CONFIG.items():
        configured_value = loaded_config.get(key, default_value)
        if isinstance(configured_value, list):
            merged_config[key] = configured_value
        else:
            logger.warning("配置项 %s 不是列表，保留默认值", key)

    logger.info("成功加载配置文件: %s", config_file)
    return merged_config


def safe_get(data: Any, *keys: str, default: Any = "") -> Any:
    """安全地从嵌套字典中获取值。"""
    try:
        result = data
        for key in keys:
            result = result[key]
        return result if result is not None else default
    except (KeyError, TypeError, IndexError) as exc:
        logger.debug("无法获取键 %s: %s", ".".join(map(str, keys)), exc)
        return default


def safe_iter(data: Any, default: Optional[List[Any]] = None) -> List[Any]:
    """安全地迭代数据，如果不可迭代则返回空列表。"""
    if isinstance(data, (list, tuple)):
        return list(data)
    return default if default is not None else []


def indicator_has_children(node: Any) -> bool:
    """判断 IOC 指标节点是否包含子节点。"""
    try:
        return len(node) > 0
    except TypeError:
        return False


def is_suspicious_pe_section(
    section_name: str,
    suspicious_sections: List[str],
    good_sections: List[str],
) -> bool:
    """判断 PE 节名是否应被视为可疑。"""
    if not section_name:
        return False
    if suspicious_sections:
        return section_name in suspicious_sections
    return section_name not in good_sections


def collect_bad_pe_sections(
    pe_sections: List[Dict[str, Any]],
    good_sections: List[str],
    suspicious_sections: List[str],
) -> List[List[Any]]:
    """根据配置提取可疑的 PE 节。"""
    bad_sections: List[List[Any]] = []

    for section in safe_iter(pe_sections):
        if not isinstance(section, dict):
            continue

        section_name = section.get("name", "")
        if not is_suspicious_pe_section(section_name, suspicious_sections, good_sections):
            continue

        bad_sections.append([
            section_name,
            section.get("size_of_data", 0),
            str(section.get("entropy", 0)),
        ])

    return bad_sections


def fetch_cuckoo_report(
    report_url: str,
    headers: Dict[str, str],
    ssl_context: ssl.SSLContext,
    timeout: float,
) -> Dict[str, Any]:
    """从 Cuckoo API 获取任务报告。"""
    request = urllib.request.Request(report_url, headers=headers)
    with urllib.request.urlopen(request, context=ssl_context, timeout=timeout) as response:
        return json.load(response)


def createMetaData(xmldoc: Any, parentnode: Any, metadata: Dict[str, Any]) -> None:
    """创建并添加元数据指标到 IOC。"""
    and_item = ioc_api.make_indicator_node("AND")
    if metadata["malfilename"] != "":
        inditem = ioc_api.make_indicatoritem_node(
            condition="is",
            document="FileItem",
            search="FileItem/FileName",
            content=str(metadata["malfilename"]),
            content_type="string",
        )
        and_item.append(inditem)
    if metadata["malfilesize"] != "":
        inditem = ioc_api.make_indicatoritem_node(
            condition="is",
            document="FileItem",
            search="FileItem/SizeInBytes",
            content=str(metadata["malfilesize"]),
            content_type="int",
        )
        and_item.append(inditem)
    if metadata["malmd5"] != "":
        inditem = ioc_api.make_indicatoritem_node(
            condition="is",
            document="FileItem",
            search="FileItem/Md5Sum",
            content=metadata["malmd5"],
            content_type="md5",
        )
        and_item.append(inditem)
    if metadata["malsha1"] != "":
        inditem = ioc_api.make_indicatoritem_node(
            condition="is",
            document="FileItem",
            search="FileItem/Sha1sum",
            content=metadata["malsha1"],
            content_type="sha1",
        )
        and_item.append(inditem)
    if metadata["malsha256"] != "":
        inditem = ioc_api.make_indicatoritem_node(
            condition="is",
            document="FileItem",
            search="FileItem/Sha256sum",
            content=metadata["malsha256"],
            content_type="sha256",
        )
        and_item.append(inditem)
    if metadata["malsha512"] != "":
        inditem = ioc_api.make_indicatoritem_node(
            condition="is",
            document="FileItem",
            search="FileItem/Sha512sum",
            content=metadata["malsha512"],
            content_type="sha512",
            context_type="iocaware",
        )
        and_item.append(inditem)
    if metadata["malfiletype"] != "":
        inditem = ioc_api.make_indicatoritem_node(
            condition="is",
            document="FileItem",
            search="FileItem/PEInfo/Type",
            content=metadata["malfiletype"],
            content_type="string",
        )
        and_item.append(inditem)
    if indicator_has_children(and_item):
        parentnode.append(and_item)

    peinfoind = ioc_api.make_indicator_node("OR")
    if len(metadata["iocimports"]) > 0:
        for importfunc in metadata["iocimports"]:
            importinditem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="FileItem",
                search="FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string",
                content=importfunc,
                content_type="string",
            )
            peinfoind.append(importinditem)
    if len(metadata["iocexports"]) > 0:
        for exportfunc in metadata["iocexports"]:
            exportinditem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="FileItem",
                search="FileItem/PEInfo/Exports/ExportedFunctions/string",
                content=exportfunc,
                content_type="string",
            )
            peinfoind.append(exportinditem)
    if len(metadata["badpesections"]) > 0:
        for section in metadata["badpesections"]:
            sectionind = ioc_api.make_indicator_node("AND")
            sectioninditem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="FileItem",
                search="FileItem/PEInfo/Sections/Section/Name",
                content=section[0],
                content_type="string",
            )
            sectionind.append(sectioninditem)

            sectioninditem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="FileItem",
                search="FileItem/PEInfo/Sections/Section/SizeInBytes",
                content=str(section[1]),
                content_type="int",
            )
            sectionind.append(sectioninditem)

            sectioninditem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="FileItem",
                search="FileItem/PEInfo/Sections/Section/Entropy/CurveData/float",
                content=str(section[2]),
                content_type="float",
            )
            sectionind.append(sectioninditem)
            peinfoind.append(sectionind)

    if len(metadata["versioninfo"]) > 0:
        infoind = ioc_api.make_indicator_node("AND")
        for infoitem, infovalue in metadata["versioninfo"].items():
            if infovalue == "" or infovalue is None:
                continue

            if "Version" in infoitem:
                itemvalue = str(infovalue).replace(", ", ".")
            else:
                itemvalue = str(infovalue)

            infoitemsearch = "FileItem/PEInfo/VersionInfoItem/" + infoitem
            infoinditem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="FileItem",
                search=infoitemsearch,
                content=str(itemvalue),
                content_type="string",
            )
            infoind.append(infoinditem)

        if indicator_has_children(infoind):
            peinfoind.append(infoind)

    if indicator_has_children(peinfoind):
        parentnode.append(peinfoind)


def addStrings(xmldoc: Any, parentnode: Any, strings: List[str]) -> None:
    """添加字符串指标到 IOC。"""
    if len(strings) == 0:
        return

    stringsind = ioc_api.make_indicator_node("AND")
    for string in strings:
        stringsinditem = ioc_api.make_indicatoritem_node(
            condition="is",
            document="FileItem",
            search="FileItem/StringList/string",
            content=string,
            content_type="string",
        )
        stringsind.append(stringsinditem)
    parentnode.append(stringsind)


def createDynamicIndicators(xmldoc: Any, parentnode: Any, dynamicindicators: Dict[str, List[Any]]) -> None:
    """创建并添加动态指标到 IOC。"""
    ind = ioc_api.make_indicator_node("OR")

    if len(dynamicindicators["droppedfiles"]) > 0:
        createdfilesind = ioc_api.make_indicator_node("OR")
        for createdfile in dynamicindicators["droppedfiles"]:
            createdfilesinditem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="FileItem",
                search="FileItem/FilenameCreated",
                content=createdfile[0],
                content_type="string",
            )
            createdfilesind.append(createdfilesinditem)
        if indicator_has_children(createdfilesind):
            ind.append(createdfilesind)

    if len(dynamicindicators["processes"]) > 0:
        processesind = ioc_api.make_indicator_node("OR")
        for process in dynamicindicators["processes"]:
            startedprocessesind = ioc_api.make_indicator_node("AND")
            startedprocessesitem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="ProcessItem",
                search="ProcessItem/name",
                content=process[0],
                content_type="string",
            )
            startedprocessesind.append(startedprocessesitem)
            startedprocessesitem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="ProcessItem",
                search="ProcessItem/pid",
                content=str(process[1]),
                content_type="int",
            )
            startedprocessesind.append(startedprocessesitem)
            startedprocessesitem = ioc_api.make_indicatoritem_node(
                condition="is",
                document="ProcessItem",
                search="ProcessItem/parentpid",
                content=str(process[2]),
                content_type="int",
            )
            startedprocessesind.append(startedprocessesitem)
            processesind.append(startedprocessesind)
        if indicator_has_children(processesind):
            ind.append(processesind)

    if len(dynamicindicators["regkeys"]) > 0:
        regkeyind = ioc_api.make_indicator_node("AND")
        for regkey in dynamicindicators["regkeys"]:
            createdregkeysind = ioc_api.make_indicatoritem_node(
                condition="is",
                document="RegistryItem",
                search="RegistryItem/KeyPath",
                content=regkey,
                content_type="string",
            )
            regkeyind.append(createdregkeysind)
        if indicator_has_children(regkeyind):
            ind.append(regkeyind)

    if len(dynamicindicators["mutexes"]) > 0:
        mutexkeyind = ioc_api.make_indicator_node("OR")
        for mutex in dynamicindicators["mutexes"]:
            createdmutexesind = ioc_api.make_indicatoritem_node(
                condition="contains",
                document="ProcessItem",
                search=MUTEX_NAME_SEARCH_PATH,
                content=mutex,
                content_type="string",
            )
            mutexkeyind.append(createdmutexesind)
        if indicator_has_children(mutexkeyind):
            ind.append(mutexkeyind)

    if indicator_has_children(ind):
        parentnode.append(ind)


def doStrings(strings: List[str]) -> List[str]:
    """提取字符串中的邮箱地址和IP地址。"""
    emailregex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    ipregex = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    emails = filter(lambda item: emailregex.search(item), strings)
    ips = filter(lambda item: ipregex.search(item), strings)

    result = list(set(emails)) + list(set(ips))
    logger.info("从字符串中提取到 %d 个邮箱/IP地址", len(result))
    return result


def build_ssl_context(allow_self_signed: bool) -> ssl.SSLContext:
    """根据配置构造 SSL 上下文。"""
    ssl_context = ssl.create_default_context()
    if allow_self_signed:
        logger.warning("警告: 已禁用SSL证书验证，这在生产环境中不安全")
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


def collect_report_artifacts(hjson: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """从 Cuckoo 报告中提取 IOC 构建所需的数据。"""
    static_info = safe_get(hjson, "static", default={})
    behavior_info = safe_get(hjson, "behavior", default={})
    behavior_summary = safe_get(behavior_info, "summary", default={})
    target_file = safe_get(hjson, "target", "file", default={})

    malmd5 = safe_get(target_file, "md5")
    malsha1 = safe_get(target_file, "sha1")
    malname = safe_get(target_file, "name")
    malsha256 = safe_get(target_file, "sha256")
    malsha512 = safe_get(target_file, "sha512")
    malsize = safe_get(target_file, "size")
    malfiletype = safe_get(target_file, "type")

    if not malname:
        raise ValueError("报告数据不完整，缺少必需的文件信息")

    logger.info("处理文件: %s (MD5: %s)", malname, malmd5)

    if malfiletype and "PE32" in malfiletype.upper():
        if "DLL" in malfiletype.upper():
            malfiletype = "Dll"
        else:
            malfiletype = "Executable"

    suspiciousimports = config.get("suspicious_imports", [])
    iocimports: List[str] = []
    try:
        pe_imports = safe_get(static_info, "pe_imports", default=[])
        for imports in safe_iter(pe_imports):
            if isinstance(imports, dict) and "imports" in imports:
                for item in safe_iter(imports.get("imports", [])):
                    if isinstance(item, dict) and item.get("name") in suspiciousimports:
                        iocimports.append(item["name"])
        logger.info("发现 %d 个可疑PE导入函数", len(iocimports))
    except (KeyError, TypeError, AttributeError) as exc:
        logger.warning("解析PE导入函数时出错: %s", exc)

    goodpesections = config.get("good_pe_sections", DEFAULT_CONFIG["good_pe_sections"])
    suspiciouspesections = config.get("suspicious_pe_sections", DEFAULT_CONFIG["suspicious_pe_sections"])
    try:
        pe_sections = safe_get(static_info, "pe_sections", default=[])
        badpesections = collect_bad_pe_sections(pe_sections, goodpesections, suspiciouspesections)
        logger.info("发现 %d 个异常PE节", len(badpesections))
    except (KeyError, TypeError, AttributeError) as exc:
        logger.warning("解析PE节信息时出错: %s", exc)
        badpesections = []

    iocexports: List[str] = []
    try:
        pe_exports = safe_get(static_info, "pe_exports", default=[])
        for exportfunc in safe_iter(pe_exports):
            if isinstance(exportfunc, dict) and "name" in exportfunc:
                iocexports.append(exportfunc["name"])
        logger.info("发现 %d 个PE导出函数", len(iocexports))
    except (KeyError, TypeError, AttributeError) as exc:
        logger.warning("解析PE导出函数时出错: %s", exc)

    pe_version_fields = config.get("pe_version_fields", DEFAULT_CONFIG["pe_version_fields"])
    versioninfo = dict.fromkeys(pe_version_fields)
    try:
        pe_versioninfo = safe_get(static_info, "pe_versioninfo", default=[])
        for item in safe_iter(pe_versioninfo):
            if isinstance(item, dict) and item.get("name") in versioninfo:
                versioninfo[item["name"]] = item.get("value", "")
        logger.info("成功解析PE版本信息")
    except (KeyError, TypeError, AttributeError) as exc:
        logger.warning("解析PE版本信息时出错: %s", exc)

    droppedfiles: List[List[Any]] = []
    try:
        dropped = safe_get(hjson, "dropped", default=[])
        for droppedfile in safe_iter(dropped):
            if isinstance(droppedfile, dict):
                droppedfiles.append([
                    droppedfile.get("name", ""),
                    droppedfile.get("size", 0),
                    droppedfile.get("md5", ""),
                    droppedfile.get("sha1", ""),
                    droppedfile.get("sha256", ""),
                    droppedfile.get("sha512", ""),
                ])
        logger.info("发现 %d 个释放的文件", len(droppedfiles))
    except (KeyError, TypeError, AttributeError) as exc:
        logger.warning("解析释放文件时出错: %s", exc)

    mutexes: List[str] = []
    try:
        if "mutex" in behavior_summary and isinstance(behavior_summary["mutex"], list):
            mutexes = behavior_summary["mutex"]
        elif "mutexes" in behavior_summary and isinstance(behavior_summary["mutexes"], list):
            mutexes = behavior_summary["mutexes"]
        logger.info("发现 %d 个互斥体", len(mutexes))
    except (KeyError, TypeError, AttributeError) as exc:
        logger.warning("解析互斥体时出错: %s", exc)

    processes: List[List[Any]] = []
    try:
        behavior_processes = safe_get(behavior_info, "processes", default=[])
        for process in safe_iter(behavior_processes):
            if isinstance(process, dict):
                processes.append([
                    process.get("process_name", ""),
                    process.get("process_id", 0),
                    process.get("parent_id", 0),
                ])
        logger.info("发现 %d 个进程", len(processes))
    except (KeyError, TypeError, AttributeError) as exc:
        logger.warning("解析进程信息时出错: %s", exc)

    regkeys: List[str] = []
    try:
        if "regkey_written" in behavior_summary and isinstance(behavior_summary["regkey_written"], list):
            regkeys = behavior_summary["regkey_written"]
        elif "keys" in behavior_summary and isinstance(behavior_summary["keys"], list):
            regkeys = behavior_summary["keys"]
        logger.info("发现 %d 个注册表键", len(regkeys))
    except (KeyError, TypeError, AttributeError) as exc:
        logger.warning("解析注册表键时出错: %s", exc)

    strings = doStrings(safe_get(hjson, "strings", default=[]))

    metadata = {
        "malfilename": malname,
        "malmd5": malmd5,
        "malsha1": malsha1,
        "malsha256": malsha256,
        "malsha512": malsha512,
        "malfilesize": malsize,
        "malfiletype": malfiletype,
        "iocexports": iocexports,
        "iocimports": iocimports,
        "badpesections": badpesections,
        "versioninfo": versioninfo,
    }
    dynamicindicators = {
        "droppedfiles": droppedfiles,
        "processes": processes,
        "regkeys": regkeys,
        "mutexes": mutexes,
    }

    return {
        "malname": malname,
        "malmd5": malmd5,
        "metadata": metadata,
        "strings": strings,
        "dynamicindicators": dynamicindicators,
    }


def write_ioc_file(ioc_root: Any, output_dir: str) -> None:
    """校验输出目录并写入 IOC 文件。"""
    if not os.path.exists(output_dir):
        print(f"警告: 输出目录 {output_dir} 不存在，尝试创建...")
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as exc:
            print(f"错误: 无法创建输出目录 - {exc}")
            raise SystemExit(1)

    if not os.access(output_dir, os.W_OK):
        print(f"错误: 没有写入权限到目录 {output_dir}")
        raise SystemExit(1)

    print(f"IOC文件将保存到: {output_dir}")
    ioc_api.write_ioc(ioc_root, output_dir)
    logger.info("OpenIOC文件已成功生成并保存到: %s", output_dir)


def main() -> int:
    """CLI 入口。"""
    configure_logging()
    load_dotenv_if_available()
    config = load_config()

    url = os.getenv("CUCKOO_API_URL")
    api_token = os.getenv("CUCKOO_API_TOKEN")

    if not url:
        print("错误: 请设置环境变量 CUCKOO_API_URL")
        print("示例: export CUCKOO_API_URL='https://192.168.22.176:1337'")
        return 1

    if not api_token:
        print("错误: 请设置环境变量 CUCKOO_API_TOKEN")
        print("示例: export CUCKOO_API_TOKEN='your_token_here'")
        return 1

    if url.startswith("http://"):
        print("警告: 您正在使用不安全的HTTP协议，建议使用HTTPS")
        print("继续使用HTTP可能导致数据泄露。是否继续? (yes/no): ", end="")
        confirm = input().strip().lower()
        if confirm not in ["yes", "y"]:
            print("操作已取消")
            return 0

    headers = {"Authorization": f"Bearer {api_token}"}

    print("请输入需要生成openioc的任务号：")
    task_id = input().strip()
    if not task_id.isdigit():
        print(f"错误: 任务号必须是纯数字，您输入的是: {task_id}")
        return 1

    report_url = f"{url}/tasks/report/{task_id}"
    allow_self_signed = os.getenv("CUCKOO_ALLOW_SELF_SIGNED", "false").lower() in ["true", "1", "yes"]
    ssl_context = build_ssl_context(allow_self_signed)
    timeout = get_request_timeout()

    try:
        hjson = fetch_cuckoo_report(report_url, headers, ssl_context, timeout)
    except urllib.error.HTTPError as exc:
        print(f"错误: HTTP请求失败 - {exc.code} {exc.reason}")
        if exc.code == 401:
            print("认证失败，请检查CUCKOO_API_TOKEN是否正确")
        elif exc.code == 404:
            print(f"任务 {task_id} 不存在")
        return 1
    except urllib.error.URLError as exc:
        print(f"错误: 网络连接失败 - {exc.reason}")
        print("请检查CUCKOO_API_URL是否正确，以及网络连接是否正常")
        return 1
    except TimeoutError:
        print(f"错误: 请求超时，超过 {timeout} 秒仍未收到响应")
        return 1
    except json.JSONDecodeError as exc:
        print(f"错误: JSON解析失败 - {exc}")
        print("服务器返回的数据格式不正确")
        return 1
    except Exception as exc:
        print(f"错误: 未知错误 - {exc}")
        return 1
    logger.info("成功获取任务 %s 的报告数据", task_id)

    try:
        report_data = collect_report_artifacts(hjson, config)
    except ValueError as exc:
        logger.error(str(exc))
        print(f"错误: {exc}")
        return 1

    malname = report_data["malname"]
    malmd5 = report_data["malmd5"]

    desc = "IOCAware OpenIOC Auto-Generated IOC for " + malname
    ioc = ioc_api.IOC(description=desc, author="162210710130")
    initindicator = ioc.top_level_indicator
    logger.info("开始生成OpenIOC文件")

    createMetaData(ioc, initindicator, report_data["metadata"])
    logger.info("已添加元数据到IOC")

    addStrings(ioc, initindicator, report_data["strings"])
    logger.info("已添加字符串到IOC")

    createDynamicIndicators(ioc, initindicator, report_data["dynamicindicators"])
    logger.info("已添加动态指标到IOC")

    output_dir = os.getenv("IOC_OUTPUT_DIR", os.getcwd())
    write_ioc_file(ioc.root, output_dir)

    print("✓ 成功生成OpenIOC文件！")
    print(f"  文件名: {malname}")
    print(f"  MD5: {malmd5}")
    print(f"  输出目录: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
