# -*-coding:utf-8-*-
# cuckoo启动
# cd /usr/local/mongodb/bin
# ./mongod
# cuckoo -d
# cuckoo web runserver 0.0.0.0:1338
# cuckoo api --host 0.0.0.0 --port 1337
import urllib.request
import json
import re
import os
import sys
import ssl
import logging
from typing import Dict, List, Any, Optional, Union
from ioc_writer import ioc_api

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('openioc.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def load_config() -> Dict[str, Any]:
    """加载配置文件

    优先加载 config.local.json（如果存在），否则加载 config.json

    Returns:
        dict: 配置字典，如果加载失败则返回默认配置
    """
    # 首先尝试加载本地配置（用户自定义，不提交到Git）
    local_config_file = os.path.join(os.path.dirname(__file__), 'config.local.json')
    config_file = os.path.join(os.path.dirname(__file__), 'config.json')

    # 优先使用本地配置
    if os.path.exists(local_config_file):
        config_file = local_config_file
        logger.info(f"使用本地配置文件: {local_config_file}")

    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
            logger.info(f"成功加载配置文件: {config_file}")
            return config
    except FileNotFoundError:
        logger.warning(f"配置文件 {config_file} 不存在，使用默认配置")
        return {
            "suspicious_imports": [],
            "good_pe_sections": [".text", ".code", "CODE", "INIT", "PAGE"],
            "pe_version_fields": ["LegalCopyright", "InternalName", "FileVersion", "CompanyName"]
        }
    except json.JSONDecodeError as e:
        logger.error(f"配置文件JSON格式错误: {e}，使用默认配置")
        return {
            "suspicious_imports": [],
            "good_pe_sections": [".text", ".code", "CODE", "INIT", "PAGE"],
            "pe_version_fields": []
        }

def safe_get(data: Any, *keys: str, default: Any = '') -> Any:
    """安全地从嵌套字典中获取值

    Args:
        data: 字典对象
        *keys: 键的路径
        default: 默认值

    Returns:
        获取到的值或默认值
    """
    try:
        result = data
        for key in keys:
            result = result[key]
        return result if result is not None else default
    except (KeyError, TypeError, IndexError) as e:
        logger.debug(f"无法获取键 {'.'.join(map(str, keys))}: {e}")
        return default

def safe_iter(data: Any, default: Optional[List] = None) -> List:
    """安全地迭代数据，如果不可迭代则返回空列表

    Args:
        data: 要迭代的数据
        default: 默认返回值

    Returns:
        可迭代的列表或默认值
    """
    if isinstance(data, (list, tuple)):
        return list(data)
    return default if default is not None else []

# # 提交文件
# r = requests.post(url + "/tasks/create/submit", files=[
#     ("files", open("1.exe", "rb")),
#     ("files", open("2.exe", "rb")),
# ], headers=HEADERS)
#
# submit_id = r.json()["submit_id"]
# task_ids = r.json()["task_ids"]
# errors = r.json()["errors"]
# curl -H "Authorization: Bearer S4MPL3" http://192.168.22.176:1337/tasks/report/8

def createMetaData(xmldoc: Any, parentnode: Any, metadata: Dict[str, Any]) -> None:
    """创建并添加元数据指标到IOC

    Args:
        xmldoc: XML文档对象（未使用，保留以兼容API）
        parentnode: 父节点，将在此节点下添加元数据
        metadata: 包含恶意软件元数据的字典
    """
    and_item = ioc_api.make_indicator_node('AND')
    if metadata['malfilename'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/FileName", content=str(metadata['malfilename']), content_type="string")
        and_item.append(inditem)
    # file size
    if metadata['malfilesize'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/SizeInBytes", content=str(metadata['malfilesize']), content_type="int")
        and_item.append(inditem)
    # file md5
    if metadata['malmd5'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Md5Sum", content=metadata['malmd5'], content_type="md5")
        and_item.append(inditem)
    if metadata['malsha1'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Sha1sum", content=metadata['malsha1'], content_type="sha1")
        and_item.append(inditem)
    if metadata['malsha256'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Sha256sum", content=metadata['malsha256'], content_type="sha256")
        and_item.append(inditem)
    # sha512 is not included in the list of OpenIOC indicators
    # so the context_type="iocware" - please see the iocaware.iocterms file
    if metadata["malsha512"] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Sha512sum", content=metadata['malsha512'], content_type="sha512", context_type="iocaware")
        and_item.append(inditem)
    if metadata['malfiletype'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Type", content=metadata['malfiletype'], content_type="string")
        and_item.append(inditem)
    parentnode.append(and_item)

    peinfoind = ioc_api.make_indicator_node("OR")
    if len(metadata['iocimports']) > 0:
        for importfunc in metadata['iocimports']:
            importinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string", content=importfunc, content_type="string")
            peinfoind.append(importinditem)
    if len(metadata['iocexports']) > 0:
        for exportfunc in metadata['iocexports']:
            exportinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Exports/ExportedFunctions/string", content=exportfunc, content_type="string")
            peinfoind.append(exportinditem)
    if len(metadata['badpesections']) > 0:
        for section in metadata['badpesections']:
            sectionind = ioc_api.make_indicator_node("AND")
            sectioninditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Sections/Section/Name", content=section[0], content_type="string")
            sectionind.append(sectioninditem)

            sectioninditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Sections/Section/SizeInBytes", content=str(section[1]), content_type="int")
            sectionind.append(sectioninditem)

            sectioninditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Sections/Section/Entropy/CurveData/float", content=str(section[2]), content_type="float")
            sectionind.append(sectioninditem)
            peinfoind.append(sectionind)

    # Include any PE Version Information
    if len(metadata['versioninfo']) > 0:
        infoind = ioc_api.make_indicator_node("AND")
        for infoitem in metadata['versioninfo']:
            if metadata['versioninfo'][infoitem] != "" and metadata['versioninfo'][infoitem] is not None:
                if "Version" in infoitem:
                    itemvalue = str(metadata['versioninfo'][infoitem]).replace(", ", ".")
                else:
                    itemvalue = str(metadata['versioninfo'][infoitem])
                infoitemsearch = "FileItem/PEInfo/VersionInfoItem/" + infoitem
                infoinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search=infoitemsearch, content=str(itemvalue), content_type="string")
                infoind.append(infoinditem)
                peinfoind.append(infoind)
    parentnode.append(peinfoind)

def addStrings(xmldoc: Any, parentnode: Any, strings: List[str]) -> None:
    """添加字符串指标（如邮箱和IP地址）到IOC

    Args:
        xmldoc: XML文档对象（未使用，保留以兼容API）
        parentnode: 父节点，将在此节点下添加字符串指标
        strings: 字符串列表
    """
    if len(strings) > 0:
        stringsind = ioc_api.make_indicator_node("AND")
        for string in strings:
            stringsinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/StringList/string", content=string, content_type="string")
            stringsind.append(stringsinditem)
        parentnode.append(stringsind)
    else:
        return

def createDynamicIndicators(xmldoc: Any, parentnode: Any, dynamicindicators: Dict[str, List]) -> None:
    """创建并添加动态指标到IOC

    动态指标包括：释放的文件、启动的进程、注册表键、互斥体等

    Args:
        xmldoc: XML文档对象（未使用，保留以兼容API）
        parentnode: 父节点，将在此节点下添加动态指标
        dynamicindicators: 包含动态指标的字典
            - droppedfiles: 释放的文件列表
            - processes: 进程列表
            - regkeys: 注册表键列表
            - mutexes: 互斥体列表
    """
    filescreated = False
    processesstarted = False
    regkeyscreated = False
    mutexescreated = False
    hasdynamicindicators = False

    if len(dynamicindicators['droppedfiles']) > 0:
        filescreated = True
        hasdynamicindicators = True
    if len(dynamicindicators['processes']) > 0:
        processesstarted = True
        hasdynamicindicators = True
    if len(dynamicindicators['regkeys']) > 0:
        regkeyscreated = True
        hasdynamicindicators = True
    if len(dynamicindicators['mutexes']) > 0:
        mutexescreated = True
        hasdynamicindicators = True

    if not hasdynamicindicators:
        return

    ind = ioc_api.make_indicator_node("OR")

    if filescreated:
        createdfilesind = ioc_api.make_indicator_node("OR")
        for createdfile in dynamicindicators['droppedfiles']:
            createdfilesinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/FilenameCreated", content=createdfile[0], content_type="string")
            createdfilesind.append(createdfilesinditem)
        ind.append(createdfilesind)
    if processesstarted:
        processesind = ioc_api.make_indicator_node("OR")
        for process in dynamicindicators['processes']:
            startedprocessesind = ioc_api.make_indicator_node("AND")
            # Process name
            startedprocessesitem = ioc_api.make_indicatoritem_node(condition="is", document="ProcessItem", search="ProcessItem/name", content=process[0], content_type="string")
            startedprocessesind.append(startedprocessesitem)
            # Process pid
            startedprocessesitem = ioc_api.make_indicatoritem_node(condition="is", document="ProcessItem", search="ProcessItem/pid", content=str(process[1]), content_type="int")
            startedprocessesind.append(startedprocessesitem)
            # Process parent pid
            startedprocessesitem = ioc_api.make_indicatoritem_node(condition="is", document="ProcessItem", search="ProcessItem/parentpid", content=str(process[2]), content_type="int")
            startedprocessesind.append(startedprocessesitem)

            processesind.append(startedprocessesind)
        ind.append(processesind)
    if regkeyscreated:
        regkeyind = ioc_api.make_indicator_node("AND")
        for regkey in dynamicindicators['regkeys']:
            createdregkeysind = ioc_api.make_indicatoritem_node(condition="is", document="RegistryItem", search="RegistryItem/KeyPath", content=regkey, content_type="string")
            regkeyind.append(createdregkeysind)
        ind.append(regkeyind)
    if mutexescreated:
        mutexkeyind = ioc_api.make_indicator_node("OR")
        for mutex in dynamicindicators['mutexes']:
            createdmutexesind = ioc_api.make_indicatoritem_node(condition="contains", document="ProcessItem", search="ProcessItem/HandList/Handl/Name", content=mutex, content_type="string")
            mutexkeyind.append(createdmutexesind)
        ind.append(mutexkeyind)
    parentnode.append(ind)
    return

def doStrings(strings: List[str]) -> List[str]:
    """提取字符串中的邮箱地址和IP地址

    Args:
        strings: 字符串列表

    Returns:
        包含邮箱和IP地址的列表
    """
    # 改进的邮箱正则表达式
    emailregex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

    # 改进的IP正则表达式 - 验证每个段在0-255之间
    ipregex = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    emails = filter(lambda i: emailregex.search(i), strings)
    ips = filter(lambda i: ipregex.search(i), strings)

    result = list(set(emails)) + list(set(ips))
    logger.info(f"从字符串中提取到 {len(result)} 个邮箱/IP地址")
    return result

if __name__ == '__main__':
    # 加载配置文件
    config = load_config()

    # 从环境变量读取配置，提高安全性
    url = os.getenv('CUCKOO_API_URL')
    api_token = os.getenv('CUCKOO_API_TOKEN')

    # 验证必需的环境变量
    if not url:
        print("错误: 请设置环境变量 CUCKOO_API_URL")
        print("示例: export CUCKOO_API_URL='https://192.168.22.176:1337'")
        sys.exit(1)

    if not api_token:
        print("错误: 请设置环境变量 CUCKOO_API_TOKEN")
        print("示例: export CUCKOO_API_TOKEN='your_token_here'")
        sys.exit(1)

    # 安全检查: 警告使用HTTP协议
    if url.startswith('http://'):
        print("警告: 您正在使用不安全的HTTP协议，建议使用HTTPS")
        print("继续使用HTTP可能导致数据泄露。是否继续? (yes/no): ", end='')
        confirm = input().strip().lower()
        if confirm not in ['yes', 'y']:
            print("操作已取消")
            sys.exit(0)

    HEADERS = {"Authorization": f"Bearer {api_token}"}

    print("请输入需要生成openioc的任务号：")
    task_id = input().strip()

    # P0修复: 验证task_id只包含数字，防止SSRF和路径遍历攻击
    if not task_id.isdigit():
        print(f"错误: 任务号必须是纯数字，您输入的是: {task_id}")
        sys.exit(1)

    # 安全构建URL
    URL = f"{url}/tasks/report/{task_id}"

    # 创建SSL上下文
    ssl_context = ssl.create_default_context()

    # 如果使用自签名证书（开发环境），可以禁用证书验证
    # 警告：生产环境不建议禁用证书验证
    allow_self_signed = os.getenv('CUCKOO_ALLOW_SELF_SIGNED', 'false').lower() in ['true', '1', 'yes']
    if allow_self_signed:
        logger.warning("警告: 已禁用SSL证书验证，这在生产环境中不安全")
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    # 创建带认证头的请求
    try:
        request = urllib.request.Request(URL, headers=HEADERS)
        html = urllib.request.urlopen(request, context=ssl_context)
        hjson = json.load(html)
    except urllib.error.HTTPError as e:
        print(f"错误: HTTP请求失败 - {e.code} {e.reason}")
        if e.code == 401:
            print("认证失败，请检查CUCKOO_API_TOKEN是否正确")
        elif e.code == 404:
            print(f"任务 {task_id} 不存在")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"错误: 网络连接失败 - {e.reason}")
        print("请检查CUCKOO_API_URL是否正确，以及网络连接是否正常")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"错误: JSON解析失败 - {e}")
        print("服务器返回的数据格式不正确")
        sys.exit(1)
    except Exception as e:
        print(f"错误: 未知错误 - {e}")
        sys.exit(1)
    logger.info(f"成功获取任务 {task_id} 的报告数据")

    # 缓存频繁访问的嵌套结构，提高性能
    static_info = safe_get(hjson, 'static', default={})
    behavior_info = safe_get(hjson, 'behavior', default={})
    behavior_summary = safe_get(behavior_info, 'summary', default={})
    target_file = safe_get(hjson, 'target', 'file', default={})

    # P1修复: 使用safe_get进行JSON数据验证
    malmd5 = safe_get(target_file, "md5")
    malsha1 = safe_get(target_file, "sha1")
    malname = safe_get(target_file, "name")
    malsha256 = safe_get(target_file, "sha256")
    malsha512 = safe_get(target_file, "sha512")
    malsize = safe_get(target_file, "size")
    malfiletype = safe_get(target_file, "type")

    if not malname:
        logger.error("无法从报告中获取文件名，数据格式可能不正确")
        print("错误: 报告数据不完整，缺少必需的文件信息")
        sys.exit(1)

    logger.info(f"处理文件: {malname} (MD5: {malmd5})")

    isPE = False
    # PE file (EXE or DLL), just executable (DOS?) or other
    if malfiletype and "PE32" in malfiletype.upper():
        isPE = True
        if "DLL" in malfiletype.upper():
            malfiletype = "Dll"
        else:
            malfiletype = "Executable"

    # Suspicious PE imports (从配置文件加载)
    suspiciousimports = config.get('suspicious_imports', [])
    iocimports = []
    # P1修复: 改进异常处理，使用safe_iter优化代码
    try:
        pe_imports = safe_get(static_info, "pe_imports", default=[])
        for imports in safe_iter(pe_imports):
            if isinstance(imports, dict) and 'imports' in imports:
                for item in safe_iter(imports.get('imports', [])):
                    if isinstance(item, dict) and 'name' in item and item['name'] in suspiciousimports:
                        iocimports.append(item['name'])
        logger.info(f"发现 {len(iocimports)} 个可疑PE导入函数")
    except (KeyError, TypeError, AttributeError) as e:
        logger.warning(f"解析PE导入函数时出错: {e}")

    # PE sections (从配置文件加载)
    goodpesections = config.get('good_pe_sections', ['.text', '.code', 'CODE', 'INIT', 'PAGE'])
    badpesections = []
    try:
        pe_sections = safe_get(static_info, "pe_sections", default=[])
        for sections in safe_iter(pe_sections):
            if isinstance(sections, dict) and 'name' in sections:
                if sections['name'] not in goodpesections:
                    badpesection = [
                        sections.get('name', ''),
                        sections.get('size_of_data', 0),
                        str(sections.get('entropy', 0))
                    ]
                    badpesections.append(badpesection)
        logger.info(f"发现 {len(badpesections)} 个异常PE节")
    except (KeyError, TypeError, AttributeError) as e:
        logger.warning(f"解析PE节信息时出错: {e}")

    # PE Exports
    iocexports = []
    try:
        pe_exports = safe_get(static_info, "pe_exports", default=[])
        for exportfunc in safe_iter(pe_exports):
            if isinstance(exportfunc, dict) and 'name' in exportfunc:
                iocexports.append(exportfunc['name'])
        logger.info(f"发现 {len(iocexports)} 个PE导出函数")
    except (KeyError, TypeError, AttributeError) as e:
        logger.warning(f"解析PE导出函数时出错: {e}")
    # PE Version Info (从配置文件加载)
    pe_version_fields = config.get('pe_version_fields', [
        'LegalCopyright', 'InternalName', 'FileVersion', 'CompanyName', 'PrivateBuild',
        'LegalTrademarks', 'Comments', 'ProductName', 'SpecialBuild', 'ProductVersion',
        'FileDescription', 'OriginalFilename'
    ])
    versioninfo = dict.fromkeys(pe_version_fields)

    try:
        pe_versioninfo = safe_get(static_info, "pe_versioninfo", default=[])
        for item in safe_iter(pe_versioninfo):
            if isinstance(item, dict) and 'name' in item and item['name'] in versioninfo:
                versioninfo[item['name']] = item.get('value', '')
        logger.info("成功解析PE版本信息")
    except (KeyError, TypeError, AttributeError) as e:
        logger.warning(f"解析PE版本信息时出错: {e}")

    # Dropped files
    droppedfiles = []
    try:
        dropped = safe_get(hjson, 'dropped', default=[])
        for droppedfile in safe_iter(dropped):
            if isinstance(droppedfile, dict):
                droppedfiles.append([
                    droppedfile.get('name', ''),
                    droppedfile.get('size', 0),
                    droppedfile.get('md5', ''),
                    droppedfile.get('sha1', ''),
                    droppedfile.get('sha256', ''),
                    droppedfile.get('sha512', '')
                ])
        logger.info(f"发现 {len(droppedfiles)} 个释放的文件")
    except (KeyError, TypeError, AttributeError) as e:
        logger.warning(f"解析释放文件时出错: {e}")

    # Mutexes
    mutexes = []
    try:
        if 'mutex' in behavior_summary:
            # Cuckoo 2.0
            mutex_list = behavior_summary['mutex']
            if isinstance(mutex_list, list):
                mutexes = mutex_list
        elif 'mutexes' in behavior_summary:
            # Cuckoo 1.x
            mutex_list = behavior_summary['mutexes']
            if isinstance(mutex_list, list):
                mutexes = mutex_list
        logger.info(f"发现 {len(mutexes)} 个互斥体")
    except (KeyError, TypeError, AttributeError) as e:
        logger.warning(f"解析互斥体时出错: {e}")

    # Processes
    processes = []
    try:
        behavior_processes = safe_get(behavior_info, 'processes', default=[])
        for process in safe_iter(behavior_processes):
            if isinstance(process, dict):
                processes.append([
                    process.get('process_name', ''),
                    process.get('process_id', 0),
                    process.get('parent_id', 0)
                ])
        logger.info(f"发现 {len(processes)} 个进程")
    except (KeyError, TypeError, AttributeError) as e:
        logger.warning(f"解析进程信息时出错: {e}")

    # grab IPv4 addresses and emails
    strings = doStrings(safe_get(hjson, 'strings', default=[]))

    # Registry Keys
    regkeys = []
    try:
        if 'regkey_written' in behavior_summary:
            # Cuckoo 2.0
            regkeys = behavior_summary['regkey_written'] if isinstance(behavior_summary['regkey_written'], list) else []
        elif 'keys' in behavior_summary:
            # Cuckoo 1.x
            regkeys = behavior_summary['keys'] if isinstance(behavior_summary['keys'], list) else []
        logger.info(f"发现 {len(regkeys)} 个注册表键")
    except (KeyError, TypeError, AttributeError) as e:
        logger.warning(f"解析注册表键时出错: {e}")

    # create our base/skeletal IOC
    desc = 'IOCAware OpenIOC Auto-Generated IOC for ' + malname
    ioc = ioc_api.IOC(description=desc, author='162210710130')
    initindicator = ioc.top_level_indicator
    logger.info("开始生成OpenIOC文件")

    # Create our metadata dictionary for getting the
    # metadata values into the IOC
    metadata = {'malfilename': malname, 'malmd5': malmd5, 'malsha1': malsha1, 'malsha256': malsha256, 'malsha512': malsha512, 'malfilesize': malsize, 'malfiletype': malfiletype, 'iocexports': iocexports, 'iocimports': iocimports, 'badpesections': badpesections, 'versioninfo': versioninfo}

    # add metadata to the IOC
    createMetaData(ioc, initindicator, metadata)
    logger.info("已添加元数据到IOC")

    # add strings to the IOC
    addStrings(ioc, initindicator, strings)
    logger.info("已添加字符串到IOC")

    # create our dictionary of dynamic indicators
    dynamicindicators = {"droppedfiles": droppedfiles, "processes": processes, "regkeys": regkeys, 'mutexes': mutexes}

    # add dynamic indicators to the IOC
    createDynamicIndicators(ioc, initindicator, dynamicindicators)
    logger.info("已添加动态指标到IOC")

    # write out the IOC
    # 从环境变量读取输出路径，如果未设置则使用当前目录
    output_dir = os.getenv('IOC_OUTPUT_DIR', os.getcwd())

    # 验证输出目录是否存在
    if not os.path.exists(output_dir):
        print(f"警告: 输出目录 {output_dir} 不存在，尝试创建...")
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            print(f"错误: 无法创建输出目录 - {e}")
            sys.exit(1)

    # 验证是否有写入权限
    if not os.access(output_dir, os.W_OK):
        print(f"错误: 没有写入权限到目录 {output_dir}")
        sys.exit(1)

    print(f"IOC文件将保存到: {output_dir}")
    ioc_api.write_ioc(ioc.root, output_dir)
    logger.info(f"OpenIOC文件已成功生成并保存到: {output_dir}")
    print(f"✓ 成功生成OpenIOC文件！")
    print(f"  文件名: {malname}")
    print(f"  MD5: {malmd5}")
    print(f"  输出目录: {output_dir}")