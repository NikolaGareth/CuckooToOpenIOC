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
from ioc_writer import ioc_api

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

def createMetaData(xmldoc, parentnode, metadata):
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

def addStrings(xmldoc, parentnode, strings):
    if len(strings) > 0:
        stringsind = ioc_api.make_indicator_node("AND")
        for string in strings:
            stringsinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/StringList/string", content=string, content_type="string")
            stringsind.append(stringsinditem)
        parentnode.append(stringsind)
    else:
        return

def createDynamicIndicators(xmldoc, parentnode, dynamicindicators):
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

def doStrings(strings):
    emailregex = re.compile(r'[A-Za-z0-9\.-_%]+@[A-Za-z0-9\.-_]+\.[A-Za-z]{2,6}')
    ipregex = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

    emails = filter(lambda i: emailregex.search(i), strings)
    ips = filter(lambda i: ipregex.search(i), strings)

    return list(set(emails)) + list(set(ips))

if __name__ == '__main__':
    url = "http://192.168.22.176:1337"
    HEADERS = {"Authorization": "Bearer S4MPL3"}
    print("请输入需要生成openioc的任务号：")
    task_id = input()
    URL = url + "/tasks/report/" + task_id
    html = urllib.request.urlopen(URL)
    hjson = json.load(html)
    # print(hjson)
    # print(hjson["target"]["file"]["md5"])
    malmd5 = hjson["target"]["file"]["md5"]
    # print(malmd5)
    malsha1 = hjson["target"]["file"]["sha1"]
    malname = hjson["target"]["file"]["name"]
    malsha256 = hjson["target"]["file"]["sha256"]
    malsha512 = hjson["target"]["file"]["sha512"]
    malsize = hjson["target"]["file"]["size"]
    malfiletype = hjson["target"]["file"]["type"]
    isPE = False
    # PE file (EXE or DLL), just executable (DOS?) or other
    if "PE32" in malfiletype.upper():
        isPE = True
        if "DLL" in malfiletype.upper():
            malfiletype = "Dll"
        else:
            malfiletype = "Executable"

    # Suspicious PE imports
    suspiciousimports = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                         'ReadProcessMemory', 'CreateProcess',
                         'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile', 'InternetConnect',
                         'CreateService',
                         'StartService', 'WriteFile', 'RegSetValueEx', 'WSAstartup', 'InternetOpen', 'InternetOpenUrl',
                         'InternetReadFile',
                         'CreateMutex', 'OpenSCManager', 'OleInitialize', 'CoInitializeEx', 'Navigate',
                         'CoCreateInstance', 'GetProcAddress',
                         'SamIConnect', 'SamrQueryInformationUser', 'SamIGetPrivateData', 'SetWindowsHookEx',
                         'GetAsyncKeyState',
                         'GetForegroundWindow', 'AdjustTokenPrivileges', 'LoadResource']
    iocimports = []
    try:
        for imports in hjson["static"]['pe_imports']:
            for item in imports['imports']:
                if item['name'] in suspiciousimports:
                    iocimports.append(item['name'])
    except:
        pass

    # PE sectionis
    goodpesections = ['.text', '.code', 'CODE', 'INIT', 'PAGE']
    badpesections = []
    try:
        for sections in hjson["static"]['pe_sections']:
            if sections['name'] not in goodpesections:
                badpesection = [sections['name'], sections['size_of_data'], str(sections['entropy'])]
                badpesections.append(badpesection)
    except:
        pass

    # PE Exports
    iocexports = []
    try:
        for exportfunc in hjson["static"]['pe_exports']:
            iocexports.append(exportfunc['name'])
    except:
        pass
    # PE Version Info
    versioninfo = dict.fromkeys(['LegalCopyright', 'InternalName', 'FileVersion', 'CompanyName', 'PrivateBuild',
                                 'LegalTrademarks', 'Comments', 'ProductName', 'SpecialBuild', 'ProductVersion',
                                 'FileDescription', 'OriginalFilename'])

    if 'pe_versioninfo' in hjson["static"]:
        for item in hjson["static"]['pe_versioninfo']:
            if item['name'] in versioninfo:
                versioninfo[item['name']] = item['value']

    # Dropped files
    droppedfiles = []
    try:
        for droppedfile in hjson['dropped']:
            droppedfiles.append([droppedfile['name'], droppedfile['size'], droppedfile['md5'], droppedfile['sha1'],
                                 droppedfile['sha256'], droppedfile['sha512']])
    except:
        pass

    # Mutexes
    mutexes = []
    try:
        if 'mutex' in hjson['behavior']['summary']:
            # Cuckoo 2.0
            for mutex in hjson['behavior']['summary']['mutex']:
                mutexes.append(mutex)
        elif 'mutexes' in hjson['behavior']['summary']:
            # Cuckoo 1.x
            for mutex in hjson['behavior']['summary']['mutexes']:
                 mutexes.append(mutex)
    except:
        pass

    # Processes
    processes = []
    try:
        for process in hjson['behavior']['processes']:
            processes.append([process['process_name'], process['process_id'], process['parent_id']])
    except:
        pass

    # grab IPv4 addresses and emails
    strings = doStrings(hjson['strings'])

    # Registry Keys
    regkeys = []
    if 'regkey_written' in hjson['behavior']['summary']:
        # Cuckoo 2.0
        regkeys = hjson['behavior']['summary']['regkey_written']
    elif 'keys' in hjson['behavior']['summary']:
        # Cuckoo 1.x
        regkeys = hjson['behavior']['summary']['keys']

    # create our base/skeletal IOC
    desc = 'IOCAware OpenIOC Auto-Generated IOC for ' + malname
    ioc = ioc_api.IOC(description=desc, author='162210710130')
    initindicator = ioc.top_level_indicator

    # Create our metadata dictionary for getting the
    # metadata values int the IOC
    metadata = {'malfilename': malname, 'malmd5': malmd5, 'malsha1': malsha1, 'malsha256': malsha256, 'malsha512': malsha512, 'malfilesize': malsize, 'malfiletype': malfiletype, 'iocexports': iocexports, 'iocimports': iocimports, 'badpesections': badpesections, 'versioninfo': versioninfo}

    # add metadata to the IOC
    createMetaData(ioc, initindicator, metadata)

    # add strings to the IOC
    addStrings(ioc, initindicator, strings)

    # create our dictionary of dynamic indicators
    dynamicindicators = {"droppedfiles": droppedfiles, "processes": processes, "regkeys": regkeys, 'mutexes': mutexes}

    # add dynamic indicators to the IOC
    createDynamicIndicators(ioc, initindicator, dynamicindicators)

    # write out the IOC
    reports_path = '/Users/nikolagareth/Downloads'
    # output_dir_format = options.get("output_dir", "{reports_path}")
    # output_dir = output_dir_format.format(reports_path=reports_path)
    output_dir = reports_path
    ioc_api.write_ioc(ioc.root, output_dir)