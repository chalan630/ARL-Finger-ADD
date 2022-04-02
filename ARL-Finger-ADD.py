#!/usr/bin/ python
# -*- coding:utf-8 -*-
import sys
import json
import requests

requests.packages.urllib3.disable_warnings()


'''
-----ARL支持字段：-------
body = " "
title = ""
header = ""
icon_hash = ""
'''


def allEhole(url, token):
    """Ehole fingerprint input

    Args:
        url (str): ARL url
        token (str): ARL token
    """    
    f = open("./finger.json",'r', encoding="utf-8")
    content =f.read()
    load_dict = json.loads(content)
        #dump_dict = json.dump(f)

    body = "body=\"{}\""
    title = "title=\"{}\""
    hash = "icon_hash=\"{}\""
    header = "header=\"{}\""

    for i in load_dict['fingerprint']:
        finger_json =  json.loads(json.dumps(i))
        name = finger_json['cms']
        if finger_json['method'] == "keyword" and finger_json['location'] == "body":
            for rule in finger_json['keyword']:
                rule = rule.replace("=", "")
                rule = body.format(rule)
                add_Finger(name, rule, url, token)

        elif finger_json['method'] == "keyword" and finger_json['location'] == "title":
            for rule in finger_json['keyword']:
                rule = title.format(rule)
                add_Finger(name, rule, url, token)

        elif finger_json['method'] == "keyword" and finger_json['location'] == "header":
            for rule in finger_json['keyword']:
                rule = header.format(rule)
                add_Finger(name, rule, url, token)

        elif finger_json['method'] == "faviconhash":
            for rule in finger_json['keyword']:
                rule = hash.format(rule)
                add_Finger(name, rule, url, token)


def addObserverWard(url, token):
    """Add ObserverWard`s Fingerprint.

    Args:
        url (str): ARL url
        token (str): ARL token
    """
    f = open("web_fingerprint_v3.json", 'r', encoding="utf-8")
    content = f.read()
    load_dict = json.loads(content)

    body = "body=\"{}\""
    title = "title=\"{}\""
    hash = "icon_hash=\"{}\""

    for i in load_dict:
        finger_json = json.loads(json.dumps(i))
        name = finger_json['name']
        if len(finger_json['keyword']):
            for rule in finger_json['keyword']:
                rule = rule.replace("\"", "\\\"")
                rule = rule.replace("=", "")
                rule = body.format(rule)
                add_Finger(name, rule, url, token)
        elif len(finger_json['headers']):
            for i, j in finger_json['headers'].items():
                rule = title.format(i + ": " + j)
                add_Finger(name, rule, url, token)


def add_Finger(name, rule, url, token):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
        "Connection": "close",
        "Token": "{}".format(token),
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/json; charset=UTF-8"
    }
    url = "{}/api/fingerprint/".format(url)
    data = {"name" : name,"human_rule": rule}
    data_json = json.dumps(data)

    try:
        response = requests.post(url, data=data_json, headers=headers, verify=False)
        if response.status_code == 200:
            print(''' Add: [\033[32;1m+\033[0m]  {}\n Rsp: [\033[32;1m+\033[0m] {}'''.format(data_json, response.text))
    except Exception as e:
        print(e)


def test(name,rule):

    return print("name: {}, rule: {}".format(name, rule))


def banner():
    print('''
           _____  _          ______ _                                     _____  _____  
     /\   |  __ \| |        |  ____(_)                              /\   |  __ \|  __ \ 
    /  \  | |__) | |  ______| |__   _ _ __   __ _  ___ _ __ ______ /  \  | |  | | |  | |
   / /\ \ |  _  /| | |______|  __| | | '_ \ / _` |/ _ \ '__|______/ /\ \ | |  | | |  | |
  / ____ \| | \ \| |____    | |    | | | | | (_| |  __/ |        / ____ \| |__| | |__| |
 /_/    \_\_|  \_\______|   |_|    |_|_| |_|\__, |\___|_|       /_/    \_\_____/|_____/ 
                                             __/ |                                      
                                            |___/          
                                                                Auther: loecho-sec
                                                                Version: 0.2
usage:
    option:
        -E      Using the Ehole fingerprint Library
        -O      Using the ObserverWard fingerprint Library
    
    example:
        python ARL-Finger-ADD.py -E https://192.168.1.1:5003/ admin password
    ''')


if __name__ == '__main__':
    try:
        flag = ""
        if len(sys.argv) != 1:
            if sys.argv[1] == "-E":
                flag = "Ehole"
            elif sys.argv[1] == "-O":
                flag = "ObserverWard"
            else:
                banner()

            login_url = sys.argv[2]
            login_name = sys.argv[3]
            login_password = sys.argv[4]

            # login
            str_data = {"username": login_name, "password": login_password}
            login_data = json.dumps(str_data)
            login_res = requests.post(url="{}api/user/login".format(login_url), headers={
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
                "Content-Type": "application/json; charset=UTF-8"}, data=login_data, verify=False)

            # 判断是否登陆成功：
            if "401" not in login_res.text:

                #print(type(login_res.text))
                token = json.loads(login_res.text)['data']['token']
                print("[+] Login Success!!")

                # main
                if flag == "Ehole":
                    allEhole(login_url, token)
                elif flag == "ObserverWard":
                    addObserverWard(login_url, token)
            else:
                print("[-] login Failure! ")
        else:
            banner()

    except Exception as a:
        sys.exit(0)
