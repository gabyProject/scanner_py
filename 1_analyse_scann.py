#!/bin/python
import os
import shutil
from datetime import datetime
import datetime
import sys
import re
import subprocess
from zipfile import ZipFile
from docxtpl import DocxTemplate
import logging.config
import random
import html


""" CSV FORMAT :
                                [LINE 1] = Project ID
                                [LINE 2] = IP address
                                [LINE 3] = URL (need to contains http:// or https://)
"""


FOLDER_TODO='todo'
FOLDER_ERROR='error'
FOLDER_SUCCESS='success'
EXTENSION=".csv"
CSV_DELIMITOR=";"
REGEX="^([0–9]{1,3}.){3}.([0–9]{1,3})$"
CHARACTER_PROTECTION=[";",",","&","|","'","\""]

LIST_FILENAME="listFile.txt"

NMAP_COMMAND="nmap -sC -sV -p- -T5 {}"
NMAP_UDP="nmap -sU -sV -Pn -p- -T5 {}"
WHOIS="whois {}"
HOST="host {}"
NIKTO="nikto -h {}"
CURL="curl -iL {}"
FEROXBUSTER="feroxbuster -u {}"
CURL_OPTION = "curl -X options {}"
CURL_HEAD = "curl --head {}"
CURL_PUT = "curl -i -X PUT {}"
CURL_DELETE = "curl -i -X DELETE {}"
CURL_TRACE = "curl -i -X TRACE {}"

KEY_RESULT = {}

userid=0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def execute_command(cmd):
    print("EXECUTE {}".format(cmd))
    logger.info("EXECUTE {} ".format(cmd))
    output = subprocess.check_output(cmd, shell=True).decode('ascii');
    return output;


def init_file():
    if os.path.isfile(LIST_FILENAME) == False:
        f=open(LIST_FILENAME,'x'):
            f.close()
        logger.info("The file {} is not exist".format(LIST_FILENAME))


def add_in_todolist(project):
    if project is None:
        logger.error("The project value in param is null")
        raise Exception("Error the project is null")
    with open(LIST_FILENAME,"a") as f:
        f.write(project)

def project_exist_in_list(project):
    with open(LIST_FILENAME) as f:
        tabs=f.readlines()
    for tab in tabs:
        if project == tab:
            logger.info("The projet {} cannot be executed".format(project))
            return
    logger.info("The project {} is executed ".format(project))


def remove_project_in_list(project):
    with open(LIST_FILENAME) as f:
        tabs = f.readlines()
    for tab in tabs:
        if tab == project:
            tabs.remove(tab)
    with open(LIST_FILENAME,'w') as f:
        for tab in tabs:
            f.write(tab)
    logger.info("The project {} is deleted".format(project))


def main():
    files = os.listdir('todo')
    for current_file in files:
        file=current_file.lower()
        if not file.endswith(EXTENSION):
            print("[ERROR] file {} don't have the good extension".format(file))
            logger.error("file {} don't have the good extension".format(file))
            file_without_extension=file.split(".")[0]
            file_out="error_{}-{}".format(file_without_extension,get_date_for_file())
            shutil.move("{}/{}".format(FOLDER_TODO,file),"{}/{}".format(FOLDER_ERROR,file_out))
            sys.exit(1)  
        else:
            lines=[]
            with(open("{}/{}".format(FOLDER_TODO,file))) as r:
                lines=r.readlines()
            print("[INFO] analyse file {}/{}".format(FOLDER_TODO,file))
            userid=file.split("_")[1]
            logger.info("Analyse file {}/{}".format(FOLDER_TODO,file))
            folder_with_path="{}/{}".format(FOLDER_TODO,file)
            for line in lines:
                tab=line.split(CSV_DELIMITOR)
                if len(tab) != 3:
                    logger.error("your csv content {} don't contain the good format".format(file))
                    print(""" [ERROR] : Your csv content {} don't contain the good format""".format(file))
                    file_without_extension=file.split(".")[0]
                    file_out="error_{}-{}".format(file_without_extension,get_date_for_file())
                    shutil.move("{}/{}".format(FOLDER_TODO,file),"{}/{}".format(FOLDER_ERROR,file_out))
                    sys.exit(1)
                else:
                    projectid=tab[0]
                    ip=tab[1]
                    url=tab[2]
                    pattern=re.compile(REGEX)
                    if pattern == False:
                        logger.error("Your IP is not in the good format")
                        print("[ERROR] Your IP is not in the good format")
                        file_without_extension=file.split(".")[0]
                        file_out="error_{}-{}".format(file_without_extension,get_date_for_file())
                        shutil.move("{}/{}".format(FOLDER_TODO,file),"{}/{}".format(FOLDER_ERROR,file_out))
                        sys.exit(1)
                    else:
                        print("NMAP")
                        logger.info("The file {} is processed ".format(file))
                        init_file()
                        if not project_exist_in_list(project):
                            add_in_todolist(projectid)
                            nmap_cmd=NMAP_COMMAND.format(ip)
                            nmap_content=execute_command(nmap_cmd)
                            check_caractere_protection(url)
                            
                            logger.info("HOST")
                            host_cmd=HOST.format(url.replace("https://","").replace("http://",""))
                            host_content=execute_command(host_cmd)
                           
                            
                            #nmap_udp=NMAP_UDP.format(ip)
                            #nmapUDP_content=execute_command(nmap_udp)
                            
                            #print("NIKTO")
                            #nikto_cmd=NIKTO.format(url)
                            #nikto_content=execute_command(nikto_cmd)
                            

                            #logger.info("CURL")
                            #url_http=url.replace("https://","http://")
                            #curl_cmd=CURL.format(url_http)
                            #curl_content=execute_command(curl_cmd)

                            logger.info("FEROXBUSTER")
                            feroxbuster_cmd=FEROXBUSTER.format(url)
                            feroxbuster_content=execute_command(feroxbuster_cmd)

                            logger.info("OPTIONS METHOD")
                            curl_option_cmd=CURL_OPTION.format(url) 
                            option_content=execute_command(curl_option_cmd)
                           
                            logger.info("HEAD METHOD")
                            curl_option_head=CURL_HEAD.format(url)
                            head_content=execute_command(curl_option_head)

                            head_content=format_and_execute(CURL_HEAD,url)
                            put_content=format_and_execute(CURL_PUT,url)
                            delete_content=format_and_execute(CURL_DELETE,url)
                            trace_content=format_and_execute(CURL_TRACE,url)
                            

                            KEY_RESULT["nmap"]=nmap_content
                            KEY_RESULT["host"]=host_content
                            #KEY_RESULT["nikto"]=nikto_content
                            #KEY_RESULT["curl"]=curl_content
                            KEY_RESULT["feroxbuster"]=feroxbuster_content
                            KEY_RESULT["options"]=option_content
                            KEY_RESULT["head"]=head_content
                            KEY_RESULT["put"]=put_content
                            KEY_RESULT["delete"]=delete_content
                            KEY_RESULT["trace"]=trace_content
                             
                            filename="success/{}_nmap_result.txt".format(projectid)
                            generate_word(KEY_RESULT,projectid)
                            file_out="{}_{}".format(iduser,file)
                            shutil.move(folder_with_path, "success/{}".format(file_out))
                            remove_project_in_list(projectid)


def format_and_execute(command,param):
    cmd_with_param=command.format(param)
    res=execute_command(cmd_with_param)
    if command.statswith('curl'):
        myHtml=res
        res=html.escape(myHtml)
    return res

def check_caractere_protection(url):
    if url.startswith('http://'):
        return True
    elif url.startswith('https://'):
        return True
    else :
        logger.error("The URL don't contains http")
        print("[ERROR] The URL don't contains http")
        exit(1)
    for char in CHARACTER_PROTECTION:
        if char in url:
            logger.error("The URL Contain the char {} ".format(char))
            print("[ERROR] The URL Contain the char {} ".format(char))
            logger.info("The url is in the good format {} ".format(url))
            exit(1)

def get_date_for_file():
    date_time=datetime.datetime.now()
    date_string=date_time.strftime("%d-%m-%Y_%H-%M-%S")
    return date_string

def generate_word(dictionnary, projectid):
    source="template/template_0.docx"
    random_number=random.randint(1,1000)
    templatename="template_{}.docx".format(random_number)
    logger.info("The filename generated is {} ".format(templatename))
    target="template/{}".format(templatename)
    shutil.copyfile(source, target)
    doc = DocxTemplate(target)
    context = dictionnary
    doc.render(context)
    docgen=target
    doc.save(docgen)
    shutil.move(target, "success/{}".format(templatename))
    print("The file is moved to success/{}".format(templatename))
    logger.info("The file is moved to success/{}".format(templatename))

if __name__ == "__main__":
    main()
