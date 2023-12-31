import os
import yara
import magic
import threading
import logging
from dotenv import load_dotenv
from logging.handlers import TimedRotatingFileHandler

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename


def yara_scan(file_path, rule_path, success, errors):
    # YARA scanning function which perfomrs on every thread.

    if allowed_file(file_path):
        try:
            currentRules = yara.compile(filepath=rule_path)
            matches = currentRules.match(filepath=file_path)
            if file_path not in success:
                success[file_path] = ""

            if matches:
                if success[file_path] == "THERE IS NO MATHCING ACCORDING TO THE RULESET":
                    success[file_path] = ""

                if "YARA SCANNER DETECTED FOLLOWING MATCHES: \n" not in success[file_path]:
                    success[file_path] = "YARA SCANNER DETECTED FOLLOWING MATCHES: \n" + \
                        success[file_path]
                for match in matches:
                    success[file_path] = success[file_path] + \
                        " - " + str(match) + "\n"
            else:
                if success[file_path] == "":
                    success[file_path] = "THERE IS NO MATHCING ACCORDING TO THE RULESET"

        except Exception as e:
            print("YARA SCANNING ERROR: DETAILES ADDED TO THE LOG FILE")
            logging.exception(e)
            errors["YARA SCANNING ERROR"] = "FOR SOME YARA RULES SOMETHING WENT WRONG, DETAILS IN error.log"

    else:
        errors[file_path] = 'File type is not allowed'


def allowed_file(file_path):
    # Magic Byte Scanner for file types
    allowedTypes = ["vnd.microsoft.portable-executable", "plain", "x-dosexec"]
    magicScanner = magic.Magic(mime=True)
    # In this application only .exe and .txt files are allowed file types. Howevery, any file type can be added into the allowedTypes
    fileType = magicScanner.from_file(file_path).split("/")[1]
    return (fileType in allowedTypes)


def file_system_check():
    # Checks and creates neccesarry directories if any of them not exist

    workdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isdir(os.path.join(workdir, 'static')):
        os.mkdir(os.path.join(workdir, 'static'))
    if not os.path.isdir(os.path.join(workdir, 'static', 'yara-rules')):
        os.mkdir(os.path.join(workdir, 'static', 'yara-rules'))
    if not os.path.isdir(os.path.join(workdir, 'static', 'uploads')):
        os.mkdir(os.path.join(workdir, 'static', 'uploads'))


def setup_logging():
    # Configure the log handler to rotate error.log every week
    log_file = 'error.log'
    log_level = logging.ERROR

    log_handler = TimedRotatingFileHandler(
        filename=log_file, when='W0', backupCount=3)
    log_handler.setLevel(log_level)

    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(log_format)
    log_handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.addHandler(log_handler)
    logger.setLevel(log_level)


app = Flask(__name__)


@app.route('/')
def main():
    return "YARA-SCANNER HOMEPAGE \n WELCOME TO PYTHON-YARA-SCAN-API"


@app.route('/upload', methods=['POST'])
def upload_file():
    # check if the post request has the file part
    if 'files[]' not in request.files:
        resp = jsonify({'[ERROR]': 'YOUR REQUEST MUST CONTAIN A file[] KEY'})
        resp.status_code = 400
        return resp

    workdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rule_folder_path = os.path.join(workdir, 'static', 'yara-rules')
    file_folder_path = os.path.join(workdir, 'static', 'uploads')
    MAX_THREAD_NUMBER = os.cpu_count()
    files = request.files.getlist('files[]')

    success = {}
    errors = {}
    threads = []

    ruleList = os.listdir(rule_folder_path)
    try:
        if len(ruleList) == 0:
            raise ValueError("[ERROR] Rule list is empty")
        if len(ruleList) > MAX_THREAD_NUMBER:
            numberOfThreads = MAX_THREAD_NUMBER

        else:
            numberOfThreads = len(ruleList)

    except Exception as e:
        print(e)

    else:
        chunks = [ruleList[x:x+numberOfThreads]
                  for x in range(0, len(ruleList), numberOfThreads)]
        for file in files:
            fileName = secure_filename(file.filename)
            file_path = os.path.join(file_folder_path, fileName)
            file.save(file_path)
            for ruleSet in chunks:
                for rule in ruleSet:
                    if not rule.endswith('.yar'):
                        pass

                    rule_directory = os.path.join(rule_folder_path, rule)
                    scan_thread = threading.Thread(target=yara_scan, args=(
                        file_path, rule_directory, success, errors))

                    scan_thread.start()
                    threads.append(scan_thread)

                for thread in threads:
                    thread.join()

                threads.clear()

            for file in os.listdir(file_folder_path):
                os.remove(os.path.join(file_folder_path, file))

    result = errors | success
    resp = jsonify(result)
    resp.status_code = 200
    return resp


if __name__ == '__main__':
    setup_logging()
    load_dotenv()
    file_system_check()
    app.run(port=os.environ.get(
        "HOST_PORT"), host=os.environ.get("HOST_IP"))
