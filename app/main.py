import os
import yara
import magic
import threading

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename


def yara_scan(file_path, rule_path, success, errors):
    # You will give the exact path of the file and yara_rule set

    if allowed_file(file_path):
        response = ""
        try:
            currentRules = yara.compile(filepath=rule_path)
            matches = currentRules.match(filepath=file_path)
        except Exception as e:
            print("YARA SCANNING ERROR: DETAILES ADDED TO THE LOG FILE")
            # TODO: Loggin will be added
        else:
            if matches:
                if response == "THERE IS NO MATHCING ACCORDING TO THE RULESET":
                    response = ""
                if "YARA SCANNER DETECTED FOLLOWING MATCHES: \n" not in response:
                    response = "YARA SCANNER DETECTED FOLLOWING MATCHES: \n" + response
                for match in matches:
                    response += " - " + str(match) + "\n"
            else:
                if response == "":
                    response = "THERE IS NO MATHCING ACCORDING TO THE RULESET"
            success[file_path] = response
    else:
        errors[file_path] = 'File type is not allowed'


def allowed_file(file_path):
    # Magic Byte Scanner for file types
    # TODO: Create an array of accepted file and do MIME check accordingly

    allowedTypes = ["vnd.microsoft.portable-executable", "plain", "x-dosexec"]
    magicScanner = magic.Magic(mime=True)
    # Checks wheter the file is .exe or not
    fileType = magicScanner.from_file(file_path).split("/")[1]

    return (fileType in allowedTypes)


app = Flask(__name__)


@app.route('/')
def main():
    return "YARA-SCANNER HOMEPAGE"


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
    MAX_THREAD_NUMBER = 16
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
                    if '.yar' not in rule:
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
    app.run(debug=True, port=8080, host="0.0.0.0")
