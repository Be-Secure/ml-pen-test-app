import os
import threading
from urllib.parse import urlparse
import requests
import aishield as ais
from flask import Flask, request
import json
import base64
import schedule
import time
# Create a Flask app instance
app = Flask(__name__)
pypi = True

org_id = '#######' #### Paste org id
x_api_key = '#########'

job_meta_data_path = 'models/bes-image-classification/fuzz-test/JobMetadata.json'

def init_aishield(org_id_val):
    """
    Description : AIShield URL , subscription key and orgid
                Initialize the
    """
    base_url = "https://api.aws.boschaishield.com/prod"
    url=base_url+"/api/ais/v1.5"
    org_id = org_id_val #<<Copy Org_id mentioned in welcome mail after AIShield Subscription>>


    """
    Description: Initialize the AIShield API
    """

    if pypi:
        #if pypi then , x-api-key generation is taken care from pypi side using given org_id
        aishield_client = ais.AIShieldApi(api_url=url,org_id=org_id)

    else:
        print("ELse")
    return aishield_client

def register_model(task:str, attack_type:str, aishield_client):
    """
    Description: Define the task and analysis type for model registration
                "task_type" : refers to the specific type of task being performed, for eg : "image_classification."
                "analysis_type" : refers to the specific type of analysis being performed,for eg : "evasion".
                For more information, check out [https://docs.boschaishield.com/api-docs/lesspostgreater-model-registration#-a-xGGsdVJB3d09cBAck-]
    """
    if pypi:
        task_type = ais.get_type("task", task)
        analysis_type = ais.get_type("analysis", attack_type)


        #Perform model registration
        try:
            status, model_registration_repsone = aishield_client.register_model(task_type=task_type, analysis_type=analysis_type)
        except Exception as e:
            print(str(e))
        
    else:
        print("Else")
    
    return status, model_registration_repsone, task_type, analysis_type

def create_dir(dir_name):
    '''
        Method creates directory on the passed parameter.
    '''
    if os.path.isdir(dir_name):
        print("directory {} already exist".format(dir_name))
    if os.path.isdir(dir_name) is False:
        os.mkdir(path=dir_name)
        print("directory {} created successfully".format(dir_name))

def download_zip_files(*args):
    '''
        Downloads the model.zip, label.zip and data.zip file from repository.
    '''
    zip_path=os.environ['HOME'] +'/zip'
    create_dir(zip_path)
    for item in args:
        response = requests.get(item)
        parsed_url = urlparse(item)
        file_name = os.path.basename(parsed_url.path)
        if response.status_code == 200:
            # If the request is successful, write the content to a local file
            with open(zip_path+'/'+file_name, 'wb') as file:
                file.write(response.content)
            print(file_name+" downloaded successfully!")
        else:
            print("Failed to download the zip file. Status code:", response.status_code)
    return zip_path

def upload_artifacts(zip_path, status, model_registration_repsone, aishield_client):
    """
    Description: Full File paths and upload input artifacts
    """
    # zip_path = 'zip/'
    data_path=os.path.join(zip_path,'data.zip') #full path of data zip
    label_path=os.path.join(zip_path,'label.zip') #full path of label zip
    model_path=os.path.join(zip_path,'model.zip') #full path of model zip
    # model_path=os.path.join(zip_path,'encrypt_model.zip') #full path of model zip. uncomment if model_encryption is 1

    if pypi:
        #upload input artifacts
        upload_status = aishield_client.upload_input_artifacts(job_details=model_registration_repsone,
                                                    data_path=data_path,
                                                    label_path=label_path,
                                                    model_path=model_path, )
        print('Upload status: {}'.format(', '.join(upload_status)))

    else:
        print("else")

def model_analysis(task_type, analysis_type, aishield_client, model_registration_repsone):
    """
    Description: Specify the appropriate configs required for vulnerability analysis and trigger model analysis
    """
    img_row,img_col,channel=28,28,1
    num_classes=10
    input_shape=(img_row,img_col,channel)
    model_encryption=0 #0 if model is uploaded directly as a zip, 1 if model is encryted as .pyc and uploaded as a zip


    if pypi:
        vuln_config = ais.VulnConfig(task_type=task_type,
                                    analysis_type=analysis_type,
                                    defense_generate=True)

        vuln_config.input_dimensions = input_shape  # input dimension for mnist digit classification
        vuln_config.number_of_classes = num_classes  # number of classes for mnist digit classification
        vuln_config.encryption_strategy = model_encryption  # value 0 (or) 1, if model is unencrypted or encrypted(pyc) respectively
        print('IC-Evasion parameters are: \n {} '.format(vuln_config.get_all_params()))



        #Run vulnerability analysis
        job_status, job_details = aishield_client.vuln_analysis(model_id=model_registration_repsone.model_id, vuln_config=vuln_config)

        #unique job_id for the analyis
        job_id = job_details.job_id
        print('\nstatus: {} \nJob_id: {} \n'.format(job_status, job_id))

        #Monitor progress for given Job ID using the Link below
        print('Click on the URL to view Vulnerability Dashboard (GUI): {}'.format(job_details.job_dashboard_uri))

    else:
        print("else")
        
    return job_id


# def download_analysis_reports(status, report_path, aishield_client, job_id):
    
#     if status == "success":
#         output_conf_vuln = ais.OutputConf(report_type=ais.get_type("report", "vulnerability"),
#                                      file_format=ais.get_type("file_format", "json"),
#                                      save_folder_path=report_path)

#         vul_report = aishield_client.save_job_report(job_id=job_id, output_config=output_conf_vuln)
        
#         output_conf_def = ais.OutputConf(report_type=ais.get_type("report", "defense"),
#                                      file_format=ais.get_type("file_format", "json"),
#                                      save_folder_path=report_path)

#         def_report = aishield_client.save_job_report(job_id=job_id, output_config=output_conf_def)
        
#         output_conf_def_art = ais.OutputConf(report_type=ais.get_type("report", "defense_artifact"),
#                                      file_format=ais.get_type("file_format", "json"),
#                                      save_folder_path=report_path)

#         def_artifact_report = aishield_client.save_job_report(job_id=job_id, output_config=output_conf_def_art)

# def get_x_api_key(org_id_val):
    
#     headers = {
#         'org_id': org_id_val
#     }
#     response = requests.get('https://api.aws.boschaishield.com/prod/api/ais/v1.5/get_aws_api_key', headers=headers)
#     if response.status_code == 200:
#         # Print the entire response content
#         x_api_key_data = response.json()        
#     else:
#         # Print the error status code and content
#         print(f"Error: {response.status_code}")
#         print(response.text)
#     return x_api_key_data['x_api_key']

def get_job_meta_data(x_api_key_val, org_id_val, job_id_val):
    '''
        Returns the meta data of a job initiated.
    '''
    headers = {
        'x-api-key': x_api_key_val,
        'org_id': org_id_val
    }
    payload = {
        'job_id': job_id_val
    }
    response = requests.get('https://api.aws.boschaishield.com/prod/api/ais/v1.5/job_detail', headers=headers, params=payload)

    if response.status_code == 200:
        # Print the entire response content
        job_meta_data_all = response.json()
        # print(job_meta_data_all)
        
    else:
        # Print the error status code and content
        print(f"Error: {response.status_code}")
        print(response.text)
    
    job_meta_data = {}
    job_meta_data.update({'JobID': job_id_val,'AttackType': job_meta_data_all['AttackType'], 'ModelInformation': job_meta_data_all['ModelInformation'], 'Time': job_meta_data_all['CreatedTimestamp'], 'AttackQueries': job_meta_data_all['NumerofAttackQueries'], 'VulnerabilityThreshold': job_meta_data_all['VulnerabiltiyThreshold']})    
    return job_meta_data  

def upload_to_github(path, data):
    '''
        Uploads the vulnerability report, defense report and jobmetadata report to ml-assessment-datastore.
    '''
    owner = 'asa1997'
    repo = 'besecure-ml-assessment-datastore'
    url = f'https://api.github.com/repos/{owner}/{repo}/contents/{path}'
    access_token = '########' #### Paste github access token
    
    json_string = json.dumps(data, indent=4)
    base64_content = base64.b64encode(json_string.encode()).decode()
    data = {
        "message": "Adding file",
        "content": base64_content
    }
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'Bearer {access_token}',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    response = requests.put(url, json=data, headers=headers)

    if response.status_code == 201:
        print("File {path} with JSON contents successfully created/updated on GitHub!")
    else:
        print(f"Failed to create/update file under {path}. Status code: {response.status_code}, Error: {response.text}")

def write_job_to_file(job_id_val):
    '''
        Saves the job_id of jobs in progress in a local file. Used to retrieve job_id of jobs in progress.
    '''
    job_folder = os.environ['HOME'] + '/.bes'
    create_dir(job_folder)
    job_file = job_folder +'/job_id.txt'
    
    if os.path.exists(job_file):
        with open(job_file, 'r') as f:
            file_contents = f.read()
    
        if job_id_val in file_contents:
            print("job id exists")
            return "job id exists"
    
    with open(job_file, 'a') as f:
        f.write(job_id_val + '\n')  # Add a newline for clarity
        print(f"{job_id_val} appended to the file:", job_file)

def download_reports(job_id_val, org_id_val, x_api_key_val, report_type_val):
    '''
        Downloads assessment reports from aishield api.
    '''
    headers = {
        'x-api-key': x_api_key_val,
        'org_id': org_id
    }
    payload = {
        'job_id': job_id_val,
        'report_type': report_type_val,
        'file_format': 3
    }
    
    response = requests.get('https://api.aws.boschaishield.com/prod/api/ais/v1.5/job_status_detailed', headers=headers, params=payload)

    if response.status_code == 200:
        # Print the entire response content
        report = response.json()
        # print(job_meta_data_all)
        return report
        
    else:
        # Print the error status code and content
        print(f"Error: {response.status_code}")
        print(response.text)

def delete_job_id(job_id_val):
    '''
        Deletes the job_id entry if the analysis is completed.
    '''
    print("delete job id")
    file_path = os.environ['HOME'] + '/.bes/job_id.txt'
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Remove the specific entry from the list of lines
    lines = [line for line in lines if line.strip() != job_id_val]

    # Write the modified content back to the file
    with open(file_path, 'w') as file:
        file.writelines(lines)
    

def check_job_status():
    '''
        Checks whether an analysis is in progress or not. If completed downloads the report and pushes to github
    '''
    print("check job status")
    vulnerability_report_path = 'models/bes-image-classification/fuzz-test/evasion/VulnerabilityReport1.json'
    defense_report_path = 'models/bes-image-classification/fuzz-test/evasion/DefenceReport1.json'
    
    
    job_file = os.environ['HOME'] + '/.bes/job_id.txt'
    with open(job_file, 'r') as f:
        file_contents = [line.strip() for line in f.readlines()]
    
    for job_id_val in file_contents:
        print(job_id_val)
        if job_id_val == '':
            continue
        headers = {
            'x-api-key': x_api_key,
            'org_id': org_id
        }
        payload = {
            'job_id': job_id_val
        }
        response = requests.get('https://api.aws.boschaishield.com/prod/api/ais/v1.5/job_status_detailed', headers=headers, params=payload)

        if response.status_code == 200:
            # Print the entire response content
            print("Response for job status: 200")
            job_status = response.json()
            # print(job_meta_data_all)
            
        else:
            # Print the error status code and content
            print(f"Error: {response.status_code}")
            print(response.text)
        
        DefenseReport_Status = job_status['DefenseReport_Status']
        VunerabilityEngine_Status = job_status['VunerabilityEngine_Status']
        
        if VunerabilityEngine_Status == 'completed' and DefenseReport_Status == 'completed':
            delete_job_id(job_id_val)
            defense_report = download_reports(job_id_val, org_id, x_api_key, 'defense')
            vulnerability_report = download_reports(job_id_val, org_id, x_api_key, 'vulnerability')
        
            upload_to_github(vulnerability_report_path, vulnerability_report)
            upload_to_github(defense_report_path, defense_report)
            
        else:
            print("analysis in progress")

schedule.every(10).seconds.do(check_job_status) # Scheduler to run check_job_status every 10 second.

def run_scheduler():
    '''
        Method to run the scheduler
    '''
    print("running scheduler")
    while True:
        schedule.run_pending()
        time.sleep(1)

scheduler_thread = threading.Thread(target=run_scheduler)
scheduler_thread.start()

#Define a route and its corresponding view function
@app.route('/ml/assessment/', methods=['POST'])
def index():
    data = request.get_json() 
    ModelUrl = data['ModelUrl']
    DataUrl = data['DataUrl']
    LabelUrl = data['LabelUrl']
    Task = data['Task']
    AnalysisType = data['AnalysisType']
    aishield_client = init_aishield(org_id)
    status, model_registration_repsone, task_type, analysis_type = register_model(Task, AnalysisType, aishield_client)
    zip_path = download_zip_files(ModelUrl, DataUrl, LabelUrl)
    upload_artifacts(zip_path, status, model_registration_repsone, aishield_client)
    job_id = model_analysis(task_type, analysis_type, aishield_client, model_registration_repsone)
    # x_api_key = get_x_api_key(org_id)
    job_meta_data = get_job_meta_data(x_api_key, org_id, job_id)
    job_meta_data.update({'ModelUrl': data['ModelUrl'], 'DataUrl': data['DataUrl'], 'LabelUrl': data['LabelUrl']})
    upload_to_github(job_meta_data_path, job_meta_data)
    # return job_meta_data
    write_job_to_file(job_id)
    return job_meta_data

# Run the app if this file is executed directly
if __name__ == '__main__':
    app.run(debug=True)
    