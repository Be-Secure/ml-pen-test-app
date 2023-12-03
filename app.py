import os
from urllib.parse import urlparse
import requests
import aishield as ais
from flask import Flask, request
import json
import base64
# Create a Flask app instance
app = Flask(__name__)
pypi = True

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

def create_dir(dir):
    if os.path.isdir(dir):
        print("directory {} already exist".format(dir))
    if os.path.isdir(dir) is False:
        os.mkdir(path=dir)
        print("directory {} created successfully".format(dir))

def download_zip_files(*args):
        
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
    img_row,img_col,channel=28,28,1
    num_classes=10
    input_shape=(img_row,img_col,channel)
    model_encryption=0 #0 if model is uploaded directly as a zip, 1 if model is encryted as .pyc and uploaded as a zip
    """
    Description: Specify the appropriate configs required for vulnerability analysis and trigger model analysis
    """


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


def download_analysis_reports(status, report_path, aishield_client, job_id):
    
    if status == "success":
        output_conf_vuln = ais.OutputConf(report_type=ais.get_type("report", "vulnerability"),
                                     file_format=ais.get_type("file_format", "json"),
                                     save_folder_path=report_path)

        vul_report = aishield_client.save_job_report(job_id=job_id, output_config=output_conf_vuln)
        
        output_conf_def = ais.OutputConf(report_type=ais.get_type("report", "defense"),
                                     file_format=ais.get_type("file_format", "json"),
                                     save_folder_path=report_path)

        def_report = aishield_client.save_job_report(job_id=job_id, output_config=output_conf_def)
        
        output_conf_def_art = ais.OutputConf(report_type=ais.get_type("report", "defense_artifact"),
                                     file_format=ais.get_type("file_format", "json"),
                                     save_folder_path=report_path)

        def_artifact_report = aishield_client.save_job_report(job_id=job_id, output_config=output_conf_def_art)

def get_x_api_key(org_id_val):
    headers = {
        'org_id': org_id_val
    }
    response = requests.get('https://api.aws.boschaishield.com/prod/api/ais/v1.5/get_aws_api_key', headers=headers)
    if response.status_code == 200:
        # Print the entire response content
        x_api_key_data = response.json()        
    else:
        # Print the error status code and content
        print(f"Error: {response.status_code}")
        print(response.text)
    return x_api_key_data['x_api_key']

def get_job_meta_data(x_api_key_val, org_id_val, job_id_val):
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

def upload_to_github(owner, repo, path, access_token, data):
    
    url = f'https://api.github.com/repos/{owner}/{repo}/contents/{path}'
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
        return "File with JSON contents successfully created/updated on GitHub!"
    else:
        return f"Failed to create/update file. Status code: {response.status_code}, Error: {response.text}"
        
# Define a route and its corresponding view function
@app.route('/ml/assessment/', methods=['POST'])
def index():

# def index(model_url, data_url, label_url, task, attack_type):
    data = request.get_json() 
    # print(data)
    org_id = 'gAAAAABlZrxoBFz5CV9EHuFIChyDLEh0_l7ZW_WEjFoZbV24TvsP7j5UuTsd3BVz3u_RGzKmJBpaNGxi1_D2CywOkDDjsOxZ5w=='
    owner = 'asa1997'
    repo = 'besecure-ml-assessment-datastore'
    job_meta_data_path = 'models/bes-image-classification/fuzz-test/JobMetadata.json'
    access_token = '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'
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
    x_api_key = get_x_api_key(org_id)
    job_meta_data = get_job_meta_data(x_api_key, org_id, job_id)
    job_meta_data.update({'ModelUrl': data['ModelUrl'], 'DataUrl': data['DataUrl'], 'LabelUrl': data['LabelUrl']})
    output = upload_to_github(owner, repo, job_meta_data_path, access_token, job_meta_data)
    return output
    # report_path = os.environ['HOME']+"/reports"
    # status ="success"
    
    # if os.path.isdir(report_path):
    #     print("directory {} already exist".format(report_path))
    # if os.path.isdir(report_path) is False:
    #     os.mkdir(path=report_path)
    #     print("directory {} created successfully".format(report_path))
    # download_analysis_reports(status, report_path, aishield_client, job_id)
    # return "Analysis in progress"
    
# Run the app if this file is executed directly
if __name__ == '__main__':
    app.run(debug=True)
