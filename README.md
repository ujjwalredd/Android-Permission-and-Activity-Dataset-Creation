# Android App Insight: Automated Extraction of Permissions, Activities, and Dataset Generation.
This repository contains code for automatically extracting permissions and activities from Android apps, as well as creating a dataset for further analysis and research purposes.

# Purpose
This code's objective is to automatically extract permissions and activities from Android applications. By doing this, it hopes to make it easier to create datasets for multiple jobs, including machine learning tasks linked to Android app analysis, permission-based analysis, activity detection, and datasets for permission-based analysis.

# Features
* Automatic extraction of permissions from Android app APK files.
* Automatic extraction of activities (UI screens) from Android app APK files.
* Dataset creation by combining extracted permissions and activities into a structured format.
* Preprocessing and cleaning of extracted data for further analysis.

# Prerequisites
* Python 3
* hashlib
* pandas
* numpy
* Androguard: https://androguard.readthedocs.io/en/latest/intro/installation.html

# Usage
* Clone this repository to your local machine.
* Install the required Python dependencies by running pip install -r requirements.txt.
* Download the APK files that you want to extract permissions and activities from and place them in the "Bengin_2017" directory.
* Run the main script "main.py" to perform the extraction and dataset creation process.
* The extracted data will be saved as "data.csv" file.

# Dataset Format
The created dataset will have the following structure:
Name | android.permission.CAMERA | android.permission.READ_SMS | a.envisionmobile.caa.MyCAA | a.envisionmobile.caa.Home 
--- | --- | --- | --- |--- 
a.envisionmobile.caa.apk | 0 | 1 | 1 | 0 
air.com.adobe.connectpro.apk | 1 | 1 | 1 | 0 

Each row represents an Android app and contains the following information:
* Name: The name of the app
* Next Columns having all the Permission and Activites of the APK.
* All the rows corresponding to the APK name t will be having valoe 0 or 1 respesenting the present or not. 

# License

This project is licensed under the MIT License.

Feel free to modify and extend this code to suit your specific needs.

# Acknowledgments

This project was inspired by the need for automated extraction and dataset creation for Android app analysis. Special thanks to the open-source tools and libraries used in this project.

# Contact
If you have any questions or suggestions regarding the code, please feel free to contact Ujjwal Reddy K S at ujjwalreddyks@gmail.com
