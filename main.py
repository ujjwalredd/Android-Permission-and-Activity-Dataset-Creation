from androguard.misc import AnalyzeAPK
import pandas as pd
import numpy as np
import os
import csv
import hashlib

def clean_txt():
    cont = open("./permissions.txt","r").readlines()
    cont_set  = set(cont)
    clean = open("./clean_permissions.txt",'w')
    for lines in cont_set:
        clean.write(lines)

def csv_format():
    test_file = open("./clean_permissions.txt")
    data = test_file.read()
    test_file.close()

    permlist = data.split('\n')
    permlist.pop()

    csv_row_data = ['NAME']
    csv_row_data += permlist

    with open('/root/Desktop/data.csv', 'w') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(csv_row_data)

def activites():
    dir = ["./Benign_2017"]
    Flag = 1
    for data in dir:
        apknamepath = data
        apknamelist = os.listdir(data)
        apknamepath = data + "/"
    for ApkName in apknamelist:
        
        TargetApk = apknamepath + ApkName
        a, d, dx = AnalyzeAPK(TargetApk)
        k = a.get_activities()

        with open("./activites.txt", 'w') as file:
            for row1 in k:
                j = "".join(map(str, row1))
                file.write(j + '\n')
        l1 = open("./permissions.txt", "r")
        l2 = open("./activites.txt", "r")
        map1 = []
        for li1 in l1:
            for li2 in l2:
                if li1 != li2:
                    if li2 != li1:
                        map1.append(li2)

        l1.close()
        l2.close()
        data1 = '{}'.format(''.join(map1))

        with open("./permissions.txt", "a") as dfile1:
            dfile1.writelines(data1)

def permission():
    dir = ["./Benign_2017"]
    Flag = 1
    for data in dir:
        apknamepath = data
        apknamelist = os.listdir(data)
        apknamepath = data + "/"
    for ApkName in apknamelist:
        
        TargetApk = apknamepath + ApkName
        a, d, dx = AnalyzeAPK(TargetApk)
        m = a.get_permissions()

        with open("./myfile.txt", 'w') as file:
            for row in m:
                s = "".join(map(str, row))
                file.write(s + '\n')


        f1 = open("./permissions.txt", "r")
        f2 = open("./myfile.txt", "r")
        tmp = []
        for line1 in f1:
            for line2 in f2:
                if line1 != line2:
                    if line2 != line1:
                        tmp.append(line2)

        f1.close()
        f2.close()
        data = '{}'.format(''.join(tmp))

        with open("./permissions.txt", "a") as file1:
            file1.writelines(data)


def Extract():
    dir = ["./Benign_2017"]
    Flag = 1
    for data in dir:
        apknamepath = data
        apknamelist = os.listdir(data)
        apknamepath = data + "/"
    for ApkName in apknamelist:
        fieldnames = []
        with open('/root/Desktop/data.csv') as csv_file:
            CSVREADER = csv.DictReader(csv_file)
            fieldnames = CSVREADER.fieldnames
        csv_master_dict = dict.fromkeys(fieldnames, 0)
        csv_master_dict['NAME'] = ApkName
        TargetApk = apknamepath + ApkName
        a, d, dx = AnalyzeAPK(TargetApk)
        df = pd.read_csv("/root/Desktop/data.csv")
        df.replace(np.nan,0)
        m = a.get_androidversion_code()
        n = a.get_min_sdk_version()
        o = a.get_max_sdk_version()
        p = a.get_target_sdk_version()
        receiver = len(a.get_receivers())
        features = len(a.get_features())
        hasher = hashlib.md5()
        l = hashlib.sha512()
        with open(TargetApk, 'rb') as f:
            co = f.read()
            hasher.update(co)
        md5 = hasher.hexdigest()
        sha256 = l.hexdigest()
        with open('/root/Desktop/data.csv', 'a') as csv_dump:
            CSVwriter = csv.DictWriter(csv_dump, fieldnames=fieldnames)
            CSVwriter.writerow({
                "androidversion_code": m,
                "NAME": ApkName,
                "min_sdk_version": n,
                "max_sdk_version": o,
                "target_sdk_version": p,
                "md5": md5,
                "Sha256": sha256,
                "get_receivers": receiver,
                "get_features": features,
            })



def get_activities():
    dir = ["./Benign_2017"]
    Flag=1
    for data in dir:
        apknamepath = data
        apknamelist = os.listdir(data)
        apknamepath = data + "/"
    for ApkName in apknamelist:
        
        TargetApk = apknamepath + ApkName
        a, d, dx = AnalyzeAPK(TargetApk)
        df = pd.read_csv("/root/Desktop/data.csv")
        mm = df[df['NAME'] == ApkName].index.values
        print(mm)
        v = a.get_activities()
        with open("./activites1.txt", 'w') as file2:
            for row1 in v:
                z = "".join(map(str, row1))
                file2.write(z + '\n')
        with open("./activites1.txt", "r") as fm:
            for line1 in fm:
                line1 = line1.replace("\r", "").replace("\n", "")
                df.loc[mm, line1]='1'
                df.to_csv("/root/Desktop/data.csv", index=False)

def get_permissions():
    dir = ["./Benign_2017"]
    Flag = 1
    for data in dir:
        apknamepath = data
        apknamelist = os.listdir(data)
        apknamepath = data + "/"
        for ApkName in apknamelist:
            
            df = pd.read_csv("/root/Desktop/data.csv")
            TargetApk = apknamepath + ApkName
            a, d, dx = AnalyzeAPK(TargetApk)
            df = pd.read_csv("/root/Desktop/data.csv")
            i = df[df['NAME'] == ApkName].index.values
            print(i)
            u = a.get_permissions()
            with open("./myfile1.txt", 'w') as file:
                for row in u:
                    s = "".join(map(str, row))
                    file.write(s + '\n')
            with open("./myfile1.txt", 'r') as fm:
                for line in fm:
                    line = line.replace("\r", "").replace("\n", "")
                    df.loc[i, line] = '1'
                    df.to_csv("/root/Desktop/data.csv", index=False)


def Main():
    permission()
    activites()
    clean_txt()
    csv_format()
    Extract()
    get_permissions()
    get_activities()


if __name__ == '__main__':
    Main()
