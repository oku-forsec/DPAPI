#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#########################################################################################
##                                                                                     ##
## This file allows offline execution of the Windows DPAPI "UnprotectData()" function, ##
## which is responsible for the DPAPI decryption process.                              ##
##                                                                                     ##
#########################################################################################

###Caution : If you have changed the password for this machine at least once, it may not be available.###

import os
from dpapick3 import blob,masterkey
import hashlib
import win32crypt 

def getDrive_info(Drive="C:", Drive_Status="Logon"):
    Mounted_Drive_List = [f"{d}:" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:")]
    Drive_Status_List = ["Logon","Logoff"]
    if Mounted_Drive_List==["C:"]:
        #print("\nMounted Drive Is C Drive Only")
        print("\nDrive : " + Drive)
        print("Drive Status : " + Drive_Status)
    elif len(Mounted_Drive_List) == 1:
        Drive = Mounted_Drive_List[0]
        print("\nDrive : " + Drive)
        print("Drive Status : " + Drive_Status)
    else:
        print("\nPlease Enter A 'Drive' Number")
        for i in range(len(Mounted_Drive_List)):
            print("%d : %s" % (i,Mounted_Drive_List[i]))
        Drive = Mounted_Drive_List[int(input("Select Number : "))]
        print("\nDrive : " + Drive)
        print("\nPlease Enter A 'Drive Status' Number")
        for i in range(len(Drive_Status_List)):
            print("%d : %s" % (i,Drive_Status_List[i]))
        Drive_Status = Drive_Status_List[int(input("Select Number : "))]
        print("\nDrive Status: " + Drive_Status)
    return Drive,Drive_Status


def getUserName(Drive):
    Users_Path = os.path.join(Drive, os.sep,"Users")
    Files = os.listdir(Users_Path)
    Users_Name_List = [f for f in Files if os.path.isdir(os.path.join(Users_Path, f))]
    print("\nPlease Enter A 'User Name' Number")
    for i in range(len(Users_Name_List)):
        print("%d : %s" % (i,Users_Name_List[i]))
    User_Name= Users_Name_List[int(input("Select Number : "))]
    print("\nUser Name : "+ User_Name)
    return User_Name


def getGUID_fromBlob(BLOB):
    try:
        DPAPI_Blob = blob.DPAPIBlob(BLOB)
        GUID = DPAPI_Blob.mkguid
        print("GUID : ",GUID)
        return GUID
    except:
        print("Error : GUID Is Not Included")
          

def getSID(Drive, User_Name, GUID):
    Protect_Path = os.path.join(Drive, os.sep, "Users", User_Name , "AppData", "Roaming", "Microsoft", "Protect") 
    Files = os.listdir(Protect_Path)
    SID_Path = [os.path.join(Protect_Path,f) for f in Files if os.path.isfile(os.path.join(Protect_Path, f, GUID))][0]
    SID = SID_Path.replace(Protect_Path + "\\","")
    print("SID : " + SID)
    return SID_Path,SID


def calcSHA1_hash(Str):
    Str2Bytes = Str.encode("utf-16")
    Hex_Bytes = Str2Bytes.hex()[4:] #remove utf-16 signature
    Str2Sha1 = hashlib.sha1(bytes.fromhex(Hex_Bytes)).hexdigest()
    print("Input(String) : " + Str + "\nOutput(SHA1) : " + Str2Sha1)
    Str2Sha1_Bytes = bytes.fromhex(Str2Sha1)
    return Str2Sha1_Bytes


def UnProtectData(BLOB, Drive="C:", Drive_Status="Logon", User_Name="Default"): #This function is "win32crypt.CryptUnprotectData(BLOB, None, None, None, 0)[1]" Online.
    DPAPI_Blob = blob.DPAPIBlob(BLOB)
    ###For Verification
    ###Drive_Info = getDrive_info()
    ###Drive,Drive_Status = Drive_Info[0],Drive_Info[1]
    ###User_Name = getUserName(Drive)

    if Drive_Status=="Logon": ## Plan: "if" and "else" convert "try" and "except" ##
        UnProtectData = win32crypt.CryptUnprotectData(BLOB, None, None, None, 0)[1]
        print("UnprotectData(WinAPI) : " + str(UnProtectData))
    else:
        UserPass = str(input("User Password : "))
        GUID = getGUID_fromBlob(BLOB)
        SID_Info = getSID(Drive,User_Name,GUID)
        SID_Path = SID_Info[0]
        SID = SID_Info[1]
    
        UserPass_sha1 = calcSHA1_hash(UserPass) ## Plan: Extract from "CREDHIST" ##

        MasterKeyFile_Path = SID_Path + "\\" + GUID
        with open(MasterKeyFile_Path,"rb") as f:
            MasterKeyFile = f.read()
        MasterKeyFile_Blob = masterkey.MasterKeyFile(MasterKeyFile)
    
        #Decrypt MaterKeyFile BLOB and Get MasterKey
        MasterKeyFile_Blob.decryptWithHash(SID,UserPass_sha1)
        MasterKey = MasterKeyFile_Blob.masterkey.key
        print("MasterKey : " + str(MasterKey))

        #Decrypt ProtectData Using MasterKey 
        DPAPI_Blob.decrypt(MasterKey)
        #print(DPAPI_Blob)
        UnProtectData = DPAPI_Blob.cleartext
        print("UnprotectData(Offline) : " + str(UnProtectData)) 
        #UnprotectData_WinAPI = win32crypt.CryptUnprotectData(BLOB, None, None, None, 0)[1]
    return UnProtectData
    

##### Verification #####
"""
String = "HelloWorld!!"
String = String.encode()
CryptData = win32crypt.CryptProtectData(String, None, None, None, None, 0)
#print(CryptData)
UncryptData = UnProtectData(CryptData)
UncryptData_WinAPI = win32crypt.CryptUnprotectData(CryptData, None, None, None, 0)[1]
print("UnprotectData(WinAPI) : " + str(UncryptData_WinAPI))
"""

