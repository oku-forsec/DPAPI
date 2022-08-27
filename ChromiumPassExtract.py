#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import UnProtectData
import sqlite3
import shutil
import json
import base64
from datetime import datetime,timedelta
from Crypto.Cipher import AES


def ConvertDate(Date_Value):
    UTC = str(datetime(1601, 1, 1) + timedelta(microseconds=Date_Value))
    if UTC=="1601-01-01 00:00:00":
        return "None"
    else:
        return UTC


def getChromium_info(Drive, User_Name): #Chromium_name:Chrome or Edge or Both
    Chrome_Path,Edge_Path = os.path.join(Drive, os.sep, "Users", User_Name , "AppData", "Local", "Google", "Chrome" , "User Data"), os.path.join(Drive, os.sep, "Users", User_Name , "AppData", "Local", "Microsoft", "Edge" , "User Data")
    Chromium_Path_Dict = {"Google Chrome":Chrome_Path, "Microsoft Edge":Edge_Path}
    if not os.path.isdir(Chrome_Path):
        del Chromium_Path_Dict["Google Chrome"]
        print("Google Chrome Not Installed")    
    if not os.path.isdir(Edge_Path):
        del Chromium_Path_Dict["Microsoft Edge"]
        print("Microsoft Edge Not Installed")
    Chromium_List = [d for d in Chromium_Path_Dict.keys()]
    try:
        if len(Chromium_List)==2:
            print("\nPlease Enter The 'Chomium Base Browser' Number Which You Want To Extract Credentials")
            for i in range(len(Chromium_List)):
                print("%d : %s" % (i,Chromium_List[i]))
            Chromium = Chromium_List[int(input("Select Number : "))]
            Chromium_Path = Chromium_Path_Dict[Chromium]
            print("\nChromium Base Browser : "+ Chromium)
        elif len(Chromium_List)==1:
            Chromium = Chromium_List[0]
            Chromium_Path = Chromium_Path_Dict[Chromium]
            print("\nChromium Base Browser : " + Chromium_Path)
        return Chromium,Chromium_Path
    except:
        print("Error : Failed To Get 'Chromium Base Browser Path'")


def getChromium_Profile(Chromium_Path):
    Files = os.listdir(Chromium_Path)
    Chromium_Profile_List = [f for f in Files if re.match("Default",f) or re.match("Profile [0-9]",f)]
    if Chromium_Profile_List==["Default"]:
        Chromium_Profile = Chromium_Profile_List[0]
        #print("\nChromium Profile Is 'Default' Only")
        print("\nProfile : " + Chromium_Profile)
    else:
        print("\nPlease Enter The 'Profile' Number")
        for i in range(len(Chromium_Profile_List)):
            print("%d : %s" % (i,Chromium_Profile_List[i]))
        Chromium_Profile = Chromium_Profile_List[int(input("Select Number : "))]
        print("\nProfile : " + Chromium_Profile)
    return Chromium_Profile


def getChromium_AES_Key(LocalState_Path, Drive="C:", Drive_Status="Logon", User_Name="Default"): #Chromium Name:Chrome or Edge
    try:
        with open(LocalState_Path,"r", encoding='utf-8') as f:
                LocalState = f.read()
                LocalState = json.loads(LocalState)
        Chromium_AES_Key = base64.b64decode(LocalState["os_crypt"]["encrypted_key"])
        Chromium_AES_Key_Blob = Chromium_AES_Key[5:] #remove "DPAPI"
        Chromium_AES_Key = UnProtectData.UnProtectData(Chromium_AES_Key_Blob, Drive, Drive_Status, User_Name)
        return Chromium_AES_Key
    except:
        print("Error : Failed To Get 'Chromium AES Key Blob'")
    

def decrypt_password(Drive,Drive_Status,User_Name,Buff, AES_Key):
    try:
        Iv = Buff[3:15]
        Password = Buff[15:]
        Cipher = AES.new(AES_Key, AES.MODE_GCM, Iv)
        Decrypted_Password = Cipher.decrypt(Password)[:-16].decode() # remove suffix bytes
        return Decrypted_Password
    except:
        try:
            return str(UnProtectData.UnProtectData(Password, Drive, Drive_Status, User_Name)) #Chrome < 80
        except Exception as e:
            #print(e)
            return "Failed To Decrypt Password or Not Supported Chromium Version" 


def getPassword(Drive,Drive_Status,User_Name,Chromium, Chromium_Path, Profile, Chromium_AES_Key):
    Credentials_DB_Path = os.path.join(Chromium_Path, Profile, "Login Data")

    try:
        shutil.copy2(Credentials_DB_Path, "Credentials_LoginData.db")  # making a temp copy since Login Data DB is locked while Chrome is running
    except:
        print("Error : Failed To Create 'Credentials_LoginData.db'")
    Conn = sqlite3.connect("Credentials_LoginData.db")
    Cursor = Conn.cursor()

    try:
        print("\nList Of Extracted '" + Chromium + "' Credentials")
        Cursor.execute('SELECT value FROM meta WHERE key = "version";')
        Version = int(Cursor.fetchone()[0])
        print("Login Data DB Version", end=" : ")
        print(Version)
        Cursor.execute("SELECT origin_url, action_url, username_value, date_created, date_last_used, password_value FROM logins")
        for r in Cursor.fetchall():
            Origin_URL, Action_URL, Username, Created, LastUsed = r[0], r[1], r[2], r[3], r[4]
            Created_UTC = ConvertDate(Created)
            LastUsed_UTC = ConvertDate(LastUsed)
            Encrypted_Password = r[5]
            Decrypted_Password = decrypt_password(Drive,Drive_Status,User_Name,Encrypted_Password, Chromium_AES_Key)
            if Username != "" or Decrypted_Password != "":
                print( "*" * 70 + "\nOriginal URL: " + Origin_URL + "\nAction URL: " + Action_URL + "\nUser Name: " + Username + "\nPassword: " + Decrypted_Password
                        + "\nCreated Time(UTC): " + Created_UTC + "\nLast Used Time(UTC): " + LastUsed_UTC + "\n" + "*" * 70 + "\n")
    except Exception as e:
        print(e)
        pass

    Cursor.close()
    Conn.close()
    try:
        os.remove("Credentials_LoginData.db")
    except Exception as e:
        pass


def getCreditCard(Drive,Drive_Status,User_Name,Chromium, Chromium_Path, Profile, Chromium_AES_Key):
    Credentials_DB_Path = os.path.join(Chromium_Path, Profile, "Web Data")

    try:
        shutil.copy2(Credentials_DB_Path, "Credentials_WebData.db")  # making a temp copy since Web Data DB is locked while Chrome is running
    except:
        print("Error : Failed To Create 'Credentials_WebData.db'")
    Conn = sqlite3.connect("Credentials_WebData.db")
    Cursor = Conn.cursor()

    try:
        print("\nList Of Extracted '" + Chromium + "' CreditCard")
        Cursor.execute('SELECT value FROM meta WHERE key = "version";')
        Version = int(Cursor.fetchone()[0])
        print("Web Data DB Version", end=" : ")
        print(Version)
        Cursor.execute("SELECT * FROM credit_cards")
        for r in Cursor.fetchall():
            Username = r[1]
            Encrypted_Password = r[4]
            Decrypted_Password = decrypt_password(Drive,Drive_Status,User_Name,Encrypted_Password, Chromium_AES_Key)
            Expire_Month = r[2]
            Expire_Year = r[3]
            print( "*" * 70 + "\nName in Card: " + Username + "\nCard Number: " + Decrypted_Password + "\nExpire Month: " + str(Expire_Month) + "\nExpire Year: " + str(Expire_Year) + "\n" + "*" * 70 + "\n")
    except Exception as e:
        print(e)
        pass

    Cursor.close()
    Conn.close()
    try:
        os.remove("Credentials_WebData.db")
    except Exception as e:
        print(e)
        pass


def getCookie(Drive,Drive_Status,User_Name,Chromium, Chromium_Path, Profile, Chromium_AES_Key):
    Cookies_DB_Path = os.path.join(Chromium_Path, Profile, "Network", "Cookies")

    try:
        shutil.copy2(Cookies_DB_Path, "Cookies_DB.db")  # making a temp copy since Web Data DB is locked while Chrome is running
    except:
        print("Error : Failed To Create 'Cookies_DB.db'")
    Conn = sqlite3.connect("Cookies_DB.db")
    Cursor = Conn.cursor()

    try:
        print("\nList Of Extracted '" + Chromium + "' Cookies")
        Cursor.execute('SELECT value FROM meta WHERE key = "version";')
        Version = int(Cursor.fetchone()[0])
        print("Cookies DB Version", end=" : ")
        print(Version)
        Query = 'SELECT host_key, path, is_secure, creation_utc, expires_utc, name, value, encrypted_value FROM cookies;'
        if Version < 10:
            Query = Query.replace('is_', '')
            Cursor.execute(Query)
        else:
            Cursor.execute(Query)
        for r in Cursor.fetchall():
            #print(r)
            Host, Path, Secure, Creation, Expires, Name, Value = r[0],r[1],r[2],r[3],r[4],r[5],r[6]
            Creation_UTC = ConvertDate(Creation)
            Expires_UTC = ConvertDate(Expires)
            Encrypted_Value = r[7]
            Decrypted_Value = decrypt_password(Drive,Drive_Status,User_Name,Encrypted_Value, Chromium_AES_Key)
            print( "*" * 70 + "\nHost: " + Host + "\nPath: " + Path + "\nSecure: " + str(Secure) + "\nCreation Time(UTC):"+ Creation_UTC + "\nExpires(UTC): " + Expires_UTC + "\nName: " 
                    + Name + "\nValue: " + Value + "\nDecrypted Value: " + Decrypted_Value + "*" * 70 + "\n")
    except Exception as e:
        #print(e)
        pass

    Cursor.close()
    Conn.close()
    try:
        os.remove("Cookies_DB.db")
    except Exception as e:
        pass


def main():
    Drive_Info = UnProtectData.getDrive_info()
    Drive, Drive_Status = Drive_Info[0], Drive_Info[1]
    User_Name = UnProtectData.getUserName(Drive)
    Chromium_Info = getChromium_info(Drive,User_Name)
    Chromium, Chromium_Path = Chromium_Info[0], Chromium_Info[1]
    LocalState_Path = os.path.join(Chromium_Path,"Local State")
    Profile = getChromium_Profile(Chromium_Path)
    Chromium_AES_Key = getChromium_AES_Key(LocalState_Path, Drive, Drive_Status, User_Name)

    getPassword(Drive,Drive_Status,User_Name,Chromium, Chromium_Path, Profile, Chromium_AES_Key)
    #getCreditCard(Drive,Drive_Status,User_Name,Chromium, Chromium_Path, Profile, Chromium_AES_Key)
    #getCookie(Drive,Drive_Status,User_Name,Chromium, Chromium_Path, Profile, Chromium_AES_Key)
    
main()