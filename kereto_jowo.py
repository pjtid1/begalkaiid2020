#!/usr/bin/env python
"""

(C) Copyright 2019 aphip_uhuy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import sys
import os
import schedule
import time
import datetime
import pycurl
import json
import cStringIO
import logging
import requests

from hashlib import md5
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

logging.basicConfig(filename='kereto_jowo-' + datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S") + '.log', level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


def main():
    print('=======================================================')
    print('              Nggolek Tiket V3.0.7')
    print('')
    print('This tools used to book ticket smartly')
    print('This program is secret software: you cant redistribute it and/or modify')
    print('it under the terms of the Himacrot License as published by')
    print('the Secret Software Society, either version 3 of the License, or')
    print('any later version.')
    print('')
    print('Usage: python kereto_jowo.py retry_num use_proxy(0 if no, 1 if yes) set_seat(0 if no, 1 if yes) recipe')
    print('')
    print('=======================================================')
    print('')

    args = len(sys.argv)
    if args < 5:
        print('\nUsage: python ' + str(sys.argv[0]) + ' retry_num use_proxy(0 if no, 1 if yes) set_seat(0 if no, 1 if yes) recipe\n')
        sys.exit()

    numretry = sys.argv[1]
    isusingproxy = sys.argv[2]
    issetseat = sys.argv[3]
    filepath = sys.argv[4]

    if not os.path.isfile(filepath):
        print("File path {} does not exist. Exiting...".format(filepath))
        sys.exit()

    if numretry == "":
        print("Num of retry cannot be blank. Exiting...")
        sys.exit()

    if isusingproxy == "":
        print("use of proxy cannot be blank. Exiting...")
        sys.exit()

    if issetseat == "":
        print("set seat cannot be blank. Exiting...")
        sys.exit()

    linedata = []
    with open(filepath) as my_file:
        linedata = my_file.readlines()

    if issetseat == "1":
        if linedata.count < 4:
            print("please define json seat data on recipe. Exiting...")
            sys.exit()

    if issetseat == "0":
        linedata[3] = "{}"

    check_first(linedata[2].strip(), linedata[1].strip(), numretry, isusingproxy)

    if(check_first):
        kai_booktiket(linedata[0].strip(), linedata[1].strip(), checkresult, numretry, isusingproxy, issetseat, linedata[3].strip())


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = 'kudalumpingtelek'
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(self.cipher.encrypt(pad(data.encode('utf-8'), AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        iv = 'kudalumpingtelek'
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(self.cipher.decrypt(raw), AES.block_size)

    def encrypt_object(self, python_obj):
        new_obj = {}
        for key, value in python_obj.items():
            value2 = AESCipher(self.key).compute_attr_value(value, 'enc')
            new_obj[key] = value2
        return new_obj

    def decrypt_object(self, enc_python_obj):
        dec_obj = {}
        for key, value in enc_python_obj.items():
            value2 = AESCipher(self.key).compute_attr_value(value, 'dec')
            dec_obj[key] = value2
        return dec_obj

    def compute_attr_value(self, value, mode):
        if type(value) is list:
            return [self.compute_attr_value(x, mode) for x in value]
        elif type(value) is dict:
            dec_obj2 = {}
            for key, value4 in value.items():
                if mode == 'dec':
                    dec_obj2[key] = AESCipher(self.key).decrypt(value4)
                else:
                    dec_obj2[key] = AESCipher(self.key).encrypt(value4)
            return dec_obj2
        else:
            if mode == 'dec':
                value3 = AESCipher(self.key).decrypt(value)
            else:
                value3 = AESCipher(self.key).encrypt(value)
            return value3


def check_first(checkdata, bookingdata, numretry, usingproxy):
    successCheck = False
    usingproxy = bool(int(usingproxy) > 0)
    retrylogin = 0
    maxretrylogin = int(numretry)
    resCheck = ""
    pwd = 'telo_pendem_tele'

    while retrylogin < maxretrylogin and not successCheck:
        try:
            reqcheck = json.loads(checkdata)
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Trying search seat : ' + str(retrylogin))
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> search seat to kai :')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data search seat to kai :')

            target = 'http://midsvc-rtsng.kai.id:8111/rtsngmid/mobile/getscheduleune'
            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Accept': 'application/json, text/plain, */*',
                'Host': 'midsvc-rtsng.kai.id:8111',
                'source': 'mobile',
                'User-Agent': 'KAI/2.6.0'}

            bookdataEncrypt = '{"staorigincode":"' + AESCipher(pwd).encrypt(reqcheck['org']) + '","stadestinationcode":"' + AESCipher(pwd).encrypt(reqcheck['des']) + '","tripdate":"' + AESCipher(pwd).encrypt(reqcheck['date']) + '"}'

            r = requests.post(target, data=bookdataEncrypt, headers=headers)

            if r.status_code != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(r.text)
                logging.warning('error search seat res : rc-> ' + str(r.status_code) + ' err-> ' + r.text)
                raise Exception

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> check res : ' + str(r.status_code))
            resCheck = json.loads(r.text)
            logging.info('check set res : ' + str(resCheck))

            if resCheck['code'] == '00':
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> check availability seat')
                if(len(resCheck['payload']) > 0):
                    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> check ' + str(len(resCheck['payload'])) + ' train')
                    for i in resCheck['payload']:
                        if i['noka'] == reqcheck['train_no']:
                            if i['subclass'] == reqcheck['subclass']:
                                if i['availability'] >= int(reqcheck['adult']):
                                    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' hooray seat found process -> check kursi : ' + str(i['availability']))
                                    global checkresult
                                    checkresult = i
                                    return successCheck
                                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' opps seat full process -> check kursi : ' + str(i['availability']))
                                raise Exception
                            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' opps no train class found')
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' opps no seat found')
                raise Exception
            else:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> check res code : ' + str(resCheck['code']) + ' - ' + str(resCheck['message']))
                raise Exception
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retrylogin += 1
            if retrylogin >= maxretrylogin:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return successCheck


def retry_login(logindata, numretry, usingproxy):
    successlogin = False
    usingproxy = bool(int(usingproxy) > 0)
    retrylogin = 0
    maxretrylogin = int(numretry)
    reslogin = ""

    while retrylogin < maxretrylogin and not successlogin:
        try:
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Retrying login no : ' + str(retrylogin))
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> login to kai :')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data login to kai :')
            # print(logindata)
            # print('#########################################')
            buf = cStringIO.StringIO()
            e = pycurl.Curl()
            e.setopt(
                e.URL, 'http://midsvc-rtsng.kai.id:8111/rtsngmid/cred/signin')
            e.setopt(e.HTTPHEADER, [
                'Content-Type: 	application/json;charset=utf-8', 'Host: midsvc-rtsng.kai.id:8111', 'Accept: application/json',
                'source: mobile', 'User-Agent: okhttp/3.12.1'])
            e.setopt(e.POST, 1)
            e.setopt(
                e.POSTFIELDS, logindata)
            e.setopt(e.WRITEFUNCTION, buf.write)
            e.setopt(e.VERBOSE, False)
            e.setopt(e.CONNECTTIMEOUT, 20)
            e.setopt(e.SSL_VERIFYPEER, 0)
            e.setopt(e.SSL_VERIFYHOST, 0)
            if(usingproxy):
                e.setopt(e.PROXY, 'proxy3.bri.co.id')
                e.setopt(e.PROXYPORT, 1707)
                e.setopt(e.PROXYTYPE, e.PROXYTYPE_HTTP)
            e.perform()

            if e.getinfo(e.HTTP_CODE) != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(buf.getvalue())
                logging.warning('error login res : ' + str(buf.getvalue))
                buf.close()
                raise Exception

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> login res : ' + buf.getvalue())
            reslogin = json.loads(buf.getvalue())
            logging.info('login res : ' + str(reslogin))
            buf.close()
            successlogin = True
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retrylogin += 1
            if retrylogin >= maxretrylogin:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return reslogin


def booking_class(loginres, logindata, bookingdata, checkdata, numretry, usingproxy):
    successbook = False
    usingproxy = bool(int(usingproxy) > 0)
    retrybook = 0
    maxretrybook = int(numretry)
    resbooking = ""
    pwd = 'telo_pendem_tele'

    while retrybook < maxretrybook and not successbook:
        try:
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Retrying no : ' + str(retrybook))
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> sending raw data booking to kai :')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data booking to kai ...')
            tokenhead = loginres['payload']
            reqbook = json.loads(bookingdata)
            checkdataraw = checkdata
            # prepare data booking
            bookdataraw = ('{"propscheduleid":"' + checkdataraw["propscheduleid"] + '",'
                           '"tripid":"' + checkdataraw['tripid'] + '",'
                           '"orgid":"' + str(checkdataraw['orgid']) + '",'
                           '"desid":"' + str(checkdataraw['desid']) + '",'
                           '"orgcode":"' + checkdataraw['orgcode'] + '",'
                           '"destcode":"' + checkdataraw['destcode'] + '",'
                           '"tripdate":"' + checkdataraw['tripdate'] + '",'
                           '"departdate":"' + checkdataraw['tripdate'] + '",'
                           '"noka":"' + checkdataraw['noka'] + '",'
                           '"extrafee":"0",'
                           '"wagonclasscode":"' + checkdataraw['wagonclasscode'] + '",'
                           '"wagonclassid":"' + str(checkdataraw['wagonclassid']) + '",'
                           '"customername":"' + reqbook['name'] + '",'
                           '"phone":"' + reqbook['phone'] + '",'
                           '"email":"' + reqbook['email'] + '",'
                           '"subclass":"' + checkdataraw['subclass'] + '",'
                           '"totpsgadult":"' + reqbook['num_pax_adult'] + '",'
                           '"totpsgchild":"0",'
                           '"totpsginfant":"' + reqbook['num_pax_infant'] + '",'
                           '"paxes":""'
                           '}')

            bookdatajson = json.loads(bookdataraw)
            bookdatajson['paxes'] = reqbook['passenger']

            bookdataEncrypt = json.dumps(AESCipher(pwd).encrypt_object(bookdatajson))
            # print(bookdataEncrypt)

            buf2 = cStringIO.StringIO()
            e2 = pycurl.Curl()
            e2.setopt(
                e2.URL, 'http://midsvc-rtsng.kai.id:8111/rtsngmid/mobile/booking')
            e2.setopt(e2.HTTPHEADER, [
                'Content-Type: 	application/json;charset=utf-8', 'accept: application/json, text/plain, */*',
                'authorization: Bearer ' + tokenhead + '', 'Host: midsvc-rtsng.kai.id:8111', 'Accept-Encoding: gzip, deflate',
                'source: mobile', 'User-Agent: okhttp/3.12.1'])
            e2.setopt(e2.POST, 1)
            e2.setopt(
                e2.POSTFIELDS, bookdataEncrypt)
            e2.setopt(e2.WRITEFUNCTION, buf2.write)
            e2.setopt(e2.VERBOSE, False)
            e2.setopt(e2.CONNECTTIMEOUT, 60)
            e2.setopt(e2.SSL_VERIFYPEER, 0)
            e2.setopt(e2.SSL_VERIFYHOST, 0)
            if(usingproxy):
                e2.setopt(e2.PROXY, 'proxy3.bri.co.id')
                e2.setopt(e2.PROXYPORT, 1707)
                e2.setopt(e2.PROXYTYPE, e2.PROXYTYPE_HTTP)
            e2.perform()

            if e2.getinfo(e2.HTTP_CODE) != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(buf2.getvalue())
                logging.warning('error booking res : ' + str(buf2.getvalue()))
                if str(buf2.getvalue()) == '{"error":"token_invalid"}' or (str(buf2.getvalue()) == '{"error":"token_expired"}'):
                    loginres = retry_login(logindata, numretry, usingproxy)
                raise Exception

            resbooking = json.loads(buf2.getvalue())
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> booking res : ' + resbooking['code'] + '-' + resbooking['message'])
            logging.info('booking res : ' + str(resbooking))
            buf2.close()
            successbook = True
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retrybook += 1
            if retrybook >= maxretrybook:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return resbooking


def payment1_class(loginres, logindata, unitcodepay, paycode, netamount, numretry, usingproxy):
    successpay = False
    usingproxy = bool(int(usingproxy) > 0)
    retrypay = 0
    maxretrypay = int(numretry)
    respay = ""
    pwd = 'telo_pendem_tele'

    while retrypay < maxretrypay and not successpay:
        try:
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> sending raw data booking phase 2 to kai :')

            datapayment = 'paycode=' + paycode + ',paytypecode=ATM,channelcodepay=MAPP,netamount=' + str(netamount) + ',tickettype=R,shiftid=15138,unitcodepay=' + unitcodepay + ',paysource=RTSNG'
            datapaymentencrypt = AESCipher(pwd).encrypt(datapayment)
            datasend = '{"data":["' + datapaymentencrypt + '"]}'
            tokenhead = loginres['payload']
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data booking phase 2 to kai ...')

            print('booking code : ' + unitcodepay)
            print('order code : ' + paycode)
            print('net ammount : ' + str(netamount))

            buf3 = cStringIO.StringIO()
            e3 = pycurl.Curl()
            e3.setopt(
                e3.URL, 'http://midsvc-rtsng.kai.id:8111/rtsngmid/py_service/mobile/checkout')
            e3.setopt(e3.HTTPHEADER, [
                'Content-Type: 	application/json;charset=utf-8', 'accept: application/json, text/plain, */*',
                'authorization: Bearer ' + tokenhead + '', 'Host: midsvc-rtsng.kai.id:8111', 'Accept-Encoding: gzip, deflate',
                'source: mobile', 'User-Agent: okhttp/3.12.1'])
            e3.setopt(e3.POST, 1)
            e3.setopt(
                e3.POSTFIELDS, datasend)
            e3.setopt(e3.WRITEFUNCTION, buf3.write)
            e3.setopt(e3.VERBOSE, False)
            e3.setopt(e3.SSL_VERIFYPEER, 0)
            e3.setopt(e3.SSL_VERIFYHOST, 0)

            if(usingproxy):
                e3.setopt(e3.PROXY, 'proxy3.bri.co.id')
                e3.setopt(e3.PROXYPORT, 1707)
                e3.setopt(e3.PROXYTYPE, e3.PROXYTYPE_HTTP)

            e3.perform()

            if e3.getinfo(e3.HTTP_CODE) != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(buf3.getvalue())
                logging.info('error pay res : ' + str(buf3.getvalue()))
                if str(buf3.getvalue()) == '{"error":"token_invalid"}' or (str(buf3.getvalue()) == '{"error":"token_expired"}'):
                    loginres = retry_login(logindata, numretry, usingproxy)
                raise Exception

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> booking phase 2 res : ' + buf3.getvalue())
            respay = json.loads(buf3.getvalue())
            logging.info('pay res : ' + str(respay))
            buf3.close()
            successpay = True
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retrypay += 1
            if retrypay >= maxretrypay:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return respay


def flag_class(loginres, logindata, commonPaycode, numretry, usingproxy):
    successflag = False
    usingproxy = bool(int(usingproxy) > 0)
    retryflag = 0
    maxretryflag = int(numretry)
    resflag = ""

    while retryflag < maxretryflag and not successflag:
        try:
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> sending raw data booking flag to kai :')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data booking flag to kai ...')

            print('commonPaye code : ' + commonPaycode)

            tokenhead = loginres['payload']

            buf4 = cStringIO.StringIO()
            e4 = pycurl.Curl()
            e4.setopt(
                e4.URL, 'http://midsvc-rtsng.kai.id:8111/rtsngmid/mobile/info/updatepaytype/' + commonPaycode + '/227')
            e4.setopt(e4.HTTPHEADER, [
                'Content-Type: 	application/json;charset=utf-8', 'accept: application/json, text/plain, */*',
                'authorization: Bearer ' + tokenhead + '', 'Host: midsvc-rtsng.kai.id:8111', 'Accept-Encoding: gzip, deflate',
                'source: mobile', 'User-Agent: okhttp/3.12.1'])
            e4.setopt(e4.WRITEFUNCTION, buf4.write)
            e4.setopt(e4.VERBOSE, False)
            e4.setopt(e4.SSL_VERIFYPEER, 0)
            e4.setopt(e4.SSL_VERIFYHOST, 0)

            if(usingproxy):
                e4.setopt(e4.PROXY, 'proxy3.bri.co.id')
                e4.setopt(e4.PROXYPORT, 1707)
                e4.setopt(e4.PROXYTYPE, e4.PROXYTYPE_HTTP)

            e4.perform()

            if e4.getinfo(e4.HTTP_CODE) != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(buf4.getvalue())
                logging.info('flag res : ' + str(buf4.getvalue()))
                if str(buf4.getvalue()) == '{"error":"token_invalid"}' or (str(buf4.getvalue()) == '{"error":"token_expired"}'):
                    loginres = retry_login(logindata, numretry, usingproxy)
                raise Exception

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> booking flag res : ' + buf4.getvalue())
            resflag = buf4.getvalue()
            logging.info('flag res : ' + str(resflag))
            buf4.close()
            successflag = True

            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retryflag += 1
            if retryflag >= maxretryflag:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return resflag


def seat_class(loginres, logindata, bookcode, numcode, numretry, usingproxy, seatdata):
    successseat = False
    usingproxy = bool(int(usingproxy) > 0)
    retryseat = 0
    maxretryseat = 1
    resseat = ""

    while retryseat < maxretryseat and not successseat:
        try:
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> sending raw data set seat to kai :')

            print(seatdata)
            dataseatjson = '{"book_code": "' + bookcode + '", "passenger":[' + seatdata + ']}'
            dataseat = str(dataseatjson)
            tokenhead = loginres['payload']
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data set seat to kai ...')

            print('data seat : ' + dataseat)

            buf6 = cStringIO.StringIO()
            e6 = pycurl.Curl()
            e6.setopt(
                e6.URL, 'https://kaiaccess11.kai.id/api/v12/manual_seat')
            e6.setopt(e6.HTTPHEADER, [
                'Content-Type: 	application/json;charset=utf-8', 'accept: application/json, text/plain, */*',
                'authorization: Bearer ' + tokenhead + '',
                'source: mobile', 'User-Agent: okhttp/3.4.1'])
            e6.setopt(e6.POST, 1)
            e6.setopt(
                e6.POSTFIELDS, dataseat)
            e6.setopt(e6.WRITEFUNCTION, buf6.write)
            e6.setopt(e6.VERBOSE, False)
            e6.setopt(e6.SSL_VERIFYPEER, 0)
            e6.setopt(e6.SSL_VERIFYHOST, 0)

            if(usingproxy):
                e6.setopt(e6.PROXY, 'proxy3.bri.co.id')
                e6.setopt(e6.PROXYPORT, 1707)
                e6.setopt(e6.PROXYTYPE, e6.PROXYTYPE_HTTP)

            e6.perform()

            ''' if e3.getinfo(e3.HTTP_CODE) != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(buf3.getvalue())
                logging.info('error pay res : ' + str(buf3.getvalue()))
                if str(buf3.getvalue()) == '{"error":"token_invalid"}' or (str(buf3.getvalue()) == '{"error":"token_expired"}'):
                    loginres = retry_login(logindata, numretry, usingproxy)
                raise Exception '''

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> set seat res : ' + buf6.getvalue())
            resseat = json.loads(buf6.getvalue())
            logging.info('pay res : ' + str(resseat))
            buf6.close()
            successseat = True
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retryseat += 1
            if retryseat >= maxretryseat:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                # sys.exit()

    return resseat


def kai_booktiket(logindata, bookingdata, checkdata, numretry, usingproxy, setseat, seatdata):
    success = False
    usingproxy = bool(int(usingproxy) > 0)
    retry = 0
    maxretry = int(numretry)

    while retry < maxretry and not success:
        try:
            reslogin = retry_login(logindata, numretry, usingproxy)

            if reslogin['code'] == "00":
                resbooking = booking_class(reslogin, logindata, bookingdata, checkdata, numretry, usingproxy)

                if resbooking['code'] == "00":
                    unitcodepay = resbooking['payload']['unitcode']
                    paycode = resbooking['payload']['paycode']
                    netamount = resbooking['payload']['netamount']
                    if setseat == "1":
                        resseat = seat_class(reslogin, logindata, unitcodepay, paycode, numretry, usingproxy, seatdata)

                    respayment = payment1_class(reslogin, logindata, unitcodepay, paycode, netamount, numretry, usingproxy)

                    if respayment['code'] == "00":
                        commonPaycode = respayment['payload']['commonPaycode']
                        resflag = flag_class(reslogin, logindata, commonPaycode, numretry, usingproxy)

                        print(resflag)
                        success = True

        except Exception as er:
            print(er)
            # logging.error('Exception : ' + er)
            # time.sleep(20)
            # continue

        retry += 1
        print('=======================================================')


if __name__ == '__main__':
    checkresult = ''
    main()
