
USERNAME = "你的校园网账户"
PASSWORD = "校园网账户密码"

















from LoginManager import LoginManager
import urequests

if __name__=="__main__":
    lm = LoginManager(USERNAME,PASSWORD)
    lm.login()
    c = urequests.get("https://api.fcloud.host/api/test/").text
    print(c)
