from __future__ import unicode_literals
import sys
import requests
import json
import yaml
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from urllib3.exceptions import InsecureRequestWarning

from email.mime.text import MIMEText
from email.utils import formataddr
import smtplib

# debug模式
filename = './config.yml' if len(sys.argv) <= 1 else sys.argv[1]
TEST = 1 if len(sys.argv) <= 2 else sys.argv[2]
debug = False
if debug:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

print('Your config is: {}'.format(filename))
print('TEST mode is {}'.format(TEST))


def sendEmail(send,msg):
    my_sender= config['Info']['Email']['account']   # 发件人邮箱账号
    my_pass = config['Info']['Email']['password']         # 发件人邮箱密码
    try:
        msg=MIMEText(getTimeStr() + str(msg),'plain','utf-8')
        msg['From']=formataddr(["结果通知",my_sender])  # 括号里的对应发件人邮箱昵称、发件人邮箱账号
        msg['To']=formataddr(["heyrict",send])              # 括号里的对应收件人邮箱昵称、收件人邮箱账号
        msg['Subject']=title_text               # 邮件的主题，也可以说是标题

        server=smtplib.SMTP_SSL(config['Info']['Email']['server'], config['Info']['Email']['port'])  # 发件人邮箱中的SMTP服务器，端口是25
        server.login(my_sender, my_pass)  # 括号中对应的是发件人邮箱账号、邮箱密码
        server.sendmail(my_sender,[send,],msg.as_string())  # 括号中对应的是发件人邮箱账号、收件人邮箱账号、发送邮件
        server.quit()  # 关闭连接
    except Exception as e:  # 如果 try 中的语句没有执行，则会执行下面的 ret=False
        log(f"邮件发送失败: {e}")
    else: print("邮件发送成功")


# 读取yml配置
def getYmlConfig(yaml_file='config.yml'):
    file = open(yaml_file, 'r', encoding="utf-8")
    file_data = file.read()
    file.close()
    config = yaml.load(file_data, Loader=yaml.FullLoader)
    return dict(config)


# 全局配置
config = getYmlConfig(yaml_file=filename)


# 获取今日校园api
def getCpdailyApis(user):
    apis = {}
    user = user['user']
    # schools = requests.get(
    #     url='https://www.cpdaily.com/v6/config/guest/tenant/list', verify=not debug).json()['data']
    ret = requests.get(url='https://static.campushoy.com/apicache/tenantListSort').json()['data']
    schools = [j for i in ret for j in i['datas']]
    flag = True
    for one in schools:
        if one['name'] == user['school']:
            # if one['joinType'] == 'NONE':
            #     log(user['school'] + ' 未加入今日校园')
            #     sys.exit(-1)
            flag = False
            params = {
                'ids': one['id']
            }
            # res = requests.get(url='https://www.cpdaily.com/v6/config/guest/tenant/info', params=params,
            #                    verify=not debug)
            res = requests.get(url='https://mobile.campushoy.com/v6/config/guest/tenant/info', params=params,
                               verify=not debug)
            data = res.json()['data'][0]
            joinType = data['joinType']
            idsUrl = data['idsUrl']
            ampUrl = data['ampUrl']
            if 'campusphere' in ampUrl or 'cpdaily' in ampUrl:
                parse = urlparse(ampUrl)
                host = parse.netloc
                res = requests.get(parse.scheme + '://' + host)
                parse = urlparse(res.url)
                apis[
                    'login-url'] = idsUrl + '/login?service=' + parse.scheme + r"%3A%2F%2F" + host + r'%2Fportal%2Flogin'
                apis['host'] = host

            ampUrl2 = data['ampUrl2']
            if 'campusphere' in ampUrl2 or 'cpdaily' in ampUrl2:
                parse = urlparse(ampUrl2)
                host = parse.netloc
                res = requests.get(parse.scheme + '://' + host)
                parse = urlparse(res.url)
                apis[
                    'login-url'] = idsUrl + '/login?service=' + parse.scheme + r"%3A%2F%2F" + host + r'%2Fportal%2Flogin'
                apis['host'] = host
            break
    if flag:
        log(user['school'] + ' 未找到该院校信息，请检查是否是学校全称错误')
        sys.exit(-1)
    log(apis)
    return apis


# 获取当前utc时间，并格式化为北京时间
def getTimeStr():
    utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
    return bj_dt.strftime("%Y-%m-%d %H:%M:%S")


# 输出调试信息，并及时刷新缓冲区
def log(content):
    print(getTimeStr() + ' ' + str(content))
    sys.stdout.flush()


# 登陆并返回session
def getSession(user, loginUrl):
    user = user['user']
    params = {
        'login_url': loginUrl,
        # 保证学工号和密码正确下面两项就不需要配置
        'needcaptcha_url': '',
        'captcha_url': '',
        'username': user['username'],
        'password': user['password']
    }

    cookies = {}
    # 借助上一个项目开放出来的登陆API，模拟登陆
    res = requests.post(config['login']['api'], params, verify=not debug)
    cookieStr = str(res.json()['cookies'])
    log(cookieStr)
    if cookieStr == 'None':
        log(res.json())
        return None

    # 解析cookie
    for line in cookieStr.split(';'):
        name, value = line.strip().split('=', 1)
        cookies[name] = value
    session = requests.session()
    session.cookies = requests.utils.cookiejar_from_dict(cookies)
    return session


# 查询表单
def queryForm(session, apis):
    host = apis['host']
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 4.4.4; OPPO R11 Plus Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Safari/537.36 yiban/8.2.14 cpdaily/8.2.14 wisedu/8.2.14',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    queryCollectWidUrl = 'https://{host}/wec-counselor-collector-apps/stu/collector/queryCollectorProcessingList'.format(
        host=host)
    params = {
        'pageSize': 6,
        'pageNumber': 1
    }
    res = session.post(queryCollectWidUrl, headers=headers,
                       data=json.dumps(params), verify=not debug)
    if len(res.json()['datas']['rows']) < 1:
        return None

    collectWid = res.json()['datas']['rows'][0]['wid']
    formWid = res.json()['datas']['rows'][0]['formWid']

    detailCollector = 'https://{host}/wec-counselor-collector-apps/stu/collector/detailCollector'.format(
        host=host)
    res = session.post(url=detailCollector, headers=headers,
                       data=json.dumps({"collectorWid": collectWid}), verify=not debug)
    schoolTaskWid = res.json()['datas']['collector']['schoolTaskWid']

    getFormFields = 'https://{host}/wec-counselor-collector-apps/stu/collector/getFormFields'.format(
        host=host)
    res = session.post(url=getFormFields, headers=headers, data=json.dumps(
        {"pageSize": 100, "pageNumber": 1, "formWid": formWid, "collectorWid": collectWid}), verify=not debug)

    form = res.json()['datas']['rows']
    required_form = list(filter(lambda x: x['isRequired'] == 1, form))
    with open('./required_selected.json', 'w') as f:
        f.write(json.dumps(required_form,ensure_ascii=False))
    return {'collectWid': collectWid, 'formWid': formWid, 'schoolTaskWid': schoolTaskWid, 'form': required_form}


# 填写form
def fillForm(session, form, host):
    sort = 1
    for formItem in form[:]:
        # 只处理必填项
        if formItem['isRequired'] == 1:
            default = config['cpdaily']['defaults'][sort - 1]['default']
            if formItem['title'] != default['title']:
                log('第%d个默认配置不正确，请检查' % sort)
                raise Exception("第%d个默认配置不正确，请检查")
            # 文本直接赋值
            if formItem['fieldType'] == 1 or formItem['fieldType'] == 5:
                formItem['value'] = default['value']
            # 单选框需要删掉多余的选项
            if formItem['fieldType'] == 2:
                # 填充默认值
                formItem['value'] = default['value']
                fieldItems = formItem['fieldItems']
                for i in range(0, len(fieldItems))[::-1]:
                    if fieldItems[i]['content'] != default['value']:
                        del fieldItems[i]
            # 多选需要分割默认选项值，并且删掉无用的其他选项
            if formItem['fieldType'] == 3:
                fieldItems = formItem['fieldItems']
                defaultValues = default['value'].split(',')
                for i in range(0, len(fieldItems))[::-1]:
                    flag = True
                    for j in range(0, len(defaultValues))[::-1]:
                        if fieldItems[i]['content'] == defaultValues[j]:
                            # 填充默认值
                            formItem['value'] += defaultValues[j] + ' '
                            flag = False
                    if flag:
                        del fieldItems[i]
            # 图片需要上传到阿里云oss
            if formItem['fieldType'] == 4:
                fileName = uploadPicture(session, default['value'], host)
                formItem['value'] = getPictureUrl(session, fileName, host)
            log('必填问题%d：' % sort + formItem['title'])
            log('答案%d：' % sort + formItem['value'])
            sort += 1
        else:
            form.remove(formItem)
    # print(form)
    return form


# 上传图片到阿里云oss
def uploadPicture(session, image, host):
    import oss2

    url = 'https://{host}/wec-counselor-collector-apps/stu/collector/getStsAccess'.format(
        host=host)
    res = session.post(url=url, headers={
        'content-type': 'application/json'}, data=json.dumps({}), verify=not debug)
    datas = res.json().get('datas')
    fileName = datas.get('fileName')
    accessKeyId = datas.get('accessKeyId')
    accessSecret = datas.get('accessKeySecret')
    securityToken = datas.get('securityToken')
    endPoint = datas.get('endPoint')
    bucket = datas.get('bucket')
    bucket = oss2.Bucket(oss2.Auth(access_key_id=accessKeyId,
                                   access_key_secret=accessSecret), endPoint, bucket)
    with open(image, "rb") as f:
        data = f.read()
    bucket.put_object(key=fileName, headers={
        'x-oss-security-token': securityToken}, data=data)
    res = bucket.sign_url('PUT', fileName, 60)
    # log(res)
    return fileName


# 获取图片上传位置
def getPictureUrl(session, fileName, host):
    url = 'https://{host}/wec-counselor-collector-apps/stu/collector/previewAttachment'.format(
        host=host)
    data = {
        'ossKey': fileName
    }
    res = session.post(url=url, headers={
        'content-type': 'application/json'}, data=json.dumps(data), verify=not debug)
    photoUrl = res.json().get('datas')
    return photoUrl


# 提交表单
def submitForm(formWid, address, collectWid, schoolTaskWid, form, session, host):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 4.4.4; OPPO R11 Plus Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Safari/537.36 okhttp/3.12.4',
        'CpdailyStandAlone': '0',
        'extension': '1',
        'Cpdaily-Extension': 'DdU824D41owubsfab36hiIHQzRhEmdOUiGzj+VU0IPgBCIHPsNOC+MlVpSoOqWebu2NjR/BBmyvlpTlqh+MFifLlsR222l+zodlIP9AIR7D1ZISnkUQdRb9hqebZlvxuFMHkKmEIamXg8SJ+d4irx5an0d+L1zcDRB9YPYZbObBZb03f1Q5oGQQvlY0wm7xHXXeGtLbxQCB6vqzLKLf1YCHSEnr53JV++aKTDS/jHxH9Bu5DIgtjv4Gn43yh0+ijKQ8PdkVHZLc=',
        'Content-Type': 'application/json; charset=utf-8',
        # 请注意这个应该和配置文件中的host保持一致
        'Host': host,
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }

    # 默认正常的提交参数json
    params = {"formWid": formWid, "address": address, "collectWid": collectWid, "schoolTaskWid": schoolTaskWid,
              "form": form, "uaIsCpadaily": True}
    # print(params)
    submitForm = 'https://{host}/wec-counselor-collector-apps/stu/collector/submitForm'.format(
        host=host)
    r = session.post(url=submitForm, headers=headers,
                     data=json.dumps(params), verify=not debug)
    msg = r.json()['message']
    return msg


title_text = '今日校园疫结果通知'


# 综合提交
def InfoSubmit(msg, send=None):
    log('InfoSubmit: {}'.format(msg))
    if(send is not None):
        if(config['Info']['Email']['enable']): sendEmail(send,msg)


def main_handler(event, context):
    try:
        for user in config['users']:
            log('当前用户：' + str(user['user']['username']))
            apis = getCpdailyApis(user)
            log('脚本开始执行。。。')
            log('开始模拟登陆。。。')
            session = getSession(user, apis['login-url'])
            if session != None:
                log('模拟登陆成功。。。')
                log('正在查询最新待填写问卷。。。')
                params = queryForm(session, apis)
                if str(params) == 'None':
                    log('获取最新待填写问卷失败，可能是辅导员还没有发布。。。')
                    InfoSubmit('没有新问卷')
                    sys.exit(-1)
                log('查询最新待填写问卷成功。。。')
                log('正在自动填写问卷。。。')
                try:
                    form = fillForm(session, params['form'], apis['host'])
                except Exception as e:
                    InfoSubmit('自动提交失败！原因： %s' % e, user['user']['email'])
                    sys.exit(-1)
                log('填写问卷成功。。。')
                if TEST == 1:
                    sys.exit(1)
                log('正在自动提交。。。')
                msg = submitForm(params['formWid'], user['user']['address'], params['collectWid'],
                                 params['schoolTaskWid'], form, session, apis['host'])
                if msg == 'SUCCESS':
                    log('自动提交成功！')
                    InfoSubmit('自动提交成功！', user['user']['email'])
                elif msg == '该收集已填写无需再次填写':
                    log('今日已提交！')
                    InfoSubmit('今日已提交！')
                else:
                    log('自动提交失败。。。')
                    log('错误是' + msg)
                    InfoSubmit('自动提交失败！错误是' + msg, user['user']['email'])
                    sys.exit(-1)
            else:
                log('模拟登陆失败。。。')
                log('原因可能是学号或密码错误，请检查配置后，重启脚本。。。')
                sys.exit(-1)
    except Exception as e:
        InfoSubmit("出现问题了！" + str(e))
        raise e
    else:
        return 'success'


# 配合Windows计划任务等使用
if __name__ == '__main__':
    print(main_handler({}, {}))
    # for user in config['users']:
    #     log(getCpdailyApis(user))
