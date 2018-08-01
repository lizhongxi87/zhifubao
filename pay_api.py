# -*- coding: utf-8 -*-

import sys

from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

python_version = sys.version_info[:2]

try:
    if (2, 6) <= python_version <= (3, 0):
        from base64 import b64encode, b64decode
        from urllib import urlopen
        from urlparse import urlparse, parse_qs
        from urllib import quote_plus

except Exception as e:

    from urllib.parse import quote_plus
    from urllib.parse import urlparse, parse_qs
    from urllib.request import urlopen
    from base64 import b64decode, b64encode

"""
Python 3, urllib.parse.quote:
>>> urllib.parse.quote('abc def/foo?bar=baz')
'abc%20def/foo%3Fbar%3Dbaz'

Python 2, urllib.pathname2url:

>>> urllib.pathname2url('abc def/foo?bar=baz')
'abc%20def/foo%3Fbar%3Dbaz'
"""

import json


class AliPay(object):
    """
    支付宝支付接口
    """

    def __init__(self, appid, app_notify_url, app_private_key_path,
                 alipay_public_key_path, return_url, debug=False):
        self.appid = appid
        self.app_notify_url = app_notify_url
        self.app_private_key_path = app_private_key_path
        self.app_private_key = None
        self.return_url = return_url
        with open(self.app_private_key_path) as fp:
            self.app_private_key = RSA.importKey(fp.read())

        self.alipay_public_key_path = alipay_public_key_path
        with open(self.alipay_public_key_path) as fp:
            # 使用支付宝的公钥验证支付宝返回的信息
            self.alipay_public_key = RSA.import_key(fp.read())

        if debug is True:  # 调用沙箱环境接口
            self.__gateway = "https://openapi.alipaydev.com/gateway.do"
        else:  # 调用支付宝正式接口
            self.__gateway = "https://openapi.alipay.com/gateway.do"

    def direct_pay(self, subject, out_trade_no, total_amount, return_url=None, **kwargs):
        biz_content = {
            "subject": subject,  # 主题
            "out_trade_no": out_trade_no,  # 用户提交订单后，生成的订单编号，
            "total_amount": total_amount,  # 提交的金额，小数两位
            "product_code": "FAST_INSTANT_TRADE_PAY",
            # "qr_pay_mode":4
        }

        biz_content.update(kwargs)  # 可以添加支付宝接口非必传参数
        data = self.build_body("alipay.trade.page.pay", biz_content, self.return_url)
        return self.sign_data(data)

    def build_body(self, method, biz_content, return_url=None):
        data = {
            "app_id": self.appid,
            "method": method,
            "charset": "utf-8",
            "sign_type": "RSA2",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "biz_content": biz_content
        }

        if return_url is not None:
            data["notify_url"] = self.app_notify_url
            data["return_url"] = self.return_url

        return data

    def sign_data(self, data):
        """
        对构造的数据进行签名

        :type data:dict
        :param data:
        {'timestamp': '2018-05-16 16:12:32',
        'charset': 'utf-8',
        'app_id': '2016080600180695',
        'biz_content': {'out_trade_no':
        '20170202',
        'product_code': 'FAST_INSTANT_TRADE_PAY',
        'total_amount': 100,
        'subject': '\xe6\xb5\x8b\xe8\xaf\x95\xe8\xae\xa2\xe5\x8d\x953'},
        'version': '1.0',
        'notify_url': 'http://127.0.0.1:8000/alipay/return/',
        'sign_type': 'RSA2',
        'method': 'alipay.trade.page.pay',
        'return_url': 'http://127.0.0.1:8000/alipay/return/'}

        :return: app_id=2016080600180695&biz_content=%7B%22out_trade_no%22%3A%22201702022%22%2C%22product_code%22%3A%22FAST_INSTANT_TRADE_PAY%22%2C%22total_amount%22%3A100%2C%22subject%22%3A%22%5Cu6d4b%5Cu8bd5%5Cu8ba2%5Cu53553%22%7D&charset=utf-8&method=alipay.trade.page.pay&notify_url=http%3A%2F%2F127.0.0.1%3A8000%2Falipay%2Freturn%2F&return_url=http%3A%2F%2F127.0.0.1%3A8000%2Falipay%2Freturn%2F&sign_type=RSA2&timestamp=2018-05-16+16%3A28%3A58&version=1.0&sign=BXJF8byrxraX0owrHGWRDVViFSJPYuemoOpHGlbgWtorQ1at6o6QrLMDnWdsEI%2FdsmrIsZV3O%2Bd4Tl6MHJoFMQmfAZ3U96w%2FZf%2FuWbCrJ78xEH1nmoms4x96qvSvq1FWR1T%2B%2BLdOT3xNAhLsIwHIe8Gw4aO%2FZ%2Ba1iR2GHYPT0Lzh%2BJno28wtfeBdjXonE7bI%2FpceZx7%2BM1vyAHOxE35735GelvkF1NytV2%2B3mAPd%2BFKmKMpAThGs03EEdJx9%2BlmpJesMNL5pwBvJXoLqq7no9npadI1sQJYvkUvjw6nubMdISOtRVhm6EgEcQ3lcHAggpZsFf0cZY2ON2Rrmlpt1qw%3D%3D

        """
        data.pop("sign", None)
        # 排序后的字符串
        unsigned_items = self.ordered_data(data)
        unsigned_string = "&".join("{0}={1}".format(k, v) for k, v in unsigned_items)
        sign = self.sign(unsigned_string.encode("utf-8"))
        # ordered_items = self.ordered_data(data)
        quoted_string = "&".join("{0}={1}".format(k, quote_plus(v)) for k, v in unsigned_items)

        # 获得最终的订单信息字符串
        signed_string = quoted_string + "&sign=" + quote_plus(sign)
        return signed_string

    def ordered_data(self, data):
        """
        对构造的数据进行排序
        :type data:dict
        :param data:
        {'timestamp': '2018-05-16 16:12:32',
        'charset': 'utf-8',
        'app_id': '2016080600180695',
        'biz_content': {'out_trade_no':
        '20170202',
        'product_code': 'FAST_INSTANT_TRADE_PAY',
        'total_amount': 100,
        'subject': '\xe6\xb5\x8b\xe8\xaf\x95\xe8\xae\xa2\xe5\x8d\x953'},
        'version': '1.0',
        'notify_url': 'http://127.0.0.1:8000/alipay/return/',
        'sign_type': 'RSA2',
        'method': 'alipay.trade.page.pay',
        'return_url': 'http://127.0.0.1:8000/alipay/return/'}

        :return:
                [('app_id', '2016080600180695'),
               ('biz_content',
                '{"out_trade_no":"201702022","product_code":"FAST_INSTANT_TRADE_PAY","total_amount":100,"subject":"\\u6d4b\\u8bd5\\u8ba2\\u53553"}'),
               ('charset', 'utf-8'), ('method', 'alipay.trade.page.pay'),
               ('notify_url', 'http://127.0.0.1:8000/alipay/return/'),
               ('return_url', 'http://127.0.0.1:8000/alipay/return/'), ('sign_type', 'RSA2'),
               ('timestamp', '2018-05-16 16:43:32'), ('version', '1.0')]

        注意字母的顺序
        """
        complex_keys = []
        for key, value in data.items():
            if isinstance(value, dict):
                complex_keys.append(key)

        # 将字典类型的数据dump出来
        for key in complex_keys:
            data[key] = json.dumps(data[key], separators=(',', ':'))
        sorted_result = sorted([(k, v) for k, v in data.items()])
        return sorted_result

    def sign(self, unsigned_string):
        """
        :type unsigned_string:basestring
        :param unsigned_string: "app_id=2016080600180695&biz_content={"out_trade_no":"201702022","product_code":"FAST_INSTANT_TRADE_PAY","total_amount":100,"subject":"\u6d4b\u8bd5\u8ba2\u53553"}&charset=utf-8&method=alipay.trade.page.pay&notify_url=http://127.0.0.1:8000/alipay/return/&return_url=http://127.0.0.1:8000/alipay/return/&sign_type=RSA2&timestamp=2018-05-16 16:36:08&version=1.0"
        :return: "aXY51u6QQJXQVrip6wBTHKywxHPs8peFCKygTTRS3nLUeZNdH5tZCBQWYP6ZnStKG/Qo7JQ88uexdd6Px5Bb1XUxOD4D4iiTL8kO8hWEw9XK08ec1dNZphMsnyjOoh+rbpxeP/ss0+iOJj1KjdaMCNwZt22eba5R7aLSfc8WoOm5MoP1ySxAXSGNSPN+JyP2lq05B88mkS5m+OfMdKYcnNYdbFMoBJNaKSDVv+d9KqnHV8zpGngQzfz3vFZivRQVDXN1LMvzRpmQsMuiPibPFwg8vXUHfR5fyfxcuxE6ohtvYgZka3Mr4mJOVogsWAFU+aWJrffPYf63nNveWrWVUw=="

        """
        # 用私有key开始计算签名
        key = self.app_private_key
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(SHA256.new(unsigned_string))

        # base64 编码，转换为unicode表示并移除回车
        sign = b64encode(signature).decode("utf8").replace("\n", "")
        return sign

    def _verify(self, raw_content, signature):
        # 开始计算签名
        key = self.alipay_public_key  # 支付宝提供的公钥
        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(raw_content.encode("utf8"))
        # 对支付宝返回的参数，移除sign_type，sign，排序后再次用支付宝的公钥签名，将签名结果与支付宝返回的sign进行校验，如下操作，比对签名
        if signer.verify(digest, b64decode(signature.encode("utf8"))):
            return True
        return False

    def verify(self, data, signature):
        if "sign_type" in data:
            sign_type = data.pop("sign_type")  # 移除sign_type
        # 排序后的字符串
        unsigned_items = self.ordered_data(data)  # 对字典中的字段重新排序
        message = "&".join(u"{}={}".format(k, v) for k, v in unsigned_items)  # 重新构建需要签名的字符串
        return self._verify(message, signature)


if __name__ == "__main__":
    alipay = AliPay(
        appid="2016080600180695",  # 支付宝生成
        app_notify_url="http://127.0.0.1:8000/alipay/notify/",
        # 支付宝发送异步（此时用户扫码完成，但没有支付，关闭了页面的支付，自己在支付宝中支付，此时跳转页面return_url满足不了）的请求（通知服务器，用户此订单已经完成，此时后台可以更改用户的相关 信息）
        app_private_key_path="keys/private_2048.txt",  # 个人私钥
        alipay_public_key_path="keys/alipay_key_2048.txt",  # 支付宝的公钥，验证支付宝回传消息使用，不是你自己的公钥,
        debug=True,  # 默认False,
        return_url="http://127.0.0.1:8000/alipay/return/"  # 同步请求，当用户支付成功后，应到跳转到我们自定义的页面中（没有关闭支付后的界面时跳转到我们提供的页面），
    )

    # url = alipay.direct_pay(
    #     subject="测试订单3",
    #     out_trade_no="20170202212",
    #     total_amount=500,
    #     return_url="http://127.0.0.1:8000/alipay/return/"
    # )
    # re_url = "https://openapi.alipaydev.com/gateway.do?{data}".format(data=url)
    # # https://openapi.alipaydev.com/gateway.do?app_id=2016080600180695&biz_content=%7B%22out_trade_no%22%3A%2220170202%22%2C%22product_code%22%3A%22FAST_INSTANT_TRADE_PAY%22%2C%22total_amount%22%3A100%2C%22subject%22%3A%22%5Cu6d4b%5Cu8bd5%5Cu8ba2%5Cu53553%22%7D&charset=utf-8&method=alipay.trade.page.pay&notify_url=http%3A%2F%2F127.0.0.1%3A8000%2Falipay%2Freturn%2F&return_url=http%3A%2F%2F127.0.0.1%3A8000%2Falipay%2Freturn%2F&sign_type=RSA2&timestamp=2018-05-16+15%3A56%3A47&version=1.0&sign=BTnawsocSGI8kD3h9UVWrNqppGa2yg6ATkc7sB1MnUEYrVL7JhXuNSKog%2B1F02vmr8S4k3SQWtLC3BQ5DrqSU8vmr0%2Fo4HRZSedxNLRr0fMVBbZqNk0VprL58nbGrxiWG72nJs7WYEM27feH2QW09%2B%2FzvODxiPt2x%2BfIPc0h0lCN6G%2FHcME7OYN%2F5vcGb4Jc%2FraYXi5IVYVDQdltC2F6MMHUYZ7MF4OtXlLeWbTgcNN7hCWgpZnYneP2fmaEGBFkcFZRyV284SsHXbfPW1RrRUOb7xH81r5heVB6WbwJ5UGVpfFaVDro63mi3zKoifh6TK7Ne1OgpI03Zh83fKWWMA%3D%3D
    #
    # # https://excashier.alipaydev.com/standard/auth.htm?payOrderId=c52a2c0d544a460dbe107789153f90f5.00
    # print(re_url)

"""
[16/May/2018 17:26:48] "GET /alipay/return/?
total_amount=100.00
&timestamp=2018-05-16+17%3A26%3A43
&sign=14Y5xw1Nw1AKMt8yv48ck5DO%2Fm0VAHhF0%2FpZF2g%2B%2F%2BJgtQbzB3Jl4gawSEKSyctcx4fTa38Ds4mNhobpEy2MFweXGLqoqYNPWEdxFpinXctEb2IHCrQ7tGxMj1amqqpJMMmnSbqEvCEkel%2Bj07rDQLW%2B6qNRSxpSISxNxm6n%2F99FhhsmnskIZUNMdwuSdXzNGnqMM5R%2FV7IUlOx8iIKbFXKavibXtQmSwGL9ZhaXehPXGCpRTwPuhUxfKL5J6ONdGtC63UmvCCWufQS74VV55FKhqSSfI2fLVhbVuViDpvh3gF4shiPGFPTXaW8CMQ8PLbd2uaCccQMqXCaa0OTxVQ%3D%3D
&trade_no=2018051621001004340200294428
&sign_type=RSA2&auth_app_id=2016080600180695
&charset=utf-8&seller_id=2088102170208070
&method=alipay.trade.page.pay.return
&app_id=2016080600180695
&out_trade_no=201702022
&version=1.0 HTTP/1.1" 500 68907

"""
# 验证支付宝返回的数据
re_url = 'http://127.0.0.1:8000/alipay/return/?charset=utf-8&out_trade_no=20170202212&method=alipay.trade.page.pay.return&total_amount=500.00&sign=aEYbONpO9dvXzNRiseIonyWAcOEXIMttpJoj3Je%2FMr64fGSx%2BKC3uF%2FeVTF9Kj%2Bv5Mh6%2BXTunlyWyg4LVUfHlV2mH4UfBDKnjYTotboACXaayoTbs5CHGhXJ0YUNWqHsFgV2IKDxW1xl%2B3Tp3%2BBWE8DH7rVTSjSkhCK%2BxGtwMX8nWXkVltZDB6XO5RwRFc649qU%2BwzevJJjmtDbz2eMPId82seHG95pAlC%2FeE3%2B6HPce1ycuFddSWCDoSEa19ISjJn8mDMYAmza0BzL2UHt7c6lo1fG0WbxbxvDFCv%2Bb784lO%2FlGp1GeikUwu3VL5sv0d8GivWdMOEi46XmsCDmFKA%3D%3D&trade_no=2018051821001004340200295635&auth_app_id=2016080600180695&version=1.0&app_id=2016080600180695&sign_type=RSA2&seller_id=2088102170208070&timestamp=2018-05-18+11%3A28%3A16'
o = urlparse(re_url)
print 'o:', o  # o: ParseResult(scheme='http', netloc='127.0.0.1:8000', path='/alipay/return/', params='', query='charset=utf-8&out_trade_no=20170202212&method=alipay.trade.page.pay.return&total_amount=500.00&sign=aEYbONpO9dvXzNRiseIonyWAcOEXIMttpJoj3Je%2FMr64fGSx%2BKC3uF%2FeVTF9Kj%2Bv5Mh6%2BXTunlyWyg4LVUfHlV2mH4UfBDKnjYTotboACXaayoTbs5CHGhXJ0YUNWqHsFgV2IKDxW1xl%2B3Tp3%2BBWE8DH7rVTSjSkhCK%2BxGtwMX8nWXkVltZDB6XO5RwRFc649qU%2BwzevJJjmtDbz2eMPId82seHG95pAlC%2FeE3%2B6HPce1ycuFddSWCDoSEa19ISjJn8mDMYAmza0BzL2UHt7c6lo1fG0WbxbxvDFCv%2Bb784lO%2FlGp1GeikUwu3VL5sv0d8GivWdMOEi46XmsCDmFKA%3D%3D&trade_no=2018051821001004340200295635&auth_app_id=2016080600180695&version=1.0&app_id=2016080600180695&sign_type=RSA2&seller_id=2088102170208070&timestamp=2018-05-18+11%3A28%3A16', fragment='')

query = parse_qs(o.query)
print 'query:', query  # query: {'trade_no': ['2018051821001004340200295635'], 'seller_id': ['2088102170208070'], 'total_amount': ['500.00'], 'timestamp': ['2018-05-18 11:28:16'], 'charset': ['utf-8'], 'app_id': ['2016080600180695'], 'sign': ['aEYbONpO9dvXzNRiseIonyWAcOEXIMttpJoj3Je/Mr64fGSx+KC3uF/eVTF9Kj+v5Mh6+XTunlyWyg4LVUfHlV2mH4UfBDKnjYTotboACXaayoTbs5CHGhXJ0YUNWqHsFgV2IKDxW1xl+3Tp3+BWE8DH7rVTSjSkhCK+xGtwMX8nWXkVltZDB6XO5RwRFc649qU+wzevJJjmtDbz2eMPId82seHG95pAlC/eE3+6HPce1ycuFddSWCDoSEa19ISjJn8mDMYAmza0BzL2UHt7c6lo1fG0WbxbxvDFCv+b784lO/lGp1GeikUwu3VL5sv0d8GivWdMOEi46XmsCDmFKA=='], 'out_trade_no': ['20170202212'], 'version': ['1.0'], 'sign_type': ['RSA2'], 'auth_app_id': ['2016080600180695'], 'method': ['alipay.trade.page.pay.return']}

processed_query = {}
ali_sign = query.pop("sign")[
    0]  # ali_sign: aEYbONpO9dvXzNRiseIonyWAcOEXIMttpJoj3Je/Mr64fGSx+KC3uF/eVTF9Kj+v5Mh6+XTunlyWyg4LVUfHlV2mH4UfBDKnjYTotboACXaayoTbs5CHGhXJ0YUNWqHsFgV2IKDxW1xl+3Tp3+BWE8DH7rVTSjSkhCK+xGtwMX8nWXkVltZDB6XO5RwRFc649qU+wzevJJjmtDbz2eMPId82seHG95pAlC/eE3+6HPce1ycuFddSWCDoSEa19ISjJn8mDMYAmza0BzL2UHt7c6lo1fG0WbxbxvDFCv+b784lO/lGp1GeikUwu3VL5sv0d8GivWdMOEi46XmsCDmFKA==

print 'ali_sign:', ali_sign

for key, value in query.items():
    processed_query[key] = value[0]
print 'processed_query:', processed_query  # processed_query: {'trade_no': '2018051821001004340200295635', 'seller_id': '2088102170208070', 'total_amount': '500.00', 'timestamp': '2018-05-18 11:28:16', 'charset': 'utf-8', 'app_id': '2016080600180695', 'out_trade_no': '20170202212', 'version': '1.0', 'sign_type': 'RSA2', 'auth_app_id': '2016080600180695', 'method': 'alipay.trade.page.pay.return'}

print '(alipay.verify(processed_query, ali_sign)):', (alipay.verify(processed_query, ali_sign))
