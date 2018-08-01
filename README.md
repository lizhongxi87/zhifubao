# zhifubao
use python2.x or python3.x to Call Alipay（zhi fu bao）
1、pip install pycryptodome(pycrypto很久没维护)
2、适用于python2.7、python3.x


接口调用流程：
一、    alipay = AliPay(
        appid="2018080600180695",  # 支付宝生成
        app_notify_url="http://127.0.0.1:8000/alipay/notify/",
        # 支付宝发送异步（此时用户扫码完成，但没有支付，关闭了页面的支付，自己在支付宝中支付，此时跳转页面return_url满足不了）的请求（通知服务器，用户此订单已经完成，此时后台可以更改用户的相关 信息）
        app_private_key_path="keys/private_2048.txt",  # 个人私钥
        alipay_public_key_path="keys/alipay_key_2048.txt",  # 支付宝的公钥，验证支付宝回传消息使用，不是你自己的公钥,
        debug=True,  # 默认False,
        return_url="http://127.0.0.1:8000/alipay/return/"  # 同步请求，当用户支付成功后，应到跳转到我们自定义的页面中（没有关闭支付后的界面时跳转到我们提供的页面），
    )

二、按支付宝文档要求，对参数进行调整，并加密签名（用自己的私钥）


三、对return_url  app_notify_url 支付宝返回的参数用支付宝的公钥进行解密，查看是否正确
