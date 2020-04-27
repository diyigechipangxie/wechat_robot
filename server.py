#!/bin/bash/evn python
# encoding=utf-8
"""
@file:server.py
@time:4/17/20|10:42 AM
"""
import hashlib
import json
import time

import xmltodict as xmltodict

import tornado.web
import tornado.httpserver
import tornado.options
import tornado.ioloop
import tornado.httpclient
import tornado.gen

tornado.options.define('port', default=9000, type=int, help='example: python example.py --port=9000')
TOKEN = 'secretString'
APP_ID = 'wx440f1d5aaa339ba3'
APP_SECRET = '73d4e6138ed985d2da4f2b76c3ac47c3'


class WechatHandler(tornado.web.RequestHandler):
	""" wechat call server interface """

	def get(self, *args, **kwargs):
		signature = self.get_argument('signature')
		timestamp = self.get_argument('timestamp')
		nonce = self.get_argument('nonce')
		echostr = self.get_argument('echostr')
		tem_li = [timestamp, nonce, echostr]
		tem_str = ''.join(tem_li) + TOKEN
		hash_sign = hashlib.sha1(tem_str.encode()).hexdigest()
		if hash_sign != signature:
			self.send_error(status_code=403)
		else:
			self.write('hello world')

	def post(self, *args, **kwargs):
		xml_data = self.request.body
		dict_data = xmltodict.parse(xml_data)['xml']
		print(dict_data)
		# construct xml_resp
		if 'text' == dict_data['MsgType']:
			dict_resp = dict(
				xml=dict(
					ToUserName=dict_data['FromUserName'],
					FromUserName=dict_data['ToUserName'],
					Content=dict_data['Content'],
					MsgType=dict_data['MsgType'],
					CreateTime=dict_data['CreateTime']
				)
			)
		else:
			dict_resp = dict(
				xml=dict(
					ToUserName=dict_data['FromUserName'],
					FromUserName=dict_data['ToUserName'],
					Content='/wx',
					MsgType='text',
					CreateTime=dict_data['CreateTime']
				)
			)
		xml_resp = xmltodict.unparse(dict_resp)
		self.write(xml_resp)


class AccessToken(object):
	""" server call wechat interface """
	__access_token = None

	@classmethod
	@tornado.gen.coroutine
	def get_access_token(cls):
		if cls.__access_token and (time.time() - cls.__access_token['create_time']) < (
				cls.__access_token['expires_in'] - 200):
			raise tornado.gen.Return(cls.__access_token['access_token'])
		else:
			yield cls.update_access_token()
			raise tornado.gen.Return(cls.__access_token['access_token'])

	@classmethod
	@tornado.gen.coroutine
	def update_access_token(cls):
		client = tornado.httpclient.AsyncHTTPClient()
		url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" + APP_ID + "&secret=" + APP_SECRET
		response = yield client.fetch(url)
		if response.error:
			raise Exception('failed to get access_token')
		else:
			json_resp = response.body
			dict_resp = json.loads(json_resp)
			if dict_resp['access_token']:
				cls.__access_token = dict(
					access_token=dict_resp['access_token'],
					create_time=time.time(),
					expires_in=dict_resp['expires_in']
				)

			else:
				raise Exception(dict_resp['errmsg'])


# class QrcodeHandler(tornado.web.RequestHandler):
#
# 	@tornado.gen.coroutine
# 	def get(self):
# 		scene_str = self.get_argument('s')
# 		try:
# 			access_token = yield AccessToken.get_access_token()
# 		except Exception as e:
# 			self.write('failed')
# 			self.send_error(status_code=403)
# 		client = tornado.httpclient.AsyncHTTPClient()
# 		# construct a request object
# 		url = 'https://api.wechat.com/cgi-bin/qrcode/create?access_token=' + access_token
# 		req_body = {
# 			"expire_seconds": 604800,
# 			"action_name": "QR_SCENE",
# 			"action_info":
# 				{"scene": {"scene_id": scene_str}}
# 		}
# 		req = tornado.httpclient.HTTPRequest(
# 			url=url,
# 			method="POST",
# 			body=json.dumps(req_body),
# 		)
# 		resp = yield client.fetch(req)
# 		if resp.error:
# 			self.write('failed')
# 		else:
# 			json_resp = resp.body
# 			dict_resp = json.loads(json_resp)
# 			self.write('<img src="https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=%s">' % dict_resp['ticket'])


if __name__ == "__main__":
	tornado.options.parse_command_line()
	app = tornado.web.Application(
		[
			(r'/api/wechat', WechatHandler),
			# (r'/api/qrcode', QrcodeHandler)
		],
		debug=True
	)
	http_ser = tornado.httpserver.HTTPServer(app)
	http_ser.listen(tornado.options.options.port)
	tornado.ioloop.IOLoop.current().start()
