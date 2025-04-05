import os
import requests
import base64
import json
import pyaes
import binascii
from datetime import datetime
import sys

def decrypt_data(ciphertext, key, iv):
    cipher = pyaes.AESModeOfOperationCBC(key, iv=iv)
    decrypted = b''.join([cipher.decrypt(ciphertext[i:i+16]) for i in range(0, len(ciphertext), 16)])
    return decrypted[:-decrypted[-1]]

def main():
    try:
        # 从环境变量获取敏感信息
        session_id = os.environ.get('PHP_SESSION_ID')
        aes_key = os.environ.get('AES_KEY', '65151f8d966bf596').encode()
        aes_iv = os.environ.get('AES_IV', '88ca0f0ea1ecf975').encode()

        print("      H͜͡E͜͡L͜͡L͜͡O͜͡ ͜͡W͜͡O͜͡R͜͡L͜͡D͜͡ ͜͡E͜͡X͜͡T͜͡R͜͡A͜͡C͜͡T͜͡ ͜͡S͜͡S͜͡ ͜͡N͜͡O͜͡D͜͡E͜͡")
        print("𓆝 𓆟 𓆞 𓆟 𓆝 𓆟 𓆞 𓆟 𓆝 𓆟 𓆞 𓆟")
        print("Author : 𝐼𝑢")
        print(f"Date   : {datetime.today().strftime('%Y-%m-%d')}")
        print("Version: 1.0")
        print("𓆝 𓆟 𓆞 𓆟 𓆝 𓆟 𓆞 𓆟 𓆝 𓆟 𓆞 𓆟")

        headers = {
            'accept': '/',
            'accept-language': 'zh-Hans-CN;q=1, en-CN;q=0.9',
            'appversion': '1.3.1',
            'user-agent': 'SkrKK/1.3.1 (iPhone; iOS 13.5; Scale/2.00)',
            'content-type': 'application/x-www-form-urlencoded',
            'Cookie': f'PHPSESSID={session_id}'
        }

        data = {'data': '4265a9c353cd8624fd2bc7b5d75d2f18b1b5e66ccd37e2dfa628bcb8f73db2f14ba98bc6a1d8d0d1c7ff1ef0823b11264d0addaba2bd6a30bdefe06f4ba994ed'}

        response = requests.post(
            'http://api.skrapp.net/api/serverlist',
            headers=headers,
            data=data
        )

        if response.status_code == 200:
            encrypted_data = binascii.unhexlify(response.text.strip())
            decrypted_data = decrypt_data(encrypted_data, aes_key, aes_iv)
            servers = json.loads(decrypted_data)

            results = []
            for server in servers['data']:
                ss_config = f"aes-256-cfb:{server['password']}@{server['ip']}:{server['port']}"
                encoded_config = base64.b64encode(ss_config.encode()).decode()
                results.append(f"ss://{encoded_config}#{server['title']}")

            # 输出结果到文件
            with open('ss_links.txt', 'w') as f:
                f.write('\n'.join(results))
            
            print("Successfully generated SS links!")
            return 0

        print(f"Request failed with status code: {response.status_code}")
        return 1

    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())