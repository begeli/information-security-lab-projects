import requests
import binascii
import time
import os

enc_url = "http://127.0.0.1:37200/"
periph_url = "http://127.0.0.1:37100/"

init_mes = b'admin$00000000001637316197922$003575c066c711913e0b95b65aa1a9810c4726af722fc9a27974845a36ffb5aa4011111111111111111111111111111111af4a445d5bfee31c1fba656aefb089f112117264ee42ae55001f1d1a3bc561787439810809ab69fa140077db71232044813b626b53623b6d1a2fbc22f65f12eadfb7a4bc563719c11e063b744f5f91f9c412272ce5af58fbeace9d7862a3c1de8cbb695293a6fe76bf77e9493ad8eab1'
header = {'content-type': 'application/xml', 'content-length': '352'}

hello_mes  = b'hello$00000000001637316197934$000389289a839f8104a19535a57c60be21c2da9312df51308e0cd363ba82885b51111111111111111111111111111111112880ccda64f655478e053e178a2b4caf3441570c37c51e5eddeb4fd3f5a15d94653de7101e9c59229b666124029fc7d2dbf080223cc1e27635e9ea1f374e44bf86208d23fe97661d97ed63d5b1585afed679e7d2855f55d403e71c50ebe0390207d926be16293d3d2aa55e6ea6d9f013'

gets_mes   = b'gets$000000000001637316198344$0011434d9f6277a8dcf01ba29124a24c7fcad984da0feb3190ed8b19fced10385a111111111111111111111111111111112880ccda64f655478e053e178a2b4cafbb53d6f4e3d6208f387806d7fdd1b29d1ef0d44c78d3f67d087385cc23e857792c42ab947b9925bb962c44ce19571c245cedc1efaf00e4e745773ec52a8de4baaa3ea5f7b11113987c0c8283a400c30e9cc7e30a72efae130bb7369a9e391735'

store_mes_1 = b'store$00000000001637316198750$0016fd8ebd2e696dc2323d83ce491aafa0d63f74a40ea31f924159d041837955a2111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5f92247f1a61e1ff48c154a7d889c8a90230a7c1edede1ef3db4d4614116d152ba252906ad668420f46e3321f294cc29272e39c5d99004d5cd4fd63b148c87970f5ae3ddce9d30afa66298b53b414b316'

store_mes_2 = b'store$00000000001637316203988$002878b97f22115c59fbb3fb4b41564a6da24ecc24c48796195c1e42d5d0e5c7ae111111111111111111111111111111112880ccda64f655478e053e178a2b4cafda230f5afde3a2b3e0b8b1fab8932fb5a31a8733254af8eb083fd31fe7a10c364799ac5800ba50b75b32e01b2766953658320f6d1e4d99487824ae501104f85ce6a467afd899cdea1a7d091a1572e0d7f8e9c7906ba8fa066517fa3c167dce4f'

stop_mes = b'admin$00000000001637316209293$00023e67314ec1ac80c7df2ee1f2c5cecb019df64c3362d198236aa68d363a10c911111111111111111111111111111111af4a445d5bfee31c1fba656aefb089f1fcd61d26f3a5c0b85aa902e80032ad7e2e09ce67e206d707c137917710832db26a7fff8c6a7831bac40ed60042e138b8d32eff104960fa9af312358ecad3c257903337a3ba1940030464248eb9677bc7e2d594a5495199ca52923101fc8da202'

hi_mes = b'hi$00000000000001637500738595$007fc187ee95e286625e037734292d5dcb9d0c3b3a8695cb5e483818b825f9e1f8111111111111111111111111111111112880ccda64f655478e053e178a2b4caf93191fcf93e111309e7d249f8ccc0245a91da8ea968d7e56afda23d92484581df4404dfdad84e177c7768eb995b90f3eb17882def7af94252f5794e2b121b6f6b45b6788835bf16fab622160b680ee030078c2740e458329593943535f1348e5'

puts_mes = b'puts$000000000001637501454584$00f582ac4a4626f490eda87fbf7b71ed53b7be4edba7771f6fe3d4f217817edf97111111111111111111111111111111112880ccda64f655478e053e178a2b4caf5ab5613f182e0310a604d2451107c7735c682dffb0d47fa1dc929e05270e2a0c76e12f608f04c8908e79496cd265078c6336ca1698fda2b310a5b3c8c2e3f7709b4716ebddbec25957f5a61ed1edcea22a2f4c7cd00c4e29844b71bd07760207'

done_mes_1 = b'done$000000000001637501460000$00602004bb13698d9ca0c121c92d01d8ccfa57f76406463843c9a8fab966ce4e10111111111111111111111111111111112880ccda64f655478e053e178a2b4cafabb7b2595d25f826815e3cbd5b147caf3e99f1031fe267b34131902d4f2673ee6ed4c10aab145b5cc9a6baa43aa202ad0265f6cf7bfd3ac47cc8472ff0065eec859db108913082faadcbfd559ec8aeaf212be50392fffededd9487d80554856c'

done_mes_2 = b'done$000000000001637501465011$00602004bb13698d9ca0c121c92d01d8ccfa57f76406463843c9a8fab966ce4e10111111111111111111111111111111112880ccda64f655478e053e178a2b4cafabb7b2595d25f826815e3cbd5b147caf3e99f1031fe267b34131902d4f2673ee6ed4c10aab145b5cc9a6baa43aa202ad0265f6cf7bfd3ac47cc8472ff0065eec859db108913082faadcbfd559ec8aeaf212be50392fffededd9487d80554856c'
	
def generate_flag_1():
	os.system("./run.sh")
	
	time.sleep(2)
	
	requests.post(enc_url + "admin", data=init_mes, headers=header)
	requests.post(enc_url + "hello", data=hello_mes, headers=header)
	requests.post(enc_url + "store", data=store_mes_1, headers=header)
	requests.post(enc_url + "store", data=store_mes_1, headers=header)
	requests.post(enc_url + "admin", data=stop_mes, headers=header)

def generate_flag_2():
	os.system("./run.sh")
	
	time.sleep(2)
	
	requests.post(enc_url + "admin", data=init_mes, headers=header)
	requests.post(enc_url + "hello", data=hello_mes, headers=header)
	requests.post(enc_url + "store", data=store_mes_1, headers=header)
	requests.post(enc_url + "store", data=store_mes_2, headers=header)
	requests.post(enc_url + "admin", data=stop_mes, headers=header)

def generate_flag_3():
	os.system("./run.sh")
	
	time.sleep(2)
	
	requests.post(enc_url + "admin", data=init_mes, headers=header)
	requests.post(enc_url + "hello", data=hello_mes, headers=header)
	requests.post(enc_url + "store", data=store_mes_1, headers=header)
	requests.post(enc_url + "admin", data=stop_mes, headers=header)

def main():
	os.chdir("/home/isl/t2")
	
	generate_flag_1()
	generate_flag_2()
	generate_flag_3()

	os.system("./run.sh")
	

if __name__ == "__main__":
	main()