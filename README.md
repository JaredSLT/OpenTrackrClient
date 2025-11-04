This program takes in parameters as hashes, uses UDP to contect OpenTrackr.org to get the seeders, leechers and number of completed downloads and serializes it into JSON as fast as it possibly can. It SHOULD work on any computer. For example:
```
C:\Users\user\CLionProjects\OpenTrackr\cmake-build-release-clang\OpenTrackr.exe -v 14fb00a4c4828584618c4ed3ff7a75d9984e8a6c
[{"info_hash":"14fb00a4c4828584618c4ed3ff7a75d9984e8a6c","seeders"196,"leechers":28,"completed":41480}]
Initialization time: 398700 ns
Hash parsing time: 4800 ns
Execution time: 219 ms

Process finished with exit code 0

```
```
C:\Users\user\CLionProjects\OpenTrackr\cmake-build-release-clang\OpenTrackr.exe -v 9bbb986a18642cb1a7c6268df4ea35f07b621970 6d089a9ad5ad19dfb2b1bda933309b37865001ae bfed63ccb64e55cf56610b85fe2041e835acaae7 d1ad4f4cccc44e6227283bd334487e777eb88edc 554cc47f9da3a45cf6a4d94802bc154358c27ee9 6d22f6691f28450a1d66d03d9dee23535757e8b9 a08adab0ca7a4b40391109e781bb5ed2df2e350e 07deaa1b42fe06e4154c8f67b8813a3988257240 aada8cf5a237e3b913096628079ac88337fb96b9 629f1c5f182b84acd1c751561aa9581dc5acf2d5 e220480501b06743c8fd6295b0c34f459634a364 2606a5830780074b089fab96904009da412c1c3d 98ff12fb63293c887517917b5cf968431fd96f1a a5e3343337df7044626992f48ec2546d7b51e39b 6f8f8e11098a60b39dd3da2d7e33bd20e0842c13 7792c2a83ba7a89f450e5357ca4457ab0ee3dfe2 4c9d18e1cde6dacd39f6443d76ddba8e7e82a06b da5a9c0a367d08927bb95eab73ce82f323c4fa79 b4cada42f869b6b142b55fd72cd490e29aee8615 14fb00a4c4828584618c4ed3ff7a75d9984e8a6c 7b9044c62bd15282dac822b60006ee623cf14de9 f821424e33a49abd8816823adbc03b340331c0af c1ce06b0aee58b9ae5fce1dfc4a9d0ec8e015a12 39f301178307b2e015f27e208a7aeb985dc13040 8f6b5776fe53e71c5d417f3ebcd08c51fa7a82da 79c25da699546296650a81413f8ada3a82d0eb38 592b32cf0a987f3b9916ae66df24988ddcf01cd8 63dbb043444e96ebaf0cd544311d3afad86ea2cc 53a4a411decdaf7e1be919607b7a4187987bf0bb 9dda240e03be6dbf060e91abf66510fbc2c07654 76d81232944a6a0f03057e03f4fb1757029be26b 427893b6c4ed7f9be45d09e0f92e236278770822 92ae1d715d996078e33581f2457344ee2034df2c ae6bbcf9270b44f3d2fd54f14e8933a7d68a4c84 ef4211584f37ca70a4b1a2e47e7e833c79abacba 5156c2fa6f6901560bf030a5fb8efb7ecb4b6644 bad9140f563172a1b85e29eb35f23455ea6ba9c2 d1c5bd9a2eec5fe6eba19e7f663af3e8d932ab8e 07e764190536559c2889ec98c1974c308373945a 9922975f45404048e721dd834722357a762beddc be55a6af7330a00908c1a558880c06d8eea0805a 14fa0162a124da2a726f4570ab171e3a942db5f8 cc6c0deab3bdd2210d9d65a22b3297f8360b3bb1 2bc57f95604d4ab278e9605651ed801f3171ae2a 91a6e71c3588df1adbae1a97bf53b3e01db7ba9a 650cb21e31b5a06a5fcb22bd5ba98c0ea9fa5624 24fe4224a4294fabee15594ec4124608d56d9696 11fe2c5676748ca73ab7adf382174c10b28da681 2c9c0c414d712881572fa2a5ab3c5c1381348f0a 2e5a7f8a673225e028f5b3e846ff070a78292108 3576045f75ff2bbe5578b7a5a4fb106805c7c849 917633b935c3ee71d51c79c24743dc67b0f50456 e0d5da1eb51067045e315460fd58566cee3a35b7 0bbd527b8d610cb040ec2c6156fa18de7edfe0b5 0dbe51bcad46651133f8b90f4f7725a92fd7ebc0 792be3f97363df1201102ed89a2cbc6cf439b9bb 4863cbbc67e9aa39444771dbaa2b28266fea353a aed06fe65a915ed8d3e5933462e387dc3ab4c5b6 e34446cd86f3981472b259d35f05fe2b9f4c57dc 497163ea78e823724b1cdaa1d6d88065afa1e2cb 803caadbaee1b71d6396ca536d757926419fbe5c bcb23960cc16fcb2e76c6dddf65636d45e075175 f1dc6a0623befe944feb967b9f58d3c6dc8aa90c 5ebcda763a8fde8c282a6f2dbe40a23fef366e75 04f02a854da07d76dfdbade90b913ad8d596c4bf 54d13ea46ea015b26666f2b7784343731e053a13 4b3e7a69f376621d57dfd5e1b9c6b341e01e8a5b 7af70dc9f90156ad7d839545c4d8a8a558f56c1e d8677f8d37528f0eaa48bb91740b4dab9288b4f1 26993329b98990d7b5d58109335c2d4341b5fb28 775c73fb4b82fa4e4cea85d920eda592bd093818 dfbcaf43a2c5a4b7c6a5ad4921ff85b3ae342123 7b337d59689c248705c7ff3473bb6f329807eb4b 4293e07264e265d2bcc756361c1461c8a67280bf
[{"info_hash":"9bbb986a18642cb1a7c6268df4ea35f07b621970","seeders"172,"leechers":15,"completed":40190},{"info_hash":"6d0
89a9ad5ad19dfb2b1bda933309b37865001ae","seeders"181,"leechers":8,"completed":57540},{"info_hash":"bfed63ccb64e55cf56610b
85fe2041e835acaae7","seeders"135,"leechers":3,"completed":27386},{"info_hash":"d1ad4f4cccc44e6227283bd334487e777eb88edc"
,"seeders"471,"leechers":79,"completed":93450},{"info_hash":"554cc47f9da3a45cf6a4d94802bc154358c27ee9","seeders"302,"lee
chers":95,"completed":61347},{"info_hash":"6d22f6691f28450a1d66d03d9dee23535757e8b9","seeders"264,"leechers":146,"comple
ted":62290},{"info_hash":"a08adab0ca7a4b40391109e781bb5ed2df2e350e","seeders"270,"leechers":28,"completed":42409},{"info
_hash":"07deaa1b42fe06e4154c8f67b8813a3988257240","seeders"193,"leechers":114,"completed":23545},{"info_hash":"aada8cf5a
237e3b913096628079ac88337fb96b9","seeders"173,"leechers":3,"completed":29463},{"info_hash":"629f1c5f182b84acd1c751561aa9
581dc5acf2d5","seeders"140,"leechers":6,"completed":68157},{"info_hash":"e220480501b06743c8fd6295b0c34f459634a364","seed
ers"188,"leechers":203,"completed":21622},{"info_hash":"2606a5830780074b089fab96904009da412c1c3d","seeders"191,"leechers
":21,"completed":26663},{"info_hash":"98ff12fb63293c887517917b5cf968431fd96f1a","seeders"145,"leechers":15,"completed":4
1453},{"info_hash":"a5e3343337df7044626992f48ec2546d7b51e39b","seeders"0,"leechers":0,"completed":0},{"info_hash":"6f8f8
e11098a60b39dd3da2d7e33bd20e0842c13","seeders"99,"leechers":8,"completed":28492},{"info_hash":"7792c2a83ba7a89f450e5357c
a4457ab0ee3dfe2","seeders"161,"leechers":3,"completed":26460},{"info_hash":"4c9d18e1cde6dacd39f6443d76ddba8e7e82a06b","s
eeders"161,"leechers":25,"completed":33561},{"info_hash":"da5a9c0a367d08927bb95eab73ce82f323c4fa79","seeders"117,"leeche
rs":6,"completed":33606},{"info_hash":"b4cada42f869b6b142b55fd72cd490e29aee8615","seeders"129,"leechers":16,"completed":
24767},{"info_hash":"14fb00a4c4828584618c4ed3ff7a75d9984e8a6c","seeders"196,"leechers":28,"completed":41480},{"info_hash
":"7b9044c62bd15282dac822b60006ee623cf14de9","seeders"114,"leechers":14,"completed":18142},{"info_hash":"f821424e33a49ab
d8816823adbc03b340331c0af","seeders"158,"leechers":27,"completed":35183},{"info_hash":"c1ce06b0aee58b9ae5fce1dfc4a9d0ec8
e015a12","seeders"125,"leechers":20,"completed":34613},{"info_hash":"39f301178307b2e015f27e208a7aeb985dc13040","seeders"
126,"leechers":15,"completed":27801},{"info_hash":"8f6b5776fe53e71c5d417f3ebcd08c51fa7a82da","seeders"83,"leechers":13,"
completed":5181},{"info_hash":"79c25da699546296650a81413f8ada3a82d0eb38","seeders"153,"leechers":51,"completed":31032},{
"info_hash":"592b32cf0a987f3b9916ae66df24988ddcf01cd8","seeders"98,"leechers":13,"completed":57927},{"info_hash":"63dbb0
43444e96ebaf0cd544311d3afad86ea2cc","seeders"126,"leechers":10,"completed":26453},{"info_hash":"53a4a411decdaf7e1be91960
7b7a4187987bf0bb","seeders"141,"leechers":11,"completed":33939},{"info_hash":"9dda240e03be6dbf060e91abf66510fbc2c07654",
"seeders"136,"leechers":27,"completed":9641},{"info_hash":"76d81232944a6a0f03057e03f4fb1757029be26b","seeders"114,"leech
ers":44,"completed":22174},{"info_hash":"427893b6c4ed7f9be45d09e0f92e236278770822","seeders"123,"leechers":31,"completed
":28997},{"info_hash":"92ae1d715d996078e33581f2457344ee2034df2c","seeders"77,"leechers":13,"completed":6840},{"info_hash
":"ae6bbcf9270b44f3d2fd54f14e8933a7d68a4c84","seeders"98,"leechers":6,"completed":22489},{"info_hash":"ef4211584f37ca70a
4b1a2e47e7e833c79abacba","seeders"107,"leechers":115,"completed":16325},{"info_hash":"5156c2fa6f6901560bf030a5fb8efb7ecb
4b6644","seeders"77,"leechers":9,"completed":8452},{"info_hash":"bad9140f563172a1b85e29eb35f23455ea6ba9c2","seeders"120,
"leechers":27,"completed":12986},{"info_hash":"d1c5bd9a2eec5fe6eba19e7f663af3e8d932ab8e","seeders"219,"leechers":24,"com
pleted":55912},{"info_hash":"07e764190536559c2889ec98c1974c308373945a","seeders"111,"leechers":2,"completed":29633},{"in
fo_hash":"9922975f45404048e721dd834722357a762beddc","seeders"92,"leechers":5,"completed":22140},{"info_hash":"be55a6af73
30a00908c1a558880c06d8eea0805a","seeders"49,"leechers":4,"completed":29418},{"info_hash":"14fa0162a124da2a726f4570ab171e
3a942db5f8","seeders"77,"leechers":6,"completed":12550},{"info_hash":"cc6c0deab3bdd2210d9d65a22b3297f8360b3bb1","seeders
"71,"leechers":6,"completed":17380},{"info_hash":"2bc57f95604d4ab278e9605651ed801f3171ae2a","seeders"36,"leechers":0,"co
mpleted":4511},{"info_hash":"91a6e71c3588df1adbae1a97bf53b3e01db7ba9a","seeders"74,"leechers":5,"completed":28339},{"inf
o_hash":"650cb21e31b5a06a5fcb22bd5ba98c0ea9fa5624","seeders"102,"leechers":13,"completed":4069},{"info_hash":"24fe4224a4
294fabee15594ec4124608d56d9696","seeders"78,"leechers":8,"completed":7892},{"info_hash":"11fe2c5676748ca73ab7adf382174c1
0b28da681","seeders"77,"leechers":3,"completed":25787},{"info_hash":"2c9c0c414d712881572fa2a5ab3c5c1381348f0a","seeders"
73,"leechers":6,"completed":9506},{"info_hash":"2e5a7f8a673225e028f5b3e846ff070a78292108","seeders"72,"leechers":5,"comp
leted":18947},{"info_hash":"3576045f75ff2bbe5578b7a5a4fb106805c7c849","seeders"84,"leechers":3,"completed":11080},{"info
_hash":"917633b935c3ee71d51c79c24743dc67b0f50456","seeders"80,"leechers":2,"completed":10597},{"info_hash":"e0d5da1eb510
67045e315460fd58566cee3a35b7","seeders"76,"leechers":12,"completed":17065},{"info_hash":"0bbd527b8d610cb040ec2c6156fa18d
e7edfe0b5","seeders"92,"leechers":11,"completed":17605},{"info_hash":"0dbe51bcad46651133f8b90f4f7725a92fd7ebc0","seeders
"128,"leechers":18,"completed":13754},{"info_hash":"792be3f97363df1201102ed89a2cbc6cf439b9bb","seeders"69,"leechers":4,"
completed":13445},{"info_hash":"4863cbbc67e9aa39444771dbaa2b28266fea353a","seeders"14,"leechers":1,"completed":4923},{"i
nfo_hash":"aed06fe65a915ed8d3e5933462e387dc3ab4c5b6","seeders"73,"leechers":4,"completed":21296},{"info_hash":"e34446cd8
6f3981472b259d35f05fe2b9f4c57dc","seeders"67,"leechers":10,"completed":21322},{"info_hash":"497163ea78e823724b1cdaa1d6d8
8065afa1e2cb","seeders"47,"leechers":13,"completed":13926},{"info_hash":"803caadbaee1b71d6396ca536d757926419fbe5c","seed
ers"79,"leechers":1,"completed":3383},{"info_hash":"bcb23960cc16fcb2e76c6dddf65636d45e075175","seeders"81,"leechers":3,"
completed":15896},{"info_hash":"f1dc6a0623befe944feb967b9f58d3c6dc8aa90c","seeders"63,"leechers":4,"completed":17001},{"
info_hash":"5ebcda763a8fde8c282a6f2dbe40a23fef366e75","seeders"15,"leechers":2,"completed":2669},{"info_hash":"04f02a854
da07d76dfdbade90b913ad8d596c4bf","seeders"52,"leechers":7,"completed":9448},{"info_hash":"54d13ea46ea015b26666f2b7784343
731e053a13","seeders"79,"leechers":14,"completed":13810},{"info_hash":"4b3e7a69f376621d57dfd5e1b9c6b341e01e8a5b","seeder
s"84,"leechers":2,"completed":10407},{"info_hash":"7af70dc9f90156ad7d839545c4d8a8a558f56c1e","seeders"69,"leechers":7,"c
ompleted":19433},{"info_hash":"d8677f8d37528f0eaa48bb91740b4dab9288b4f1","seeders"58,"leechers":16,"completed":8123},{"i
nfo_hash":"26993329b98990d7b5d58109335c2d4341b5fb28","seeders"65,"leechers":55,"completed":2017},{"info_hash":"775c73fb4
b82fa4e4cea85d920eda592bd093818","seeders"81,"leechers":10,"completed":17294},{"info_hash":"dfbcaf43a2c5a4b7c6a5ad4921ff
85b3ae342123","seeders"71,"leechers":21,"completed":16872},{"info_hash":"7b337d59689c248705c7ff3473bb6f329807eb4b","seed
ers"64,"leechers":9,"completed":10148},{"info_hash":"4293e07264e265d2bcc756361c1461c8a67280bf","seeders"94,"leechers":7,
"completed":14030}]
Initialization time: 465400 ns
Hash parsing time: 9700 ns
Execution time: 234 ms

Process finished with exit code 0

```

Where my ping is:
```
PS C:\Users\user> ping opentrackr.org

Pinging opentrackr.org [93.158.213.92] with 32 bytes of data:
Reply from 93.158.213.92: bytes=32 time=112ms TTL=52
Reply from 93.158.213.92: bytes=32 time=112ms TTL=52
Reply from 93.158.213.92: bytes=32 time=115ms TTL=52
Reply from 93.158.213.92: bytes=32 time=112ms TTL=52

Ping statistics for 93.158.213.92:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 112ms, Maximum = 115ms, Average = 112ms
```

latency is the biggest problem as I'm in Canada and they're in Sweden.
