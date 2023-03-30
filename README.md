# Mys_C2Exchange
Simple C2 via MS Exchange to evade AV and bypass network policy.  

__This repo was created for the purpose of research and organization protection via RedTeaming. Using this software for illegal purposes or profit is strictly prohibited. Besides that, publishing unauthorized modified version is also prohibited, or otherwise bear legal responsibilities.__  


### How to use
- Start C2 server:
```
cd ccserver
go run .
```
- Type "help" for more information.
- Build beacon.
- Upload and run the beacon in target.  

### Build beacon
- Change ListenerId and private key in main.go.
- Build the beacon with garble to evade AV.
```
garble build [build flags] [packages]
```  

#### Happy hacking 🎉🎉🎉
