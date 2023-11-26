这是一个xxe生成payload脚本，使用python3，写的很简单。payload使用的是https://github.com/payloadbox/xxe-injection-payload-list/tree/master/Intruder

后期感觉xxe注入测试不如直接从payload表中单独一个个进行加工，尤其是需要目录扫描的，可以写脚本生成payload表(win/lin常见目录)。输入到burpsuite进行批量测试。