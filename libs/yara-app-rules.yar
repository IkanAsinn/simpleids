rule SQLi: mal
{
    meta:
        author = "Matthew Jang"
        maltype = "SQL Injection for MySQL, Oracle, SQL Server, etc."
        reference = "https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/#SyntaxBasicAttacks"
        description = "YARA rule to detect the most common SQL injection commands/strings"

    strings:
        $char1 = "1=1"                        // 1=1 is always true
        $char2 = "--"                         // line comments
        $char3 = "#"
        $str1 = "CONCAT" nocase               // for MySQL
        $str2 = "CHAR" nocase
        $str3 = "Hex" nocase
        $str4 = "admin' --"                   // bypassing login screen
        $str5 = "admin' #"
        $str6 = "admin' /*"                   
        $str7 = "MD5" nocase
        $str8 = "HAVING" nocase 
        $str9 = "ORDER BY" nocase
        $str10 = "CAST" nocase
        $str11 = "CONVERT" nocase
        $str12 = "@@version"
        $str13 = "bcp" nocase
        $str14 = "VERSION" nocase
        $str15 = "WHERE" nocase
        $str16 = "LIMIT" nocase
        $str17 = "EXEC" nocase 
        $str18 = "';shutdown --"
        $str19 = "WAITFOR DELAY" nocase
        $str20 = "NOT EXIST" nocase
        $str21 = "NOT IN" nocase
        $str22 = "BENCHMARK" nocase
        $str23 = "pg_sleep"
        $str24 = "sleep"                      // for MySQL
        $str25 = "--sp_password" nocase
        $str26 = "SHA1" nocase
        $str27 = "PASSWORD" nocase
        $str28 = "ENCODE" nocase
        $str29 = "COMPRESS" nocase
        $str30 = "SCHEME" nocase
        $str31 = "ROW_COUNT" nocase
        $str32 = "DROP members--" nocase
        $str33 = "ASCII" nocase
        $str34 = "UNION" nocase
        $str35 = "UNION SELECT" nocase
        $str36 = "INFORMATION" nocase
        $str37 = "SCHEMA" nocase
        $str38 = "INFORMATION_SCHEMA" nocase 

    condition:
        any of ($char1, $char2, $char3) and
        any of ($str1, $str2, $str3, $str4, $str5, $str6, $str7, $str8, $str9, $str10, $str11, $str12, $str13, $str14, $str15, $str16, $str17, $str18, $str19, $str20, $str21, $str22, $str23, $str24, $str25, $str26, $str27, $str28, $str29, $str30, $str31, $str32, $str33, $str34, $str35, $str36, $str37, $str38)
}



rule xss_multiple_payload_detection {
    meta:
        description = "Detect XSS attacks with specific payloads"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadAllTheThings"
        date = "2024-04-24"

    strings:
        $xss_payload1 = "<>" nocase
        $xss_payload2 = "script" nocase
        $xss_payload3 = "\" =\"\" '></><script></script><svg onload\"=\"alertonload=test\"\" onload=prompt`xss`>" nocase
        $xss_payload4 = "<script>alert('XSS')</script>"
        $xss_payload5 = "<scr<script>ipt>alert('XSS')</scr<script>ipt>"
        $xss_payload6 = "\"> <script>alert('XSS')</script>"
        $xss_payload7 = "\"> <script>alert(String.fromCharCode(88,83,83))</script>"
        $xss_payload8 = "<script>\\u0061lert('22')</script>"
        $xss_payload9 = "<script>eval('\\x61lert(\\'33\\')')</script>"
        $xss_payload10 = "<script>eval(8680439..toString(30))(983801..toString(36))</script>"
        $xss_payload11 = "<object/data=\"jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;\">"
        $xss_image_payload1 = "<img src=x onerror=alert('XSS');>"
        $xss_image_payload2 = "<img src=x onerror=alert('XSS')//"
        $xss_image_payload3 = "<img src=x onerror=alert(String.fromCharCode(88,83,83));>"
        $xss_image_payload4 = "<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>"
        $xss_image_payload5 = "<img src=x:alert(alt) onerror=eval(src) alt=xss>"
        $xss_image_payload6 = "\"> <img src=x onerror=alert('XSS');>"
        $xss_image_payload7 = "\"> <img src=x onerror=alert(String.fromCharCode(88,83,83));>"
        $xss_image_payload8 = "<><img src=1 onerror=alert(1)>"
        $xss_svg_payload1 = "<svgonload=alert(1)>"
        $xss_svg_payload2 = "<svg/onload=alert('XSS')>"
        $xss_svg_payload3 = "<svg onload=alert(1)//"
        $xss_svg_payload4 = "<svg/onload=alert(String.fromCharCode(88,83,83))>"
        $xss_svg_payload5 = "<svg id=alert(1) onload=eval(id)>"
        $xss_svg_payload6 = "\"> <svg/onload=alert(String.fromCharCode(88,83,83))>"
        $xss_svg_payload7 = "\"> <svg/onload=alert(/XSS/)>"
        $xss_svg_payload8 = "<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)"
        $xss_svg_payload9 = "<svg><script>alert('33')"
        $xss_svg_payload10 = "<svg><script>alert&lpar;'33'&rpar;"

        $additional_payload1 = "<script>alert(123);</script>"
        $additional_payload2 = "<ScRipT>alert(\"XSS\");</ScRipT>"
        $additional_payload3 = "<script>alert(123)</script>"
        $additional_payload4 = "<script>alert(\"hellox worldss\");</script>"
        $additional_payload5 = "<script>alert(“XSS”)</script>"
        $additional_payload6 = "<script>alert(“XSS”);</script>"
        $additional_payload7 = "<script>alert(‘XSS’)</script>"
        $additional_payload8 = "\" ><script>alert(“XSS”)</script>"
        $additional_payload9 = "<script>alert(/XSS”)</script>"
        $additional_payload10 = "<script>alert(/XSS/)</script>"
        $additional_payload11 = "</script><script>alert(1)</script>"
        $additional_payload12 = "'; alert(1);"
        $additional_payload13 = "')alert(1);//"
        $additional_payload14 = "<ScRiPt>alert(1)</sCriPt>"
        $additional_payload15 = "<IMG SRC=jAVasCrIPt:alert(‘XSS’)>"
        $additional_payload16 = "<IMG SRC=”javascript:alert(‘XSS’);”>"
        $additional_payload17 = "<IMG SRC=javascript:alert(&quot;XSS&quot;)>"
        $additional_payload18 = "<IMG SRC=javascript:alert(‘XSS’)>"
        $additional_payload19 = "<img src=xss onerror=alert(1)>"

    condition:
        any of ($xss_payload*) or any of ($xss_image_payload*) or any of ($xss_svg_payload*) or any of ($additional_payload*)
}

rule detect_xss_payloads_bypass_with_condition_and_bypass_HTML5 {
    meta:
        description = "Detect various XSS payloads"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadAllTheThings"
        date = "2024-04-25"

    strings:
        $xss_payload1 = "<body onload=alert(/XSS/.source)>"
        $xss_payload2 = "<input autofocus onfocus=alert(1)>"
        $xss_payload3 = "<select autofocus onfocus=alert(1)>"
        $xss_payload4 = "<textarea autofocus onfocus=alert(1)>"
        $xss_payload5 = "<keygen autofocus onfocus=alert(1)>"
        $xss_payload6 = "<video/poster/onerror=alert(1)>"
        $xss_payload7 = "<video><source onerror=\"javascript:alert(1)\">"
        $xss_payload8 = "<video src=_ onloadstart=\"alert(1)\">"
        $xss_payload9 = "<details/open/ontoggle=\"alert`1`\">"
        $xss_payload10 = "<audio src onloadstart=alert(1)>"
        $xss_payload11 = "<marquee onstart=alert(1)>"
        $xss_payload12 = "<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>"
        $xss_payload13 = "<body ontouchstart=alert(1)>"
        $xss_payload14 = "<body ontouchend=alert(1)>"
        $xss_payload15 = "<body ontouchmove=alert(1)>"

        $bypass_payload1 = "<sCrIpt>alert(1)</ScRipt>" nocase
        $bypass_payload2 = "<script x>" nocase
        $bypass_payload3 = "<script x>alert('XSS')"
        $bypass_payload4 = "eval('ale'+'rt(0)');" nocase
        $bypass_payload5 = "Function(\"ale\"+\"rt(1)\")();" nocase
        $bypass_payload6 = "new Function`al\\ert\\`6\\``;" nocase
        $bypass_payload7 = "setTimeout('ale'+'rt(2)');" nocase
        $bypass_payload8 = "setInterval('ale'+'rt(10)');" nocase
        $bypass_payload9 = "Set.constructor('ale'+'rt(13)')();" nocase
        $bypass_payload10 = "Set.constructor`al\\x65rt\\x2814\\x29```;" nocase
        $bypass_payload11 = "<script>window['alert'](document['domain'])</script>" nocase
        $bypass_payload12 = "<img/src='1'/onerror=alert(0)>" nocase

    condition:
        any of ($xss_payload*) or any of ($bypass_payload*)
}